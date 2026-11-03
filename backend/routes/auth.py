# =============================================================================
# routes/auth.py — Registration, Login, Logout & Account endpoints
# =============================================================================
from datetime import datetime, timezone
import re
from flask import Blueprint, request, jsonify
from pymongo.errors import DuplicateKeyError

from utils.db import (
    get_user_by_email,
    create_user,
    update_user_last_login,
    update_user_password,
    revoke_token,
)
from utils.auth_helpers import hash_password, check_password, create_jwt, jwt_required
from utils.rate_limit import login_rate_limiter, register_rate_limiter
from utils.audit import (
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSeverity,
    check_suspicious_login_activity,
    is_admin_user,
    record_audit_event,
)

auth_bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# Input validation limits and patterns
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
MIN_PASSWORD_LEN = 6
MAX_PASSWORD_LEN = 128
MAX_EMAIL_LEN = 254

# Constant dummy bcrypt hash (cost 12) used to equalize execution time and prevent timing attacks
DUMMY_BCRYPT_HASH = "$2b$12$e80e1y3/E6t3iP8JgQG3QO9s4u8h7dG0F2G4V6B8N0M2Q4W6E8R0T"


def _validate_auth_input(data: dict) -> tuple[str | None, str | None, str | None]:
    """
    Validate email and password input safely.
    Returns (email, password, error_message).
    """
    if not isinstance(data, dict):
        return None, None, "Invalid request payload format"

    email_raw = data.get("email")
    password_raw = data.get("password")

    if email_raw is None or not isinstance(email_raw, str):
        return None, None, "Email is required"
    if password_raw is None or not isinstance(password_raw, str):
        return None, None, "Password is required"

    email = email_raw.strip().lower()
    password = password_raw

    if not email:
        return None, None, "Email cannot be empty"
    if len(email) > MAX_EMAIL_LEN:
        return None, None, f"Email must not exceed {MAX_EMAIL_LEN} characters"
    if not EMAIL_RE.match(email):
        return None, None, "Invalid email format"

    if not password:
        return None, None, "Password cannot be empty"
    if len(password) < MIN_PASSWORD_LEN:
        return None, None, f"Password must be at least {MIN_PASSWORD_LEN} characters"
    if len(password) > MAX_PASSWORD_LEN:
        return None, None, f"Password must not exceed {MAX_PASSWORD_LEN} characters"
    if not any(char.isdigit() for char in password):
        return None, None, "Password must contain at least 1 number"

    return email, password, None


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------
@auth_bp.route("/register", methods=["POST"])
def register():
    """Create a new user account with rate limiting and return a JWT."""
    ip = request.remote_addr or "127.0.0.1"
    ip_key = f"reg_ip:{ip}"

    # Rate limiting on registration to prevent account-creation flooding
    is_limited, retry_after = register_rate_limiter.is_rate_limited(ip_key)
    if is_limited:
        record_audit_event(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            outcome=AuditOutcome.BLOCKED,
            severity=AuditSeverity.WARNING,
            resource_type=AuditResourceType.AUTH,
            details={"action": "register", "retry_after": retry_after},
            request_obj=request,
        )
        resp = jsonify(
            {
                "success": False,
                "msg": f"Too many registration attempts. Please try again in {retry_after} seconds.",
                "error": "Rate limit exceeded",
                "retry_after": retry_after,
            }
        )
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    register_rate_limiter.record_failure(ip_key)

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"success": False, "msg": "Malformed JSON payload", "error": "Malformed JSON payload"}), 400

    email, password, err = _validate_auth_input(data)
    if err:
        return jsonify({"success": False, "msg": err, "error": err}), 400

    if get_user_by_email(email):
        return jsonify({"success": False, "msg": "User already exists", "error": "User already exists"}), 409

    hashed = hash_password(password)
    try:
        user = create_user(email, hashed)
    except DuplicateKeyError:
        return jsonify({"success": False, "msg": "User already exists", "error": "User already exists"}), 409

    user_id = str(user["_id"])
    token = create_jwt(user_id, email)
    is_admin = is_admin_user(user)

    record_audit_event(
        event_type=AuditEventType.USER_REGISTER,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=user_id,
        user_email=email,
        resource_id=user_id,
        resource_type=AuditResourceType.AUTH,
        details={"status": "registered"},
        request_obj=request,
    )

    return (
        jsonify(
            {
                "success": True,
                "msg": "Registration successful",
                "token": token,
                "user": {"id": user_id, "email": email, "is_admin": is_admin, "role": "admin" if is_admin else "user"},
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# POST /login
# ---------------------------------------------------------------------------
@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate user credentials with rate limiting and return a JWT."""
    ip = request.remote_addr or "127.0.0.1"
    ip_key = f"ip:{ip}"

    # Check IP-level rate limiting before processing
    is_limited, retry_after = login_rate_limiter.is_rate_limited(ip_key)
    if is_limited:
        record_audit_event(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            outcome=AuditOutcome.BLOCKED,
            severity=AuditSeverity.CRITICAL,
            resource_type=AuditResourceType.AUTH,
            details={"action": "login_ip_limit", "retry_after": retry_after},
            request_obj=request,
        )
        resp = jsonify(
            {
                "success": False,
                "msg": f"Too many failed attempts. Please try again in {retry_after} seconds.",
                "error": "Rate limit exceeded",
                "retry_after": retry_after,
            }
        )
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"success": False, "msg": "Malformed JSON payload", "error": "Malformed JSON payload"}), 400

    email, password, err = _validate_auth_input(data)
    if err:
        return jsonify({"success": False, "msg": err, "error": err}), 400

    email_key = f"email:{email}"
    is_email_limited, retry_after_email = login_rate_limiter.is_rate_limited(email_key)
    if is_email_limited:
        record_audit_event(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            outcome=AuditOutcome.BLOCKED,
            severity=AuditSeverity.CRITICAL,
            user_email=email,
            resource_type=AuditResourceType.AUTH,
            details={"action": "login_email_limit", "retry_after": retry_after_email},
            request_obj=request,
        )
        resp = jsonify(
            {
                "success": False,
                "msg": f"Too many failed attempts for this account. Please try again in {retry_after_email} seconds.",
                "error": "Rate limit exceeded",
                "retry_after": retry_after_email,
            }
        )
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after_email)
        return resp

    user = get_user_by_email(email)
    pwd_to_check = user["password"] if user else DUMMY_BCRYPT_HASH
    valid_pwd = check_password(password, pwd_to_check)
    if not user or not valid_pwd:
        # Record failure for both IP and email
        login_rate_limiter.record_failure(ip_key)
        login_rate_limiter.record_failure(email_key)

        record_audit_event(
            event_type=AuditEventType.LOGIN_FAILED,
            outcome=AuditOutcome.FAILURE,
            severity=AuditSeverity.WARNING,
            user_email=email,
            resource_type=AuditResourceType.AUTH,
            details={"reason": "Invalid credentials", "email": email},
            request_obj=request,
        )
        check_suspicious_login_activity(ip, email, request_obj=request)

        return jsonify({"success": False, "msg": "Invalid email or password", "error": "Invalid email or password"}), 401

    # Successful login: reset rate limit counters
    login_rate_limiter.reset(ip_key)
    login_rate_limiter.reset(email_key)

    update_user_last_login(email)
    user_id = str(user["_id"])
    token = create_jwt(user_id, email)
    is_admin = is_admin_user(user)

    record_audit_event(
        event_type=AuditEventType.LOGIN_SUCCESS,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=user_id,
        user_email=email,
        resource_id=user_id,
        resource_type=AuditResourceType.AUTH,
        details={"status": "authenticated"},
        request_obj=request,
    )

    return jsonify(
        {
            "success": True,
            "msg": "Login successful",
            "token": token,
            "user": {"id": user_id, "email": email, "is_admin": is_admin, "role": "admin" if is_admin else "user"},
        }
    )


# ---------------------------------------------------------------------------
# GET /me — Authenticated user profile and session verification
# ---------------------------------------------------------------------------
@auth_bp.route("/me", methods=["GET"])
@auth_bp.route("/user", methods=["GET"])
@jwt_required
def me():
    """Return identity claims for the authenticated user session."""
    user = get_user_by_email(request.user_email)
    if not user:
        return jsonify({"success": False, "msg": "User account not found"}), 404

    created_at = user.get("created_at")
    last_login = user.get("last_login")
    is_admin = is_admin_user(user)

    return jsonify(
        {
            "success": True,
            "user": {
                "id": str(user["_id"]),
                "email": user["email"],
                "is_admin": is_admin,
                "role": "admin" if is_admin else "user",
                "created_at": created_at.isoformat() if isinstance(created_at, datetime) else str(created_at) if created_at else None,
                "last_login": last_login.isoformat() if isinstance(last_login, datetime) else str(last_login) if last_login else None,
            },
        }
    ), 200


# ---------------------------------------------------------------------------
# POST /change-password
# ---------------------------------------------------------------------------
@auth_bp.route("/change-password", methods=["POST"])
@jwt_required
def change_password():
    """Update user account password with verification of current password."""
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""

    if not isinstance(old_password, str) or not old_password:
        return jsonify({"success": False, "msg": "Current password is required"}), 400
    if not isinstance(new_password, str) or not new_password:
        return jsonify({"success": False, "msg": "New password is required"}), 400

    if len(new_password) < MIN_PASSWORD_LEN:
        return jsonify({"success": False, "msg": f"New password must be at least {MIN_PASSWORD_LEN} characters"}), 400
    if len(new_password) > MAX_PASSWORD_LEN:
        return jsonify({"success": False, "msg": f"New password must not exceed {MAX_PASSWORD_LEN} characters"}), 400
    if not any(char.isdigit() for char in new_password):
        return jsonify({"success": False, "msg": "New password must contain at least 1 number"}), 400
    if old_password == new_password:
        return jsonify({"success": False, "msg": "New password must be different from current password"}), 400

    user = get_user_by_email(request.user_email)
    if not user or not check_password(old_password, user["password"]):
        record_audit_event(
            event_type=AuditEventType.PASSWORD_CHANGE_FAILED,
            outcome=AuditOutcome.FAILURE,
            severity=AuditSeverity.WARNING,
            user_id=request.user_id,
            user_email=request.user_email,
            resource_type=AuditResourceType.AUTH,
            details={"reason": "Incorrect current password"},
            request_obj=request,
        )
        return jsonify({"success": False, "msg": "Incorrect current password"}), 401

    new_hash = hash_password(new_password)
    update_user_password(request.user_email, new_hash)

    # Revoke current token and return newly issued token
    token_hash = getattr(request, "token_hash", None)
    payload = getattr(request, "token_payload", {}) or {}
    exp_ts = payload.get("exp")
    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else datetime.now(timezone.utc)
    if token_hash:
        revoke_token(token_hash, expires_at)

    new_token = create_jwt(request.user_id, request.user_email)

    record_audit_event(
        event_type=AuditEventType.PASSWORD_CHANGE_SUCCESS,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=request.user_id,
        user_email=request.user_email,
        resource_type=AuditResourceType.AUTH,
        details={"status": "Password changed successfully"},
        request_obj=request,
    )

    return jsonify({"success": True, "msg": "Password updated successfully", "token": new_token}), 200


# ---------------------------------------------------------------------------
# POST /logout
# ---------------------------------------------------------------------------
@auth_bp.route("/logout", methods=["POST"])
@jwt_required
def logout():
    """Revoke the current JWT session."""
    token_hash = getattr(request, "token_hash", None)
    payload = getattr(request, "token_payload", {}) or {}

    exp_ts = payload.get("exp")
    if exp_ts:
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
    else:
        expires_at = datetime.now(timezone.utc)

    if token_hash:
        revoke_token(token_hash, expires_at)

    record_audit_event(
        event_type=AuditEventType.LOGOUT,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=request.user_id,
        user_email=request.user_email,
        resource_type=AuditResourceType.AUTH,
        details={"action": "User logged out"},
        request_obj=request,
    )

    return jsonify({"success": True, "msg": "Logged out successfully"}), 200
