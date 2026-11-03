# =============================================================================
# utils/auth_helpers.py — JWT creation / validation & password hashing
# =============================================================================
from datetime import datetime, timezone, timedelta
from functools import wraps
import hashlib
import uuid

import bcrypt
import jwt
from flask import request, jsonify

from config import Config
from utils.db import is_token_revoked


# ---------------------------------------------------------------------------
# Password hashing (bcrypt)
# ---------------------------------------------------------------------------
def hash_password(plain: str) -> str:
    """Return a bcrypt hash of the plaintext password."""
    if not plain:
        raise ValueError("Password cannot be empty")
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        # Invalid hash format in DB
        return False


# ---------------------------------------------------------------------------
# Token hashing (for revocation indexing without storing raw JWTs)
# ---------------------------------------------------------------------------
def hash_token(token: str) -> str:
    """Compute a SHA-256 hash of the token for revocation storage."""
    return hashlib.sha256((token or "").strip().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def create_jwt(user_id: str, email: str) -> str:
    """Issue a signed JWT containing user identity claims."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email.strip().lower(),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(hours=Config.JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)


def decode_jwt(token: str) -> dict | None:
    """Decode and validate a JWT. Returns the payload or None."""
    payload, _ = decode_jwt_with_reason(token)
    return payload


def decode_jwt_with_reason(token: str) -> tuple[dict | None, str | None]:
    """Decode JWT and return (payload, error_code)."""
    if not token or not isinstance(token, str) or len(token) > 4096:
        return None, "token_invalid"
    try:
        payload = jwt.decode(
            token,
            Config.JWT_SECRET_KEY,
            algorithms=[Config.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
        if not payload.get("sub") or not payload.get("email"):
            return None, "token_invalid"
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "token_expired"
    except jwt.InvalidTokenError:
        return None, "token_invalid"
    except Exception:
        return None, "token_invalid"


# ---------------------------------------------------------------------------
# Flask decorator — protects routes
# ---------------------------------------------------------------------------
def jwt_required(f):
    """Decorator that enforces a valid, non-revoked Bearer token on the request."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header or not auth_header.startswith("Bearer "):
            return (
                jsonify(
                    {
                        "success": False,
                        "code": "missing_token",
                        "msg": "Missing or invalid token",
                    }
                ),
                401,
            )

        parts = auth_header.split(" ", 1)
        token = parts[1].strip() if len(parts) > 1 else ""
        if not token:
            return jsonify({"success": False, "code": "missing_token", "msg": "Missing token"}), 401

        if len(token) > 4096:
            return jsonify({"success": False, "code": "token_invalid", "msg": "Token invalid"}), 401

        # Check if token is revoked
        t_hash = hash_token(token)
        if is_token_revoked(t_hash):
            return (
                jsonify(
                    {
                        "success": False,
                        "code": "token_revoked",
                        "msg": "Session has expired or token was revoked. Please log in again.",
                    }
                ),
                401,
            )

        payload, reason = decode_jwt_with_reason(token)
        if payload is None:
            msg = "Token expired" if reason == "token_expired" else "Token invalid"
            return jsonify({"success": False, "code": reason, "msg": msg}), 401

        # Attach user info to request context
        request.user_id = str(payload.get("sub", ""))
        request.user_email = payload.get("email", "").strip().lower()
        request.token = token
        request.token_hash = t_hash
        request.token_payload = payload
        return f(*args, **kwargs)

    return decorated
