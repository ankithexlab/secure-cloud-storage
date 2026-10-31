# =============================================================================
# routes/auth.py — Registration & Login endpoints
# =============================================================================
import re
from flask import Blueprint, request, jsonify

from utils.db import get_user_by_email, create_user, update_user_last_login
from utils.auth_helpers import hash_password, check_password, create_jwt

auth_bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
MIN_PASSWORD_LEN = 6


def _validate_auth_input(data: dict) -> tuple[str | None, str | None, str | None]:
    """Return (email, password, error_message)."""
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email:
        return None, None, "Email is required"
    if not EMAIL_RE.match(email):
        return None, None, "Invalid email format"
    if not password:
        return None, None, "Password is required"
    if len(password) < MIN_PASSWORD_LEN:
        return None, None, f"Password must be at least {MIN_PASSWORD_LEN} characters"
    if not any(char.isdigit() for char in password):
        return None, None, "Password must contain at least 1 number"

    return email, password, None


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------
@auth_bp.route("/register", methods=["POST"])
def register():
    """Create a new user account and return a JWT."""
    data = request.get_json(silent=True) or {}
    email, password, err = _validate_auth_input(data)
    if err:
        return jsonify({"success": False, "msg": err, "error": err}), 400

    if get_user_by_email(email):
        return jsonify({"success": False, "msg": "User already exists", "error": "User already exists"}), 409

    hashed = hash_password(password)
    user = create_user(email, hashed)
    user_id = str(user["_id"])

    token = create_jwt(user_id, email)

    return (
        jsonify(
            {
                "success": True,
                "msg": "Registration successful",
                "token": token,
                "user": {"id": user_id, "email": email},
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# POST /login
# ---------------------------------------------------------------------------
@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate user credentials and return a JWT."""
    data = request.get_json(silent=True) or {}
    email, password, err = _validate_auth_input(data)
    if err:
        return jsonify({"success": False, "msg": err, "error": err}), 400

    user = get_user_by_email(email)
    if not user or not check_password(password, user["password"]):
        return jsonify({"success": False, "msg": "Invalid email or password", "error": "Invalid email or password"}), 401

    update_user_last_login(email)
    user_id = str(user["_id"])
    token = create_jwt(user_id, email)

    return jsonify(
        {
            "success": True,
            "msg": "Login successful",
            "token": token,
            "user": {"id": user_id, "email": email},
        }
    )
