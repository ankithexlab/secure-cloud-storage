# =============================================================================
# utils/auth_helpers.py — JWT creation / validation & password hashing
# =============================================================================
from datetime import datetime, timezone, timedelta
from functools import wraps

import bcrypt
import jwt
from flask import request, jsonify

from config import Config


# ---------------------------------------------------------------------------
# Password hashing (bcrypt)
# ---------------------------------------------------------------------------
def hash_password(plain: str) -> str:
    """Return a bcrypt hash of the plaintext password."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # Invalid hash format in DB
        return False


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def create_jwt(user_id: str, email: str) -> str:
    """Issue a signed JWT containing user identity claims."""
    payload = {
        "sub": user_id,
        "email": email,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc)
        + timedelta(hours=Config.JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)


def decode_jwt(token: str) -> dict | None:
    """Decode and validate a JWT. Returns the payload or None."""
    try:
        return jwt.decode(
            token, Config.JWT_SECRET_KEY, algorithms=[Config.JWT_ALGORITHM]
        )
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def decode_jwt_with_reason(token: str) -> tuple[dict | None, str | None]:
    """Decode JWT and return (payload, error_code)."""
    try:
        payload = jwt.decode(
            token,
            Config.JWT_SECRET_KEY,
            algorithms=[Config.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "token_expired"
    except jwt.InvalidTokenError:
        return None, "token_invalid"


# ---------------------------------------------------------------------------
# Flask decorator — protects routes
# ---------------------------------------------------------------------------
def jwt_required(f):
    """Decorator that enforces a valid Bearer token on the request."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
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

        token = auth_header.split(" ", 1)[1]
        payload, reason = decode_jwt_with_reason(token)
        if payload is None:
            msg = "Token expired" if reason == "token_expired" else "Token invalid"
            return jsonify({"success": False, "code": reason, "msg": msg}), 401

        # Attach user info to request context
        request.user_id = str(payload.get("sub", ""))
        request.user_email = payload.get("email", "")
        return f(*args, **kwargs)

    return decorated
