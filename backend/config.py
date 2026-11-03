# =============================================================================
# config.py — Centralised application configuration
# =============================================================================
import os
import re
import warnings

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _clean_mongo_uri(raw_uri: str) -> str:
    uri = (raw_uri or "").strip()
    while uri.startswith("MONGODB_URI="):
        uri = uri[len("MONGODB_URI="):].strip()
    return uri or "mongodb://127.0.0.1:27017/securecloud"


def _parse_csv_env(key: str, default_values: list[str]) -> list[str]:
    value = os.environ.get(key, "").strip()
    if not value:
        return default_values
    return [item.strip() for item in value.split(",") if item.strip()]


def mask_secret(value: str | None, show_chars: int = 3) -> str:
    """Safely mask a secret string for logging or reports without revealing contents."""
    if not value:
        return "<unset>"
    if len(value) <= show_chars * 2:
        return "***"
    return f"{value[:show_chars]}***{value[-show_chars:]}"


def mask_uri(raw_uri: str) -> str:
    """Mask credentials in MongoDB or connection URIs."""
    if not raw_uri:
        return "<empty>"
    # Replace ://user:password@ with ://user:***@
    return re.sub(r"://([^:@\s]+):([^@\s]+)@", r"://\1:***@", raw_uri)


class Config:
    """Application-wide configuration loaded from environment variables."""

    # Environment
    ENV = os.environ.get("FLASK_ENV") or os.environ.get("ENV") or "development"
    IS_PRODUCTION = ENV.lower() in ("production", "prod")

    # Flask core secrets
    _DEV_SECRET = "dev-secret-key-change-me"
    _DEV_JWT_SECRET = "dev-jwt-key-change-me"

    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    if not SECRET_KEY:
        if IS_PRODUCTION:
            raise RuntimeError("CRITICAL: SECRET_KEY must be set to a secure string in production.")
        SECRET_KEY = _DEV_SECRET

    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
    if not JWT_SECRET_KEY:
        if IS_PRODUCTION:
            raise RuntimeError("CRITICAL: JWT_SECRET_KEY must be set to a secure string in production.")
        JWT_SECRET_KEY = _DEV_JWT_SECRET

    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
    JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "24"))

    # Rate limiting for auth
    AUTH_RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get("AUTH_RATE_LIMIT_MAX_ATTEMPTS", "5"))
    AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("AUTH_RATE_LIMIT_WINDOW_SECONDS", "60"))

    # MongoDB
    MONGODB_URI = _clean_mongo_uri(os.environ.get("MONGODB_URI", "mongodb://127.0.0.1:27017/securecloud"))
    MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "securecloud")

    # Backblaze B2 (S3-compatible) Object Storage
    B2_KEY_ID = os.environ.get("B2_KEY_ID") or os.environ.get("AWS_ACCESS_KEY", "")
    B2_APPLICATION_KEY = os.environ.get("B2_APPLICATION_KEY") or os.environ.get("AWS_SECRET_KEY", "")
    B2_BUCKET_NAME = os.environ.get("B2_BUCKET_NAME") or os.environ.get("BUCKET_NAME", "secure-cloud-files-demo")
    B2_ENDPOINT_URL = os.environ.get("B2_ENDPOINT_URL", "https://s3.us-east-005.backblazeb2.com")

    # AWS S3 compatibility aliases
    AWS_ACCESS_KEY = B2_KEY_ID
    AWS_SECRET_KEY = B2_APPLICATION_KEY
    BUCKET_NAME = B2_BUCKET_NAME
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-005")

    # CORS
    _DEFAULT_DEV_CORS = [
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:5000",
        "http://localhost:5000",
    ]
    CORS_ORIGINS = _parse_csv_env("CORS_ORIGINS", _DEFAULT_DEV_CORS)

    # Admin access configuration
    _DEFAULT_ADMIN_EMAILS = ["admin@securecloud.com"]
    ADMIN_EMAILS = [email.lower() for email in _parse_csv_env("ADMIN_EMAILS", _DEFAULT_ADMIN_EMAILS)]

    # Upload limits: 70MB request body allows full 50MB encrypted payload + Base64 overhead
    MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE", str(50 * 1024 * 1024)))
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(70 * 1024 * 1024)))

    @classmethod
    def validate(cls) -> dict:
        """Validate configuration health without leaking secret values."""
        issues = []
        warnings_list = []

        if cls.IS_PRODUCTION:
            if cls.SECRET_KEY == cls._DEV_SECRET or len(cls.SECRET_KEY) < 16:
                issues.append("SECRET_KEY is insecure or using default dev key in production")
            if cls.JWT_SECRET_KEY == cls._DEV_JWT_SECRET or len(cls.JWT_SECRET_KEY) < 16:
                issues.append("JWT_SECRET_KEY is insecure or using default dev key in production")
            if "*" in cls.CORS_ORIGINS:
                issues.append("CORS_ORIGINS must not contain wildcard '*' in production")
        else:
            if cls.SECRET_KEY == cls._DEV_SECRET:
                warnings_list.append("Using default dev SECRET_KEY")
            if cls.JWT_SECRET_KEY == cls._DEV_JWT_SECRET:
                warnings_list.append("Using default dev JWT_SECRET_KEY")

        if not cls.MONGODB_URI:
            issues.append("MONGODB_URI is not set")

        b2_configured = bool(cls.B2_KEY_ID and cls.B2_APPLICATION_KEY and cls.B2_BUCKET_NAME)
        if not b2_configured:
            warnings_list.append("Backblaze B2 is not fully configured (storage operations will be unavailable)")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings_list,
            "b2_configured": b2_configured,
            "environment": cls.ENV,
            "mongo_uri_masked": mask_uri(cls.MONGODB_URI),
            "b2_bucket": cls.B2_BUCKET_NAME if b2_configured else "<not configured>",
        }
