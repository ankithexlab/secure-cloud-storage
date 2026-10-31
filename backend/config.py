# =============================================================================
# config.py — Centralised application configuration
# =============================================================================
import os

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


class Config:
    """Application-wide configuration loaded from environment variables."""

    # Flask core
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-jwt-key-change-me")
    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
    JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "24"))

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
    CORS_ORIGINS = _parse_csv_env(
        "CORS_ORIGINS",
        [
            "http://127.0.0.1:3000",
            "http://localhost:3000",
            "https://secure-cloud.vercel.app",
        ],
    )

    # Upload limits
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024)))
