# =============================================================================
# utils/s3.py — Backblaze B2 (S3-compatible) upload / download / delete helpers
# =============================================================================
import re
import uuid
from pathlib import Path

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    NoCredentialsError,
    PartialCredentialsError,
    ReadTimeoutError,
)

from config import Config

_client = None


# ---------------------------------------------------------------------------
# Storage Exception Hierarchy
# ---------------------------------------------------------------------------
class StorageError(Exception):
    """Base exception for cloud storage operations."""
    def __init__(self, message: str = "Cloud storage error"):
        super().__init__(message)
        self.message = message


class StorageNotFoundError(StorageError):
    """Raised when an object or bucket is not found (404 / NoSuchKey)."""
    def __init__(self, message: str = "Storage object not found"):
        super().__init__(message)


class StorageAuthError(StorageError):
    """Raised when credentials or authentication to storage fails (403 / InvalidAccessKeyId)."""
    def __init__(self, message: str = "Cloud storage authentication failed"):
        super().__init__(message)


class StorageTimeoutError(StorageError):
    """Raised when storage network operations time out."""
    def __init__(self, message: str = "Storage operation timed out"):
        super().__init__(message)


# ---------------------------------------------------------------------------
# Configuration & Client Initialization
# ---------------------------------------------------------------------------
def _ensure_s3_config() -> None:
    if not Config.B2_BUCKET_NAME:
        raise StorageAuthError("Backblaze B2 bucket name is missing")
    if not Config.B2_KEY_ID or not Config.B2_APPLICATION_KEY:
        raise StorageAuthError("Backblaze B2 credentials are not configured")


def _get_client():
    global _client
    if _client is None:
        _ensure_s3_config()
        _client = boto3.client(
            "s3",
            endpoint_url=Config.B2_ENDPOINT_URL,
            aws_access_key_id=Config.B2_KEY_ID,
            aws_secret_access_key=Config.B2_APPLICATION_KEY,
            region_name=getattr(Config, "AWS_REGION", "us-east-005"),
            config=BotoConfig(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=10,
                read_timeout=30,
            ),
        )
    return _client


def check_b2_connection() -> dict:
    """
    Verify connectivity and configuration of the Backblaze B2 bucket.
    Returns: {"connected": bool, "bucket": str, "error": str | None}
    """
    try:
        _ensure_s3_config()
        client = _get_client()
        client.head_bucket(Bucket=Config.B2_BUCKET_NAME)
        return {"connected": True, "bucket": Config.B2_BUCKET_NAME, "error": None}
    except StorageAuthError as exc:
        return {"connected": False, "bucket": Config.B2_BUCKET_NAME, "error": exc.message}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        return {"connected": False, "bucket": Config.B2_BUCKET_NAME, "error": f"B2 error: {code}"}
    except Exception as exc:
        return {"connected": False, "bucket": Config.B2_BUCKET_NAME, "error": str(exc)}


# ---------------------------------------------------------------------------
# Sanitization Utilities
# ---------------------------------------------------------------------------
def _safe_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and invalid characters."""
    raw = str(filename or "file.bin").strip()
    # Extract only the base name (strips ../, /path/to/, and C:\path\to\)
    cleaned = Path(raw).name.strip()
    # Strip null bytes, control chars, slashes, backslashes, colons, asterisks, quotes, pipes, angle brackets
    cleaned = re.sub(r"[\x00-\x1f\x7f/\\:\*\?\"<>\|]", "", cleaned)
    # Strip leading/trailing dots and spaces
    cleaned = cleaned.strip(". ")
    if not cleaned:
        cleaned = "file.bin"
    # Truncate to reasonable length (preserving extension)
    if len(cleaned) > 200:
        stem = Path(cleaned).stem[:180]
        ext = Path(cleaned).suffix[:20]
        cleaned = f"{stem}{ext}"
    return cleaned or "file.bin"


def _safe_mime_type(mime_type: str | None) -> str:
    """Sanitize MIME type to prevent HTTP response header injection (CRLF)."""
    raw = str(mime_type or "application/octet-stream").strip()
    if re.match(r"^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$", raw) and len(raw) <= 100:
        return raw.lower()
    return "application/octet-stream"


# ---------------------------------------------------------------------------
# Storage Operations
# ---------------------------------------------------------------------------
def upload_bytes_to_s3(data: bytes, filename: str, mime_type: str = "application/octet-stream") -> str:
    """Upload raw encrypted bytes to Backblaze B2 and return the unique object key."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Upload payload must be bytes")
    payload = bytes(data)
    if len(payload) == 0:
        raise ValueError("Refusing to upload empty payload")

    client = _get_client()
    safe_name = _safe_filename(filename)
    safe_mime = _safe_mime_type(mime_type)
    object_key = f"encrypted/{uuid.uuid4().hex}_{safe_name}"
    try:
        client.put_object(
            Bucket=Config.B2_BUCKET_NAME,
            Key=object_key,
            Body=payload,
            ContentType=safe_mime,
            ContentLength=len(payload),
        )
        return object_key
    except (NoCredentialsError, PartialCredentialsError):
        raise StorageAuthError("Backblaze B2 credentials are not configured")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidAccessKeyId", "SignatureDoesNotMatch", "AccessDenied", "AuthFailure"):
            raise StorageAuthError("Cloud storage authentication failed")
        if code in ("RequestTimeout", "SocketTimeout"):
            raise StorageTimeoutError("Storage upload timed out")
        raise StorageError(f"B2 upload failed: {code}")
    except (ConnectTimeoutError, ReadTimeoutError):
        raise StorageTimeoutError("Storage upload connection timed out")
    except BotoCoreError:
        raise StorageError("B2 upload failed")


def download_from_s3_stream(key: str):
    """Return a streaming body for the B2 object (does not buffer full contents in RAM)."""
    if not key:
        raise StorageError("B2 storage key is missing")

    client = _get_client()
    try:
        response = client.get_object(Bucket=Config.B2_BUCKET_NAME, Key=key)
        return response["Body"]
    except (NoCredentialsError, PartialCredentialsError):
        raise StorageAuthError("Backblaze B2 credentials are not configured")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404"):
            raise StorageNotFoundError("Storage object not found")
        if code in ("InvalidAccessKeyId", "SignatureDoesNotMatch", "AccessDenied", "AuthFailure"):
            raise StorageAuthError("Cloud storage authentication failed")
        if code in ("RequestTimeout", "SocketTimeout"):
            raise StorageTimeoutError("Storage download timed out")
        raise StorageError(f"B2 download failed: {code}")
    except (ConnectTimeoutError, ReadTimeoutError):
        raise StorageTimeoutError("Storage download connection timed out")
    except BotoCoreError:
        raise StorageError("B2 download failed")


def download_from_s3(key: str) -> bytes:
    """Download object bytes from B2 (buffering helper; keep for legacy use)."""
    body = download_from_s3_stream(key)
    data = body.read()
    return data if isinstance(data, bytes) else bytes(data)


def delete_from_s3(key: str) -> bool:
    """Delete an object from Backblaze B2 storage (idempotent)."""
    if not key:
        return False

    client = _get_client()
    try:
        client.delete_object(Bucket=Config.B2_BUCKET_NAME, Key=key)
        return True
    except (NoCredentialsError, PartialCredentialsError):
        raise StorageAuthError("Backblaze B2 credentials are not configured")
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code in ("NoSuchKey", "404"):
            return True  # Already deleted
        if error_code in ("InvalidAccessKeyId", "SignatureDoesNotMatch", "AccessDenied"):
            raise StorageAuthError("Cloud storage authentication failed")
        raise StorageError(f"B2 delete failed: {error_code}")
    except (ConnectTimeoutError, ReadTimeoutError):
        raise StorageTimeoutError("Storage delete timed out")
    except BotoCoreError:
        raise StorageError("B2 delete failed")


def generate_presigned_url(key: str, expires_in: int = 900) -> str:
    """Generate a temporary presigned URL for B2 object download (bounded 60s - 3600s)."""
    if not key:
        raise StorageError("B2 storage key is missing")
    bounded_expires = max(60, min(int(expires_in), 3600))
    client = _get_client()
    try:
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": Config.B2_BUCKET_NAME, "Key": key},
            ExpiresIn=bounded_expires,
        )
    except (NoCredentialsError, PartialCredentialsError):
        raise StorageAuthError("Backblaze B2 credentials are not configured")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidAccessKeyId", "SignatureDoesNotMatch", "AccessDenied"):
            raise StorageAuthError("Cloud storage authentication failed")
        raise StorageError("Could not generate presigned URL")
    except BotoCoreError:
        raise StorageError("Could not generate presigned URL")


# Backblaze B2 named aliases
upload_bytes_to_b2 = upload_bytes_to_s3
download_from_b2_stream = download_from_s3_stream
download_from_b2 = download_from_s3
delete_from_b2 = delete_from_s3
generate_presigned_url_b2 = generate_presigned_url
