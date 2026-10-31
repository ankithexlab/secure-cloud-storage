# =============================================================================
# utils/s3.py — Backblaze B2 (S3-compatible) upload / download / delete helpers
# =============================================================================
import uuid
from pathlib import Path

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, PartialCredentialsError

from config import Config

_client = None


def _ensure_s3_config() -> None:
    if not Config.B2_BUCKET_NAME:
        raise RuntimeError("Backblaze B2 bucket name is missing")
    if not Config.B2_KEY_ID or not Config.B2_APPLICATION_KEY:
        raise RuntimeError("Backblaze B2 credentials are not configured")


def _get_client():
    global _client
    if _client is None:
        _ensure_s3_config()
        _client = boto3.client(
            "s3",
            endpoint_url=Config.B2_ENDPOINT_URL,
            aws_access_key_id=Config.B2_KEY_ID,
            aws_secret_access_key=Config.B2_APPLICATION_KEY,
            config=BotoConfig(signature_version="s3v4"),
        )
    return _client


def _safe_filename(filename: str) -> str:
    cleaned = Path(filename or "file.bin").name.strip()
    return cleaned or "file.bin"


def upload_bytes_to_s3(data: bytes, filename: str, mime_type: str = "application/octet-stream") -> str:
    """Upload raw encrypted bytes to Backblaze B2 and return the object key."""
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError("Upload payload must be bytes")
    payload = bytes(data)
    if len(payload) == 0:
        raise RuntimeError("Refusing to upload empty payload")

    client = _get_client()
    object_key = f"encrypted/{uuid.uuid4().hex}_{_safe_filename(filename)}"
    try:
        client.put_object(
            Bucket=Config.B2_BUCKET_NAME,
            Key=object_key,
            Body=payload,
            ContentType=mime_type or "application/octet-stream",
            ContentLength=len(payload),
        )
        return object_key
    except (NoCredentialsError, PartialCredentialsError):
        raise RuntimeError("Backblaze B2 credentials are not configured")
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"B2 upload failed: {exc}")


def download_from_s3_stream(key: str):
    """Return a streaming body for the B2 object (does not buffer full contents in RAM)."""
    if not key:
        raise RuntimeError("B2 storage key is missing")

    client = _get_client()
    try:
        response = client.get_object(Bucket=Config.B2_BUCKET_NAME, Key=key)
        return response["Body"]
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"B2 download failed: {exc}")


def download_from_s3(key: str) -> bytes:
    """Download object bytes from B2 (buffering helper; keep for legacy use)."""
    body = download_from_s3_stream(key)
    data = body.read()
    return data if isinstance(data, bytes) else bytes(data)


def delete_from_s3(key: str) -> bool:
    """Delete an object from Backblaze B2 storage."""
    if not key:
        return False

    client = _get_client()
    try:
        client.delete_object(Bucket=Config.B2_BUCKET_NAME, Key=key)
        return True
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"B2 delete failed: {exc}")


def generate_presigned_url(key: str, expires_in: int = 900) -> str:
    """Generate a temporary presigned URL for B2 object download."""
    if not key:
        raise RuntimeError("B2 storage key is missing")
    client = _get_client()
    try:
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": Config.B2_BUCKET_NAME, "Key": key},
            ExpiresIn=max(60, int(expires_in)),
        )
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"Could not generate presigned URL: {exc}")


# Backblaze B2 named aliases
upload_bytes_to_b2 = upload_bytes_to_s3
download_from_b2_stream = download_from_s3_stream
download_from_b2 = download_from_s3
delete_from_b2 = delete_from_s3
generate_presigned_url_b2 = generate_presigned_url
