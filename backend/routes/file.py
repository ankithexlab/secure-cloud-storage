# =============================================================================
# routes/file.py — Upload / List / Download / Delete file endpoints
# =============================================================================
import base64
import hashlib
import logging

from flask import Blueprint, Response, jsonify, request

from config import Config
from utils.auth_helpers import check_password, jwt_required
from utils.db import add_file_record, get_user_files, get_file_by_id, get_user_storage_stats, delete_file_record
from utils.audit import (
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSeverity,
    record_audit_event,
    record_unauthorized_access,
)
from utils.s3 import (
    StorageAuthError,
    StorageError,
    StorageNotFoundError,
    StorageTimeoutError,
    _safe_filename,
    _safe_mime_type,
    delete_from_s3,
    download_from_s3_stream,
    generate_presigned_url,
    upload_bytes_to_s3,
)

logger = logging.getLogger(__name__)

file_bp = Blueprint("file", __name__)


# ---------------------------------------------------------------------------
# Helper: Verify ownership
# ---------------------------------------------------------------------------
def _load_owned_file_or_error(file_id: str):
    """Load file metadata and enforce strict server-side owner authorization."""
    if not file_id or not isinstance(file_id, str):
        return None, (jsonify({"success": False, "msg": "Invalid file ID format"}), 400)

    file_doc = get_file_by_id(file_id)
    if not file_doc:
        return None, (jsonify({"success": False, "msg": "File not found"}), 404)

    owner_email = (file_doc.get("user_email") or "").strip().lower()
    req_email = (getattr(request, "user_email", None) or "").strip().lower()

    if not owner_email or not req_email or owner_email != req_email:
        record_unauthorized_access(
            resource_type=AuditResourceType.FILE,
            resource_id=file_id,
            reason="Unauthorized attempt to access another user's file",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        return None, (jsonify({"success": False, "msg": "Access denied"}), 403)

    return file_doc, None


def _build_encrypted_download_response(file_doc: dict, encrypted_body, content_length: int | None = None, extra_headers: dict | None = None):
    if encrypted_body is None:
        return jsonify({"success": False, "msg": "Downloaded payload was empty"}), 502

    is_legacy = bool(file_doc.get("is_legacy") or file_doc.get("file_password_hash"))
    safe_name = _safe_filename(file_doc.get("filename", "file.bin"))
    safe_mime = _safe_mime_type(file_doc.get("mime_type", "application/octet-stream"))

    headers = {
        "Content-Disposition": f'attachment; filename="{safe_name}"',
        "X-IV": file_doc.get("iv", ""),
        "X-Salt": file_doc.get("salt", ""),
        "X-Wrapped-Key": file_doc.get("wrapped_key", ""),
        "X-Key-Fingerprint": file_doc.get("key_fingerprint", ""),
        "X-Original-Mime": safe_mime,
        "X-Is-Legacy": "true" if is_legacy else "false",
        "X-Integrity-Hash": file_doc.get("integrity_hash", ""),
        "X-Algorithm": file_doc.get("algorithm", "AES-GCM-256"),
        "Access-Control-Expose-Headers": "Content-Disposition, X-IV, X-Salt, X-Wrapped-Key, X-Key-Fingerprint, X-Original-Mime, X-Is-Legacy, X-Integrity-Hash, X-Algorithm, Content-Length, X-Token-Downloads-Remaining, X-Share-Downloads-Remaining, X-Share-Permission, X-Deprecated",
    }

    if content_length is not None:
        headers["Content-Length"] = str(int(content_length))

    if extra_headers:
        headers.update(extra_headers)

    return Response(
        encrypted_body,
        status=200,
        mimetype="application/octet-stream",
        headers=headers,
    )


# ---------------------------------------------------------------------------
# POST /upload — Zero-Knowledge Encrypted Upload
# ---------------------------------------------------------------------------
@file_bp.route("/upload", methods=["POST"])
@jwt_required
def upload():
    """
    Receive client-side encrypted data and persist to S3 + MongoDB.
    ZERO-KNOWLEDGE: Plaintext encryption password and raw file contents are NEVER received.

    Expects JSON body:
      - filename (str)
      - encrypted_content (base64 string — already encrypted by the browser)
      - mime_type (str, optional)
      - size (int, original file size)
      - iv (str, base64 — AES-GCM IV)
      - salt (str, base64 — PBKDF2 salt)
    """
    data = request.get_json(silent=True) or {}

    raw_filename = (data.get("filename") or "").strip()
    encrypted_content = data.get("encrypted_content", "")
    mime_type = _safe_mime_type(data.get("mime_type"))
    iv = data.get("iv", "")
    salt = data.get("salt", "")
    wrapped_key = (data.get("wrapped_key") or "").strip()
    key_fingerprint = (data.get("key_fingerprint") or data.get("rsa_fingerprint") or "").strip()
    integrity_hash = (data.get("integrity_hash") or data.get("hash") or "").strip()
    algorithm = (data.get("algorithm") or ("AES-GCM-256+RSA-OAEP" if wrapped_key else "AES-GCM-256")).strip()
    kdf = (data.get("kdf") or ("NONE" if wrapped_key else "PBKDF2-SHA256")).strip()
    iterations = data.get("iterations") if data.get("iterations") is not None else (0 if wrapped_key else 100000)
    version = (data.get("version") or ("2.0" if wrapped_key else "1.0")).strip()

    if not raw_filename:
        return jsonify({"success": False, "msg": "Filename is required"}), 400
    if not encrypted_content:
        return jsonify({"success": False, "msg": "Encrypted content is required"}), 400

    filename = _safe_filename(raw_filename)

    # Decode base64 → raw bytes for S3
    try:
        raw_bytes = base64.b64decode(encrypted_content, validate=True)
    except Exception:
        return jsonify({"success": False, "msg": "Invalid base64 encrypted content"}), 400

    if len(raw_bytes) == 0:
        return jsonify({"success": False, "msg": "Refusing to upload empty file"}), 400

    if len(raw_bytes) > Config.MAX_UPLOAD_SIZE:
        return jsonify({"success": False, "msg": f"File exceeds {Config.MAX_UPLOAD_SIZE // (1024 * 1024)} MB limit"}), 413

    if not iv:
        return jsonify({"success": False, "msg": "Missing encryption metadata (iv)"}), 400

    if not salt and not wrapped_key:
        return jsonify({"success": False, "msg": "Missing encryption metadata: either salt or wrapped_key is required"}), 400

    if wrapped_key:
        try:
            wk_bytes = base64.b64decode(wrapped_key, validate=True)
            if len(wk_bytes) < 128 or len(wk_bytes) > 1024:
                return jsonify({"success": False, "msg": "Invalid wrapped key length"}), 400
        except Exception:
            return jsonify({"success": False, "msg": "Invalid base64 wrapped key format"}), 400

    file_hash = hashlib.sha256(raw_bytes).hexdigest()

    # Prefer original file size from frontend; fall back to encrypted payload size
    provided_size = data.get("size")
    try:
        provided_size = int(provided_size)
    except (TypeError, ValueError):
        provided_size = 0
    file_size = provided_size if provided_size > 0 else len(raw_bytes)

    # 1. Upload to Backblaze B2
    try:
        s3_key = upload_bytes_to_s3(raw_bytes, filename, mime_type="application/octet-stream")
    except StorageAuthError:
        return jsonify({"success": False, "msg": "Cloud storage configuration error"}), 503
    except StorageTimeoutError:
        return jsonify({"success": False, "msg": "Storage upload timed out"}), 504
    except (StorageError, Exception) as exc:
        logger.error(f"Storage upload failed: {exc}")
        return jsonify({"success": False, "msg": "Storage upload failed"}), 500

    # 2. Persist metadata in MongoDB with atomic rollback on failure
    try:
        file_doc = add_file_record(
            user_email=request.user_email,
            filename=filename,
            file_hash=file_hash,
            s3_key=s3_key,
            file_password_hash="",  # ZERO-KNOWLEDGE: Password is not stored or accepted
            size=file_size,
            mime_type=mime_type,
            iv=iv,
            salt=salt,
            is_legacy=False,
            integrity_hash=integrity_hash,
            algorithm=algorithm,
            kdf=kdf,
            iterations=iterations,
            version=version,
            wrapped_key=wrapped_key,
            key_fingerprint=key_fingerprint,
        )
    except Exception as exc:
        logger.error(f"MongoDB insert failed after storage upload, rolling back {s3_key}: {exc}")
        try:
            delete_from_s3(s3_key)
        except Exception as cleanup_err:
            logger.error(f"Failed to cleanup orphaned storage object {s3_key}: {cleanup_err}")
        return jsonify({"success": False, "msg": "Failed to persist file metadata"}), 500

    file_id_str = str(file_doc["_id"])
    record_audit_event(
        event_type=AuditEventType.FILE_UPLOAD,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=request.user_email,
        resource_id=file_id_str,
        resource_type=AuditResourceType.FILE,
        details={
            "filename": filename,
            "size": file_size,
            "mime_type": mime_type,
            "algorithm": algorithm,
            "is_legacy": False,
        },
        request_obj=request,
    )

    return (
        jsonify(
            {
                "success": True,
                "msg": "File uploaded successfully",
                "file_id": file_id_str,
                "filename": filename,
                "s3_key": s3_key,
                "size": file_size,
                "mime_type": mime_type,
                "iv": iv,
                "salt": salt,
                "wrapped_key": wrapped_key,
                "key_fingerprint": key_fingerprint,
                "integrity_hash": integrity_hash,
                "algorithm": algorithm,
                "is_legacy": False,
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# GET /files — List files
# ---------------------------------------------------------------------------
@file_bp.route("/files", methods=["GET"])
@jwt_required
def files():
    """Return all file metadata for the authenticated user."""
    user_files = get_user_files(request.user_email)
    stats = get_user_storage_stats(request.user_email)

    return jsonify({"success": True, "files": user_files, "stats": stats}), 200


# ---------------------------------------------------------------------------
# GET /download/<file_id> — Zero-Knowledge Authenticated Download
# ---------------------------------------------------------------------------
@file_bp.route("/download/<file_id>", methods=["GET"])
@jwt_required
def download(file_id: str):
    """
    Download the encrypted ciphertext from S3 and stream it to the client.
    The browser decrypts it client-side with AES-256-GCM.
    Enforces user ownership and JWT authentication.
    """
    file_doc, err = _load_owned_file_or_error(file_id)
    if err:
        return err

    try:
        body = download_from_s3_stream(file_doc["s3_key"])
        content_length = getattr(body, "content_length", None)
    except StorageNotFoundError:
        return jsonify({"success": False, "msg": "Storage object not found"}), 404
    except StorageAuthError:
        return jsonify({"success": False, "msg": "Cloud storage configuration error"}), 503
    except StorageTimeoutError:
        return jsonify({"success": False, "msg": "Storage operation timed out"}), 504
    except StorageError as exc:
        logger.error(f"Storage download failed: {exc}")
        return jsonify({"success": False, "msg": "Storage download failed"}), 502
    except Exception as exc:
        logger.error(f"Unexpected download error: {exc}")
        return jsonify({"success": False, "msg": "Storage download failed"}), 502

    record_audit_event(
        event_type=AuditEventType.FILE_DOWNLOAD,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=request.user_email,
        resource_id=file_id,
        resource_type=AuditResourceType.FILE,
        details={"filename": file_doc.get("filename"), "size": file_doc.get("size")},
        request_obj=request,
    )

    return _build_encrypted_download_response(file_doc, body, content_length=content_length)


# ---------------------------------------------------------------------------
# POST /download/<file_id> — Deprecated Legacy Download with Server-Side Password Check
# ---------------------------------------------------------------------------
@file_bp.route("/download/<file_id>", methods=["POST"])
@jwt_required
def download_protected(file_id: str):
    """
    Legacy download path. Maintained for backwards-compatibility with older clients.
    Deprecated in favor of authenticated GET /download/<file_id> with client-side verification.
    """
    file_doc, err = _load_owned_file_or_error(file_id)
    if err:
        return err

    stored_hash = (file_doc.get("file_password_hash") or "").strip()
    if stored_hash:
        data = request.get_json(silent=True) or {}
        password = (data.get("password") or "").strip()
        if password and not check_password(password, stored_hash):
            return jsonify({"success": False, "msg": "Incorrect password"}), 401

    try:
        body = download_from_s3_stream(file_doc["s3_key"])
        content_length = getattr(body, "content_length", None)
    except StorageNotFoundError:
        return jsonify({"success": False, "msg": "Storage object not found"}), 404
    except StorageAuthError:
        return jsonify({"success": False, "msg": "Cloud storage configuration error"}), 503
    except StorageTimeoutError:
        return jsonify({"success": False, "msg": "Storage operation timed out"}), 504
    except (StorageError, Exception) as exc:
        logger.error(f"Storage legacy download failed: {exc}")
        return jsonify({"success": False, "msg": "Storage download failed"}), 502

    extra_headers = {
        "X-Deprecated": "POST /download/<file_id> is deprecated; use authenticated GET /download/<file_id>"
    }
    return _build_encrypted_download_response(file_doc, body, content_length=content_length, extra_headers=extra_headers)


# ---------------------------------------------------------------------------
# GET /download-url/<file_id> — Presigned URL flow
# ---------------------------------------------------------------------------
@file_bp.route("/download-url/<file_id>", methods=["GET"])
@jwt_required
def download_url(file_id: str):
    """Generate a temporary presigned URL for direct encrypted download."""
    file_doc, err = _load_owned_file_or_error(file_id)
    if err:
        return err

    expires_param = request.args.get("expires_in", 900)
    try:
        expires_in = int(expires_param)
    except (ValueError, TypeError):
        expires_in = 900

    try:
        presigned_url = generate_presigned_url(file_doc["s3_key"], expires_in=expires_in)
    except StorageNotFoundError:
        return jsonify({"success": False, "msg": "Storage object not found"}), 404
    except StorageAuthError:
        return jsonify({"success": False, "msg": "Cloud storage configuration error"}), 503
    except StorageTimeoutError:
        return jsonify({"success": False, "msg": "Storage operation timed out"}), 504
    except Exception as exc:
        logger.error(f"Presigned URL generation failed: {exc}")
        return jsonify({"success": False, "msg": "Failed to generate presigned URL"}), 502

    record_audit_event(
        event_type=AuditEventType.FILE_DOWNLOAD_URL_GENERATED,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=request.user_email,
        resource_id=file_id,
        resource_type=AuditResourceType.FILE,
        details={"filename": file_doc.get("filename"), "expires_in": expires_in},
        request_obj=request,
    )

    return jsonify(
        {
            "success": True,
            "url": presigned_url,
            "filename": file_doc.get("filename", ""),
            "iv": file_doc.get("iv", ""),
            "salt": file_doc.get("salt", ""),
            "wrapped_key": file_doc.get("wrapped_key", ""),
            "key_fingerprint": file_doc.get("key_fingerprint", ""),
            "integrity_hash": file_doc.get("integrity_hash", ""),
            "algorithm": file_doc.get("algorithm", "AES-GCM-256"),
            "mime_type": file_doc.get("mime_type", "application/octet-stream"),
            "is_legacy": bool(file_doc.get("is_legacy") or file_doc.get("file_password_hash")),
        }
    ), 200


# ---------------------------------------------------------------------------
# DELETE /files/<file_id> — Delete file from B2 and metadata from MongoDB
# ---------------------------------------------------------------------------
@file_bp.route("/files/<file_id>", methods=["DELETE"])
@file_bp.route("/file/<file_id>", methods=["DELETE"])
@file_bp.route("/delete/<file_id>", methods=["DELETE", "POST"])
@jwt_required
def delete_file(file_id: str):
    """
    Delete file from Backblaze B2 and remove metadata from MongoDB.
    Verifies that the file belongs to the authenticated user.
    """
    file_doc, err = _load_owned_file_or_error(file_id)
    if err:
        return err

    storage_key = file_doc.get("s3_key")
    if storage_key:
        try:
            delete_from_s3(storage_key)
        except StorageAuthError:
            logger.error(f"Storage auth error during deletion of {storage_key}")
            # Proceed to remove MongoDB document to avoid dangling broken record
        except Exception as exc:
            logger.warning(f"Storage deletion reported error for {storage_key}: {exc}")
            # Proceed to remove MongoDB document to avoid dangling broken record

    deleted = delete_file_record(file_id, request.user_email)
    if not deleted:
        return jsonify({"success": False, "msg": "Failed to remove file metadata"}), 500

    record_audit_event(
        event_type=AuditEventType.FILE_DELETE,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=request.user_email,
        resource_id=file_id,
        resource_type=AuditResourceType.FILE,
        details={"filename": file_doc.get("filename")},
        request_obj=request,
    )

    return jsonify({"success": True, "msg": "File deleted successfully", "file_id": file_id}), 200
