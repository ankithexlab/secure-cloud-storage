# =============================================================================
# routes/tokens.py — Secure Access Token Management (Phase 8)
# =============================================================================
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import secrets

from bson.objectid import ObjectId
from flask import Blueprint, jsonify, request

from routes.file import _build_encrypted_download_response
from utils.auth_helpers import jwt_required
from utils.db import (
    access_tokens_col,
    consume_token_for_download,
    create_access_token_record,
    get_file_access_tokens,
    get_file_by_id,
    get_user_all_access_tokens,
    revoke_access_token_by_id,
    validate_token_for_view,
)
from utils.s3 import (
    StorageAuthError,
    StorageError,
    StorageNotFoundError,
    StorageTimeoutError,
    download_from_s3_stream,
)
from utils.audit import (
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSeverity,
    record_audit_event,
    record_unauthorized_access,
)

logger = logging.getLogger(__name__)

tokens_bp = Blueprint("tokens", __name__)

TOKEN_PREFIX = "sct_"
MIN_EXPIRY_SECONDS = 60          # 1 minute
MAX_EXPIRY_SECONDS = 30 * 86400  # 30 days
DEFAULT_EXPIRY_SECONDS = 86400   # 24 hours


def _extract_token_from_request() -> str:
    """
    Extract raw token from request without logging.
    Supports:
      1. X-Access-Token header
      2. Authorization: Bearer sct_...
      3. ?token= query parameter
    """
    token = request.headers.get("X-Access-Token", "").strip()
    if token:
        return token

    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.startswith("Bearer "):
        bearer_val = auth_header[7:].strip()
        if bearer_val.startswith(TOKEN_PREFIX):
            return bearer_val

    query_token = request.args.get("token", "").strip()
    if query_token:
        return query_token

    return ""


# ---------------------------------------------------------------------------
# POST /tokens/create — Generate a high-entropy access token
# ---------------------------------------------------------------------------
@tokens_bp.route("/tokens/create", methods=["POST"])
@tokens_bp.route("/tokens", methods=["POST"])
@jwt_required
def create_token():
    """
    Generate a cryptographically secure access token for a file.
    ZERO-KNOWLEDGE:
      - Raw token is high-entropy CSPRNG (256 bits).
      - Raw token is returned ONCE in the response body.
      - ONLY the SHA-256 hash is persisted in MongoDB.
    """
    data = request.get_json(silent=True) or {}

    file_id = (data.get("file_id") or "").strip()
    if not file_id:
        return jsonify({"success": False, "msg": "file_id is required"}), 400

    file_doc = get_file_by_id(file_id)
    if not file_doc:
        return jsonify({"success": False, "msg": "File not found"}), 404

    # Strict ownership check
    owner_email = (file_doc.get("user_email") or "").strip().lower()
    req_email = (getattr(request, "user_email", None) or "").strip().lower()
    if not owner_email or owner_email != req_email:
        record_unauthorized_access(
            resource_type=AuditResourceType.TOKEN,
            resource_id=file_id,
            reason="User attempted to create access token for a file they do not own",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        return jsonify({"success": False, "msg": "Access denied"}), 403

    # Scope validation (download vs view)
    scope = (data.get("scope") or "download").strip().lower()
    if scope not in ("download", "view"):
        return jsonify({"success": False, "msg": "Invalid scope. Must be 'download' or 'view'"}), 400

    # Configurable download limit (1 = single-use, 0 = unlimited)
    max_downloads = data.get("max_downloads")
    if max_downloads is None:
        max_downloads = 1  # Default to single-use for high security
    try:
        max_downloads = int(max_downloads)
        if max_downloads < 0:
            max_downloads = 0
    except (ValueError, TypeError):
        return jsonify({"success": False, "msg": "max_downloads must be an integer"}), 400

    # Expiry validation
    expires_in_seconds = data.get("expires_in_seconds")
    if expires_in_seconds is None:
        hours = data.get("expires_in_hours")
        if hours is not None:
            try:
                expires_in_seconds = int(float(hours) * 3600)
            except (ValueError, TypeError):
                expires_in_seconds = DEFAULT_EXPIRY_SECONDS
        else:
            expires_in_seconds = DEFAULT_EXPIRY_SECONDS

    try:
        expires_in_seconds = int(expires_in_seconds)
    except (ValueError, TypeError):
        expires_in_seconds = DEFAULT_EXPIRY_SECONDS

    expires_in_seconds = max(MIN_EXPIRY_SECONDS, min(MAX_EXPIRY_SECONDS, expires_in_seconds))
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)

    label = (data.get("label") or "").strip()[:100]

    # Generate 256 bits of cryptographic entropy via secrets module
    raw_token = f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"

    # Compute SHA-256 digest for database persistence
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    token_doc = create_access_token_record(
        token_hash=token_hash,
        file_id=file_id,
        user_email=req_email,
        scope=scope,
        expires_at=expires_at,
        max_downloads=max_downloads,
        label=label,
    )

    record_audit_event(
        event_type=AuditEventType.TOKEN_CREATE,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=req_email,
        resource_id=str(token_doc["_id"]),
        resource_type=AuditResourceType.TOKEN,
        details={
            "file_id": file_id,
            "scope": scope,
            "max_downloads": max_downloads,
            "expires_in_seconds": expires_in_seconds,
        },
        request_obj=request,
    )

    return (
        jsonify(
            {
                "success": True,
                "msg": "Access token generated successfully",
                "token": raw_token,  # RETURNED ONCE ONLY
                "token_id": str(token_doc["_id"]),
                "file_id": file_id,
                "filename": file_doc.get("filename", ""),
                "scope": scope,
                "max_downloads": max_downloads,
                "is_single_use": max_downloads == 1,
                "expires_at": expires_at.isoformat(),
                "created_at": token_doc["created_at"].isoformat(),
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# GET /tokens/file/<file_id> — List tokens for a specific file
# ---------------------------------------------------------------------------
@tokens_bp.route("/tokens/file/<file_id>", methods=["GET"])
@jwt_required
def list_file_tokens(file_id: str):
    """List all tokens for a given file owned by the authenticated caller."""
    file_doc = get_file_by_id(file_id)
    if not file_doc:
        return jsonify({"success": False, "msg": "File not found"}), 404

    owner_email = (file_doc.get("user_email") or "").strip().lower()
    req_email = (getattr(request, "user_email", None) or "").strip().lower()
    if not owner_email or owner_email != req_email:
        return jsonify({"success": False, "msg": "Access denied"}), 403

    tokens = get_file_access_tokens(file_id, req_email)
    return jsonify({"success": True, "file_id": file_id, "tokens": tokens}), 200


# ---------------------------------------------------------------------------
# GET /tokens — List all tokens created by authenticated user
# ---------------------------------------------------------------------------
@tokens_bp.route("/tokens", methods=["GET"])
@jwt_required
def list_user_tokens():
    """List all tokens created by the authenticated user."""
    req_email = (getattr(request, "user_email", None) or "").strip().lower()
    tokens = get_user_all_access_tokens(req_email)
    return jsonify({"success": True, "tokens": tokens}), 200


# ---------------------------------------------------------------------------
# DELETE /tokens/<token_id> — Revoke token immediately
# ---------------------------------------------------------------------------
@tokens_bp.route("/tokens/<token_id>", methods=["DELETE"])
@tokens_bp.route("/tokens/<token_id>/revoke", methods=["POST"])
@jwt_required
def revoke_token(token_id: str):
    """Immediately revoke an access token."""
    req_email = (getattr(request, "user_email", None) or "").strip().lower()

    try:
        oid = ObjectId(token_id)
    except Exception:
        return jsonify({"success": False, "msg": "Invalid token ID format"}), 400

    token_doc = access_tokens_col.find_one({"_id": oid})
    if not token_doc:
        return jsonify({"success": False, "msg": "Access token not found"}), 404

    if token_doc.get("user_email") != req_email:
        record_unauthorized_access(
            resource_type=AuditResourceType.TOKEN,
            resource_id=token_id,
            reason="Permission denied — cannot revoke another user's token",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        return jsonify({"success": False, "msg": "Permission denied — cannot revoke another user's token"}), 403

    access_tokens_col.update_one(
        {"_id": oid},
        {"$set": {"is_revoked": True, "revoked_at": datetime.now(timezone.utc)}},
    )

    record_audit_event(
        event_type=AuditEventType.TOKEN_REVOKE,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=req_email,
        resource_id=token_id,
        resource_type=AuditResourceType.TOKEN,
        details={"status": "revoked"},
        request_obj=request,
    )

    return jsonify({"success": True, "msg": "Access token revoked successfully", "token_id": token_id}), 200


# ---------------------------------------------------------------------------
# GET /tokens/validate — Validate an access token (view-only inspection)
# ---------------------------------------------------------------------------
@tokens_bp.route("/tokens/validate", methods=["GET"])
def validate_token():
    """
    Validate an access token without consuming download limit.
    Enforces expiry, revocation, and limit validation.
    """
    raw_token = _extract_token_from_request()
    if not raw_token:
        return jsonify({"success": False, "msg": "Access token is required"}), 401

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token_doc, err_msg = validate_token_for_view(token_hash)
    if err_msg:
        record_unauthorized_access(
            resource_type=AuditResourceType.TOKEN,
            reason=f"Token validation failed: {err_msg}",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        return jsonify({"success": False, "msg": err_msg}), 403

    file_doc = get_file_by_id(token_doc["file_id"])
    if not file_doc:
        return jsonify({"success": False, "msg": "Associated file not found"}), 404

    max_dls = token_doc.get("max_downloads", 1)
    used_dls = token_doc.get("downloads_used", 0)
    downloads_remaining = max(0, max_dls - used_dls) if max_dls > 0 else "unlimited"

    record_audit_event(
        event_type=AuditEventType.TOKEN_VALIDATE,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_email=token_doc.get("user_email"),
        resource_id=str(token_doc.get("_id")),
        resource_type=AuditResourceType.TOKEN,
        details={"file_id": str(token_doc.get("file_id")), "scope": token_doc.get("scope")},
        request_obj=request,
    )

    return (
        jsonify(
            {
                "success": True,
                "valid": True,
                "scope": token_doc.get("scope", "download"),
                "max_downloads": max_dls,
                "downloads_used": used_dls,
                "downloads_remaining": downloads_remaining,
                "expires_at": token_doc.get("expires_at").isoformat()
                if token_doc.get("expires_at")
                else None,
                "file": {
                    "id": str(file_doc["_id"]),
                    "filename": file_doc.get("filename", ""),
                    "size": file_doc.get("size", 0),
                    "mime_type": file_doc.get("mime_type", "application/octet-stream"),
                    "algorithm": file_doc.get("algorithm", "AES-GCM-256"),
                },
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# GET /tokens/download or /access/download/<raw_token> — Token-authorized download
# ---------------------------------------------------------------------------
@tokens_bp.route("/tokens/download", methods=["GET"])
@tokens_bp.route("/access/download/<raw_token>", methods=["GET"])
def token_download(raw_token: str | None = None):
    """
    Download file using an access token.
    ATOMIC CONSUMPTION:
      - Validates token scope (must be 'download').
      - Atomically checks and increments downloads_used in a single MongoDB operation.
      - Prevents race conditions on single-use (1 download) tokens.
      - Streams encrypted ciphertext from Backblaze B2.
      - Zero-knowledge: recipient decrypts client-side using Web Crypto.
    """
    if not raw_token:
        raw_token = _extract_token_from_request()

    if not raw_token:
        return jsonify({"success": False, "msg": "Access token is required"}), 401

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # Atomically validate and consume 1 download
    token_doc, err_msg = consume_token_for_download(token_hash)
    if err_msg:
        record_unauthorized_access(
            resource_type=AuditResourceType.TOKEN,
            reason=f"Token download rejected: {err_msg}",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        # Generic security response to prevent enumeration
        return jsonify({"success": False, "msg": err_msg}), 403

    file_doc = get_file_by_id(token_doc["file_id"])
    if not file_doc:
        return jsonify({"success": False, "msg": "Associated file not found"}), 404

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
        logger.error(f"Token storage download failed: {exc}")
        return jsonify({"success": False, "msg": "Storage download failed"}), 502

    # Include token consumption metadata in response headers
    extra_headers = {
        "X-Token-Downloads-Remaining": str(
            max(0, token_doc.get("max_downloads", 1) - token_doc.get("downloads_used", 0))
            if token_doc.get("max_downloads", 1) > 0
            else "unlimited"
        )
    }

    record_audit_event(
        event_type=AuditEventType.TOKEN_DOWNLOAD,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_email=token_doc.get("user_email"),
        resource_id=str(token_doc.get("_id")),
        resource_type=AuditResourceType.TOKEN,
        details={"file_id": str(token_doc.get("file_id"))},
        request_obj=request,
    )

    return _build_encrypted_download_response(
        file_doc, body, content_length=content_length, extra_headers=extra_headers
    )
