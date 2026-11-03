# =============================================================================
# routes/shares.py — Secure File Sharing Endpoints (Phase 9)
# =============================================================================
from datetime import datetime, timezone, timedelta
import hashlib
import logging
import secrets

from bson.objectid import ObjectId
from flask import Blueprint, jsonify, request

from routes.file import _build_encrypted_download_response
from utils.auth_helpers import jwt_required
from utils.db import (
    access_tokens_col,
    consume_share_for_download,
    create_access_token_record,
    create_file_share_record,
    file_shares_col,
    files_col,
    get_file_by_id,
    get_share_by_id,
    get_shares_by_owner,
    get_shares_for_recipient,
    revoke_file_share,
    user_keys_col,
    users_col,
    validate_share_for_view,
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

shares_bp = Blueprint("shares", __name__)

TOKEN_PREFIX = "sct_"
MIN_EXPIRY_SECONDS = 60           # 1 minute
MAX_EXPIRY_SECONDS = 30 * 86400   # 30 days
DEFAULT_EXPIRY_SECONDS = 86400    # 24 hours


# ---------------------------------------------------------------------------
# POST /shares — Share file with one or more registered users
# ---------------------------------------------------------------------------
@shares_bp.route("/shares", methods=["POST"])
@jwt_required
def create_share():
    """
    Share an existing encrypted file with registered recipient(s).
    ZERO-KNOWLEDGE:
      - Plaintext file contents and private keys NEVER touch the backend.
      - Owner's browser unwraps the file's AES data key and wraps it with recipient's RSA public key.
      - The file payload in Backblaze B2 is NOT re-encrypted or duplicated.
    """
    req_email = (getattr(request, "user_email", None) or "").strip().lower()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "msg": "Request payload must be a JSON object"}), 400

    file_id = (data.get("file_id") or "").strip()
    if not file_id:
        return jsonify({"success": False, "msg": "file_id is required"}), 400

    file_doc = get_file_by_id(file_id)
    if not file_doc:
        return jsonify({"success": False, "msg": "File not found"}), 404

    # Verify ownership
    if file_doc.get("user_email") != req_email:
        record_unauthorized_access(
            resource_type=AuditResourceType.SHARE,
            resource_id=file_id,
            reason="User attempted to share a file they do not own",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        return jsonify({"success": False, "msg": "Permission denied: you do not own this file"}), 403

    # Support single share or batch shares: {"file_id": ..., "shares": [...]} or single fields
    shares_input = data.get("shares")
    if shares_input is None:
        # Single share format
        shares_input = [
            {
                "recipient_email": data.get("recipient_email"),
                "wrapped_key": data.get("wrapped_key"),
                "key_fingerprint": data.get("key_fingerprint"),
                "permission": data.get("permission", "download"),
                "expires_in_seconds": data.get("expires_in_seconds", DEFAULT_EXPIRY_SECONDS),
                "max_downloads": data.get("max_downloads", 1),
                "note": data.get("note", ""),
            }
        ]
    elif not isinstance(shares_input, list) or len(shares_input) == 0:
        return jsonify({"success": False, "msg": "shares must be a non-empty list of recipient shares"}), 400

    created_shares = []
    errors = []

    for idx, item in enumerate(shares_input):
        if not isinstance(item, dict):
            errors.append(f"Share item #{idx} must be an object")
            continue

        recipient_email = (item.get("recipient_email") or "").strip().lower()
        if not recipient_email or "@" not in recipient_email:
            errors.append(f"Share item #{idx}: valid recipient_email is required")
            continue

        if recipient_email == req_email:
            errors.append(f"Share item #{idx}: cannot share a file with yourself")
            continue

        # Verify recipient is registered
        recipient_user = users_col.find_one({"email": recipient_email})
        if not recipient_user:
            errors.append(f"Recipient '{recipient_email}' is not a registered user")
            continue

        # Verify recipient has published an RSA public key
        recipient_key_doc = user_keys_col.find_one({"user_email": recipient_email})
        if not recipient_key_doc or not recipient_key_doc.get("public_key"):
            errors.append(f"Recipient '{recipient_email}' has not registered an RSA public key")
            continue

        wrapped_key = (item.get("wrapped_key") or "").strip()
        if not wrapped_key or len(wrapped_key) < 100:
            errors.append(f"Share item #{idx}: valid recipient-wrapped AES key (wrapped_key) is required")
            continue

        key_fingerprint = (item.get("key_fingerprint") or "").strip()
        expected_fp = recipient_key_doc.get("fingerprint", "")
        if key_fingerprint and expected_fp:
            norm_key_fp = key_fingerprint.replace("SHA256:", "").replace(":", "").upper()
            norm_exp_fp = expected_fp.replace("SHA256:", "").replace(":", "").upper()
            if norm_key_fp != norm_exp_fp:
                errors.append(f"Key fingerprint mismatch for recipient '{recipient_email}' (key substitution detected)")
                continue
        elif expected_fp:
            key_fingerprint = expected_fp

        permission = (item.get("permission") or "download").strip().lower()
        if permission not in ("download", "view"):
            permission = "download"

        try:
            expires_in_sec = int(item.get("expires_in_seconds", DEFAULT_EXPIRY_SECONDS))
            expires_in_sec = max(MIN_EXPIRY_SECONDS, min(expires_in_sec, MAX_EXPIRY_SECONDS))
        except (ValueError, TypeError):
            expires_in_sec = DEFAULT_EXPIRY_SECONDS

        try:
            max_dls = int(item.get("max_downloads", 1))
            max_dls = max(0, max_dls)
        except (ValueError, TypeError):
            max_dls = 1

        note = (item.get("note") or "").strip()[:200]

        # Generate linked Phase 8 token for temporary link support
        raw_token = f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_sec)

        token_record = create_access_token_record(
            token_hash=token_hash,
            file_id=file_id,
            user_email=req_email,
            scope=permission,
            expires_at=token_expires_at,
            max_downloads=max_dls,
            label=f"Share with {recipient_email}",
        )

        share_doc = create_file_share_record(
            file_id=file_id,
            owner_email=req_email,
            recipient_email=recipient_email,
            wrapped_key=wrapped_key,
            key_fingerprint=key_fingerprint,
            permission=permission,
            expires_in_seconds=expires_in_sec,
            max_downloads=max_dls,
            note=note,
            token_id=token_record.get("id"),
            token_hash=token_hash,
        )

        share_doc["token"] = raw_token
        share_doc["share_url"] = f"/api/shares/access/{raw_token}"
        created_shares.append(share_doc)

        record_audit_event(
            event_type=AuditEventType.SHARE_CREATE,
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            user_id=getattr(request, "user_id", None),
            user_email=req_email,
            resource_id=str(share_doc.get("id")),
            resource_type=AuditResourceType.SHARE,
            details={
                "file_id": file_id,
                "recipient_email": recipient_email,
                "permission": permission,
                "expires_in_seconds": expires_in_sec,
                "max_downloads": max_dls,
            },
            request_obj=request,
        )

    if not created_shares and errors:
        msg = errors[0] if len(errors) == 1 else "Failed to create shares"
        if msg.startswith("Share item #0: "):
            msg = msg[len("Share item #0: "):]
        return jsonify({"success": False, "msg": msg, "errors": errors}), 400

    response_payload = {
        "success": True,
        "msg": f"Successfully created {len(created_shares)} file share(s)",
        "shares": [
            {
                "id": s["id"],
                "file_id": s["file_id"],
                "recipient_email": s["recipient_email"],
                "permission": s["permission"],
                "max_downloads": s["max_downloads"],
                "expires_at": s["expires_at"].isoformat() if isinstance(s.get("expires_at"), datetime) else str(s.get("expires_at")),
                "token": s.get("token"),
                "share_url": s.get("share_url"),
                "note": s.get("note", ""),
            }
            for s in created_shares
        ],
    }
    if errors:
        response_payload["warnings"] = errors

    # If single share requested, return direct share fields for convenience
    if len(created_shares) == 1:
        first = created_shares[0]
        response_payload["share_id"] = first["id"]
        response_payload["token"] = first.get("token")
        response_payload["share_url"] = first.get("share_url")
        response_payload["recipient_email"] = first["recipient_email"]

    return jsonify(response_payload), 201


# ---------------------------------------------------------------------------
# GET /shares/sent — List all shares created by authenticated caller (History)
# ---------------------------------------------------------------------------
@shares_bp.route("/shares/sent", methods=["GET"])
@jwt_required
def list_sent_shares():
    """Retrieve full sharing history of shares created by authenticated caller."""
    req_email = (getattr(request, "user_email", None) or "").strip().lower()
    file_id = request.args.get("file_id")
    shares = get_shares_by_owner(req_email, file_id=file_id)
    return jsonify({"success": True, "shares": shares, "total": len(shares)}), 200


# ---------------------------------------------------------------------------
# GET /shares/file/<file_id> — List shares for a specific file owned by caller
# ---------------------------------------------------------------------------
@shares_bp.route("/shares/file/<file_id>", methods=["GET"])
@jwt_required
def list_file_shares(file_id: str):
    """Retrieve sharing history for a single file owned by caller."""
    req_email = (getattr(request, "user_email", None) or "").strip().lower()
    file_doc = get_file_by_id(file_id)
    if not file_doc:
        return jsonify({"success": False, "msg": "File not found"}), 404

    if file_doc.get("user_email") != req_email:
        return jsonify({"success": False, "msg": "Permission denied: you do not own this file"}), 403

    shares = get_shares_by_owner(req_email, file_id=file_id)
    return jsonify({"success": True, "file_id": file_id, "shares": shares}), 200


# ---------------------------------------------------------------------------
# GET /shares/received — List all files shared with authenticated caller
# ---------------------------------------------------------------------------
@shares_bp.route("/shares/received", methods=["GET"])
@jwt_required
def list_received_shares():
    """List all file shares received by the authenticated recipient."""
    req_email = (getattr(request, "user_email", None) or "").strip().lower()
    shares = get_shares_for_recipient(req_email)
    return jsonify({"success": True, "shares": shares, "total": len(shares)}), 200


# ---------------------------------------------------------------------------
# GET /shares/<share_id> — Inspect share details (Recipient or Owner)
# ---------------------------------------------------------------------------
@shares_bp.route("/shares/<share_id>", methods=["GET"])
@jwt_required
def get_share_details(share_id: str):
    """Get metadata for a specific share without consuming download quota."""
    req_email = (getattr(request, "user_email", None) or "").strip().lower()

    share = get_share_by_id(share_id)
    if not share:
        return jsonify({"success": False, "msg": "Share record not found"}), 404

    # Caller must be either recipient or owner
    if share.get("recipient_email") != req_email and share.get("owner_email") != req_email:
        record_unauthorized_access(
            resource_type=AuditResourceType.SHARE,
            resource_id=share_id,
            reason="User attempted to inspect a share they are not party to",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        return jsonify({"success": False, "msg": "Access denied: you are not authorized to view this share"}), 403

    file_doc = get_file_by_id(share["file_id"])
    if not file_doc:
        return jsonify({"success": False, "msg": "Associated file not found"}), 404

    now = datetime.now(timezone.utc)
    expires_at = share.get("expires_at")
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    is_expired = bool(expires_at and expires_at <= now)
    is_revoked = bool(share.get("is_revoked"))
    max_dl = share.get("max_downloads", 1)
    used_dl = share.get("downloads_used", 0)
    is_exhausted = bool(max_dl > 0 and used_dl >= max_dl)

    status = "revoked" if is_revoked else ("expired" if is_expired else ("exhausted" if is_exhausted else "active"))

    record_audit_event(
        event_type=AuditEventType.SHARE_ACCESS_VIEW,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=req_email,
        resource_id=share_id,
        resource_type=AuditResourceType.SHARE,
        details={"status": status, "permission": share.get("permission")},
        request_obj=request,
    )

    return (
        jsonify(
            {
                "success": True,
                "share": {
                    "id": str(share["_id"]),
                    "file_id": str(file_doc["_id"]),
                    "filename": file_doc.get("filename", ""),
                    "size": file_doc.get("size", 0),
                    "mime_type": file_doc.get("mime_type", "application/octet-stream"),
                    "algorithm": file_doc.get("algorithm", "AES-GCM-256+RSA-OAEP"),
                    "iv": file_doc.get("iv", ""),
                    "integrity_hash": file_doc.get("integrity_hash", ""),
                    "wrapped_key": share.get("wrapped_key", ""),
                    "key_fingerprint": share.get("key_fingerprint", ""),
                    "owner_email": share.get("owner_email"),
                    "recipient_email": share.get("recipient_email"),
                    "permission": share.get("permission", "download"),
                    "max_downloads": max_dl,
                    "downloads_used": used_dl,
                    "downloads_remaining": max(0, max_dl - used_dl) if max_dl > 0 else "unlimited",
                    "status": status,
                    "is_revoked": is_revoked,
                    "is_expired": is_expired,
                    "is_exhausted": is_exhausted,
                    "expires_at": expires_at.isoformat() if expires_at else None,
                    "created_at": share["created_at"].isoformat() if isinstance(share.get("created_at"), datetime) else str(share.get("created_at")),
                    "note": share.get("note", ""),
                },
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# GET /shares/<share_id>/download — Authenticated Recipient Download
# ---------------------------------------------------------------------------
@shares_bp.route("/shares/<share_id>/download", methods=["GET"])
@jwt_required
def download_shared_file(share_id: str):
    """
    Download a shared file as an authorized recipient.
    ATOMIC CONSUMPTION:
      - Validates recipient identity against JWT.
      - Enforces permission == 'download' (view-only rejected with 403).
      - Checks expiration and revocation.
      - Atomically increments downloads_used if max_downloads > 0 (prevents race conditions).
      - Streams encrypted file payload from Backblaze B2.
      - Sends recipient's specific wrapped AES key in X-Wrapped-Key header.
    """
    req_email = (getattr(request, "user_email", None) or "").strip().lower()

    # Atomically validate and consume 1 download quota
    share_doc, err_msg = consume_share_for_download(share_id, req_email)
    if err_msg:
        record_unauthorized_access(
            resource_type=AuditResourceType.SHARE,
            resource_id=share_id,
            reason=f"Share download denied: {err_msg}",
            severity=AuditSeverity.WARNING,
            request_obj=request,
        )
        return jsonify({"success": False, "msg": err_msg}), 403

    def _rollback_share_quota():
        if share_doc.get("max_downloads", 1) > 0:
            try:
                file_shares_col.update_one(
                    {"_id": share_doc["_id"], "downloads_used": {"$gt": 0}},
                    {"$inc": {"downloads_used": -1}},
                )
            except Exception:
                pass

    file_doc = get_file_by_id(share_doc["file_id"])
    if not file_doc:
        _rollback_share_quota()
        return jsonify({"success": False, "msg": "Associated file not found"}), 404

    try:
        body = download_from_s3_stream(file_doc["s3_key"])
        content_length = getattr(body, "content_length", None)
    except StorageNotFoundError:
        _rollback_share_quota()
        return jsonify({"success": False, "msg": "Storage object not found"}), 404
    except StorageAuthError:
        _rollback_share_quota()
        return jsonify({"success": False, "msg": "Cloud storage configuration error"}), 503
    except StorageTimeoutError:
        _rollback_share_quota()
        return jsonify({"success": False, "msg": "Storage operation timed out"}), 504
    except (StorageError, Exception) as exc:
        _rollback_share_quota()
        logger.error(f"Share download failed: {exc}")
        return jsonify({"success": False, "msg": "Storage download failed"}), 502

    max_dl = share_doc.get("max_downloads", 1)
    used_dl = share_doc.get("downloads_used", 0)
    remaining = str(max(0, max_dl - used_dl)) if max_dl > 0 else "unlimited"

    # Override file doc's wrapped key with recipient-specific wrapped key
    recipient_file_doc = dict(file_doc)
    recipient_file_doc["wrapped_key"] = share_doc.get("wrapped_key", "")
    recipient_file_doc["key_fingerprint"] = share_doc.get("key_fingerprint", "")

    extra_headers = {
        "X-Share-Downloads-Remaining": remaining,
        "X-Share-Permission": share_doc.get("permission", "download"),
    }

    record_audit_event(
        event_type=AuditEventType.SHARE_ACCESS_DOWNLOAD,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=req_email,
        resource_id=share_id,
        resource_type=AuditResourceType.SHARE,
        details={"file_id": str(share_doc.get("file_id"))},
        request_obj=request,
    )

    return _build_encrypted_download_response(
        recipient_file_doc, body, content_length=content_length, extra_headers=extra_headers
    )


# ---------------------------------------------------------------------------
# DELETE /shares/<share_id> — Revoke File Share (Owner only)
# ---------------------------------------------------------------------------
@shares_bp.route("/shares/<share_id>", methods=["DELETE"])
@shares_bp.route("/shares/<share_id>/revoke", methods=["POST"])
@jwt_required
def revoke_share(share_id: str):
    """Immediately revoke an existing file share (owner only)."""
    req_email = (getattr(request, "user_email", None) or "").strip().lower()

    ok, msg = revoke_file_share(share_id, req_email)
    if not ok:
        status_code = 403 if "permission" in msg.lower() else (400 if "format" in msg.lower() else 404)
        if status_code == 403:
            record_unauthorized_access(
                resource_type=AuditResourceType.SHARE,
                resource_id=share_id,
                reason="Unauthorized share revocation attempt",
                severity=AuditSeverity.WARNING,
                request_obj=request,
            )
        return jsonify({"success": False, "msg": msg}), status_code

    record_audit_event(
        event_type=AuditEventType.SHARE_REVOKE,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=req_email,
        resource_id=share_id,
        resource_type=AuditResourceType.SHARE,
        details={"status": "revoked"},
        request_obj=request,
    )

    return jsonify({"success": True, "msg": "File share revoked successfully", "share_id": share_id}), 200


# ---------------------------------------------------------------------------
# GET /shares/access/<raw_token> — Direct Token Download for Shared Files
# ---------------------------------------------------------------------------
@shares_bp.route("/shares/access/<raw_token>", methods=["GET"])
def download_shared_file_with_token(raw_token: str):
    """
    Direct temporary link download using linked Phase 8 access token.
    Atomically consumes token quota and streams encrypted ciphertext.
    """
    if not raw_token or not raw_token.startswith(TOKEN_PREFIX):
        return jsonify({"success": False, "msg": "Invalid access token format"}), 400

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # Find share associated with this token hash
    share = file_shares_col.find_one({"token_hash": token_hash})
    if not share:
        return jsonify({"success": False, "msg": "Invalid or expired share token"}), 403

    # Atomically consume download from share
    recipient_email = share.get("recipient_email")
    share_doc, err_msg = consume_share_for_download(str(share["_id"]), recipient_email)
    if err_msg:
        return jsonify({"success": False, "msg": err_msg}), 403

    def _rollback_token_quota():
        if share_doc.get("max_downloads", 1) > 0:
            try:
                file_shares_col.update_one(
                    {"_id": share_doc["_id"], "downloads_used": {"$gt": 0}},
                    {"$inc": {"downloads_used": -1}},
                )
            except Exception:
                pass

    file_doc = get_file_by_id(share_doc["file_id"])
    if not file_doc:
        _rollback_token_quota()
        return jsonify({"success": False, "msg": "Associated file not found"}), 404

    try:
        body = download_from_s3_stream(file_doc["s3_key"])
        content_length = getattr(body, "content_length", None)
    except Exception as exc:
        _rollback_token_quota()
        logger.error(f"Token share stream error: {exc}")
        return jsonify({"success": False, "msg": "Storage download failed"}), 502

    max_dl = share_doc.get("max_downloads", 1)
    used_dl = share_doc.get("downloads_used", 0)
    remaining = str(max(0, max_dl - used_dl)) if max_dl > 0 else "unlimited"

    recipient_file_doc = dict(file_doc)
    recipient_file_doc["wrapped_key"] = share_doc.get("wrapped_key", "")
    recipient_file_doc["key_fingerprint"] = share_doc.get("key_fingerprint", "")

    extra_headers = {
        "X-Share-Downloads-Remaining": remaining,
        "X-Share-Permission": share_doc.get("permission", "download"),
    }

    return _build_encrypted_download_response(
        recipient_file_doc, body, content_length=content_length, extra_headers=extra_headers
    )
