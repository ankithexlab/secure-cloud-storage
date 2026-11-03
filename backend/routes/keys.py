# =============================================================================
# routes/keys.py — RSA-OAEP Public Key Registration & Retrieval Endpoints
# =============================================================================
import base64
import hashlib
import hmac
import logging
import re

from flask import Blueprint, jsonify, request

from utils.auth_helpers import jwt_required
from utils.db import (
    delete_user_key,
    get_user_keypair_backup,
    get_user_public_key,
    save_user_key,
    users_col,
)
from utils.audit import (
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSeverity,
    record_audit_event,
)

logger = logging.getLogger(__name__)

keys_bp = Blueprint("keys", __name__)

PEM_HEADER = "-----BEGIN PUBLIC KEY-----"
PEM_FOOTER = "-----END PUBLIC KEY-----"


def _extract_der_and_fingerprint(public_key_pem: str) -> tuple[bytes | None, str | None, str | None]:
    """
    Parse a public key PEM string, decode to DER bytes, and calculate its SHA-256 fingerprint.
    Returns: (der_bytes, formatted_fingerprint, error_msg)
    """
    if not public_key_pem or not isinstance(public_key_pem, str):
        return None, None, "Public key must be a non-empty string"

    clean_str = public_key_pem.strip()
    if PEM_HEADER not in clean_str or PEM_FOOTER not in clean_str:
        # If headers are missing, check if it's already a raw base64 SPKI
        base64_content = re.sub(r"\s+", "", clean_str)
    else:
        # Extract content between headers
        start = clean_str.find(PEM_HEADER) + len(PEM_HEADER)
        end = clean_str.find(PEM_FOOTER)
        if start >= end:
            return None, None, "Malformed PEM header/footer boundaries"
        base64_content = re.sub(r"\s+", "", clean_str[start:end])

    if not base64_content:
        return None, None, "Public key content is empty"

    try:
        der_bytes = base64.b64decode(base64_content, validate=True)
    except Exception:
        return None, None, "Invalid base64 encoding in public key"

    # RSA-2048 SPKI is typically 294 bytes; allow 250 to 8192 bytes for RSA-2048 to RSA-4096
    if len(der_bytes) < 250 or len(der_bytes) > 8192:
        return None, None, f"Invalid RSA SPKI key length ({len(der_bytes)} bytes). Expected 2048-bit or stronger key."

    digest = hashlib.sha256(der_bytes).digest()
    pairs = [f"{b:02X}" for b in digest]
    formatted_fp = f"SHA256:{':'.join(pairs)}"

    return der_bytes, formatted_fp, None


# ---------------------------------------------------------------------------
# POST /keys/register — Register / Update RSA Public Key
# ---------------------------------------------------------------------------
@keys_bp.route("/keys/register", methods=["POST"])
@jwt_required
def register_key():
    """
    Register user's RSA public key with fingerprint verification.
    Optionally accepts client-encrypted private key backup (ZERO-KNOWLEDGE).
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "msg": "Request payload must be a JSON object"}), 400

    public_key = (data.get("public_key") or "").strip()
    client_fp = (data.get("fingerprint") or "").strip().upper()
    key_type = (data.get("key_type") or "RSA-OAEP-2048").strip()

    der_bytes, calculated_fp, err = _extract_der_and_fingerprint(public_key)
    if err:
        return jsonify({"success": False, "msg": err}), 400

    # Verify fingerprint authenticity to prevent key substitution attacks
    if client_fp:
        norm_client_fp = client_fp.replace("SHA256:", "").replace(":", "").upper()
        norm_calc_fp = calculated_fp.replace("SHA256:", "").replace(":", "").upper()
        if not hmac.compare_digest(norm_client_fp, norm_calc_fp):
            return jsonify({
                "success": False,
                "msg": "Public key fingerprint mismatch. Key substitution detected."
            }), 400

    # Optional client-encrypted private key backup
    enc_priv_key = (data.get("encrypted_private_key") or "").strip()
    iv = (data.get("iv") or "").strip()
    salt = (data.get("salt") or "").strip()
    integrity_hash = (data.get("integrity_hash") or "").strip()

    if enc_priv_key:
        if not iv or not salt:
            return jsonify({
                "success": False,
                "msg": "Encrypted private key backup requires IV and salt"
            }), 400
        if len(enc_priv_key) > 65536:
            return jsonify({"success": False, "msg": "Encrypted private key exceeds size limit"}), 400

    # Store in MongoDB
    saved = save_user_key(
        user_email=request.user_email,
        public_key=public_key,
        fingerprint=calculated_fp,
        key_type=key_type,
        encrypted_private_key=enc_priv_key,
        iv=iv,
        salt=salt,
        integrity_hash=integrity_hash,
    )

    if not saved:
        return jsonify({"success": False, "msg": "Failed to persist key record"}), 500

    record_audit_event(
        event_type=AuditEventType.KEY_REGISTER,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=request.user_email,
        resource_id=calculated_fp,
        resource_type=AuditResourceType.KEY,
        details={"key_type": key_type, "fingerprint": calculated_fp, "has_backup": bool(enc_priv_key)},
        request_obj=request,
    )

    return jsonify({
        "success": True,
        "msg": "Public key registered successfully",
        "fingerprint": calculated_fp,
        "key_type": key_type,
    }), 201


# ---------------------------------------------------------------------------
# GET /keys/me — Get Authenticated User's Keys & Backups
# ---------------------------------------------------------------------------
@keys_bp.route("/keys/me", methods=["GET"])
@jwt_required
def get_my_keys():
    """Retrieve the authenticated user's registered keys and encrypted backup."""
    doc = get_user_keypair_backup(request.user_email)
    if not doc:
        return jsonify({"success": False, "msg": "No keys registered for this account"}), 404

    return jsonify({
        "success": True,
        "user_email": request.user_email,
        "public_key": doc.get("public_key"),
        "fingerprint": doc.get("fingerprint"),
        "key_type": doc.get("key_type", "RSA-OAEP-2048"),
        "has_backup": bool(doc.get("encrypted_private_key")),
        "encrypted_private_key": doc.get("encrypted_private_key", ""),
        "iv": doc.get("iv", ""),
        "salt": doc.get("salt", ""),
        "integrity_hash": doc.get("integrity_hash", ""),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }), 200


# ---------------------------------------------------------------------------
# GET /keys/<email> — Lookup User Public Key (For Secure Sharing in Phase 7)
# ---------------------------------------------------------------------------
@keys_bp.route("/keys/<email>", methods=["GET"])
@jwt_required
def get_user_key(email: str):
    """
    Fetch public key and fingerprint for any registered user.
    ZERO-KNOWLEDGE: NEVER exposes private key backups, iv, or salt to other users.
    """
    target_email = (email or "").strip().lower()
    if not target_email:
        return jsonify({"success": False, "msg": "Target email is required"}), 400

    doc = get_user_public_key(target_email)
    if not doc:
        user_exists = users_col.find_one({"email": target_email})
        if not user_exists:
            return jsonify({"success": False, "msg": f"Recipient '{target_email}' is not a registered user"}), 404
        return jsonify({"success": False, "msg": f"Recipient '{target_email}' has not registered an RSA public key"}), 404

    return jsonify({
        "success": True,
        "user_email": doc.get("user_email"),
        "public_key": doc.get("public_key"),
        "fingerprint": doc.get("fingerprint"),
        "key_type": doc.get("key_type", "RSA-OAEP-2048"),
        "created_at": doc.get("created_at"),
    }), 200


# ---------------------------------------------------------------------------
# DELETE /keys/me — Revoke Registered Keypair
# ---------------------------------------------------------------------------
@keys_bp.route("/keys/me", methods=["DELETE"])
@jwt_required
def delete_my_keys():
    """Revoke and delete the authenticated user's registered keys."""
    deleted = delete_user_key(request.user_email)
    if not deleted:
        return jsonify({"success": False, "msg": "No keys found to delete"}), 404

    record_audit_event(
        event_type=AuditEventType.KEY_DELETE,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        user_id=getattr(request, "user_id", None),
        user_email=request.user_email,
        resource_type=AuditResourceType.KEY,
        details={"status": "revoked"},
        request_obj=request,
    )

    return jsonify({
        "success": True,
        "msg": "Keypair revoked successfully"
    }), 200
