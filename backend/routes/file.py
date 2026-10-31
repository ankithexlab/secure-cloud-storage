# =============================================================================
# routes/file.py — Upload / List / Download file endpoints
# =============================================================================
import base64
import hashlib

from flask import Blueprint, Response, jsonify, request

from utils.auth_helpers import check_password, hash_password, jwt_required
from utils.db import add_file_record, get_user_files, get_file_by_id, get_user_storage_stats, delete_file_record
from utils.s3 import (
    download_from_s3,
    download_from_s3_stream,
    generate_presigned_url,
    upload_bytes_to_s3,
    delete_from_s3,
)




file_bp = Blueprint("file", __name__)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# POST /upload
# ---------------------------------------------------------------------------
@file_bp.route("/upload", methods=["POST"])
@jwt_required
def upload():
    """
    Receive client-side encrypted data and persist to S3 + MongoDB.

    Expects JSON body:
      - filename (str)
      - encrypted_content (base64 string — already encrypted by the browser)
      - mime_type (str, optional)
      - size (int, original file size)
      - iv (str, base64 — initialisation vector used for AES)
      - salt (str, base64 — PBKDF2 salt used for key derivation)
    """
    data = request.get_json(silent=True) or {}

    filename = (data.get("filename") or "").strip()
    encrypted_content = data.get("encrypted_content", "")
    mime_type = (data.get("mime_type") or "application/octet-stream").strip()
    iv = data.get("iv", "")
    salt = data.get("salt", "")

    if not filename:
        return jsonify({"success": False, "msg": "Filename is required"}), 400
    if not encrypted_content:
        return jsonify({"success": False, "msg": "Encrypted content is required"}), 400

    # Decode base64 → raw bytes for S3
    try:
        raw_bytes = base64.b64decode(encrypted_content, validate=True)
    except Exception:
        return jsonify({"success": False, "msg": "Invalid base64 encrypted content"}), 400

    if len(raw_bytes) > MAX_UPLOAD_SIZE:
        return jsonify({"success": False, "msg": "File exceeds 50 MB limit"}), 413

    if not iv or not salt:
        return jsonify({"success": False, "msg": "Missing encryption metadata (iv/salt)"}), 400

    file_hash = hashlib.sha256(raw_bytes).hexdigest()
    file_password = (data.get("file_password") or "").strip()
    file_password_hash = hash_password(file_password) if file_password else ""

    # Prefer original file size from frontend; fall back to encrypted payload size.
    provided_size = data.get("size")
    try:
        provided_size = int(provided_size)
    except (TypeError, ValueError):
        provided_size = 0
    file_size = provided_size if provided_size > 0 else len(raw_bytes)

    try:
        s3_key = upload_bytes_to_s3(raw_bytes, filename, mime_type="application/octet-stream")
    except Exception as exc:
        return jsonify({
            "success": False,
            "msg": f"S3 upload failed: {str(exc)}"
        }), 500

    # Record metadata in MongoDB (incl iv/salt/mime_type/size)
    file_doc = add_file_record(
        user_email=request.user_email,
        filename=filename,
        file_hash=file_hash,
        s3_key=s3_key,
        file_password_hash=file_password_hash,
        size=file_size,
        mime_type=mime_type,
        iv=iv,
        salt=salt,
    )

    return (
        jsonify(
            {
                "success": True,
                "msg": "File uploaded successfully",
                "file_id": str(file_doc["_id"]),
                "filename": filename,
                "s3_key": s3_key,
                "size": file_size,
                "mime_type": mime_type,
                "iv": iv,
                "salt": salt,
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# GET /files
# ---------------------------------------------------------------------------
@file_bp.route("/files", methods=["GET"])
@jwt_required
def files():
    """Return all file metadata for the authenticated user."""
    user_files = get_user_files(request.user_email)
    stats = get_user_storage_stats(request.user_email)

    return jsonify({"success": True, "files": user_files, "stats": stats}), 200


def _build_encrypted_download_response(file_doc: dict, encrypted_body, content_length: int | None = None):
    if encrypted_body is None:
        return jsonify({"success": False, "msg": "Downloaded payload was empty"}), 502

    headers = {
        "Content-Disposition": f'attachment; filename="{file_doc["filename"]}"',
        "X-IV": file_doc.get("iv", ""),
        "X-Salt": file_doc.get("salt", ""),
        "X-Original-Mime": file_doc.get("mime_type", "application/octet-stream"),
        "Access-Control-Expose-Headers": "Content-Disposition, X-IV, X-Salt, X-Original-Mime, Content-Length",
    }

    # If we have a known size (S3 ContentLength), set Content-Length for smoother client handling.
    if content_length is not None:
        headers["Content-Length"] = str(int(content_length))

    return Response(
        encrypted_body,
        status=200,
        mimetype="application/octet-stream",
        headers=headers,
    )



def _load_owned_file_or_error(file_id: str):
    file_doc = get_file_by_id(file_id)
    if not file_doc:
        return None, (jsonify({"success": False, "msg": "File not found"}), 404)
    if file_doc.get("user_email") != request.user_email:
        return None, (jsonify({"success": False, "msg": "Access denied"}), 403)
    return file_doc, None


# ---------------------------------------------------------------------------
# GET /download/<file_id> — Legacy (no password check)
# ---------------------------------------------------------------------------
@file_bp.route("/download/<file_id>", methods=["GET"])
@jwt_required
def download(file_id: str):
    """
    Download the encrypted file from S3 and stream it to the client.
    The browser will decrypt it client-side.
    """
    file_doc, err = _load_owned_file_or_error(file_id)
    if err:
        return err

    try:
        body = download_from_s3_stream(file_doc["s3_key"])
        content_length = getattr(body, "content_length", None)
    except Exception as exc:
        return jsonify({"success": False, "msg": f"S3 download failed: {str(exc)}"}), 502

    return _build_encrypted_download_response(file_doc, body, content_length=content_length)



# ---------------------------------------------------------------------------
# POST /download/<file_id> — Password protected

# ---------------------------------------------------------------------------
@file_bp.route("/download/<file_id>", methods=["POST"])
@jwt_required
def download_protected(file_id: str):
    """
    Password-protected download. Expects JSON: { "password": str }
    """
    data = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()
    if not password:
        return jsonify({"success": False, "msg": "Password required"}), 400

    file_doc, err = _load_owned_file_or_error(file_id)
    if err:
        return err

    # If server-side password hash exists, validate it.
    stored_hash = (file_doc.get("file_password_hash") or "").strip()
    if stored_hash and not check_password(password, stored_hash):
        return jsonify({"success": False, "msg": "Incorrect password"}), 401

    try:
        body = download_from_s3_stream(file_doc["s3_key"])
        content_length = getattr(body, "content_length", None)
    except Exception as exc:
        return jsonify({"success": False, "msg": f"S3 download failed: {str(exc)}"}), 502

    return _build_encrypted_download_response(file_doc, body, content_length=content_length)


# ---------------------------------------------------------------------------
# GET /download-url/<file_id> — Optional presigned URL flow

# ---------------------------------------------------------------------------
@file_bp.route("/download-url/<file_id>", methods=["GET"])
@jwt_required
def download_url(file_id: str):
    file_doc, err = _load_owned_file_or_error(file_id)
    if err:
        return err
    try:
        presigned_url = generate_presigned_url(file_doc["s3_key"])
    except Exception as exc:
        return jsonify({"success": False, "msg": f"Failed to generate URL: {str(exc)}"}), 502
    return jsonify(
        {
            "success": True,
            "url": presigned_url,
            "filename": file_doc.get("filename", ""),
            "iv": file_doc.get("iv", ""),
            "salt": file_doc.get("salt", ""),
            "mime_type": file_doc.get("mime_type", "application/octet-stream"),
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
        except Exception as exc:
            return jsonify({"success": False, "msg": f"Storage deletion failed: {str(exc)}"}), 502

    deleted = delete_file_record(file_id, request.user_email)
    if not deleted:
        return jsonify({"success": False, "msg": "Failed to remove file metadata"}), 500

    return jsonify({"success": True, "msg": "File deleted successfully", "file_id": file_id}), 200
