# =============================================================================
# utils/db.py — MongoDB connection & data-access helpers
# =============================================================================
from datetime import datetime, timezone, timedelta
import logging

from bson.objectid import ObjectId
from pymongo import DESCENDING, MongoClient

from config import Config, mask_uri

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
client = MongoClient(Config.MONGODB_URI, serverSelectionTimeoutMS=5000)
try:
    client.admin.command("ping")
    print(f"MongoDB successfully connected to {mask_uri(Config.MONGODB_URI)}!")
except Exception as e:
    print(f"ERROR: Could not connect to MongoDB at {mask_uri(Config.MONGODB_URI)}")
    print(f"Exception details: {e}")

try:
    db = client.get_default_database()
    if db is None:
        db = client[getattr(Config, "MONGODB_DB_NAME", "securecloud")]
except Exception:
    db = client[getattr(Config, "MONGODB_DB_NAME", "securecloud")]

users_col = db["users"]
files_col = db["files"]
revoked_tokens_col = db["revoked_tokens"]
user_keys_col = db["user_keys"]
access_tokens_col = db["access_tokens"]
file_shares_col = db["file_shares"]
audit_logs_col = db["audit_logs"]

# Ensure indexes (idempotent)
try:
    users_col.create_index("email", unique=True)
    files_col.create_index([("user_email", 1), ("upload_date", -1)])
    files_col.create_index("s3_key")
    revoked_tokens_col.create_index("expires_at", expireAfterSeconds=0)
    revoked_tokens_col.create_index("token_hash", unique=True)
    user_keys_col.create_index("user_email", unique=True)
    access_tokens_col.create_index("token_hash", unique=True)
    access_tokens_col.create_index([("user_email", 1), ("created_at", -1)])
    access_tokens_col.create_index([("file_id", 1), ("created_at", -1)])
    access_tokens_col.create_index("expires_at")
    file_shares_col.create_index([("owner_email", 1), ("created_at", -1)])
    file_shares_col.create_index([("recipient_email", 1), ("created_at", -1)])
    file_shares_col.create_index([("file_id", 1), ("recipient_email", 1)])
    file_shares_col.create_index("token_hash", sparse=True)
    file_shares_col.create_index("expires_at")
    audit_logs_col.create_index("sequence", unique=True)
    audit_logs_col.create_index([("timestamp", -1)])
    audit_logs_col.create_index("event_type")
    audit_logs_col.create_index("outcome")
    audit_logs_col.create_index("severity")
    audit_logs_col.create_index("user_email")
    audit_logs_col.create_index("user_id")
    audit_logs_col.create_index("resource_id")
    audit_logs_col.create_index([("timestamp", -1), ("event_type", 1)])
    audit_logs_col.create_index([("timestamp", -1), ("severity", 1)])
    audit_logs_col.create_index([("user_email", 1), ("timestamp", -1)])
except Exception as e:
    print(f"WARNING: Could not create database indexes: {e}")


# ---------------------------------------------------------------------------
# In-memory fallback for revoked tokens (ensures safety if DB has transient issue)
# ---------------------------------------------------------------------------
_in_memory_revoked: dict[str, float] = {}


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------
def get_user_by_email(email: str):
    """Return the user document or None."""
    if not email:
        return None
    return users_col.find_one({"email": email.strip().lower()})


def update_user_last_login(email: str):
    """Update the user's last_login timestamp."""
    users_col.update_one(
        {"email": email.strip().lower()},
        {"$set": {"last_login": datetime.now(timezone.utc)}},
    )


def update_user_password(email: str, new_password_hash: str) -> bool:
    """Update user password hash and record updated_at timestamp."""
    if not email or not new_password_hash:
        return False
    res = users_col.update_one(
        {"email": email.strip().lower()},
        {"$set": {"password": new_password_hash, "password_updated_at": datetime.now(timezone.utc)}},
    )
    return res.modified_count > 0


def create_user(email: str, password_hash: str) -> dict:
    """Insert a new user and return the created document."""
    doc = {
        "email": email.strip().lower(),
        "password": password_hash,
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
    }
    result = users_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


def get_user_by_id(user_id: str):
    """Fetch user by ObjectId string."""
    try:
        return users_col.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Token Revocation Helpers
# ---------------------------------------------------------------------------
def revoke_token(token_hash: str, expires_at: datetime) -> bool:
    """Revoke a token by recording its hash until expiration."""
    if not token_hash:
        return False

    exp_ts = expires_at.timestamp() if isinstance(expires_at, datetime) else float(expires_at)
    _in_memory_revoked[token_hash] = exp_ts

    try:
        revoked_tokens_col.update_one(
            {"token_hash": token_hash},
            {"$set": {"expires_at": expires_at, "revoked_at": datetime.now(timezone.utc)}},
            upsert=True,
        )
        return True
    except Exception as exc:
        logger.warning(f"Failed to record revoked token in MongoDB: {exc}")
        return True  # in-memory revocation still succeeded


def is_token_revoked(token_hash: str) -> bool:
    """Check if token hash is in revocation store."""
    if not token_hash:
        return False

    now_ts = datetime.now(timezone.utc).timestamp()

    # Check in-memory store first
    if token_hash in _in_memory_revoked:
        if _in_memory_revoked[token_hash] > now_ts:
            return True
        else:
            del _in_memory_revoked[token_hash]

    try:
        doc = revoked_tokens_col.find_one({"token_hash": token_hash})
        if doc:
            doc_exp = doc.get("expires_at")
            if isinstance(doc_exp, datetime):
                # Ensure UTC tz-aware comparison
                if doc_exp.tzinfo is None:
                    doc_exp = doc_exp.replace(tzinfo=timezone.utc)
                if doc_exp > datetime.now(timezone.utc):
                    return True
            return True
    except Exception as exc:
        logger.warning(f"Error checking revoked token in MongoDB: {exc}")

    return False


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------
def add_file_record(
    user_email: str,
    filename: str,
    file_hash: str,
    s3_key: str,
    file_password_hash: str = "",
    size: int = 0,
    mime_type: str = "application/octet-stream",
    iv: str = "",
    salt: str = "",
    is_legacy: bool = False,
    integrity_hash: str = "",
    algorithm: str = "AES-GCM-256",
    kdf: str = "PBKDF2-SHA256",
    iterations: int = 100000,
    version: str = "1.0",
    wrapped_key: str = "",
    key_fingerprint: str = "",
) -> dict:
    """Persist file metadata and return the inserted document."""
    doc = {
        "user_email": user_email.strip().lower(),
        "filename": filename,
        "file_hash": file_hash,
        "s3_key": s3_key,
        "size": int(size or 0),
        "mime_type": mime_type or "application/octet-stream",
        "iv": iv or "",
        "salt": salt or "",
        "wrapped_key": wrapped_key or "",
        "key_fingerprint": key_fingerprint or "",
        "is_legacy": bool(is_legacy or file_password_hash),
        "integrity_hash": integrity_hash or "",
        "algorithm": algorithm or "AES-GCM-256",
        "kdf": kdf or "PBKDF2-SHA256",
        "iterations": int(iterations or 100000),
        "version": version or "1.0",
        "upload_date": datetime.now(timezone.utc),
    }

    # Only store file_password_hash if explicitly provided (for legacy backwards-compat)
    if file_password_hash:
        doc["file_password_hash"] = file_password_hash

    result = files_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


def get_user_files(user_email: str) -> list:
    """Return all files belonging to a user, newest first. Never exposes password hashes."""
    normalized_email = (user_email or "").strip().lower()
    cursor = files_col.find({"user_email": normalized_email}).sort("upload_date", DESCENDING)
    results = []
    for doc in cursor:
        is_legacy = bool(doc.get("is_legacy") or doc.get("file_password_hash"))
        results.append(
            {
                "id": str(doc["_id"]),
                "filename": doc["filename"],
                "size": doc.get("size", 0),
                "mime_type": doc.get("mime_type", "application/octet-stream"),
                "s3_key": doc.get("s3_key", ""),
                "iv": doc.get("iv", ""),
                "salt": doc.get("salt", ""),
                "wrapped_key": doc.get("wrapped_key", ""),
                "key_fingerprint": doc.get("key_fingerprint", ""),
                "integrity_hash": doc.get("integrity_hash", ""),
                "algorithm": doc.get("algorithm", "AES-GCM-256"),
                "is_legacy": is_legacy,
                "upload_date": doc["upload_date"].isoformat()
                if isinstance(doc["upload_date"], datetime)
                else str(doc["upload_date"]),
            }
        )
    return results


def get_file_by_id(file_id: str):
    """Fetch a single file record by its ObjectId string."""
    try:
        return files_col.find_one({"_id": ObjectId(file_id)})
    except Exception:
        return None


def get_user_storage_stats(user_email: str) -> dict:
    """Return aggregate storage statistics for the user."""
    normalized_email = (user_email or "").strip().lower()
    pipeline = [
        {"$match": {"user_email": normalized_email}},
        {
            "$group": {
                "_id": None,
                "total_files": {"$sum": 1},
                "total_size": {"$sum": "$size"},
            }
        },
    ]
    result = list(files_col.aggregate(pipeline))
    if result:
        return {
            "total_files": result[0]["total_files"],
            "total_size": result[0]["total_size"],
        }
    return {"total_files": 0, "total_size": 0}


def delete_file_record(file_id: str, user_email: str) -> bool:
    """Delete a file document from MongoDB for the specified user."""
    try:
        normalized_email = (user_email or "").strip().lower()
        res = files_col.delete_one({"_id": ObjectId(file_id), "user_email": normalized_email})
        return res.deleted_count > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# RSA Public Key & Encrypted Private Key Backup Helpers
# ---------------------------------------------------------------------------
def save_user_key(
    user_email: str,
    public_key: str,
    fingerprint: str,
    key_type: str = "RSA-OAEP-2048",
    encrypted_private_key: str = "",
    iv: str = "",
    salt: str = "",
    integrity_hash: str = "",
) -> bool:
    """Register or update an RSA public key and optional encrypted private key backup."""
    normalized_email = (user_email or "").strip().lower()
    if not normalized_email or not public_key or not fingerprint:
        return False

    update_fields = {
        "user_email": normalized_email,
        "public_key": public_key.strip(),
        "fingerprint": fingerprint.strip().upper(),
        "key_type": key_type or "RSA-OAEP-2048",
        "updated_at": datetime.now(timezone.utc),
    }

    if encrypted_private_key:
        update_fields["encrypted_private_key"] = encrypted_private_key.strip()
        update_fields["iv"] = (iv or "").strip()
        update_fields["salt"] = (salt or "").strip()
        update_fields["integrity_hash"] = (integrity_hash or "").strip()

    res = user_keys_col.update_one(
        {"user_email": normalized_email},
        {
            "$set": update_fields,
            "$setOnInsert": {"created_at": datetime.now(timezone.utc)},
        },
        upsert=True,
    )
    return res.acknowledged


def get_user_public_key(user_email: str) -> dict | None:
    """
    Retrieve public key metadata for any user.
    ZERO-KNOWLEDGE: NEVER returns encrypted_private_key, iv, or salt.
    """
    normalized_email = (user_email or "").strip().lower()
    doc = user_keys_col.find_one(
        {"user_email": normalized_email},
        {"_id": 0, "user_email": 1, "public_key": 1, "fingerprint": 1, "key_type": 1, "created_at": 1},
    )
    if not doc:
        return None

    if "created_at" in doc and isinstance(doc["created_at"], datetime):
        doc["created_at"] = doc["created_at"].isoformat()
    return doc


def get_user_keypair_backup(user_email: str) -> dict | None:
    """
    Retrieve the complete keypair record including client-encrypted private key backup.
    Strictly authorized to the authenticated key owner only.
    """
    normalized_email = (user_email or "").strip().lower()
    doc = user_keys_col.find_one(
        {"user_email": normalized_email},
        {"_id": 0},
    )
    if not doc:
        return None

    for dt_field in ("created_at", "updated_at"):
        if dt_field in doc and isinstance(doc[dt_field], datetime):
            doc[dt_field] = doc[dt_field].isoformat()
    return doc


def delete_user_key(user_email: str) -> bool:
    """Revoke and delete the user's registered public key and backups."""
    normalized_email = (user_email or "").strip().lower()
    res = user_keys_col.delete_one({"user_email": normalized_email})
    return res.deleted_count > 0


# ---------------------------------------------------------------------------
# Access Token helpers (Phase 8 — Secure Access Token Management)
# ---------------------------------------------------------------------------
def create_access_token_record(
    token_hash: str,
    file_id: str,
    user_email: str,
    scope: str = "download",
    expires_at: datetime | None = None,
    max_downloads: int = 1,
    label: str = "",
) -> dict:
    """
    Persist an access token record in MongoDB.
    SECURITY: ONLY the SHA-256 hash of the token is saved. Plaintext tokens are NEVER stored.
    """
    doc = {
        "token_hash": token_hash,
        "file_id": str(file_id),
        "user_email": user_email.strip().lower(),
        "scope": scope if scope in ("download", "view") else "download",
        "expires_at": expires_at,
        "max_downloads": int(max_downloads) if max_downloads is not None else 1,
        "downloads_used": 0,
        "is_revoked": False,
        "revoked_at": None,
        "label": (label or "").strip()[:100],
        "created_at": datetime.now(timezone.utc),
        "last_used_at": None,
    }
    result = access_tokens_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    doc["id"] = str(result.inserted_id)
    return doc


def find_token_by_hash(token_hash: str) -> dict | None:
    """Find token record by its SHA-256 hash."""
    if not token_hash:
        return None
    return access_tokens_col.find_one({"token_hash": token_hash})


def consume_token_for_download(token_hash: str) -> tuple[dict | None, str | None]:
    """
    Atomically validate and increment downloads_used for a download token.
    Prevents race conditions on single-use or limited-download tokens using MongoDB atomic operators.
    Returns (token_doc, error_message).
    """
    if not token_hash:
        return None, "Invalid access token"

    now = datetime.now(timezone.utc)
    token = access_tokens_col.find_one({"token_hash": token_hash})
    if not token:
        return None, "Invalid access token"

    if token.get("is_revoked"):
        return None, "Access token has been revoked"

    expires_at = token.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            return None, "Access token has expired"

    if token.get("scope") != "download":
        return None, "Access token does not have download permission"

    max_downloads = token.get("max_downloads", 1)

    # Unlimited downloads (max_downloads <= 0)
    if max_downloads <= 0:
        updated = access_tokens_col.find_one_and_update(
            {"_id": token["_id"], "is_revoked": False},
            {"$inc": {"downloads_used": 1}, "$set": {"last_used_at": now}},
            return_document=True,
        )
        return updated, None

    # Atomic single-use / limit check: downloads_used MUST be strictly less than max_downloads
    updated = access_tokens_col.find_one_and_update(
        {
            "_id": token["_id"],
            "is_revoked": False,
            "downloads_used": {"$lt": max_downloads},
        },
        {"$inc": {"downloads_used": 1}, "$set": {"last_used_at": now}},
        return_document=True,
    )

    if not updated:
        return None, "Download limit reached for this access token"

    return updated, None


def validate_token_for_view(token_hash: str) -> tuple[dict | None, str | None]:
    """
    Validate token validity for view scope or inspection without consuming download quota.
    Returns (token_doc, error_message).
    """
    if not token_hash:
        return None, "Invalid access token"

    now = datetime.now(timezone.utc)
    token = access_tokens_col.find_one({"token_hash": token_hash})
    if not token:
        return None, "Invalid access token"

    if token.get("is_revoked"):
        return None, "Access token has been revoked"

    expires_at = token.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            return None, "Access token has expired"

    max_downloads = token.get("max_downloads", 1)
    if max_downloads > 0 and token.get("downloads_used", 0) >= max_downloads:
        return None, "Token usage limit has been reached"

    return token, None


def revoke_access_token_by_id(token_id: str, user_email: str) -> bool:
    """Revoke an access token immediately. Ensures user owns the token."""
    try:
        oid = ObjectId(token_id)
    except Exception:
        return False

    res = access_tokens_col.update_one(
        {"_id": oid, "user_email": user_email.strip().lower()},
        {"$set": {"is_revoked": True, "revoked_at": datetime.now(timezone.utc)}},
    )
    return res.modified_count > 0


def get_file_access_tokens(file_id: str, user_email: str) -> list:
    """Return all tokens for a file owned by user_email. NEVER exposes token_hash."""
    cursor = access_tokens_col.find(
        {"file_id": str(file_id), "user_email": user_email.strip().lower()}
    ).sort("created_at", DESCENDING)

    now = datetime.now(timezone.utc)
    results = []
    for doc in cursor:
        expires_at = doc.get("expires_at")
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        is_expired = bool(expires_at and expires_at <= now)
        is_revoked = bool(doc.get("is_revoked"))
        max_dl = doc.get("max_downloads", 1)
        used_dl = doc.get("downloads_used", 0)
        is_exhausted = bool(max_dl > 0 and used_dl >= max_dl)

        status = "revoked" if is_revoked else ("expired" if is_expired else ("exhausted" if is_exhausted else "active"))

        results.append(
            {
                "id": str(doc["_id"]),
                "file_id": doc["file_id"],
                "scope": doc.get("scope", "download"),
                "label": doc.get("label", ""),
                "max_downloads": max_dl,
                "downloads_used": used_dl,
                "is_revoked": is_revoked,
                "is_expired": is_expired,
                "is_exhausted": is_exhausted,
                "status": status,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "created_at": doc["created_at"].isoformat()
                if isinstance(doc.get("created_at"), datetime)
                else str(doc.get("created_at")),
                "last_used_at": doc["last_used_at"].isoformat()
                if isinstance(doc.get("last_used_at"), datetime)
                else None,
            }
        )
    return results


def get_user_all_access_tokens(user_email: str) -> list:
    """Return all tokens created by user_email. NEVER exposes token_hash."""
    cursor = access_tokens_col.find(
        {"user_email": user_email.strip().lower()}
    ).sort("created_at", DESCENDING)

    now = datetime.now(timezone.utc)
    results = []
    for doc in cursor:
        expires_at = doc.get("expires_at")
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        is_expired = bool(expires_at and expires_at <= now)
        is_revoked = bool(doc.get("is_revoked"))
        max_dl = doc.get("max_downloads", 1)
        used_dl = doc.get("downloads_used", 0)
        is_exhausted = bool(max_dl > 0 and used_dl >= max_dl)

        status = "revoked" if is_revoked else ("expired" if is_expired else ("exhausted" if is_exhausted else "active"))

        results.append(
            {
                "id": str(doc["_id"]),
                "file_id": doc["file_id"],
                "scope": doc.get("scope", "download"),
                "label": doc.get("label", ""),
                "max_downloads": max_dl,
                "downloads_used": used_dl,
                "is_revoked": is_revoked,
                "is_expired": is_expired,
                "is_exhausted": is_exhausted,
                "status": status,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "created_at": doc["created_at"].isoformat()
                if isinstance(doc.get("created_at"), datetime)
                else str(doc.get("created_at")),
                "last_used_at": doc["last_used_at"].isoformat()
                if isinstance(doc.get("last_used_at"), datetime)
                else None,
            }
        )
    return results


# =============================================================================
# Phase 9: Secure File Sharing Database Helpers
# =============================================================================

def create_file_share_record(
    file_id: str,
    owner_email: str,
    recipient_email: str,
    wrapped_key: str,
    key_fingerprint: str,
    permission: str = "download",
    expires_in_seconds: int = 86400,
    max_downloads: int = 1,
    note: str = "",
    token_id: str = None,
    token_hash: str = None,
) -> dict:
    """
    Create a secure file share record for a recipient.
    ZERO-KNOWLEDGE:
      - Plaintext files and private keys are never stored.
      - wrapped_key is the file's AES data key wrapped client-side with recipient's public key.
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=max(60, min(expires_in_seconds, 30 * 86400)))

    doc = {
        "file_id": str(file_id),
        "owner_email": owner_email.strip().lower(),
        "recipient_email": recipient_email.strip().lower(),
        "wrapped_key": wrapped_key.strip(),
        "key_fingerprint": key_fingerprint.strip(),
        "permission": permission if permission in ("download", "view") else "download",
        "expires_at": expires_at,
        "max_downloads": max(0, int(max_downloads)),
        "downloads_used": 0,
        "is_revoked": False,
        "revoked_at": None,
        "note": (note or "").strip()[:200],
        "token_id": str(token_id) if token_id else None,
        "token_hash": str(token_hash) if token_hash else None,
        "created_at": now,
        "last_accessed_at": None,
    }

    result = file_shares_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    doc["id"] = str(result.inserted_id)
    return doc


def get_share_by_id(share_id: str):
    """Fetch a single share record by its ObjectId string."""
    try:
        return file_shares_col.find_one({"_id": ObjectId(share_id)})
    except Exception:
        return None


def get_shares_by_owner(owner_email: str, file_id: str = None) -> list:
    """
    Return sharing history created by owner_email.
    Optionally filters by file_id.
    """
    query = {"owner_email": owner_email.strip().lower()}
    if file_id:
        query["file_id"] = str(file_id)

    cursor = file_shares_col.find(query).sort("created_at", DESCENDING)
    now = datetime.now(timezone.utc)
    results = []

    for doc in cursor:
        expires_at = doc.get("expires_at")
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        is_expired = bool(expires_at and expires_at <= now)
        is_revoked = bool(doc.get("is_revoked"))
        max_dl = doc.get("max_downloads", 1)
        used_dl = doc.get("downloads_used", 0)
        is_exhausted = bool(max_dl > 0 and used_dl >= max_dl)

        status = "revoked" if is_revoked else ("expired" if is_expired else ("exhausted" if is_exhausted else "active"))

        # Lookup file name for convenience
        file_doc = get_file_by_id(doc["file_id"])
        filename = file_doc.get("filename", "Unknown File") if file_doc else "Unknown File"
        file_size = file_doc.get("size", 0) if file_doc else 0

        results.append({
            "id": str(doc["_id"]),
            "file_id": doc["file_id"],
            "filename": filename,
            "file_size": file_size,
            "owner_email": doc["owner_email"],
            "recipient_email": doc["recipient_email"],
            "key_fingerprint": doc.get("key_fingerprint", ""),
            "permission": doc.get("permission", "download"),
            "max_downloads": max_dl,
            "downloads_used": used_dl,
            "downloads_remaining": max(0, max_dl - used_dl) if max_dl > 0 else "unlimited",
            "is_revoked": is_revoked,
            "is_expired": is_expired,
            "is_exhausted": is_exhausted,
            "status": status,
            "note": doc.get("note", ""),
            "token_id": doc.get("token_id"),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "created_at": doc["created_at"].isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at")),
            "last_accessed_at": doc["last_accessed_at"].isoformat() if isinstance(doc.get("last_accessed_at"), datetime) else None,
        })
    return results


def get_shares_for_recipient(recipient_email: str) -> list:
    """
    Return all file shares received by recipient_email.
    Includes file metadata and status.
    """
    cursor = file_shares_col.find(
        {"recipient_email": recipient_email.strip().lower()}
    ).sort("created_at", DESCENDING)

    now = datetime.now(timezone.utc)
    results = []

    for doc in cursor:
        expires_at = doc.get("expires_at")
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        is_expired = bool(expires_at and expires_at <= now)
        is_revoked = bool(doc.get("is_revoked"))
        max_dl = doc.get("max_downloads", 1)
        used_dl = doc.get("downloads_used", 0)
        is_exhausted = bool(max_dl > 0 and used_dl >= max_dl)

        status = "revoked" if is_revoked else ("expired" if is_expired else ("exhausted" if is_exhausted else "active"))

        file_doc = get_file_by_id(doc["file_id"])
        if not file_doc:
            continue

        results.append({
            "id": str(doc["_id"]),
            "file_id": doc["file_id"],
            "filename": file_doc.get("filename", ""),
            "size": file_doc.get("size", 0),
            "mime_type": file_doc.get("mime_type", "application/octet-stream"),
            "upload_date": file_doc.get("upload_date").isoformat() if isinstance(file_doc.get("upload_date"), datetime) else str(file_doc.get("upload_date")),
            "iv": file_doc.get("iv", ""),
            "salt": file_doc.get("salt", ""),
            "integrity_hash": file_doc.get("integrity_hash", ""),
            "algorithm": file_doc.get("algorithm", "AES-GCM-256+RSA-OAEP"),
            "owner_email": doc["owner_email"],
            "wrapped_key": doc.get("wrapped_key", ""),
            "key_fingerprint": doc.get("key_fingerprint", ""),
            "permission": doc.get("permission", "download"),
            "max_downloads": max_dl,
            "downloads_used": used_dl,
            "downloads_remaining": max(0, max_dl - used_dl) if max_dl > 0 else "unlimited",
            "is_revoked": is_revoked,
            "is_expired": is_expired,
            "is_exhausted": is_exhausted,
            "status": status,
            "note": doc.get("note", ""),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "created_at": doc["created_at"].isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at")),
        })
    return results


def revoke_file_share(share_id: str, owner_email: str) -> tuple[bool, str]:
    """
    Revoke a file share. Strictly requires owner_email match.
    Also revokes linked access token if present.
    """
    try:
        oid = ObjectId(share_id)
    except Exception:
        return False, "Invalid share ID format"

    share = file_shares_col.find_one({"_id": oid})
    if not share:
        return False, "Share not found"

    if share.get("owner_email") != owner_email.strip().lower():
        return False, "Permission denied — cannot revoke another user's share"

    if share.get("is_revoked"):
        return True, "Share is already revoked"

    now = datetime.now(timezone.utc)
    file_shares_col.update_one(
        {"_id": oid},
        {"$set": {"is_revoked": True, "revoked_at": now}}
    )

    # Revoke linked access token if any (by token_id or token_hash)
    token_id = share.get("token_id")
    token_hash = share.get("token_hash")
    token_query = None
    if token_id:
        try:
            token_query = {"_id": ObjectId(token_id)}
        except Exception:
            token_query = None
    if not token_query and token_hash:
        token_query = {"token_hash": token_hash}
    if token_query:
        try:
            access_tokens_col.update_one(
                token_query,
                {"$set": {"is_revoked": True, "revoked_at": now}}
            )
        except Exception:
            pass

    return True, "Share revoked successfully"


def consume_share_for_download(share_id: str, recipient_email: str) -> tuple[dict | None, str | None]:
    """
    Atomic share verification and download quota consumption.
    Validates recipient, expiration, revocation, permission, and increments quota in a single operation.
    """
    try:
        oid = ObjectId(share_id)
    except Exception:
        return None, "Invalid share ID"

    share = file_shares_col.find_one({"_id": oid})
    if not share:
        return None, "Share not found"

    if share.get("recipient_email") != recipient_email.strip().lower():
        return None, "Access denied: you are not the designated recipient of this share"

    if share.get("permission") != "download":
        return None, "This share has view-only permission; file download is not permitted"

    if share.get("is_revoked"):
        return None, "This share has been revoked by the owner"

    now = datetime.now(timezone.utc)
    expires_at = share.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            return None, "This share link has expired"

    max_downloads = share.get("max_downloads", 1)

    if max_downloads == 0:
        # Unlimited downloads within validity window (atomic update)
        updated = file_shares_col.find_one_and_update(
            {
                "_id": oid,
                "recipient_email": recipient_email.strip().lower(),
                "is_revoked": False,
            },
            {"$inc": {"downloads_used": 1}, "$set": {"last_accessed_at": now}},
            return_document=True,
        )
        if not updated:
            curr = file_shares_col.find_one({"_id": oid})
            if curr and curr.get("is_revoked"):
                return None, "This share has been revoked by the owner"
            return None, "Access denied: share is no longer valid"
        return updated, None

    # ATOMIC CONDITION: find_one_and_update prevents race conditions on download limits
    updated = file_shares_col.find_one_and_update(
        {
            "_id": oid,
            "recipient_email": recipient_email.strip().lower(),
            "is_revoked": False,
            "downloads_used": {"$lt": max_downloads},
        },
        {
            "$inc": {"downloads_used": 1},
            "$set": {"last_accessed_at": now},
        },
        return_document=True,
    )

    if not updated:
        curr = file_shares_col.find_one({"_id": oid})
        if curr and curr.get("is_revoked"):
            return None, "This share has been revoked by the owner"
        if curr and curr.get("expires_at"):
            exp = curr.get("expires_at")
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= datetime.now(timezone.utc):
                return None, "This share link has expired"
        return None, "Share download limit has been reached"

    return updated, None


def validate_share_for_view(share_id: str, recipient_email: str) -> tuple[dict | None, str | None]:
    """
    Inspect a share without consuming download limit.
    Validates recipient identity, revocation, and expiration.
    """
    try:
        oid = ObjectId(share_id)
    except Exception:
        return None, "Invalid share ID"

    share = file_shares_col.find_one({"_id": oid})
    if not share:
        return None, "Share not found"

    if share.get("recipient_email") != recipient_email.strip().lower():
        return None, "Access denied: you are not the designated recipient of this share"

    if share.get("is_revoked"):
        return None, "This share has been revoked by the owner"

    now = datetime.now(timezone.utc)
    expires_at = share.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            return None, "This share link has expired"

    max_downloads = share.get("max_downloads", 1)
    if max_downloads > 0 and share.get("downloads_used", 0) >= max_downloads:
        return None, "Share download limit has been reached"

    return share, None

