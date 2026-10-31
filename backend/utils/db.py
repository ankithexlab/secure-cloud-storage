# =============================================================================
# utils/db.py — MongoDB connection & data-access helpers
# =============================================================================
from datetime import datetime, timezone

from bson.objectid import ObjectId
from pymongo import DESCENDING, MongoClient

from config import Config

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
client = MongoClient(Config.MONGODB_URI, serverSelectionTimeoutMS=5000)
try:
    client.admin.command("ping")
    print(f"MongoDB successfully connected to {Config.MONGODB_URI}!")
except Exception as e:
    print(f"ERROR: Could not connect to MongoDB at {Config.MONGODB_URI}")
    print(f"Exception details: {e}")

try:
    db = client.get_default_database()
    if db is None:
        db = client[getattr(Config, "MONGODB_DB_NAME", "securecloud")]
except Exception:
    db = client[getattr(Config, "MONGODB_DB_NAME", "securecloud")]

users_col = db["users"]
files_col = db["files"]

# Ensure indexes (idempotent)
try:
    users_col.create_index("email", unique=True)
    files_col.create_index("user_email")
    files_col.create_index("upload_date")
except Exception as e:
    print(f"WARNING: Could not create database indexes: {e}")


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------
def get_user_by_email(email: str):
    """Return the user document or None."""
    return users_col.find_one({"email": email})


def update_user_last_login(email: str):
    """Update the user's last_login timestamp."""
    users_col.update_one(
        {"email": email},
        {"$set": {"last_login": datetime.now(timezone.utc)}},
    )


def create_user(email: str, password_hash: str) -> dict:
    """Insert a new user and return the created document."""
    doc = {
        "email": email,
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
) -> dict:
    """Persist file metadata and return the inserted document."""
    doc = {
        "user_email": user_email,
        "filename": filename,
        "file_hash": file_hash,
        "file_password_hash": file_password_hash or "",
        "s3_key": s3_key,
        "size": int(size or 0),
        "mime_type": mime_type or "application/octet-stream",
        "iv": iv or "",
        "salt": salt or "",
        "upload_date": datetime.now(timezone.utc),
    }
    result = files_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


def get_user_files(user_email: str) -> list:
    """Return all files belonging to a user, newest first."""
    cursor = files_col.find({"user_email": user_email}).sort("upload_date", DESCENDING)
    results = []
    for doc in cursor:
        results.append(
            {
                "id": str(doc["_id"]),
                "filename": doc["filename"],
                "size": doc.get("size", 0),
                "mime_type": doc.get("mime_type", "application/octet-stream"),
                "s3_key": doc.get("s3_key", ""),
                "iv": doc.get("iv", ""),
                "salt": doc.get("salt", ""),
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
    pipeline = [
        {"$match": {"user_email": user_email}},
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
        res = files_col.delete_one({"_id": ObjectId(file_id), "user_email": user_email})
        return res.deleted_count > 0
    except Exception:
        return False
