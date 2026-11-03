# =============================================================================
# models/user.py — Document schema reference
# =============================================================================
# MongoDB documents for the `users` collection:
#
#   {
#       "_id":        ObjectId,
#       "email":      str  (unique, lowercase),
#       "password":   str  (bcrypt hash),
#       "is_admin":   bool (optional, True for admin users),
#       "role":       str  ("admin" | "user"),
#       "created_at": datetime (UTC),
#       "last_login": datetime (UTC) or None
#   }
#
# MongoDB documents for the `files` collection:
#
#   {
#       "_id":                ObjectId,
#       "user_email":         str  (lowercase email of the file owner),
#       "filename":           str,
#       "size":               int  (original file size in bytes),
#       "file_hash":          str  (SHA-256 of encrypted bytes),
#       "s3_key":             str  (Backblaze B2 object key),
#       "mime_type":          str,
#       "iv":                 str  (base64 AES-GCM IV),
#       "salt":               str  (base64 PBKDF2 salt),
#       "is_legacy":          bool (True for pre-remediation uploads),
#       "file_password_hash": str  (OPTIONAL: only on legacy records),
#       "upload_date":        datetime (UTC)
#   }
#
# MongoDB documents for the `revoked_tokens` collection:
#
#   {
#       "_id":        ObjectId,
#       "token_hash": str  (unique SHA-256 hash of revoked JWT),
#       "expires_at": datetime (UTC, with TTL index for auto-cleanup),
#       "revoked_at": datetime (UTC)
#   }
#
# MongoDB documents for the `audit_logs` collection (Phase 11):
#
#   {
#       "_id":           ObjectId,
#       "sequence":      int       (strictly monotonic sequence number, unique),
#       "timestamp":     datetime  (UTC timestamp of event),
#       "event_type":    str       (e.g., LOGIN_SUCCESS, FILE_UPLOAD, UNAUTHORIZED_ACCESS),
#       "severity":      str       (INFO | WARNING | CRITICAL),
#       "outcome":       str       (SUCCESS | FAILURE | DENIED | BLOCKED),
#       "user_id":       str|None  (Subject user ID if authenticated, or None/anonymous),
#       "user_email":    str|None  (Sanitized user email),
#       "resource_id":   str|None  (Target resource ID, e.g. file_id, share_id, token_id),
#       "resource_type": str       (auth | file | share | token | key | security | admin | system),
#       "ip_address":    str       (Sanitized client IP),
#       "user_agent":    str       (Sanitized, truncated user-agent string),
#       "details":       dict      (Safe, non-sensitive metadata — NEVER keys/tokens/PII/passwords),
#       "previous_hash": str       (SHA-256 hash of previous block or genesis),
#       "entry_hash":    str       (SHA-256 hash linking previous hash, sequence & record contents)
#   }
