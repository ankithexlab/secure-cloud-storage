# =============================================================================
# models/user.py — User document schema reference
# =============================================================================
# MongoDB documents for the `users` collection:
#
#   {
#       "_id":        ObjectId,
#       "email":      str  (unique),
#       "password":   str  (bcrypt hash),
#       "created_at": datetime (UTC)
#   }
#
# MongoDB documents for the `files` collection:
#
#   {
#       "_id":         ObjectId,
#       "user_id":     str  (stringified user ObjectId),
#       "filename":    str,
#       "size":        int  (original file size in bytes),
#       "s3_key":      str  (S3 object key),
#       "mime_type":   str,
#       "iv":          str  (base64 AES-GCM IV),
#       "salt":        str  (base64 PBKDF2 salt),
#       "upload_date": datetime (UTC)
#   }
