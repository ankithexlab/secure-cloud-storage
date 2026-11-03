# =============================================================================
# tests/test_e2e_qa.py — Comprehensive End-to-End & Quality Assurance Suite
#
# Covers Phase 12 requirements:
#   - 50 MB upload limits and boundary testing
#   - Tampered files, corrupted tags, invalid hashes
#   - Multi-user isolation, cross-tenant authorization
#   - Expired & revoked access tokens and file shares
#   - Invalid credentials, brute-force defense, account security
#   - Network & storage failures (auth, timeout, 404, atomic rollback)
#   - Live MongoDB & Backblaze B2 End-to-End lifecycle test
# =============================================================================
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import sys
import uuid
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import Config
from utils.auth_helpers import create_jwt, hash_password
from utils.audit import (
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSeverity,
    verify_audit_log_integrity,
)
from utils.db import (
    access_tokens_col,
    audit_logs_col,
    create_access_token_record,
    create_file_share_record,
    file_shares_col,
    files_col,
    user_keys_col,
    users_col,
)
from utils.s3 import (
    StorageAuthError,
    StorageError,
    StorageNotFoundError,
    StorageTimeoutError,
)

SAMPLE_RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0pUkfwIV8Mm5dIT2Qbux
7hb3DFK0G+83pqj00gwPYGifgJtZ7mpqyVW9lOAFpHiNKRdjqVDkw46N97/8jgYu
Y/7l4mhpDVKFKOc/0C2QeIzwzxR08cQCs7I71F+7jmKzMCzyHv1kT5wcr+1U8vtO
DLW/K/vHE12D/OI8kdrhDOsjpYGTi0Sb1GBjxxT/2D20ZlhXItaKrbU1f98s6heC
8U4MCNyj6lhaXXBiKfDqIcdG0NcwX60YzuoQVYzXJBQduDg2TgSivGjxtDyx/FW7
x98wQQbBNRtI638x1msI4qEueawcpA+00104Qg5g4aBruwrKwtaJ7ZPCxRSqNdhu
HwIDAQAB
-----END PUBLIC KEY-----"""

SAMPLE_RSA_FINGERPRINT = "SHA256:5E:E7:1A:22:F2:15:86:6D:98:EC:9F:E1:7E:77:28:73:1C:4B:F3:B3:CA:7C:22:D8:4F:05:62:E3:F2:2F:CD:0D"


@pytest.fixture(scope="session")
def app():
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


@pytest.fixture()
def alice_auth():
    email = f"alice_qa_{uuid.uuid4().hex[:8]}@example.com"
    uid = uuid.uuid4().hex[:24]
    token = create_jwt(uid, email)
    return {"email": email, "user_id": uid, "token": token}


@pytest.fixture()
def bob_auth():
    email = f"bob_qa_{uuid.uuid4().hex[:8]}@example.com"
    uid = uuid.uuid4().hex[:24]
    token = create_jwt(uid, email)
    return {"email": email, "user_id": uid, "token": token}


# =============================================================================
# 1. 50 MB Upload Limits & Boundary Testing
# =============================================================================
class TestUploadLimitsAndBoundary50MB:
    def test_upload_exact_50mb_boundary_accepted(self, client, alice_auth):
        """
        Upload payload of exactly 50 MB (50 * 1024 * 1024 = 52,428,800 bytes)
        is accepted (201 Created) under the 50 MB limit.
        """
        raw_size = 50 * 1024 * 1024  # exactly 50 MB
        raw_50mb_bytes = b"0" * raw_size

        payload = {
            "filename": "boundary_50mb.dat",
            "encrypted_content": "QUJDRA==",
            "size": raw_size,
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
            "algorithm": "AES-GCM-256",
        }

        orig_b64 = base64.b64decode
        def selective_b64(s, *args, **kwargs):
            if kwargs.get("validate"):
                return raw_50mb_bytes
            return orig_b64(s, *args, **kwargs)

        with patch("routes.file.base64.b64decode", side_effect=selective_b64), \
             patch("routes.file.upload_bytes_to_s3", return_value="encrypted/boundary_50mb.dat"):
            res = client.post(
                "/api/upload",
                json=payload,
                headers={"Authorization": f"Bearer {alice_auth['token']}"},
            )
            assert res.status_code == 201
            data = res.get_json()
            assert data["success"] is True
            assert data["size"] == raw_size
            files_col.delete_one({"filename": "boundary_50mb.dat", "user_email": alice_auth["email"]})

    def test_upload_exceeding_50mb_rejected_with_413(self, client, alice_auth):
        """
        Upload payload of 50 MB + 1 byte (52,428,801 bytes)
        is rejected with HTTP 413 and clear limit message.
        """
        raw_size = 50 * 1024 * 1024 + 1  # 50MB + 1 byte
        raw_over_bytes = b"0" * raw_size

        payload = {
            "filename": "over_50mb.dat",
            "encrypted_content": "QUJDRA==",
            "size": raw_size,
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }

        orig_b64 = base64.b64decode
        def selective_b64_over(s, *args, **kwargs):
            if kwargs.get("validate"):
                return raw_over_bytes
            return orig_b64(s, *args, **kwargs)

        with patch("routes.file.base64.b64decode", side_effect=selective_b64_over):
            res = client.post(
                "/api/upload",
                json=payload,
                headers={"Authorization": f"Bearer {alice_auth['token']}"},
            )
            assert res.status_code == 413
            data = res.get_json()
            assert data["success"] is False
            assert "50 mb limit" in data["msg"].lower() or "exceeds" in data["msg"].lower()

    def test_upload_zero_byte_empty_file_rejected_with_400(self, client, alice_auth):
        """Uploading empty payload is rejected with HTTP 400."""
        payload = {
            "filename": "empty.bin",
            "encrypted_content": "",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        res = client.post(
            "/api/upload",
            json=payload,
            headers={"Authorization": f"Bearer {alice_auth['token']}"},
        )
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_upload_corrupted_base64_rejected_with_400(self, client, alice_auth):
        """Malformed base64 ciphertext is rejected with HTTP 400."""
        payload = {
            "filename": "corrupt_b64.bin",
            "encrypted_content": "not-valid-base-64-!!!@@@###$$$",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        res = client.post(
            "/api/upload",
            json=payload,
            headers={"Authorization": f"Bearer {alice_auth['token']}"},
        )
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "base64" in data["msg"].lower()


# =============================================================================
# 2. Tampered Files, Corrupted Keys & Integrity Verification
# =============================================================================
class TestTamperedFilesAndIntegrityVerification:
    def test_tampered_wrapped_rsa_key_too_short_rejected(self, client, alice_auth):
        """Wrapped RSA data key shorter than 128 bytes is rejected with 400."""
        payload = {
            "filename": "short_key.bin",
            "encrypted_content": base64.b64encode(b"ciphertext123").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "wrapped_key": base64.b64encode(b"too_short").decode(),  # only 9 bytes
            "key_fingerprint": SAMPLE_RSA_FINGERPRINT,
        }
        res = client.post(
            "/api/upload",
            json=payload,
            headers={"Authorization": f"Bearer {alice_auth['token']}"},
        )
        assert res.status_code == 400
        assert "wrapped key length" in res.get_json()["msg"].lower()

    def test_tampered_wrapped_rsa_key_too_long_rejected(self, client, alice_auth):
        """Wrapped RSA data key longer than 1024 bytes is rejected with 400."""
        payload = {
            "filename": "long_key.bin",
            "encrypted_content": base64.b64encode(b"ciphertext123").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "wrapped_key": base64.b64encode(b"A" * 1025).decode(),
            "key_fingerprint": SAMPLE_RSA_FINGERPRINT,
        }
        res = client.post(
            "/api/upload",
            json=payload,
            headers={"Authorization": f"Bearer {alice_auth['token']}"},
        )
        assert res.status_code == 400
        assert "wrapped key length" in res.get_json()["msg"].lower()

    def test_tampered_wrapped_rsa_key_invalid_base64_rejected(self, client, alice_auth):
        """Malformed base64 wrapped key is rejected with 400."""
        payload = {
            "filename": "corrupt_key.bin",
            "encrypted_content": base64.b64encode(b"ciphertext123").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "wrapped_key": "not*valid*base64*characters!!",
            "key_fingerprint": SAMPLE_RSA_FINGERPRINT,
        }
        res = client.post(
            "/api/upload",
            json=payload,
            headers={"Authorization": f"Bearer {alice_auth['token']}"},
        )
        assert res.status_code == 400
        assert "wrapped key format" in res.get_json()["msg"].lower()

    def test_missing_encryption_metadata_rejected(self, client, alice_auth):
        """Upload without IV is rejected with 400."""
        payload = {
            "filename": "no_iv.bin",
            "encrypted_content": base64.b64encode(b"ciphertext123").decode(),
            "iv": "",
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        res = client.post(
            "/api/upload",
            json=payload,
            headers={"Authorization": f"Bearer {alice_auth['token']}"},
        )
        assert res.status_code == 400
        assert "iv" in res.get_json()["msg"].lower()

    def test_download_exposes_integrity_hash_header_for_client_verification(self, client, alice_auth):
        """Download response exposes X-Integrity-Hash allowing client to detect corrupted ciphertext."""
        from bson.objectid import ObjectId

        expected_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        doc = {
            "user_email": alice_auth["email"],
            "filename": "integrity_verify.bin",
            "file_hash": "original_s3_hash",
            "s3_key": "encrypted/integrity_verify.bin",
            "size": 256,
            "mime_type": "application/octet-stream",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
            "integrity_hash": expected_hash,
            "algorithm": "AES-GCM-256",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            with patch("routes.file.download_from_s3_stream", return_value=b"server_ciphertext_bytes"):
                res = client.get(
                    f"/api/download/{fid}",
                    headers={"Authorization": f"Bearer {alice_auth['token']}"},
                )
                assert res.status_code == 200
                assert res.headers.get("X-Integrity-Hash") == expected_hash
                assert res.headers.get("X-Algorithm") == "AES-GCM-256"
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})

    def test_sanitized_file_upload_and_download_flow(self, client, alice_auth):
        """Regression test for sanitized file upload: verifies end-to-end flow with JWT auth, S3, DB metadata, and download headers."""
        from bson.objectid import ObjectId

        masked_text = "Patient PAN: [REDACTED_PAN], Contact: [REDACTED_PHONE]"
        sha256_hash = hashlib.sha256(masked_text.encode("utf-8")).hexdigest()
        raw_ciphertext = b"ciphertext_sanitized_bytes_12345"
        b64_ciphertext = base64.b64encode(raw_ciphertext).decode("utf-8")
        b64_iv = base64.b64encode(b"iv_12_bytes!").decode("utf-8")
        b64_salt = base64.b64encode(b"salt_16_bytes!!").decode("utf-8")

        upload_payload = {
            "filename": "patient_records_masked.txt",
            "mime_type": "text/plain",
            "size": len(masked_text.encode("utf-8")),
            "encrypted_content": b64_ciphertext,
            "iv": b64_iv,
            "salt": b64_salt,
            "wrapped_key": "",
            "key_fingerprint": "",
            "integrity_hash": sha256_hash,
            "algorithm": "AES-GCM-256",
            "kdf": "PBKDF2-SHA256",
            "iterations": 100000,
            "version": "1.0",
        }

        with patch("routes.file.upload_bytes_to_s3", return_value="encrypted/patient_records_masked.txt"):
            res = client.post(
                "/api/upload",
                json=upload_payload,
                headers={"Authorization": f"Bearer {alice_auth['token']}"},
            )
            assert res.status_code == 201
            data = res.get_json()
            assert data["success"] is True
            fid = data["file_id"]
            assert data["filename"] == "patient_records_masked.txt"

        try:
            # Verify database record
            db_file = files_col.find_one({"_id": ObjectId(fid)})
            assert db_file is not None
            assert db_file["user_email"] == alice_auth["email"]
            assert db_file["filename"] == "patient_records_masked.txt"
            assert db_file["integrity_hash"] == sha256_hash
            assert db_file["iv"] == b64_iv
            assert db_file["salt"] == b64_salt
            assert db_file["is_legacy"] is False

            # Verify download with valid token returns headers
            with patch("routes.file.download_from_s3_stream", return_value=raw_ciphertext):
                dl_res = client.get(
                    f"/api/download/{fid}",
                    headers={"Authorization": f"Bearer {alice_auth['token']}"},
                )
                assert dl_res.status_code == 200
                assert dl_res.data == raw_ciphertext
                assert dl_res.headers.get("X-IV") == b64_iv
                assert dl_res.headers.get("X-Salt") == b64_salt
                assert dl_res.headers.get("X-Integrity-Hash") == sha256_hash

            # Verify download without auth header fails with 401
            unauth_res = client.get(f"/api/download/{fid}")
            assert unauth_res.status_code == 401
            assert unauth_res.get_json()["code"] == "missing_token"

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})


# =============================================================================
# 3. Multi-User Permissions & Cross-Tenant Isolation
# =============================================================================
class TestMultiUserPermissionsAndIsolation:
    @pytest.fixture()
    def alice_file(self, alice_auth):
        from bson.objectid import ObjectId

        doc = {
            "user_email": alice_auth["email"],
            "filename": "alice_confidential.pdf",
            "file_hash": "alice_hash_123",
            "s3_key": "encrypted/alice_confidential.pdf",
            "size": 512,
            "mime_type": "application/pdf",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
            "integrity_hash": "sha256_alice_hash",
            "algorithm": "AES-GCM-256",
            "upload_date": datetime.now(timezone.utc),
        }
        res = files_col.insert_one(doc)
        fid = str(res.inserted_id)
        yield fid
        files_col.delete_one({"_id": ObjectId(fid)})

    def test_bob_cannot_download_alice_file(self, client, bob_auth, alice_file):
        """Bob receives 403 Forbidden attempting to download Alice's file."""
        res = client.get(
            f"/api/download/{alice_file}",
            headers={"Authorization": f"Bearer {bob_auth['token']}"},
        )
        assert res.status_code == 403
        assert res.get_json()["success"] is False

    def test_bob_cannot_get_presigned_url_for_alice_file(self, client, bob_auth, alice_file):
        """Bob receives 403 Forbidden attempting to generate a presigned URL for Alice's file."""
        res = client.get(
            f"/api/download-url/{alice_file}",
            headers={"Authorization": f"Bearer {bob_auth['token']}"},
        )
        assert res.status_code == 403
        assert res.get_json()["success"] is False

    def test_bob_cannot_delete_alice_file(self, client, bob_auth, alice_file):
        """Bob receives 403 Forbidden attempting to delete Alice's file."""
        res = client.delete(
            f"/api/files/{alice_file}",
            headers={"Authorization": f"Bearer {bob_auth['token']}"},
        )
        assert res.status_code == 403
        assert res.get_json()["success"] is False

    def test_bob_cannot_create_access_token_for_alice_file(self, client, bob_auth, alice_file):
        """Bob receives 403 Forbidden attempting to generate an access token for Alice's file."""
        payload = {"file_id": alice_file, "permission": "download"}
        res = client.post(
            "/api/tokens/create",
            json=payload,
            headers={"Authorization": f"Bearer {bob_auth['token']}"},
        )
        assert res.status_code == 403
        assert res.get_json()["success"] is False

    def test_bob_cannot_create_share_for_alice_file(self, client, bob_auth, alice_file):
        """Bob receives 403 Forbidden attempting to share Alice's file."""
        payload = {
            "file_id": alice_file,
            "recipient_email": "charlie@example.com",
            "wrapped_key": base64.b64encode(b"X" * 256).decode(),
            "key_fingerprint": SAMPLE_RSA_FINGERPRINT,
        }
        res = client.post(
            "/api/shares",
            json=payload,
            headers={"Authorization": f"Bearer {bob_auth['token']}"},
        )
        assert res.status_code == 403
        assert res.get_json()["success"] is False

    def test_unauthorized_access_records_audit_trail(self, client, bob_auth, alice_file):
        """Every cross-user violation generates an UNAUTHORIZED_ACCESS_ATTEMPT audit log."""
        client.get(
            f"/api/download/{alice_file}",
            headers={"Authorization": f"Bearer {bob_auth['token']}"},
        )
        log_entry = audit_logs_col.find_one(
            {
                "event_type": AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
                "user_email": bob_auth["email"],
                "resource_id": alice_file,
            }
        )
        assert log_entry is not None
        assert log_entry["outcome"] == AuditOutcome.DENIED
        assert log_entry["severity"] in (AuditSeverity.WARNING, AuditSeverity.CRITICAL)


# =============================================================================
# 4. Access Tokens & Shares Lifecycle (Expired & Revoked)
# =============================================================================
class TestAccessTokensAndSharesLifecycle:
    @pytest.fixture()
    def test_file_for_tokens(self, alice_auth):
        from bson.objectid import ObjectId

        doc = {
            "user_email": alice_auth["email"],
            "filename": "token_lifecycle_doc.txt",
            "file_hash": "token_test_hash",
            "s3_key": "encrypted/token_lifecycle_doc.txt",
            "size": 128,
            "mime_type": "text/plain",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
            "upload_date": datetime.now(timezone.utc),
        }
        res = files_col.insert_one(doc)
        fid = str(res.inserted_id)
        yield fid
        files_col.delete_one({"_id": ObjectId(fid)})

    def test_expired_access_token_rejected_on_download(self, client, alice_auth, test_file_for_tokens):
        """Expired access token returns 403 on download."""
        raw_token = f"sct_{uuid.uuid4().hex}{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        doc = {
            "file_id": test_file_for_tokens,
            "token_hash": token_hash,
            "user_email": alice_auth["email"],
            "scope": "download",
            "expires_at": datetime.now(timezone.utc) - timedelta(hours=1),
            "max_downloads": 5,
            "downloads_used": 0,
            "is_revoked": False,
            "created_at": datetime.now(timezone.utc) - timedelta(hours=2),
        }
        access_tokens_col.insert_one(doc)

        try:
            res = client.get(f"/api/tokens/download?token={raw_token}")
            assert res.status_code == 403
            data = res.get_json()
            assert data["success"] is False
            assert "expired" in data["msg"].lower()
        finally:
            access_tokens_col.delete_one({"token_hash": token_hash})

    def test_revoked_access_token_rejected_on_download(self, client, alice_auth, test_file_for_tokens):
        """Revoked access token returns 403 on download."""
        raw_token = f"sct_{uuid.uuid4().hex}{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        doc = {
            "file_id": test_file_for_tokens,
            "token_hash": token_hash,
            "user_email": alice_auth["email"],
            "scope": "download",
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
            "max_downloads": 5,
            "downloads_used": 0,
            "is_revoked": True,
            "revoked_at": datetime.now(timezone.utc),
            "created_at": datetime.now(timezone.utc),
        }
        access_tokens_col.insert_one(doc)

        try:
            res = client.get(f"/api/tokens/download?token={raw_token}")
            assert res.status_code == 403
            data = res.get_json()
            assert data["success"] is False
            assert "revoked" in data["msg"].lower()
        finally:
            access_tokens_col.delete_one({"token_hash": token_hash})

    def test_view_only_token_rejects_download(self, client, alice_auth, test_file_for_tokens):
        """Access token with view permission returns 403 on download."""
        raw_token = f"sct_{uuid.uuid4().hex}{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        doc = {
            "file_id": test_file_for_tokens,
            "token_hash": token_hash,
            "user_email": alice_auth["email"],
            "scope": "view",
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
            "max_downloads": 5,
            "downloads_used": 0,
            "is_revoked": False,
            "created_at": datetime.now(timezone.utc),
        }
        access_tokens_col.insert_one(doc)

        try:
            res = client.get(f"/api/tokens/download?token={raw_token}")
            assert res.status_code == 403
            assert "download permission" in res.get_json()["msg"].lower()
        finally:
            access_tokens_col.delete_one({"token_hash": token_hash})


# =============================================================================
# 5. Invalid Credentials, Brute-Force & Account Security
# =============================================================================
class TestInvalidCredentialsAndSecurityDefenses:
    def test_invalid_credentials_returns_401(self, client):
        """Login with wrong password returns 401."""
        res = client.post(
            "/api/login",
            json={"email": "nonexistent_qa_user@example.com", "password": "WrongPassword123!"},
        )
        assert res.status_code == 401
        assert res.get_json()["success"] is False

    def test_missing_credentials_returns_400(self, client):
        """Login with missing email or password returns 400."""
        res1 = client.post("/api/login", json={"email": "", "password": "ValidPassword123!"})
        assert res1.status_code == 400

        res2 = client.post("/api/login", json={"email": "user@example.com", "password": ""})
        assert res2.status_code == 400

    def test_rapid_failed_logins_triggers_rate_limiting_and_audit(self, client):
        """Repeated failed logins trigger 429 and rate limit / brute force alerts."""
        target_email = f"brute_force_{uuid.uuid4().hex[:8]}@example.com"

        for _ in range(Config.AUTH_RATE_LIMIT_MAX_ATTEMPTS):
            client.post("/api/login", json={"email": target_email, "password": "WrongPassword123!"})

        # Next request must be rate limited with 429
        res = client.post("/api/login", json={"email": target_email, "password": "WrongPassword123!"})
        assert res.status_code == 429
        assert "too many" in res.get_json()["msg"].lower() or "rate limit" in res.get_json()["msg"].lower()

        # Verify rate limit or suspicious activity audit record exists
        suspicious_event = audit_logs_col.find_one(
            {
                "event_type": {"$in": [AuditEventType.RATE_LIMIT_EXCEEDED, AuditEventType.SUSPICIOUS_ACTIVITY, AuditEventType.LOGIN_FAILED]},
                "user_email": target_email,
            }
        )
        assert suspicious_event is not None


# =============================================================================
# 6. Network & Cloud Storage Failure Resiliency
# =============================================================================
class TestNetworkAndStorageFailures:
    def test_b2_storage_auth_error_returns_503(self, client, alice_auth):
        """B2 credentials or authorization failure returns 503 Service Unavailable."""
        payload = {
            "filename": "auth_err.txt",
            "encrypted_content": base64.b64encode(b"hello world").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        with patch("routes.file.upload_bytes_to_s3", side_effect=StorageAuthError("B2 key expired")):
            res = client.post(
                "/api/upload",
                json=payload,
                headers={"Authorization": f"Bearer {alice_auth['token']}"},
            )
            assert res.status_code == 503
            assert "configuration error" in res.get_json()["msg"].lower()

    def test_b2_storage_timeout_returns_504(self, client, alice_auth):
        """B2 storage connection timeout returns 504 Gateway Timeout."""
        payload = {
            "filename": "timeout_err.txt",
            "encrypted_content": base64.b64encode(b"hello world").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        with patch("routes.file.upload_bytes_to_s3", side_effect=StorageTimeoutError("B2 socket timed out")):
            res = client.post(
                "/api/upload",
                json=payload,
                headers={"Authorization": f"Bearer {alice_auth['token']}"},
            )
            assert res.status_code == 504
            assert "timed out" in res.get_json()["msg"].lower()

    def test_atomic_rollback_cleans_b2_object_on_database_failure(self, client, alice_auth):
        """If MongoDB write fails after successful B2 upload, the orphaned S3 object is immediately deleted."""
        payload = {
            "filename": "rollback_test.dat",
            "encrypted_content": base64.b64encode(b"sample encrypted bytes").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        fake_key = f"encrypted/qa_rollback_{uuid.uuid4().hex}.bin"

        with patch("routes.file.upload_bytes_to_s3", return_value=fake_key), \
             patch("routes.file.add_file_record", side_effect=RuntimeError("Simulated MongoDB write lock")), \
             patch("routes.file.delete_from_s3") as mock_delete:
            res = client.post(
                "/api/upload",
                json=payload,
                headers={"Authorization": f"Bearer {alice_auth['token']}"},
            )
            assert res.status_code == 500
            mock_delete.assert_called_once_with(fake_key)


# =============================================================================
# 7. Live Backblaze B2 & Live MongoDB End-to-End Test (Real Cloud Integration)
# =============================================================================
B2_CONFIGURED = Config.validate()["b2_configured"]

@pytest.mark.skipif(not B2_CONFIGURED, reason="Backblaze B2 credentials are not configured")
class TestLiveStorageAndDatabaseEndToEnd:
    """
    Live End-to-End integration test verified against LIVE MongoDB and LIVE Backblaze B2.
    Uses safe, ephemeral test accounts and UUID-isolated keys.
    Cleans up all created resources upon completion.
    """

    def test_full_live_e2e_storage_sharing_token_audit_lifecycle(self, client):
        tag = uuid.uuid4().hex[:8]
        alice_email = f"live_alice_{tag}@example.com"
        bob_email = f"live_bob_{tag}@example.com"
        test_pass = "LivePass123!Secure"

        alice_token = None
        bob_token = None
        uploaded_file_id = None
        s3_key_to_delete = None

        try:
            # Step 1: Register live Alice and Bob in MongoDB
            res_reg_alice = client.post("/api/register", json={"email": alice_email, "password": test_pass})
            assert res_reg_alice.status_code == 201
            alice_token = res_reg_alice.get_json()["token"]

            res_reg_bob = client.post("/api/register", json={"email": bob_email, "password": test_pass})
            assert res_reg_bob.status_code == 201
            bob_token = res_reg_bob.get_json()["token"]

            # Step 2: Bob registers RSA Public Key
            res_key = client.post(
                "/api/keys/register",
                json={"public_key": SAMPLE_RSA_PUBLIC_KEY, "fingerprint": SAMPLE_RSA_FINGERPRINT},
                headers={"Authorization": f"Bearer {bob_token}"},
            )
            assert res_key.status_code == 201

            # Step 3: Alice looks up Bob's public key (no private backup leaked)
            res_lookup = client.get(f"/api/keys/{bob_email}", headers={"Authorization": f"Bearer {alice_token}"})
            assert res_lookup.status_code == 200
            assert res_lookup.get_json()["public_key"] == SAMPLE_RSA_PUBLIC_KEY
            assert "encrypted_private_key" not in res_lookup.get_json()

            # Step 4: Live Upload of encrypted payload to Backblaze B2
            test_payload_bytes = f"LIVE_B2_ZERO_KNOWLEDGE_PAYLOAD_{tag}".encode("utf-8")
            integrity_hash = hashlib.sha256(test_payload_bytes).hexdigest()
            b64_content = base64.b64encode(test_payload_bytes).decode("utf-8")

            upload_payload = {
                "filename": f"live_test_{tag}.enc",
                "encrypted_content": b64_content,
                "size": len(test_payload_bytes),
                "iv": base64.b64encode(b"1" * 12).decode("utf-8"),
                "salt": base64.b64encode(b"2" * 16).decode("utf-8"),
                "integrity_hash": integrity_hash,
                "algorithm": "AES-GCM-256",
            }

            res_upload = client.post(
                "/api/upload",
                json=upload_payload,
                headers={"Authorization": f"Bearer {alice_token}"},
            )
            assert res_upload.status_code == 201
            data_upload = res_upload.get_json()
            assert data_upload["success"] is True
            uploaded_file_id = data_upload["file_id"]
            s3_key_to_delete = data_upload["s3_key"]
            assert s3_key_to_delete.startswith("encrypted/")

            # Step 5: Live Download of encrypted payload from Backblaze B2
            res_dl = client.get(
                f"/api/download/{uploaded_file_id}",
                headers={"Authorization": f"Bearer {alice_token}"},
            )
            assert res_dl.status_code == 200
            assert res_dl.data == test_payload_bytes
            assert res_dl.headers.get("X-Integrity-Hash") == integrity_hash

            # Step 6: Alice generates presigned download URL on Backblaze B2
            res_ps = client.get(
                f"/api/download-url/{uploaded_file_id}?expires_in=300",
                headers={"Authorization": f"Bearer {alice_token}"},
            )
            assert res_ps.status_code == 200
            presigned_url = res_ps.get_json()["url"]
            assert "https://" in presigned_url
            assert Config.B2_BUCKET_NAME in presigned_url

            # Step 7: Alice shares file with Bob (wrapped with Bob's RSA key)
            wrapped_key_b64 = base64.b64encode(b"K" * 256).decode("utf-8")
            share_payload = {
                "file_id": uploaded_file_id,
                "recipient_email": bob_email,
                "wrapped_key": wrapped_key_b64,
                "key_fingerprint": SAMPLE_RSA_FINGERPRINT,
                "permission": "download",
                "expires_in_seconds": 3600,
                "max_downloads": 2,
            }
            res_share = client.post(
                "/api/shares",
                json=share_payload,
                headers={"Authorization": f"Bearer {alice_token}"},
            )
            assert res_share.status_code == 201
            share_data = res_share.get_json()
            share_id = share_data.get("share_id") or share_data["shares"][0]["id"]

            # Step 8: Bob downloads shared file from Backblaze B2
            res_bob_dl = client.get(
                f"/api/shares/{share_id}/download",
                headers={"Authorization": f"Bearer {bob_token}"},
            )
            assert res_bob_dl.status_code == 200
            assert res_bob_dl.data == test_payload_bytes
            assert res_bob_dl.headers.get("X-Wrapped-Key") == wrapped_key_b64

            # Step 9: Alice creates Access Token and downloads via token
            res_tok = client.post(
                "/api/tokens/create",
                json={"file_id": uploaded_file_id, "permission": "download", "max_uses": 2},
                headers={"Authorization": f"Bearer {alice_token}"},
            )
            assert res_tok.status_code == 201
            raw_sct_token = res_tok.get_json()["token"]
            assert raw_sct_token.startswith("sct_")

            res_tok_dl = client.get(f"/api/tokens/download?token={raw_sct_token}")
            assert res_tok_dl.status_code == 200
            assert res_tok_dl.data == test_payload_bytes

            # Step 10: Verify Cryptographic Audit Chain in MongoDB
            audit_records = list(
                audit_logs_col.find(
                    {"user_email": {"$in": [alice_email, bob_email]}}
                ).sort("sequence", 1)
            )
            assert len(audit_records) >= 5, f"Expected at least 5 audit records, found {len(audit_records)}"

            # Verify complete chain integrity
            verify_result = verify_audit_log_integrity()
            assert verify_result["verified"] is True
            assert verify_result["chain_intact"] is True
            assert verify_result["broken_at_sequence"] is None

        finally:
            # Step 11: Ephemeral Cleanup (Safe: only ephemeral test data removed)
            if s3_key_to_delete:
                from utils.s3 import delete_from_s3
                delete_from_s3(s3_key_to_delete)

            if uploaded_file_id:
                from bson.objectid import ObjectId
                files_col.delete_one({"_id": ObjectId(uploaded_file_id)})

            file_shares_col.delete_many({"recipient_email": bob_email})
            access_tokens_col.delete_many({"owner_email": alice_email})
            user_keys_col.delete_many({"user_email": {"$in": [alice_email, bob_email]}})
            users_col.delete_many({"email": {"$in": [alice_email, bob_email]}})
            audit_logs_col.delete_many({"user_email": {"$in": [alice_email, bob_email]}})
