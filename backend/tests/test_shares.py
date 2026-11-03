# =============================================================================
# tests/test_shares.py — Phase 9 Secure File Sharing Automated Tests
# =============================================================================
import concurrent.futures
import io
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
from bson.objectid import ObjectId

# Ensure backend package root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.auth_helpers import create_jwt
from utils.db import (
    access_tokens_col,
    file_shares_col,
    files_col,
    user_keys_col,
    users_col,
)


@pytest.fixture(scope="session")
def app():
    """Create a Flask test application."""
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


# Dummy 2048-bit RSA SPKI public key & valid fingerprint for tests
MOCK_PUBKEY_PEM_A = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y1o8k7Y/z7q7y5H8gXo\n"
    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZAB\n"
    "CDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123\n"
    "456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345\n"
    "6789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx\n"
    "yz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n"
    "0123456789AB==\n"
    "-----END PUBLIC KEY-----"
)
MOCK_FP_A = "SHA256:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20"

MOCK_PUBKEY_PEM_B = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Z2p9l8Z/a8r8z6I9hYp\n"
    "bcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZAB\n"
    "CDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123\n"
    "456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345\n"
    "6789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx\n"
    "yz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n"
    "0123456789CD==\n"
    "-----END PUBLIC KEY-----"
)
MOCK_FP_B = "SHA256:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F:30:31:32:33:34:35:36:37:38:39:3A:3B:3C:3D:3E:3F:40"

TEST_WRAPPED_KEY_B64_A = "V1JBUFBFREtFWV9GT1JfUkVDSVBJRU5UX0FfQUVTMjU2X0RBVEFfS0VZX1RFU1RfU1RSSU5HX0VYQU1QTEVfQkFTRTY0X0NPTlRFTlQ=" * 3
TEST_WRAPPED_KEY_B64_B = "V1JBUFBFREtFWV9GT1JfUkVDSVBJRU5UX0JfQUVTMjU2X0RBVEFfS0VZX1RFU1RfU1RSSU5HX0VYQU1QTEVfQkFTRTY0X0NPTlRFTlQ=" * 3


def _setup_test_user_with_keys(email: str, pubkey_pem: str, fp: str):
    """Helper to ensure a user exists and has a registered public key."""
    norm_email = email.strip().lower()
    users_col.update_one(
        {"email": norm_email},
        {"$set": {"email": norm_email, "created_at": datetime.now(timezone.utc)}},
        upsert=True,
    )
    user_keys_col.update_one(
        {"user_email": norm_email},
        {
            "$set": {
                "user_email": norm_email,
                "public_key": pubkey_pem,
                "fingerprint": fp,
                "key_type": "RSA-OAEP-2048",
                "created_at": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )


class TestSecureFileSharing:
    """Automated test suite for Phase 9: Secure File Sharing."""

    def test_share_create_requires_auth(self, client):
        """Unauthenticated POST /api/shares returns 401."""
        res = client.post("/api/shares", json={"file_id": "000000000000000000000001"})
        assert res.status_code == 401
        assert res.get_json()["success"] is False

    def test_share_create_non_owner_forbidden(self, client):
        """User B cannot share a file owned by User A."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        attacker_email = f"attacker_{uuid.uuid4().hex[:8]}@example.com"
        attacker_token = create_jwt("000000000000000000000080", attacker_email)

        file_doc = {
            "user_email": owner_email,
            "filename": "secret_design.cad",
            "file_hash": "hash_cad",
            "s3_key": "encrypted/secret_design.cad",
            "size": 1024,
            "mime_type": "application/octet-stream",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {attacker_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": "alice@example.com",
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                },
            )
            assert res.status_code == 403
            assert "permission" in res.get_json()["msg"].lower()
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})

    def test_share_create_unregistered_recipient_rejected(self, client):
        """Sharing with a non-registered recipient is rejected with a clear 400 error."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000081", owner_email)

        file_doc = {
            "user_email": owner_email,
            "filename": "quarterly_budget.xlsx",
            "file_hash": "hash_xlsx",
            "s3_key": "encrypted/quarterly_budget.xlsx",
            "size": 2048,
            "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": "unregistered_ghost_user@example.com",
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                },
            )
            assert res.status_code == 400
            assert "not a registered user" in str(res.get_json())
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})

    def test_share_create_recipient_without_key_rejected(self, client):
        """Sharing with a registered user who hasn't registered an RSA key is rejected."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000082", owner_email)
        recipient_email = f"nokey_{uuid.uuid4().hex[:8]}@example.com"

        # Register user in users collection but without key in user_keys
        users_col.insert_one({"email": recipient_email})

        file_doc = {
            "user_email": owner_email,
            "filename": "memo.txt",
            "file_hash": "hash_memo",
            "s3_key": "encrypted/memo.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recipient_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                },
            )
            assert res.status_code == 400
            assert "not registered an rsa public key" in str(res.get_json()).lower()
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            users_col.delete_one({"email": recipient_email})

    def test_share_create_key_fingerprint_mismatch_rejected(self, client):
        """Fingerprint mismatch (key substitution attack) is strictly rejected."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000083", owner_email)
        recipient_email = f"recip_{uuid.uuid4().hex[:8]}@example.com"

        _setup_test_user_with_keys(recipient_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "contract.pdf",
            "file_hash": "hash_contract",
            "s3_key": "encrypted/contract.pdf",
            "size": 512,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recipient_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "key_fingerprint": "SHA256:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
                },
            )
            assert res.status_code == 400
            assert "mismatch" in str(res.get_json()).lower()
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            users_col.delete_one({"email": recipient_email})
            user_keys_col.delete_one({"user_email": recipient_email})

    def test_share_create_success_and_multi_recipient(self, client):
        """
        File owner can share with multiple recipients simultaneously.
        Each recipient receives an independently wrapped AES key.
        """
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000084", owner_email)
        recip_a = f"alice_{uuid.uuid4().hex[:8]}@example.com"
        recip_b = f"bob_{uuid.uuid4().hex[:8]}@example.com"

        _setup_test_user_with_keys(recip_a, MOCK_PUBKEY_PEM_A, MOCK_FP_A)
        _setup_test_user_with_keys(recip_b, MOCK_PUBKEY_PEM_B, MOCK_FP_B)

        file_doc = {
            "user_email": owner_email,
            "filename": "team_roadmap.pdf",
            "file_hash": "hash_roadmap",
            "s3_key": "encrypted/team_roadmap.pdf",
            "size": 4096,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            # Batch share with both Alice (download) and Bob (view)
            res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "shares": [
                        {
                            "recipient_email": recip_a,
                            "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                            "key_fingerprint": MOCK_FP_A,
                            "permission": "download",
                            "max_downloads": 2,
                        },
                        {
                            "recipient_email": recip_b,
                            "wrapped_key": TEST_WRAPPED_KEY_B64_B,
                            "key_fingerprint": MOCK_FP_B,
                            "permission": "view",
                            "max_downloads": 0,
                        },
                    ],
                },
            )
            assert res.status_code == 201
            data = res.get_json()
            assert data["success"] is True
            assert len(data["shares"]) == 2

            # Verify in MongoDB: two independent share documents exist
            doc_a = file_shares_col.find_one({"file_id": fid, "recipient_email": recip_a})
            doc_b = file_shares_col.find_one({"file_id": fid, "recipient_email": recip_b})
            assert doc_a is not None and doc_b is not None
            assert doc_a["wrapped_key"] == TEST_WRAPPED_KEY_B64_A
            assert doc_b["wrapped_key"] == TEST_WRAPPED_KEY_B64_B
            assert doc_a["permission"] == "download"
            assert doc_b["permission"] == "view"

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_many({"email": {"$in": [recip_a, recip_b]}})
            user_keys_col.delete_many({"user_email": {"$in": [recip_a, recip_b]}})

    def test_received_shares_listing_isolation(self, client):
        """Recipient sees only files shared with them, never files shared with others."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000085", owner_email)
        recip_a = f"alice_{uuid.uuid4().hex[:8]}@example.com"
        recip_b = f"bob_{uuid.uuid4().hex[:8]}@example.com"
        token_a = create_jwt("000000000000000000000086", recip_a)
        token_b = create_jwt("000000000000000000000087", recip_b)

        _setup_test_user_with_keys(recip_a, MOCK_PUBKEY_PEM_A, MOCK_FP_A)
        _setup_test_user_with_keys(recip_b, MOCK_PUBKEY_PEM_B, MOCK_FP_B)

        file_doc = {
            "user_email": owner_email,
            "filename": "for_alice_only.pdf",
            "file_hash": "hash_alice",
            "s3_key": "encrypted/for_alice_only.pdf",
            "size": 1024,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_a,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                },
            )

            # Alice sees the file
            res_a = client.get("/api/shares/received", headers={"Authorization": f"Bearer {token_a}"})
            assert res_a.status_code == 200
            shares_a = res_a.get_json()["shares"]
            assert any(s["file_id"] == fid for s in shares_a)

            # Bob DOES NOT see the file
            res_b = client.get("/api/shares/received", headers={"Authorization": f"Bearer {token_b}"})
            assert res_b.status_code == 200
            shares_b = res_b.get_json()["shares"]
            assert not any(s["file_id"] == fid for s in shares_b)

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_many({"email": {"$in": [recip_a, recip_b]}})
            user_keys_col.delete_many({"user_email": {"$in": [recip_a, recip_b]}})

    def test_view_only_permission_rejects_download(self, client):
        """A share with view permission strictly rejects download attempts with 403."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000088", owner_email)
        recip_email = f"viewer_{uuid.uuid4().hex[:8]}@example.com"
        recip_token = create_jwt("000000000000000000000089", recip_email)

        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "confidential_brief.pdf",
            "file_hash": "hash_brief",
            "s3_key": "encrypted/confidential_brief.pdf",
            "size": 1024,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "view",
                },
            )
            share_id = create_res.get_json()["share_id"]

            # Recipient can view metadata
            details_res = client.get(f"/api/shares/{share_id}", headers={"Authorization": f"Bearer {recip_token}"})
            assert details_res.status_code == 200
            assert details_res.get_json()["share"]["permission"] == "view"

            # Recipient cannot download
            dl_res = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {recip_token}"})
            assert dl_res.status_code == 403
            assert "view-only" in dl_res.get_json()["msg"].lower()

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_authorized_recipient_download_streams_ciphertext_and_headers(self, client):
        """Authorized recipient download streams ciphertext and exposes recipient's wrapped key in headers."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000090", owner_email)
        recip_email = f"downloader_{uuid.uuid4().hex[:8]}@example.com"
        recip_token = create_jwt("000000000000000000000091", recip_email)

        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "payload.bin",
            "file_hash": "hash_payload",
            "s3_key": "encrypted/payload.bin",
            "size": 128,
            "mime_type": "application/octet-stream",
            "iv": "iv_custom_96bit",
            "integrity_hash": "sha256_payload_integrity",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                    "max_downloads": 2,
                },
            )
            share_id = create_res.get_json()["share_id"]

            mock_stream = io.BytesIO(b"ENCRYPTED_STREAM_PAYLOAD_BYTES")
            mock_stream.content_length = len(b"ENCRYPTED_STREAM_PAYLOAD_BYTES")

            with patch("routes.shares.download_from_s3_stream", return_value=mock_stream):
                dl_res = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {recip_token}"})
                assert dl_res.status_code == 200
                assert dl_res.headers.get("X-Wrapped-Key") == TEST_WRAPPED_KEY_B64_A
                assert dl_res.headers.get("X-IV") == "iv_custom_96bit"
                assert dl_res.headers.get("X-Integrity-Hash") == "sha256_payload_integrity"
                assert dl_res.headers.get("X-Share-Downloads-Remaining") == "1"

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_unauthorized_user_cannot_download_share(self, client):
        """User C cannot download a file shared with User B."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000092", owner_email)
        recip_email = f"target_{uuid.uuid4().hex[:8]}@example.com"
        attacker_email = f"intruder_{uuid.uuid4().hex[:8]}@example.com"
        attacker_token = create_jwt("000000000000000000000093", attacker_email)

        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "private_intel.docx",
            "file_hash": "hash_intel",
            "s3_key": "encrypted/private_intel.docx",
            "size": 512,
            "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                },
            )
            share_id = create_res.get_json()["share_id"]

            # Attacker attempts download
            dl_res = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {attacker_token}"})
            assert dl_res.status_code == 403
            assert "designated recipient" in dl_res.get_json()["msg"].lower()

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_expired_share_download_rejected(self, client):
        """Expired shares cannot be downloaded."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000094", owner_email)
        recip_email = f"recipient_{uuid.uuid4().hex[:8]}@example.com"
        recip_token = create_jwt("000000000000000000000095", recip_email)

        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "time_sensitive.txt",
            "file_hash": "hash_time",
            "s3_key": "encrypted/time_sensitive.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                },
            )
            share_id = create_res.get_json()["share_id"]

            # Manually expire in DB
            file_shares_col.update_one(
                {"_id": ObjectId(share_id)},
                {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(hours=1)}},
            )

            dl_res = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {recip_token}"})
            assert dl_res.status_code == 403
            assert "expired" in dl_res.get_json()["msg"].lower()

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_owner_revocation_enforcement(self, client):
        """Owner can revoke a share; non-owner cannot; revoked shares are rejected."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000096", owner_email)
        recip_email = f"recip_{uuid.uuid4().hex[:8]}@example.com"
        recip_token = create_jwt("000000000000000000000097", recip_email)
        attacker_email = f"attacker_{uuid.uuid4().hex[:8]}@example.com"
        attacker_token = create_jwt("000000000000000000000098", attacker_email)

        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "revokable.pdf",
            "file_hash": "hash_revokable",
            "s3_key": "encrypted/revokable.pdf",
            "size": 100,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                },
            )
            share_id = create_res.get_json()["share_id"]

            # Attacker cannot revoke
            attacker_revoke = client.delete(f"/api/shares/{share_id}", headers={"Authorization": f"Bearer {attacker_token}"})
            assert attacker_revoke.status_code == 403

            # Owner revokes
            owner_revoke = client.delete(f"/api/shares/{share_id}", headers={"Authorization": f"Bearer {owner_token}"})
            assert owner_revoke.status_code == 200
            assert owner_revoke.get_json()["success"] is True

            # Recipient cannot download revoked share
            dl_res = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {recip_token}"})
            assert dl_res.status_code == 403
            assert "revoked" in dl_res.get_json()["msg"].lower()

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_atomic_concurrency_race_condition_on_share_download(self, client):
        """
        Concurrency Race Condition Test on Share Quota:
        10 threads concurrently attempt to download a single-use share (max_downloads=1).
        ATOMICITY GUARANTEE: Exactly 1 succeeds (200), and 9 fail with 403.
        """
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000099", owner_email)
        recip_email = f"concur_{uuid.uuid4().hex[:8]}@example.com"
        recip_token = create_jwt("000000000000000000000100", recip_email)

        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "atomic_share.dat",
            "file_hash": "hash_atomic_share",
            "s3_key": "encrypted/atomic_share.dat",
            "size": 64,
            "mime_type": "application/octet-stream",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                    "max_downloads": 1,
                },
            )
            share_id = create_res.get_json()["share_id"]

            def download_attempt():
                stream = io.BytesIO(b"PARALLEL_ENCRYPTED_STREAM_BYTES")
                stream.content_length = len(b"PARALLEL_ENCRYPTED_STREAM_BYTES")
                with patch("routes.shares.download_from_s3_stream", return_value=stream):
                    return client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {recip_token}"})

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(download_attempt) for _ in range(10)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            status_codes = [r.status_code for r in results]

            # Exactly 1 success (200), 9 rejections (403)
            assert status_codes.count(200) == 1, f"Expected 1 success, got {status_codes.count(200)}: {status_codes}"
            assert status_codes.count(403) == 9, f"Expected 9 rejections, got {status_codes.count(403)}: {status_codes}"

            # Verify in DB: downloads_used == 1
            doc = file_shares_col.find_one({"_id": ObjectId(share_id)})
            assert doc["downloads_used"] == 1

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_sharing_history_sent_listing(self, client):
        """Owner can view full sharing history with correct status."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000101", owner_email)
        recip_email = f"hist_{uuid.uuid4().hex[:8]}@example.com"

        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "history_file.pdf",
            "file_hash": "hash_hist",
            "s3_key": "encrypted/history_file.pdf",
            "size": 100,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                },
            )

            # Owner queries /shares/sent
            hist_res = client.get("/api/shares/sent", headers={"Authorization": f"Bearer {owner_token}"})
            assert hist_res.status_code == 200
            shares = hist_res.get_json()["shares"]
            target = next((s for s in shares if s["file_id"] == fid), None)
            assert target is not None
            assert target["recipient_email"] == recip_email
            assert target["status"] == "active"
            assert target["filename"] == "history_file.pdf"

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_share_create_same_account_rejected(self, client):
        """Owner attempting to share a file with themselves is rejected with clear 400 error."""
        owner_email = f"self_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000102", owner_email)
        _setup_test_user_with_keys(owner_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "self_file.pdf",
            "file_hash": "hash_self",
            "s3_key": "encrypted/self_file.pdf",
            "size": 100,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": owner_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                },
            )
            assert res.status_code == 400
            data = res.get_json()
            assert data["success"] is False
            assert "cannot share a file with yourself" in data["msg"].lower()
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            users_col.delete_one({"email": owner_email})
            user_keys_col.delete_one({"user_email": owner_email})

    def test_share_create_links_token_id_and_token_hash_and_revokes_both(self, client):
        """Verify token_id is properly populated on share creation and revoked upon share revocation."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000103", owner_email)
        recip_email = f"recip_{uuid.uuid4().hex[:8]}@example.com"
        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "linked_token.pdf",
            "file_hash": "hash_linked",
            "s3_key": "encrypted/linked_token.pdf",
            "size": 100,
            "mime_type": "application/pdf",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                },
            )
            assert create_res.status_code == 201
            share_id = create_res.get_json()["share_id"]

            share_record = file_shares_col.find_one({"_id": ObjectId(share_id)})
            assert share_record is not None
            assert share_record.get("token_id") is not None
            assert ObjectId.is_valid(share_record["token_id"])

            token_doc = access_tokens_col.find_one({"_id": ObjectId(share_record["token_id"])})
            assert token_doc is not None
            assert token_doc["is_revoked"] is False

            # Revoke the share
            revoke_res = client.delete(f"/api/shares/{share_id}", headers={"Authorization": f"Bearer {owner_token}"})
            assert revoke_res.status_code == 200

            # Verify both share and linked access token are revoked
            revoked_share = file_shares_col.find_one({"_id": ObjectId(share_id)})
            assert revoked_share["is_revoked"] is True

            revoked_token = access_tokens_col.find_one({"_id": ObjectId(share_record["token_id"])})
            assert revoked_token["is_revoked"] is True

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_share_quota_rollback_on_cloud_storage_failure(self, client):
        """Storage failures roll back atomically consumed download quota so users do not lose access."""
        from utils.s3 import StorageTimeoutError

        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000104", owner_email)
        recip_email = f"rollback_{uuid.uuid4().hex[:8]}@example.com"
        recip_token = create_jwt("000000000000000000000105", recip_email)
        _setup_test_user_with_keys(recip_email, MOCK_PUBKEY_PEM_A, MOCK_FP_A)

        file_doc = {
            "user_email": owner_email,
            "filename": "rollback_test.dat",
            "file_hash": "hash_rollback",
            "s3_key": "encrypted/rollback_test.dat",
            "size": 100,
            "mime_type": "application/octet-stream",
            "iv": "iv_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {owner_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": recip_email,
                    "wrapped_key": TEST_WRAPPED_KEY_B64_A,
                    "permission": "download",
                    "max_downloads": 1,
                },
            )
            share_id = create_res.get_json()["share_id"]

            # First attempt: storage timeout occurs -> quota rolled back
            with patch("routes.shares.download_from_s3_stream", side_effect=StorageTimeoutError("Storage timed out")):
                fail_res = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {recip_token}"})
                assert fail_res.status_code == 504

            # Verify in DB: downloads_used was rolled back to 0
            share_db = file_shares_col.find_one({"_id": ObjectId(share_id)})
            assert share_db["downloads_used"] == 0

            # Second attempt: storage succeeds -> download succeeds and quota consumed to 1
            stream = io.BytesIO(b"RECOVERED_STREAM_BYTES")
            stream.content_length = len(b"RECOVERED_STREAM_BYTES")
            with patch("routes.shares.download_from_s3_stream", return_value=stream):
                ok_res = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {recip_token}"})
                assert ok_res.status_code == 200

            # Verify in DB: downloads_used is now 1
            share_db_after = file_shares_col.find_one({"_id": ObjectId(share_id)})
            assert share_db_after["downloads_used"] == 1

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_one({"email": recip_email})
            user_keys_col.delete_one({"user_email": recip_email})

    def test_unregistered_recipient_key_lookup_reports_clear_error(self, client):
        """Looking up public key for unregistered user returns 404 with specific message."""
        owner_email = f"caller_{uuid.uuid4().hex[:8]}@example.com"
        owner_token = create_jwt("000000000000000000000106", owner_email)

        res = client.get("/api/keys/ghost_nonexistent_user@example.com", headers={"Authorization": f"Bearer {owner_token}"})
        assert res.status_code == 404
        assert "not a registered user" in res.get_json()["msg"].lower()
