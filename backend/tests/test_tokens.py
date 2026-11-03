# =============================================================================
# tests/test_tokens.py — Phase 8 Access Token Management Automated Tests
#
# Tests covered:
#   1. Token creation requires valid JWT authentication.
#   2. High entropy CSPRNG token generated with 'sct_' prefix.
#   3. Direct MongoDB inspection: ONLY SHA-256 hash stored; raw token NEVER stored.
#   4. Non-owner cannot create tokens for other users' files (403 Forbidden).
#   5. Validate endpoint inspects token without consuming download quota.
#   6. View scope token strictly rejected on download endpoint (403 Forbidden).
#   7. Expired token strictly rejected on validate and download (403 Forbidden).
#   8. Immediate revocation stops subsequent validations and downloads.
#   9. Non-owner cannot revoke tokens (403 Forbidden).
#  10. Token listing endpoints never leak token_hash or plaintext token.
#  11. Atomic single-use concurrency test: 10 concurrent threads attempt download
#      on a single-use token; exactly 1 succeeds, 9 fail with 403 (Zero double-spending).
#  12. Direct download route GET /api/access/download/<raw_token> with headers.
# =============================================================================
import concurrent.futures
import hashlib
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
from utils.db import files_col, access_tokens_col


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


class TestAccessTokenManagement:
    """Automated tests for Phase 8 Access Token Management."""

    def test_token_create_requires_auth(self, client):
        """Unauthenticated request to /tokens/create returns 401."""
        res = client.post("/api/tokens/create", json={"file_id": "000000000000000000000001"})
        assert res.status_code == 401
        assert res.get_json()["success"] is False

    def test_token_create_success_and_sha256_storage(self, client):
        """
        Token creation returns CSPRNG raw token with sct_ prefix.
        Direct DB inspection proves ONLY SHA-256 hash is persisted, never raw token.
        """
        user_email = f"tokenowner_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000060", user_email)

        file_doc = {
            "user_email": user_email,
            "filename": "confidential_spec.pdf",
            "file_hash": "hash_spec_123",
            "s3_key": "encrypted/confidential_spec.pdf",
            "size": 1024,
            "mime_type": "application/pdf",
            "iv": "iv_spec",
            "salt": "salt_spec",
            "integrity_hash": "int_spec",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "file_id": fid,
                    "scope": "download",
                    "expires_in_seconds": 3600,
                    "max_downloads": 1,
                    "label": "Audit Review Token",
                },
            )
            assert res.status_code == 201
            data = res.get_json()
            assert data["success"] is True
            raw_token = data["token"]
            token_id = data["token_id"]

            # 1. Verify token structure & high entropy
            assert raw_token.startswith("sct_")
            assert len(raw_token) > 30

            # 2. Inspect MongoDB directly: Verify ONLY SHA-256 hash is stored
            stored = access_tokens_col.find_one({"_id": ObjectId(token_id)})
            assert stored is not None
            expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            assert stored["token_hash"] == expected_hash
            # Verify plaintext token is strictly absent from the database document
            assert raw_token not in str(stored)
            assert stored["downloads_used"] == 0
            assert stored["max_downloads"] == 1
            assert stored["scope"] == "download"
            assert stored["label"] == "Audit Review Token"
            assert stored["is_revoked"] is False

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})

    def test_token_create_non_owner_forbidden(self, client):
        """User B cannot create an access token for User A's file."""
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        attacker_email = f"attacker_{uuid.uuid4().hex[:8]}@example.com"
        attacker_token = create_jwt("000000000000000000000061", attacker_email)

        file_doc = {
            "user_email": owner_email,
            "filename": "vault.pdf",
            "file_hash": "hash_vault",
            "s3_key": "encrypted/vault.pdf",
            "size": 500,
            "mime_type": "application/pdf",
            "iv": "iv",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {attacker_token}"},
                json={"file_id": fid, "scope": "download"},
            )
            assert res.status_code == 403
            assert res.get_json()["success"] is False
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})

    def test_token_validate_endpoint_does_not_consume_quota(self, client):
        """Validating a token via GET /api/tokens/validate returns info without incrementing downloads_used."""
        user_email = f"inspector_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000062", user_email)

        file_doc = {
            "user_email": user_email,
            "filename": "inspected_doc.pdf",
            "file_hash": "hash_inspected",
            "s3_key": "encrypted/inspected_doc.pdf",
            "size": 750,
            "mime_type": "application/pdf",
            "iv": "iv",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={"file_id": fid, "max_downloads": 1, "scope": "download"},
            )
            raw_token = create_res.get_json()["token"]
            token_id = create_res.get_json()["token_id"]

            # Validate multiple times
            for _ in range(3):
                val_res = client.get("/api/tokens/validate", headers={"X-Access-Token": raw_token})
                assert val_res.status_code == 200
                val_data = val_res.get_json()
                assert val_data["valid"] is True
                assert val_data["downloads_remaining"] == 1
                assert val_data["file"]["filename"] == "inspected_doc.pdf"

            # Check DB: downloads_used must still be 0
            doc = access_tokens_col.find_one({"_id": ObjectId(token_id)})
            assert doc["downloads_used"] == 0

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})

    def test_token_view_scope_rejects_download(self, client):
        """A token with view scope cannot be used on the download endpoint."""
        user_email = f"viewonly_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000063", user_email)

        file_doc = {
            "user_email": user_email,
            "filename": "read_only.txt",
            "file_hash": "hash_ro",
            "s3_key": "encrypted/read_only.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={"file_id": fid, "scope": "view", "max_downloads": 1},
            )
            raw_token = create_res.get_json()["token"]

            # Attempt download with view-only token
            dl_res = client.get("/api/tokens/download", headers={"X-Access-Token": raw_token})
            assert dl_res.status_code == 403
            assert dl_res.get_json()["success"] is False
            assert "download" in dl_res.get_json()["msg"].lower()

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})

    def test_token_expiry_enforcement(self, client):
        """Expired tokens are strictly rejected with 403."""
        user_email = f"exp_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000064", user_email)

        file_doc = {
            "user_email": user_email,
            "filename": "exp.txt",
            "file_hash": "hash_exp",
            "s3_key": "encrypted/exp.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={"file_id": fid, "expires_in_seconds": 3600},
            )
            raw_token = create_res.get_json()["token"]
            token_id = create_res.get_json()["token_id"]

            # Manually expire the token in DB
            access_tokens_col.update_one(
                {"_id": ObjectId(token_id)},
                {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(hours=2)}},
            )

            # Validate must fail with 403
            val_res = client.get("/api/tokens/validate", headers={"X-Access-Token": raw_token})
            assert val_res.status_code == 403
            assert "expired" in val_res.get_json()["msg"].lower()

            # Download must fail with 403
            dl_res = client.get("/api/tokens/download", headers={"X-Access-Token": raw_token})
            assert dl_res.status_code == 403
            assert "expired" in dl_res.get_json()["msg"].lower()

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})

    def test_token_immediate_revocation(self, client):
        """Revoked tokens cannot be validated or used for downloads."""
        user_email = f"rev_{uuid.uuid4().hex[:8]}@example.com"
        other_email = f"other_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000065", user_email)
        other_token = create_jwt("000000000000000000000066", other_email)

        file_doc = {
            "user_email": user_email,
            "filename": "rev.txt",
            "file_hash": "hash_rev",
            "s3_key": "encrypted/rev.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={"file_id": fid, "max_downloads": 5},
            )
            raw_token = create_res.get_json()["token"]
            token_id = create_res.get_json()["token_id"]

            # Other user cannot revoke
            other_revoke = client.delete(f"/api/tokens/{token_id}", headers={"Authorization": f"Bearer {other_token}"})
            assert other_revoke.status_code == 403

            # Owner revokes
            revoke_res = client.delete(f"/api/tokens/{token_id}", headers={"Authorization": f"Bearer {token}"})
            assert revoke_res.status_code == 200
            assert revoke_res.get_json()["success"] is True

            # Subsequent validate fails
            val_res = client.get("/api/tokens/validate", headers={"X-Access-Token": raw_token})
            assert val_res.status_code == 403
            assert "revoked" in val_res.get_json()["msg"].lower()

            # Subsequent download fails
            dl_res = client.get("/api/tokens/download", headers={"X-Access-Token": raw_token})
            assert dl_res.status_code == 403
            assert "revoked" in dl_res.get_json()["msg"].lower()

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})

    def test_token_listing_never_leaks_hash_or_plaintext(self, client):
        """Token list endpoints never expose token_hash or plaintext token."""
        user_email = f"leakcheck_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000067", user_email)

        file_doc = {
            "user_email": user_email,
            "filename": "leakcheck.pdf",
            "file_hash": "hash_leak",
            "s3_key": "encrypted/leakcheck.pdf",
            "size": 100,
            "mime_type": "application/pdf",
            "iv": "iv",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={"file_id": fid, "label": "Secret Token"},
            )
            raw_token = create_res.get_json()["token"]

            # 1. Check /tokens (all user tokens)
            list_res = client.get("/api/tokens", headers={"Authorization": f"Bearer {token}"})
            assert list_res.status_code == 200
            tokens = list_res.get_json()["tokens"]
            assert len(tokens) >= 1
            for t in tokens:
                assert "token_hash" not in t
                assert "token" not in t
                assert raw_token not in str(t)

            # 2. Check /tokens/file/<fid>
            file_tokens_res = client.get(f"/api/tokens/file/{fid}", headers={"Authorization": f"Bearer {token}"})
            assert file_tokens_res.status_code == 200
            f_tokens = file_tokens_res.get_json()["tokens"]
            assert len(f_tokens) >= 1
            for t in f_tokens:
                assert "token_hash" not in t
                assert "token" not in t
                assert raw_token not in str(t)

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})

    def test_atomic_single_use_concurrency_race_condition(self, client):
        """
        Concurrency Race Condition Test:
        10 threads simultaneously attempt to consume a single-use token (max_downloads=1).
        ATOMICITY GUARANTEE: Exactly 1 request succeeds (200), and 9 requests fail with 403.
        Zero double-spending or replay allowed.
        """
        user_email = f"race_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000068", user_email)

        file_doc = {
            "user_email": user_email,
            "filename": "single_use_prize.dat",
            "file_hash": "hash_prize",
            "s3_key": "encrypted/single_use_prize.dat",
            "size": 128,
            "mime_type": "application/octet-stream",
            "iv": "iv_sample",
            "salt": "salt_sample",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={"file_id": fid, "max_downloads": 1, "scope": "download"},
            )
            assert create_res.status_code == 201
            raw_token = create_res.get_json()["token"]
            token_id = create_res.get_json()["token_id"]

            def make_download_request():
                stream = io.BytesIO(b"ENCRYPTED_PAYLOAD_BYTES")
                stream.content_length = len(b"ENCRYPTED_PAYLOAD_BYTES")
                with patch("routes.tokens.download_from_s3_stream", return_value=stream):
                    return client.get("/api/tokens/download", headers={"X-Access-Token": raw_token})

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_download_request) for _ in range(10)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            status_codes = [r.status_code for r in results]

            # Exactly 1 request must succeed with 200 OK
            assert status_codes.count(200) == 1, f"Expected exactly 1 success, got {status_codes.count(200)}: {status_codes}"
            # Remaining 9 requests must be rejected with 403 Forbidden (quota exhausted)
            assert status_codes.count(403) == 9, f"Expected exactly 9 rejections, got {status_codes.count(403)}: {status_codes}"

            # Verify in MongoDB: downloads_used must be strictly 1
            doc = access_tokens_col.find_one({"_id": ObjectId(token_id)})
            assert doc["downloads_used"] == 1

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})

    def test_download_via_direct_url_route(self, client):
        """GET /api/access/download/<raw_token> allows seamless download and returns remaining header."""
        user_email = f"direct_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000069", user_email)

        file_doc = {
            "user_email": user_email,
            "filename": "direct_shared.pdf",
            "file_hash": "hash_direct",
            "s3_key": "encrypted/direct_shared.pdf",
            "size": 256,
            "mime_type": "application/pdf",
            "iv": "iv_direct",
            "salt": "salt_direct",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            create_res = client.post(
                "/api/tokens/create",
                headers={"Authorization": f"Bearer {token}"},
                json={"file_id": fid, "max_downloads": 2, "scope": "download"},
            )
            raw_token = create_res.get_json()["token"]

            def get_stream(*args, **kwargs):
                s = io.BytesIO(b"DIRECT_STREAM_PAYLOAD")
                s.content_length = len(b"DIRECT_STREAM_PAYLOAD")
                return s

            with patch("routes.tokens.download_from_s3_stream", side_effect=get_stream):
                # Download 1
                dl1 = client.get(f"/api/access/download/{raw_token}")
                assert dl1.status_code == 200
                assert dl1.headers.get("X-Token-Downloads-Remaining") == "1"
                assert dl1.headers.get("X-IV") == "iv_direct"

                # Download 2 (exhausts quota)
                dl2 = client.get(f"/api/access/download/{raw_token}")
                assert dl2.status_code == 200
                assert dl2.headers.get("X-Token-Downloads-Remaining") == "0"

                # Download 3 (rejected)
                dl3 = client.get(f"/api/access/download/{raw_token}")
                assert dl3.status_code == 403
                assert dl3.get_json()["success"] is False

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            access_tokens_col.delete_many({"file_id": fid})
