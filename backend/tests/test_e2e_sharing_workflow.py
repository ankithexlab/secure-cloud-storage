# =============================================================================
# tests/test_e2e_sharing_workflow.py — Targeted End-to-End Sharing Workflow
# =============================================================================
import base64
import hashlib
import io
import os
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from bson.objectid import ObjectId

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.auth_helpers import create_jwt
from utils.db import (
    access_tokens_col,
    file_shares_col,
    files_col,
    user_keys_col,
    users_col,
)

# Standard test SPKI keys & verified SHA-256 fingerprints
ALICE_PUBKEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0pUkfwIV8Mm5dIT2Qbux\n"
    "7hb3DFK0G+83pqj00gwPYGifgJtZ7mpqyVW9lOAFpHiNKRdjqVDkw46N97/8jgYu\n"
    "Y/7l4mhpDVKFKOc/0C2QeIzwzxR08cQCs7I71F+7jmKzMCzyHv1kT5wcr+1U8vtO\n"
    "DLW/K/vHE12D/OI8kdrhDOsjpYGTi0Sb1GBjxxT/2D20ZlhXItaKrbU1f98s6heC\n"
    "8U4MCNyj6lhaXXBiKfDqIcdG0NcwX60YzuoQVYzXJBQduDg2TgSivGjxtDyx/FW7\n"
    "x98wQQbBNRtI638x1msI4qEueawcpA+00104Qg5g4aBruwrKwtaJ7ZPCxRSqNdhu\n"
    "HwIDAQAB\n"
    "-----END PUBLIC KEY-----"
)
ALICE_FINGERPRINT = "SHA256:5E:E7:1A:22:F2:15:86:6D:98:EC:9F:E1:7E:77:28:73:1C:4B:F3:B3:CA:7C:22:D8:4F:05:62:E3:F2:2F:CD:0D"

BOB_PUBKEY_PEM = (
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
BOB_FINGERPRINT = "SHA256:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F:30:31:32:33:34:35:36:37:38:39:3A:3B:3C:3D:3E:3F:40"

TEST_WRAPPED_KEY_BOB = base64.b64encode(b"BOB_WRAPPED_AES256_DATA_KEY_OAEP_PADDING_SIMULATED_CONTENT_BYTES_" * 4).decode("utf-8")
TEST_WRAPPED_KEY_ALICE = base64.b64encode(b"ALICE_WRAPPED_AES256_DATA_KEY_OAEP_PADDING_SIMULATED_CONTENT_BYTES" * 4).decode("utf-8")


@pytest.fixture(scope="session")
def app():
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


class TestEndToEndTwoAccountSharingWorkflow:
    """Full end-to-end verification of file sharing between Alice and Bob."""

    def test_full_two_account_sharing_and_receiving_lifecycle(self, client):
        # 1. Setup two accounts: Alice (Owner) and Bob (Recipient), plus Attacker (Charlie)
        alice_email = f"alice_{uuid.uuid4().hex[:8]}@example.com"
        bob_email = f"bob_{uuid.uuid4().hex[:8]}@example.com"
        charlie_email = f"charlie_{uuid.uuid4().hex[:8]}@example.com"

        alice_token = create_jwt("000000000000000000000201", alice_email)
        bob_token = create_jwt("000000000000000000000202", bob_email)
        charlie_token = create_jwt("000000000000000000000203", charlie_email)

        # Register users
        users_col.insert_many([
            {"email": alice_email, "created_at": datetime.now(timezone.utc)},
            {"email": bob_email, "created_at": datetime.now(timezone.utc)},
            {"email": charlie_email, "created_at": datetime.now(timezone.utc)},
        ])

        # Register RSA public keys for Alice and Bob
        user_keys_col.insert_many([
            {
                "user_email": alice_email,
                "public_key": ALICE_PUBKEY_PEM,
                "fingerprint": ALICE_FINGERPRINT,
                "key_type": "RSA-OAEP-2048",
                "created_at": datetime.now(timezone.utc),
            },
            {
                "user_email": bob_email,
                "public_key": BOB_PUBKEY_PEM,
                "fingerprint": BOB_FINGERPRINT,
                "key_type": "RSA-OAEP-2048",
                "created_at": datetime.now(timezone.utc),
            },
        ])

        # 2. Alice has an encrypted file stored in CipherVault
        simulated_ciphertext = b"CIPHERVAULT_ENCRYPTED_AES_GCM_FILE_BYTES_PAYLOAD" * 8
        iv_b64 = base64.b64encode(b"initial_iv_96").decode("utf-8")
        file_sha256 = hashlib.sha256(simulated_ciphertext).hexdigest()

        file_doc = {
            "user_email": alice_email,
            "filename": "q4_financial_statement.pdf",
            "file_hash": file_sha256,
            "s3_key": "encrypted/q4_financial_statement.pdf",
            "size": len(simulated_ciphertext),
            "mime_type": "application/pdf",
            "iv": iv_b64,
            "wrapped_key": TEST_WRAPPED_KEY_ALICE,
            "key_fingerprint": ALICE_FINGERPRINT,
            "integrity_hash": file_sha256,
            "algorithm": "AES-GCM-256+RSA-OAEP",
            "upload_date": datetime.now(timezone.utc),
        }
        fid = str(files_col.insert_one(file_doc).inserted_id)

        try:
            # 3. Alice looks up Bob's public key
            lookup_res = client.get(f"/api/keys/{bob_email}", headers={"Authorization": f"Bearer {alice_token}"})
            assert lookup_res.status_code == 200
            bob_key_info = lookup_res.get_json()
            assert bob_key_info["fingerprint"] == BOB_FINGERPRINT
            assert bob_key_info["public_key"] == BOB_PUBKEY_PEM

            # 4. Alice shares file with Bob (Single-use download quota = 1)
            share_res = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {alice_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": bob_email,
                    "wrapped_key": TEST_WRAPPED_KEY_BOB,
                    "key_fingerprint": BOB_FINGERPRINT,
                    "permission": "download",
                    "max_downloads": 1,
                    "note": "Quarterly financials for review",
                },
            )
            assert share_res.status_code == 201
            share_json = share_res.get_json()
            assert share_json["success"] is True
            share_id = share_json["share_id"]

            # Verify linked token was created with valid id in DB
            share_rec = file_shares_col.find_one({"_id": ObjectId(share_id)})
            assert share_rec is not None
            assert share_rec.get("token_id") is not None
            assert ObjectId.is_valid(share_rec["token_id"])

            # 5. Bob views "Shared with Me" listing
            received_res = client.get("/api/shares/received", headers={"Authorization": f"Bearer {bob_token}"})
            assert received_res.status_code == 200
            bob_shares = received_res.get_json()["shares"]
            assert any(s["id"] == share_id for s in bob_shares)
            target_share = next(s for s in bob_shares if s["id"] == share_id)
            assert target_share["filename"] == "q4_financial_statement.pdf"
            assert target_share["owner_email"] == alice_email
            assert target_share["status"] == "active"
            assert target_share["permission"] == "download"

            # 6. IDOR verification: Charlie attempts to inspect or download Bob's share -> 403 Forbidden
            charlie_inspect = client.get(f"/api/shares/{share_id}", headers={"Authorization": f"Bearer {charlie_token}"})
            assert charlie_inspect.status_code == 403

            with patch("routes.shares.download_from_s3_stream", return_value=io.BytesIO(simulated_ciphertext)):
                charlie_dl = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {charlie_token}"})
                assert charlie_dl.status_code == 403

            # 7. Bob inspects share details before downloading
            bob_inspect = client.get(f"/api/shares/{share_id}", headers={"Authorization": f"Bearer {bob_token}"})
            assert bob_inspect.status_code == 200
            assert bob_inspect.get_json()["share"]["downloads_remaining"] == 1

            # 8. Bob downloads the shared file (Quota = 1)
            fake_stream = io.BytesIO(simulated_ciphertext)
            fake_stream.content_length = len(simulated_ciphertext)
            with patch("routes.shares.download_from_s3_stream", return_value=fake_stream):
                bob_dl = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {bob_token}"})
                assert bob_dl.status_code == 200
                assert bob_dl.headers.get("X-Wrapped-Key") == TEST_WRAPPED_KEY_BOB
                assert bob_dl.headers.get("X-IV") == iv_b64
                assert bob_dl.headers.get("X-Integrity-Hash") == file_sha256
                assert bob_dl.headers.get("X-Share-Downloads-Remaining") == "0"
                assert bob_dl.data == simulated_ciphertext

            # 9. Bob attempts a 2nd download -> Quota exhausted -> 403 Forbidden
            with patch("routes.shares.download_from_s3_stream", return_value=io.BytesIO(simulated_ciphertext)):
                bob_exhausted_dl = client.get(f"/api/shares/{share_id}/download", headers={"Authorization": f"Bearer {bob_token}"})
                assert bob_exhausted_dl.status_code == 403
                assert "download limit" in bob_exhausted_dl.get_json()["msg"].lower()

            # 10. Alice shares another file with Bob, then revokes it
            share_res_2 = client.post(
                "/api/shares",
                headers={"Authorization": f"Bearer {alice_token}"},
                json={
                    "file_id": fid,
                    "recipient_email": bob_email,
                    "wrapped_key": TEST_WRAPPED_KEY_BOB,
                    "key_fingerprint": BOB_FINGERPRINT,
                    "permission": "download",
                    "max_downloads": 5,
                },
            )
            share_id_2 = share_res_2.get_json()["share_id"]

            # Alice revokes share_id_2
            revoke_res = client.delete(f"/api/shares/{share_id_2}", headers={"Authorization": f"Bearer {alice_token}"})
            assert revoke_res.status_code == 200

            # Bob attempts download on revoked share -> 403 Forbidden
            with patch("routes.shares.download_from_s3_stream", return_value=io.BytesIO(simulated_ciphertext)):
                bob_revoked_dl = client.get(f"/api/shares/{share_id_2}/download", headers={"Authorization": f"Bearer {bob_token}"})
                assert bob_revoked_dl.status_code == 403
                assert "revoked" in bob_revoked_dl.get_json()["msg"].lower()

            # 11. Alice lists sent shares -> sees both shares with accurate status
            sent_res = client.get("/api/shares/sent", headers={"Authorization": f"Bearer {alice_token}"})
            assert sent_res.status_code == 200
            sent_shares = sent_res.get_json()["shares"]
            s1 = next(s for s in sent_shares if s["id"] == share_id)
            s2 = next(s for s in sent_shares if s["id"] == share_id_2)
            assert s1["status"] == "exhausted"
            assert s2["status"] == "revoked"

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
            file_shares_col.delete_many({"file_id": fid})
            users_col.delete_many({"email": {"$in": [alice_email, bob_email, charlie_email]}})
            user_keys_col.delete_many({"user_email": {"$in": [alice_email, bob_email]}})
