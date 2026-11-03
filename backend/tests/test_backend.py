# =============================================================================
# tests/test_backend.py — Phase 1 automated test suite
#
# Run with:  cd backend && venv\Scripts\python.exe -m pytest tests/ -v
#
# Test categories:
#   - Unit: auth_helpers, rate_limit, config, db helpers
#   - Integration: Flask routes via test client (mocked MongoDB / S3 where needed)
#
# NOTE: B2/MongoDB integration tests that require live credentials are clearly
#       marked as INTEGRATION and skip automatically when credentials are absent.
# =============================================================================
import base64
import hashlib
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

# ── make sure backend package root is importable ─────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# =============================================================================
# Fixtures
# =============================================================================

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


@pytest.fixture()
def valid_token(app):
    """Issue a real JWT for testing authenticated endpoints."""
    from utils.auth_helpers import create_jwt
    return create_jwt("000000000000000000000001", "testuser@example.com")


@pytest.fixture()
def expired_token():
    """Return a token that expired in the past."""
    import jwt as pyjwt
    from config import Config
    payload = {
        "sub": "000000000000000000000001",
        "email": "testuser@example.com",
        "jti": "expiredtoken",
        "iat": datetime.now(timezone.utc) - timedelta(hours=48),
        "exp": datetime.now(timezone.utc) - timedelta(hours=24),
    }
    return pyjwt.encode(payload, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """Clear in-memory rate limiters between tests to prevent test coupling."""
    from utils.rate_limit import login_rate_limiter, register_rate_limiter
    login_rate_limiter.clear()
    register_rate_limiter.clear()
    yield
    login_rate_limiter.clear()
    register_rate_limiter.clear()


# =============================================================================
# 1. Config validation
# =============================================================================

class TestConfig:
    def test_validate_returns_dict(self):
        from config import Config
        result = Config.validate()
        assert isinstance(result, dict)
        assert "valid" in result
        assert "b2_configured" in result
        assert "environment" in result

    def test_mask_uri_masks_password(self):
        from config import mask_uri
        uri = "mongodb://admin:supersecret@localhost:27017/db"
        masked = mask_uri(uri)
        assert "supersecret" not in masked
        assert "admin" in masked
        assert "***" in masked

    def test_mask_uri_no_credentials(self):
        from config import mask_uri
        uri = "mongodb://127.0.0.1:27017/securecloud"
        masked = mask_uri(uri)
        assert masked == uri  # nothing to mask

    def test_mask_secret(self):
        from config import mask_secret
        assert mask_secret("") == "<unset>"
        assert mask_secret(None) == "<unset>"
        result = mask_secret("mysecretkey123")
        assert "mysecretkey123" not in result
        assert "***" in result

    def test_dev_secrets_in_dev_mode(self):
        """Dev mode should not raise even with default secrets."""
        from config import Config
        assert Config.SECRET_KEY is not None
        assert Config.JWT_SECRET_KEY is not None


# =============================================================================
# 2. Password hashing
# =============================================================================

class TestPasswordHashing:
    def test_hash_is_not_plain(self):
        from utils.auth_helpers import hash_password
        hashed = hash_password("testPassword1")
        assert hashed != "testPassword1"
        assert len(hashed) > 30

    def test_check_correct_password(self):
        from utils.auth_helpers import hash_password, check_password
        h = hash_password("correctPass1")
        assert check_password("correctPass1", h) is True

    def test_check_wrong_password(self):
        from utils.auth_helpers import hash_password, check_password
        h = hash_password("correctPass1")
        assert check_password("wrongPass1", h) is False

    def test_empty_plain_raises(self):
        from utils.auth_helpers import hash_password
        with pytest.raises(ValueError):
            hash_password("")

    def test_check_empty_returns_false(self):
        from utils.auth_helpers import check_password
        assert check_password("", "somehash") is False
        assert check_password("password1", "") is False

    def test_check_invalid_hash_format(self):
        from utils.auth_helpers import check_password
        assert check_password("password1", "notabcrypthash") is False


# =============================================================================
# 3. JWT creation and validation
# =============================================================================

class TestJWT:
    def test_create_and_decode(self):
        from utils.auth_helpers import create_jwt, decode_jwt
        token = create_jwt("abc123", "user@test.com")
        payload = decode_jwt(token)
        assert payload is not None
        assert payload["email"] == "user@test.com"
        assert payload["sub"] == "abc123"

    def test_expired_token_returns_none(self, expired_token):
        from utils.auth_helpers import decode_jwt
        result = decode_jwt(expired_token)
        assert result is None

    def test_expired_token_reason(self, expired_token):
        from utils.auth_helpers import decode_jwt_with_reason
        payload, reason = decode_jwt_with_reason(expired_token)
        assert payload is None
        assert reason == "token_expired"

    def test_invalid_token_reason(self):
        from utils.auth_helpers import decode_jwt_with_reason
        payload, reason = decode_jwt_with_reason("not.a.valid.token")
        assert payload is None
        assert reason == "token_invalid"

    def test_token_contains_jti(self):
        from utils.auth_helpers import create_jwt, decode_jwt
        token = create_jwt("uid1", "user@test.com")
        payload = decode_jwt(token)
        assert "jti" in payload

    def test_hash_token_deterministic(self):
        from utils.auth_helpers import hash_token
        t = "sometoken"
        assert hash_token(t) == hash_token(t)
        assert hash_token(t) == hashlib.sha256(t.encode()).hexdigest()


# =============================================================================
# 4. Rate limiting
# =============================================================================

class TestRateLimiter:
    def setup_method(self):
        from utils.rate_limit import SlidingWindowRateLimiter
        self.limiter = SlidingWindowRateLimiter(max_attempts=3, window_seconds=60)

    def test_not_limited_initially(self):
        limited, _ = self.limiter.is_rate_limited("test_key_1")
        assert limited is False

    def test_limited_after_max_failures(self):
        for _ in range(3):
            self.limiter.record_failure("test_key_2")
        limited, retry_after = self.limiter.is_rate_limited("test_key_2")
        assert limited is True
        assert retry_after > 0

    def test_reset_clears_limit(self):
        for _ in range(3):
            self.limiter.record_failure("test_key_3")
        self.limiter.reset("test_key_3")
        limited, _ = self.limiter.is_rate_limited("test_key_3")
        assert limited is False

    def test_different_keys_are_independent(self):
        for _ in range(3):
            self.limiter.record_failure("key_a")
        limited_a, _ = self.limiter.is_rate_limited("key_a")
        limited_b, _ = self.limiter.is_rate_limited("key_b")
        assert limited_a is True
        assert limited_b is False


# =============================================================================
# 5. Health endpoint
# =============================================================================

class TestHealth:
    def test_health_endpoint_returns_200(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "mongo" in data
        assert "storage" in data

    def test_root_endpoint(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

    def test_404_handler(self, client):
        response = client.get("/api/nonexistent-endpoint-xyz")
        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False


# =============================================================================
# 6. Registration endpoint
# =============================================================================

class TestRegistration:
    def test_register_missing_email(self, client):
        res = client.post("/api/register", json={"password": "Password1"})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_register_invalid_email(self, client):
        res = client.post("/api/register", json={"email": "notanemail", "password": "Password1"})
        assert res.status_code == 400

    def test_register_short_password(self, client):
        res = client.post("/api/register", json={"email": "user@test.com", "password": "abc"})
        assert res.status_code == 400

    def test_register_no_number_in_password(self, client):
        res = client.post("/api/register", json={"email": "user@test.com", "password": "NoNumbers"})
        assert res.status_code == 400

    def test_register_success_and_duplicate(self, client):
        """Test successful registration and duplicate detection."""
        import uuid
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"

        # First registration should succeed
        res = client.post("/api/register", json={"email": email, "password": "ValidPass1"})
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert "token" in data
        assert data["user"]["email"] == email

        # Second registration should fail with 409
        res2 = client.post("/api/register", json={"email": email, "password": "ValidPass1"})
        assert res2.status_code == 409
        assert res2.get_json()["success"] is False

    def test_register_case_insensitive_duplicate(self, client):
        """Upper and lower case emails must collide and return 409."""
        import uuid
        tag = uuid.uuid4().hex[:8]
        res1 = client.post("/api/register", json={"email": f"CASE_{tag}@example.com", "password": "ValidPass1"})
        assert res1.status_code == 201

        res2 = client.post("/api/register", json={"email": f"case_{tag}@example.com", "password": "ValidPass1"})
        assert res2.status_code == 409
        assert res2.get_json()["success"] is False

    def test_register_oversized_inputs(self, client):
        """Inputs exceeding maximum boundaries should be rejected with 400."""
        res_pw = client.post("/api/register", json={"email": "good@example.com", "password": "A1" * 70})
        assert res_pw.status_code == 400
        assert "128" in res_pw.get_json()["msg"]

        long_email = f"{'a' * 250}@example.com"
        res_email = client.post("/api/register", json={"email": long_email, "password": "ValidPass1"})
        assert res_email.status_code == 400

    def test_register_non_string_fields(self, client):
        """Type confusion payloads must be rejected safely."""
        res = client.post("/api/register", json={"email": 12345, "password": "ValidPass1"})
        assert res.status_code == 400

        res2 = client.post("/api/register", json={"email": "valid@example.com", "password": ["not", "string"]})
        assert res2.status_code == 400

    def test_register_rate_limit(self, client):
        """Excessive registration attempts from same IP trigger 429."""
        from utils.rate_limit import register_rate_limiter
        register_rate_limiter.clear()

        responses = []
        for i in range(12):
            res = client.post(
                "/api/register",
                json={"email": f"regflood_{i}@example.com", "password": "ValidPass1"},
                environ_base={"REMOTE_ADDR": "192.168.1.100"},
            )
            responses.append(res.status_code)
        assert 429 in responses


# =============================================================================
# 7. Login endpoint
# =============================================================================

class TestLogin:
    def test_login_invalid_credentials(self, client):
        res = client.post("/api/login", json={
            "email": "nonexistent_xyz@example.com",
            "password": "WrongPass1"
        })
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False

    def test_login_missing_password(self, client):
        res = client.post("/api/login", json={"email": "user@test.com"})
        assert res.status_code == 400

    def test_login_success_returns_token(self, client):
        """Register then login and verify token is returned."""
        import uuid
        email = f"logintest_{uuid.uuid4().hex[:8]}@example.com"
        password = "LoginPass1"

        client.post("/api/register", json={"email": email, "password": password})
        res = client.post("/api/login", json={"email": email, "password": password})

        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "token" in data
        assert data["user"]["email"] == email

    def test_login_wrong_password_after_register(self, client):
        import uuid
        email = f"wrongpw_{uuid.uuid4().hex[:8]}@example.com"
        client.post("/api/register", json={"email": email, "password": "CorrectPass1"})

        res = client.post("/api/login", json={"email": email, "password": "WrongPass1"})
        assert res.status_code == 401

    def test_login_generic_error_on_unknown_email(self, client):
        """Unknown email gives identical message to wrong password to prevent user enumeration."""
        res_unknown = client.post("/api/login", json={"email": "nonexistent_enum@example.com", "password": "WrongPass1"})
        assert res_unknown.status_code == 401
        assert res_unknown.get_json()["msg"] == "Invalid email or password"

    def test_login_oversized_inputs_rejected(self, client):
        """Oversized credentials rejected before bcrypt calculation."""
        res = client.post("/api/login", json={"email": "good@example.com", "password": "A1" * 70})
        assert res.status_code == 400


# =============================================================================
# 8. JWT middleware (protected routes)
# =============================================================================

class TestJWTMiddleware:
    def test_files_requires_auth(self, client):
        res = client.get("/api/files")
        assert res.status_code == 401
        assert res.get_json()["code"] == "missing_token"

    def test_files_with_invalid_token(self, client):
        res = client.get("/api/files", headers={"Authorization": "Bearer invalidtoken"})
        assert res.status_code == 401

    def test_files_with_expired_token(self, client, expired_token):
        res = client.get("/api/files", headers={"Authorization": f"Bearer {expired_token}"})
        assert res.status_code == 401
        data = res.get_json()
        assert data["code"] == "token_expired"

    def test_upload_requires_auth(self, client):
        res = client.post("/api/upload", json={})
        assert res.status_code == 401

    def test_delete_requires_auth(self, client):
        res = client.delete("/api/files/000000000000000000000001")
        assert res.status_code == 401

    def test_download_requires_auth(self, client):
        res = client.get("/api/download/000000000000000000000001")
        assert res.status_code == 401

    def test_me_requires_auth(self, client):
        res = client.get("/api/me")
        assert res.status_code == 401

    def test_change_password_requires_auth(self, client):
        res = client.post("/api/change-password", json={})
        assert res.status_code == 401

    def test_files_with_empty_bearer(self, client):
        res = client.get("/api/files", headers={"Authorization": "Bearer "})
        assert res.status_code == 401
        assert res.get_json()["code"] == "missing_token"

    def test_files_with_oversized_token(self, client):
        res = client.get("/api/files", headers={"Authorization": f"Bearer {'a' * 5000}"})
        assert res.status_code == 401

    def test_files_with_tampered_signature(self, client, valid_token):
        tampered = valid_token[:-4] + "xxxx"
        res = client.get("/api/files", headers={"Authorization": f"Bearer {tampered}"})
        assert res.status_code == 401
        assert res.get_json()["code"] == "token_invalid"


# =============================================================================
# 9. Logout and token revocation
# =============================================================================

class TestLogout:
    def test_logout_requires_auth(self, client):
        res = client.post("/api/logout")
        assert res.status_code == 401

    def test_logout_with_valid_token(self, client, valid_token):
        res = client.post("/api/logout", headers={"Authorization": f"Bearer {valid_token}"})
        # Should succeed
        assert res.status_code == 200
        assert res.get_json()["success"] is True

    def test_revoked_token_is_rejected(self, client):
        """After logout, the same token should be rejected."""
        import uuid
        email = f"revoke_{uuid.uuid4().hex[:8]}@example.com"
        reg = client.post("/api/register", json={"email": email, "password": "RevokePass1"})
        token = reg.get_json()["token"]

        # Logout (revoke token)
        client.post("/api/logout", headers={"Authorization": f"Bearer {token}"})

        # Subsequent request with same token should fail
        res = client.get("/api/files", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401
        data = res.get_json()
        assert data["code"] in ("token_revoked", "token_expired", "token_invalid")


# =============================================================================
# 10. Upload validation (no real B2 call)
# =============================================================================

class TestUploadValidation:
    def test_upload_missing_filename(self, client, valid_token):
        payload = {
            "encrypted_content": base64.b64encode(b"data").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        res = client.post("/api/upload",
                          json=payload,
                          headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 400
        assert "Filename" in res.get_json()["msg"]

    def test_upload_missing_encrypted_content(self, client, valid_token):
        payload = {
            "filename": "test.txt",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        res = client.post("/api/upload",
                          json=payload,
                          headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 400

    def test_upload_invalid_base64(self, client, valid_token):
        payload = {
            "filename": "test.txt",
            "encrypted_content": "not-valid-base64!!!",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        res = client.post("/api/upload",
                          json=payload,
                          headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 400
        assert "base64" in res.get_json()["msg"].lower()

    def test_upload_missing_iv_salt(self, client, valid_token):
        payload = {
            "filename": "test.txt",
            "encrypted_content": base64.b64encode(b"encrypted").decode(),
        }
        res = client.post("/api/upload",
                          json=payload,
                          headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 400
        assert "iv" in res.get_json()["msg"].lower() or "salt" in res.get_json()["msg"].lower()

    def test_upload_password_not_stored(self, client, valid_token):
        """Verify the backend does NOT accept or store file_password."""
        # Even if client accidentally sends file_password, backend should not error on it
        # (just silently ignore it) and not fail
        from unittest.mock import patch as mock_patch
        fake_doc = {
            "_id": MagicMock(__str__=lambda s: "000000000000000000000001"),
            "user_email": "testuser@example.com",
            "filename": "test.txt",
            "s3_key": "encrypted/fakefile.txt",
            "iv": "abc",
            "salt": "def",
        }
        with mock_patch("routes.file.upload_bytes_to_s3", return_value="encrypted/fakefile.txt"), \
             mock_patch("routes.file.add_file_record", return_value=fake_doc):
            payload = {
                "filename": "test.txt",
                "encrypted_content": base64.b64encode(b"x" * 32).decode(),
                "iv": base64.b64encode(b"a" * 12).decode(),
                "salt": base64.b64encode(b"b" * 16).decode(),
                "size": 100,
                "mime_type": "text/plain",
                "file_password": "this_should_be_ignored",
            }
            res = client.post("/api/upload",
                              json=payload,
                              headers={"Authorization": f"Bearer {valid_token}"})
            # Should succeed (201) because password is safely ignored
            assert res.status_code == 201
            data = res.get_json()
            assert data["success"] is True
            # Critically: file_password must NOT appear in the response
            assert "file_password" not in str(data)
            assert "password" not in str(data).lower().replace("is_legacy", "")


# =============================================================================
# 11. File access authorization
# =============================================================================

class TestFileAuthorization:
    def test_files_list_with_valid_token(self, client, valid_token):
        """Valid JWT should be able to hit /api/files (empty list is fine)."""
        res = client.get("/api/files",
                         headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "files" in data

    def test_download_nonexistent_file_returns_404(self, client, valid_token):
        res = client.get("/api/download/000000000000000000000001",
                         headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 404

    def test_delete_nonexistent_file_returns_404(self, client, valid_token):
        res = client.delete("/api/files/000000000000000000000001",
                            headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 404

    def test_delete_wrong_owner_returns_403(self, client):
        """File owned by user A cannot be deleted by user B."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        user_a_email = "usera@example.com"
        user_b_email = "userb@example.com"
        token_b = create_jwt("bbbbbbbbbbbbbbbbbbbbbbb2", user_b_email)

        # Insert a file owned by user_a
        doc = {
            "user_email": user_a_email,
            "filename": "user_a_file.txt",
            "file_hash": "abc",
            "s3_key": "encrypted/userA_file.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        file_id = str(inserted.inserted_id)

        try:
            # user_b tries to delete user_a's file
            res = client.delete(f"/api/files/{file_id}",
                                headers={"Authorization": f"Bearer {token_b}"})
            assert res.status_code == 403
            assert res.get_json()["success"] is False
        finally:
            files_col.delete_one({"_id": ObjectId(file_id)})

    def test_download_wrong_owner_returns_403(self, client):
        """File owned by user A cannot be downloaded by user B."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        user_a_email = "usera_dl@example.com"
        user_b_email = "userb_dl@example.com"
        token_b = create_jwt("bbbbbbbbbbbbbbbbbbbbbbb3", user_b_email)

        doc = {
            "user_email": user_a_email,
            "filename": "user_a_download.txt",
            "file_hash": "abc",
            "s3_key": "encrypted/userA_download.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        file_id = str(inserted.inserted_id)

        try:
            res = client.get(f"/api/download/{file_id}",
                             headers={"Authorization": f"Bearer {token_b}"})
            assert res.status_code == 403
        finally:
            files_col.delete_one({"_id": ObjectId(file_id)})


# =============================================================================
# 12. S3 filename sanitization (unit test)
# =============================================================================

class TestFileSanitization:
    def test_safe_filename_strips_path_traversal(self):
        from utils.s3 import _safe_filename
        assert "/" not in _safe_filename("../../etc/passwd")
        assert "\\" not in _safe_filename("..\\windows\\system32")

    def test_safe_filename_empty_becomes_default(self):
        from utils.s3 import _safe_filename
        assert _safe_filename("") == "file.bin"
        assert _safe_filename(None) == "file.bin"

    def test_safe_filename_normal_preserved(self):
        from utils.s3 import _safe_filename
        assert _safe_filename("document.pdf") == "document.pdf"
        assert _safe_filename("my file.txt") == "my file.txt"


# =============================================================================
# 13. Rate limit on login endpoint
# =============================================================================

class TestLoginRateLimit:
    def test_rate_limit_triggered(self, client):
        """After several failed logins, should return 429."""
        from utils.rate_limit import login_rate_limiter
        # Use a unique IP to avoid pollution from other tests
        login_rate_limiter.clear()

        email = "ratelimit_test_unique@example.com"
        # Make 6 failed attempts (limit is 5)
        responses = []
        for _ in range(6):
            res = client.post("/api/login",
                              json={"email": email, "password": "WrongPass1"},
                              environ_base={"REMOTE_ADDR": "10.99.99.99"})
            responses.append(res.status_code)
        # At least one should be 429
        assert 429 in responses


# =============================================================================
# 14. DB helper unit tests
# =============================================================================

class TestDBHelpers:
    def test_is_token_revoked_false_for_unknown(self):
        from utils.db import is_token_revoked
        assert is_token_revoked("definitely_not_revoked_token_hash") is False

    def test_revoke_and_check(self):
        from utils.db import revoke_token, is_token_revoked
        import uuid
        fake_hash = hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        revoke_token(fake_hash, expires)
        assert is_token_revoked(fake_hash) is True

    def test_get_user_by_email_nonexistent(self):
        from utils.db import get_user_by_email
        assert get_user_by_email("definitely_does_not_exist_xyz@nope.com") is None

    def test_get_file_by_id_bad_id(self):
        from utils.db import get_file_by_id
        assert get_file_by_id("not-a-valid-object-id") is None
        assert get_file_by_id("000000000000000000000000") is None


# =============================================================================
# 15. User profile endpoint
# =============================================================================

class TestUserProfile:
    def test_me_success(self, client):
        import uuid
        email = f"profile_{uuid.uuid4().hex[:8]}@example.com"
        reg = client.post("/api/register", json={"email": email, "password": "ProfilePass1"})
        token = reg.get_json()["token"]

        res = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["user"]["email"] == email
        assert "id" in data["user"]

    def test_user_alias(self, client):
        import uuid
        email = f"alias_{uuid.uuid4().hex[:8]}@example.com"
        reg = client.post("/api/register", json={"email": email, "password": "ProfilePass1"})
        token = reg.get_json()["token"]

        res = client.get("/api/user", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        assert res.get_json()["user"]["email"] == email


# =============================================================================
# 16. Password change endpoint
# =============================================================================

class TestPasswordChange:
    def test_change_password_success(self, client):
        import uuid
        email = f"pwchange_{uuid.uuid4().hex[:8]}@example.com"
        reg = client.post("/api/register", json={"email": email, "password": "OldPassword1"})
        old_token = reg.get_json()["token"]

        # Change password
        res = client.post(
            "/api/change-password",
            json={"old_password": "OldPassword1", "new_password": "NewPassword2"},
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        new_token = data["token"]
        assert new_token != old_token

        # Old token must now be revoked
        res_old = client.get("/api/files", headers={"Authorization": f"Bearer {old_token}"})
        assert res_old.status_code == 401

        # Login with old password must fail
        res_fail = client.post("/api/login", json={"email": email, "password": "OldPassword1"})
        assert res_fail.status_code == 401

        # Login with new password must succeed
        res_ok = client.post("/api/login", json={"email": email, "password": "NewPassword2"})
        assert res_ok.status_code == 200

    def test_change_password_wrong_current(self, client):
        import uuid
        email = f"wrongcurr_{uuid.uuid4().hex[:8]}@example.com"
        reg = client.post("/api/register", json={"email": email, "password": "OldPassword1"})
        token = reg.get_json()["token"]

        res = client.post(
            "/api/change-password",
            json={"old_password": "IncorrectPassword1", "new_password": "NewPassword2"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 401
        assert "Incorrect" in res.get_json()["msg"]

    def test_change_password_validation(self, client, valid_token):
        # Short new password
        res1 = client.post(
            "/api/change-password",
            json={"old_password": "OldPassword1", "new_password": "abc"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res1.status_code == 400

        # Same new password
        res2 = client.post(
            "/api/change-password",
            json={"old_password": "OldPassword1", "new_password": "OldPassword1"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res2.status_code == 400


# =============================================================================
# 17. Server-side authorization edge cases
# =============================================================================

class TestAuthorizationEdgeCases:
    def test_cross_user_file_access_with_differing_casing(self, client):
        """Cross-user rejection must hold regardless of email casing differences."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        owner_email = "owner_case@example.com"
        attacker_email = "attacker_case@example.com"
        attacker_token = create_jwt("000000000000000000000099", attacker_email.upper())

        doc = {
            "user_email": owner_email,
            "filename": "private_doc.txt",
            "file_hash": "hash123",
            "s3_key": "encrypted/priv.txt",
            "size": 50,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            res_dl = client.get(f"/api/download/{fid}", headers={"Authorization": f"Bearer {attacker_token}"})
            assert res_dl.status_code == 403

            res_del = client.delete(f"/api/files/{fid}", headers={"Authorization": f"Bearer {attacker_token}"})
            assert res_del.status_code == 403
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})





# =============================================================================
# 18. S3 / B2 Sanitization and MIME validation
# =============================================================================

class TestB2SanitizationAndMime:
    def test_safe_filename_advanced_traversal(self):
        from utils.s3 import _safe_filename
        assert _safe_filename("../../etc/passwd") == "passwd"
        assert _safe_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
        assert _safe_filename("evil:file*?.txt") == "evilfile.txt"
        assert _safe_filename("../../../secret.bin") == "secret.bin"

    def test_safe_filename_length_boundary(self):
        from utils.s3 import _safe_filename
        very_long = ("a" * 250) + ".pdf"
        cleaned = _safe_filename(very_long)
        assert len(cleaned) <= 200
        assert cleaned.endswith(".pdf")

    def test_safe_mime_type_valid(self):
        from utils.s3 import _safe_mime_type
        assert _safe_mime_type("image/png") == "image/png"
        assert _safe_mime_type("application/pdf") == "application/pdf"
        assert _safe_mime_type("text/plain") == "text/plain"

    def test_safe_mime_type_crlf_injection(self):
        from utils.s3 import _safe_mime_type
        # CRLF injection attempt
        malicious = "text/html\r\nSet-Cookie: evil=1"
        assert _safe_mime_type(malicious) == "application/octet-stream"

    def test_safe_mime_type_invalid_chars(self):
        from utils.s3 import _safe_mime_type
        assert _safe_mime_type("<script>alert(1)</script>") == "application/octet-stream"
        assert _safe_mime_type("") == "application/octet-stream"
        assert _safe_mime_type(None) == "application/octet-stream"


# =============================================================================
# 19. B2 Storage Error Handling & Atomic Rollback (Mocked)
# =============================================================================

class TestB2StorageErrorHandling:
    def test_download_missing_s3_object_returns_404(self, client):
        """When object is missing from B2 (NoSuchKey / 404), endpoint returns 404 cleanly."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from utils.s3 import StorageNotFoundError
        from bson.objectid import ObjectId

        email = "missings3@example.com"
        token = create_jwt("000000000000000000000088", email)
        doc = {
            "user_email": email,
            "filename": "missing.txt",
            "file_hash": "hash123",
            "s3_key": "encrypted/missing.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            with patch("routes.file.download_from_s3_stream", side_effect=StorageNotFoundError("Storage object not found")):
                res = client.get(f"/api/download/{fid}", headers={"Authorization": f"Bearer {token}"})
                assert res.status_code == 404
                data = res.get_json()
                assert data["success"] is False
                assert "not found" in data["msg"].lower()
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})




    def test_download_storage_auth_error_returns_503(self, client):
        """When storage credentials fail, endpoint returns 503 without leaking credentials."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from utils.s3 import StorageAuthError
        from bson.objectid import ObjectId

        email = "storageauth@example.com"
        token = create_jwt("000000000000000000000087", email)
        doc = {
            "user_email": email,
            "filename": "autherr.txt",
            "file_hash": "hash123",
            "s3_key": "encrypted/autherr.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            with patch("routes.file.download_from_s3_stream", side_effect=StorageAuthError("Cloud storage authentication failed")):
                res = client.get(f"/api/download/{fid}", headers={"Authorization": f"Bearer {token}"})
                assert res.status_code == 503
                data = res.get_json()
                assert data["success"] is False
                assert "configuration error" in data["msg"].lower() or "unavailable" in data["msg"].lower()
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})




    def test_download_storage_timeout_returns_504(self, client):
        """When storage connection times out, endpoint returns 504 Gateway Timeout."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from utils.s3 import StorageTimeoutError
        from bson.objectid import ObjectId

        email = "storagetimeout@example.com"
        token = create_jwt("000000000000000000000086", email)
        doc = {
            "user_email": email,
            "filename": "timeouterr.txt",
            "file_hash": "hash123",
            "s3_key": "encrypted/timeouterr.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            with patch("routes.file.download_from_s3_stream", side_effect=StorageTimeoutError("Storage operation timed out")):
                res = client.get(f"/api/download/{fid}", headers={"Authorization": f"Bearer {token}"})
                assert res.status_code == 504
                data = res.get_json()
                assert data["success"] is False
                assert "timed out" in data["msg"].lower()
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})




    def test_upload_storage_auth_error_returns_503(self, client, valid_token):
        """Storage auth error during upload returns 503."""
        from utils.s3 import StorageAuthError
        payload = {
            "filename": "doc.txt",
            "encrypted_content": base64.b64encode(b"hello world").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        with patch("routes.file.upload_bytes_to_s3", side_effect=StorageAuthError("B2 auth failed")):
            res = client.post("/api/upload", json=payload, headers={"Authorization": f"Bearer {valid_token}"})
            assert res.status_code == 503
            assert "configuration error" in res.get_json()["msg"].lower()

    def test_upload_storage_timeout_returns_504(self, client, valid_token):
        """Storage timeout during upload returns 504."""
        from utils.s3 import StorageTimeoutError
        payload = {
            "filename": "doc.txt",
            "encrypted_content": base64.b64encode(b"hello world").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        with patch("routes.file.upload_bytes_to_s3", side_effect=StorageTimeoutError("B2 timed out")):
            res = client.post("/api/upload", json=payload, headers={"Authorization": f"Bearer {valid_token}"})
            assert res.status_code == 504
            assert "timed out" in res.get_json()["msg"].lower()

    def test_upload_empty_file_rejected_with_400(self, client, valid_token):
        """Uploading an empty payload returns 400."""
        payload = {
            "filename": "empty.txt",
            "encrypted_content": "",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        res = client.post("/api/upload", json=payload, headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 400
        msg = res.get_json()["msg"].lower()
        assert "required" in msg or "empty" in msg

    def test_upload_atomic_rollback_on_db_failure(self, client, valid_token):
        """If MongoDB fails after storage upload, the orphaned B2 object is immediately deleted."""
        payload = {
            "filename": "rollback_test.txt",
            "encrypted_content": base64.b64encode(b"encrypted bytes").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
        }
        test_key = "encrypted/test_rollback_uuid_rollback_test.txt"
        with patch("routes.file.upload_bytes_to_s3", return_value=test_key), \
             patch("routes.file.add_file_record", side_effect=RuntimeError("MongoDB disk full")), \
             patch("routes.file.delete_from_s3") as mock_delete:
            res = client.post("/api/upload", json=payload, headers={"Authorization": f"Bearer {valid_token}"})
            assert res.status_code == 500
            # S3 cleanup must have been called for the uploaded object key
            mock_delete.assert_called_once_with(test_key)


# =============================================================================
# 20. B2 Presigned URL Tests (Mocked)
# =============================================================================

class TestB2PresignedUrls:
    def test_presigned_url_bounds_min_expiry(self):
        from utils.s3 import generate_presigned_url
        with patch("utils.s3._get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.generate_presigned_url.return_value = "https://b2.test/download?sig=xyz"
            mock_get_client.return_value = mock_client

            generate_presigned_url("encrypted/key.bin", expires_in=10)
            mock_client.generate_presigned_url.assert_called_once()
            call_kwargs = mock_client.generate_presigned_url.call_args[1]
            assert call_kwargs["ExpiresIn"] == 60  # Bounded to minimum 60s

    def test_presigned_url_bounds_max_expiry(self):
        from utils.s3 import generate_presigned_url
        with patch("utils.s3._get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.generate_presigned_url.return_value = "https://b2.test/download?sig=xyz"
            mock_get_client.return_value = mock_client

            generate_presigned_url("encrypted/key.bin", expires_in=999999)
            mock_client.generate_presigned_url.assert_called_once()
            call_kwargs = mock_client.generate_presigned_url.call_args[1]
            assert call_kwargs["ExpiresIn"] == 3600  # Bounded to maximum 3600s (1h)

    def test_presigned_url_empty_key_raises(self):
        from utils.s3 import generate_presigned_url, StorageError
        with pytest.raises(StorageError):
            generate_presigned_url("")

    def test_download_url_endpoint_authorized(self, client):
        """Authorized user receives temporary presigned URL."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        email = "presigned_user@example.com"
        token = create_jwt("000000000000000000000085", email)
        doc = {
            "user_email": email,
            "filename": "presigned_file.txt",
            "file_hash": "hash123",
            "s3_key": "encrypted/presigned_file.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            with patch("routes.file.generate_presigned_url", return_value="https://b2.test/presigned?token=123"):
                res = client.get(f"/api/download-url/{fid}", headers={"Authorization": f"Bearer {token}"})
                assert res.status_code == 200
                data = res.get_json()
                assert data["success"] is True
                assert data["url"] == "https://b2.test/presigned?token=123"
                assert data["filename"] == "presigned_file.txt"
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})




    def test_download_url_endpoint_wrong_owner_returns_403(self, client):
        """Cross-user request for presigned download URL is rejected with 403."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        owner_email = "owner_ps@example.com"
        attacker_email = "attacker_ps@example.com"
        attacker_token = create_jwt("000000000000000000000084", attacker_email)

        doc = {
            "user_email": owner_email,
            "filename": "secret_ps.txt",
            "file_hash": "hash123",
            "s3_key": "encrypted/secret_ps.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": "iv",
            "salt": "salt",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            res = client.get(f"/api/download-url/{fid}", headers={"Authorization": f"Bearer {attacker_token}"})
            assert res.status_code == 403
            assert res.get_json()["success"] is False
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})





# =============================================================================
# 21. Live Backblaze B2 Storage Tests (Clearly Distinguished Live Tests)
# =============================================================================

from config import Config
B2_CONFIGURED = Config.validate()["b2_configured"]

@pytest.mark.skipif(not B2_CONFIGURED, reason="Backblaze B2 credentials are not configured")
class TestB2LiveStorage:
    def test_live_b2_connection_check(self):
        """Verify live connectivity and head_bucket on Backblaze B2."""
        from utils.s3 import check_b2_connection
        result = check_b2_connection()
        assert result["connected"] is True
        assert result["bucket"] == Config.B2_BUCKET_NAME
        assert result["error"] is None

    def test_live_b2_bucket_is_private(self):
        """Verify that public unauthenticated HTTP requests to B2 bucket are denied."""
        import urllib.request
        import urllib.error

        bucket_url = f"{Config.B2_ENDPOINT_URL}/{Config.B2_BUCKET_NAME}/"
        unauth_status = None
        try:
            urllib.request.urlopen(bucket_url)
            unauth_status = 200
        except urllib.error.HTTPError as exc:
            unauth_status = exc.code
        except Exception:
            unauth_status = 0

        # Backblaze B2 returns 401 or 403 to unauthenticated bucket requests
        assert unauth_status in (401, 403), f"Expected 401/403 for private bucket, got {unauth_status}"

    def test_live_b2_lifecycle_upload_download_presigned_delete(self):
        """
        End-to-end live storage lifecycle against real Backblaze B2.
        Operates ONLY on an ephemeral test object with UUID key.
        Never touches or deletes real user files.
        """
        import uuid
        from utils.s3 import (
            upload_bytes_to_s3,
            download_from_s3,
            generate_presigned_url,
            delete_from_s3,
        )

        test_tag = uuid.uuid4().hex
        filename = f"live_test_{test_tag}.bin"
        payload = f"LIVE_B2_PAYLOAD_CONTENT_{test_tag}".encode("utf-8")

        # 1. Upload to live B2
        key = upload_bytes_to_s3(payload, filename, mime_type="application/octet-stream")
        assert key.startswith("encrypted/")
        assert test_tag in key

        try:
            # 2. Download from live B2
            retrieved_bytes = download_from_s3(key)
            assert retrieved_bytes == payload, "Retrieved bytes must match uploaded bytes exactly"

            # 3. Generate presigned URL
            presigned_url = generate_presigned_url(key, expires_in=120)
            assert presigned_url.startswith("https://")
            assert Config.B2_BUCKET_NAME in presigned_url
            assert "X-Amz-Signature=" in presigned_url or "X-Amz-Algorithm=" in presigned_url

        finally:
            # 4. Clean up test object
            deleted = delete_from_s3(key)
            assert deleted is True

            # 5. Verify idempotent delete
            deleted_again = delete_from_s3(key)
            assert deleted_again is True


# =============================================================================
# 22. Encryption Engine Metadata Verification (Phase 5)
# =============================================================================

class TestEncryptionMetadata:
    def test_upload_persists_integrity_and_algorithm_metadata(self, client, valid_token):
        """Upload persists integrity_hash, algorithm, kdf, and returns them."""
        from unittest.mock import patch as mock_patch
        payload = {
            "filename": "aes_gcm_test.txt",
            "encrypted_content": base64.b64encode(b"ciphertext123").decode(),
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
            "integrity_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "algorithm": "AES-GCM-256",
            "kdf": "PBKDF2-SHA256",
            "iterations": 100000,
            "version": "1.0",
        }
        with mock_patch("routes.file.upload_bytes_to_s3", return_value="encrypted/fake_enc_doc.bin"):
            res = client.post("/api/upload", json=payload, headers={"Authorization": f"Bearer {valid_token}"})
            assert res.status_code == 201
            data = res.get_json()
            assert data["success"] is True
            assert data["integrity_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            assert data["algorithm"] == "AES-GCM-256"

    def test_download_headers_expose_integrity_and_algorithm(self, client):
        """Download response exposes X-Integrity-Hash and X-Algorithm headers."""
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        email = "headercheck@example.com"
        token = create_jwt("000000000000000000000077", email)
        doc = {
            "user_email": email,
            "filename": "integrity_headers.txt",
            "file_hash": "hash123",
            "s3_key": "encrypted/integrity_headers.txt",
            "size": 100,
            "mime_type": "text/plain",
            "iv": base64.b64encode(b"a" * 12).decode(),
            "salt": base64.b64encode(b"b" * 16).decode(),
            "integrity_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "algorithm": "AES-GCM-256",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            with patch("routes.file.download_from_s3_stream", return_value=b"mock-cipher-bytes"):
                res = client.get(f"/api/download/{fid}", headers={"Authorization": f"Bearer {token}"})
                assert res.status_code == 200
                assert res.headers.get("X-Integrity-Hash") == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                assert res.headers.get("X-Algorithm") == "AES-GCM-256"
                assert "X-Integrity-Hash" in res.headers.get("Access-Control-Expose-Headers")
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})


# =============================================================================
# 23. RSA Public Key Management & Storage (Phase 6)
# =============================================================================

TEST_RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0pUkfwIV8Mm5dIT2Qbux
7hb3DFK0G+83pqj00gwPYGifgJtZ7mpqyVW9lOAFpHiNKRdjqVDkw46N97/8jgYu
Y/7l4mhpDVKFKOc/0C2QeIzwzxR08cQCs7I71F+7jmKzMCzyHv1kT5wcr+1U8vtO
DLW/K/vHE12D/OI8kdrhDOsjpYGTi0Sb1GBjxxT/2D20ZlhXItaKrbU1f98s6heC
8U4MCNyj6lhaXXBiKfDqIcdG0NcwX60YzuoQVYzXJBQduDg2TgSivGjxtDyx/FW7
x98wQQbBNRtI638x1msI4qEueawcpA+00104Qg5g4aBruwrKwtaJ7ZPCxRSqNdhu
HwIDAQAB
-----END PUBLIC KEY-----"""

TEST_RSA_FINGERPRINT = "SHA256:5E:E7:1A:22:F2:15:86:6D:98:EC:9F:E1:7E:77:28:73:1C:4B:F3:B3:CA:7C:22:D8:4F:05:62:E3:F2:2F:CD:0D"


class TestRsaKeyManagement:
    def test_keys_register_requires_auth(self, client):
        res = client.post("/api/keys/register", json={"public_key": TEST_RSA_PUBLIC_KEY_PEM})
        assert res.status_code == 401

    def test_keys_register_invalid_pem_rejected(self, client, valid_token):
        res = client.post(
            "/api/keys/register",
            json={"public_key": "not-a-valid-rsa-pem"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_keys_register_fingerprint_mismatch_rejected(self, client, valid_token):
        """Detect and reject key substitution when fingerprint doesn't match public key."""
        res = client.post(
            "/api/keys/register",
            json={
                "public_key": TEST_RSA_PUBLIC_KEY_PEM,
                "fingerprint": "SHA256:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
            },
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "substitution" in data["msg"].lower() or "mismatch" in data["msg"].lower()

    def test_keys_register_success_and_retrieve_me(self, client):
        """User registers public key and encrypted backup, then retrieves it from /keys/me."""
        import uuid
        from utils.auth_helpers import create_jwt
        from utils.db import user_keys_col

        email = f"rsa_user_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000066", email)

        try:
            # Register key with encrypted backup
            payload = {
                "public_key": TEST_RSA_PUBLIC_KEY_PEM,
                "fingerprint": TEST_RSA_FINGERPRINT,
                "key_type": "RSA-OAEP-2048",
                "encrypted_private_key": base64.b64encode(b"encrypted_pkcs8_bytes").decode(),
                "iv": base64.b64encode(b"a" * 12).decode(),
                "salt": base64.b64encode(b"b" * 16).decode(),
            }
            res_reg = client.post(
                "/api/keys/register",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res_reg.status_code == 201
            assert res_reg.get_json()["success"] is True

            # Retrieve own keys
            res_me = client.get("/api/keys/me", headers={"Authorization": f"Bearer {token}"})
            assert res_me.status_code == 200
            data_me = res_me.get_json()
            assert data_me["success"] is True
            assert data_me["user_email"] == email
            assert data_me["fingerprint"] == TEST_RSA_FINGERPRINT
            assert data_me["has_backup"] is True
            assert "encrypted_private_key" in data_me

        finally:
            user_keys_col.delete_one({"user_email": email})

    def test_keys_lookup_other_user_public_key_hides_private_backup(self, client):
        """Authenticated user can lookup other user's public key, but private backup is NEVER exposed."""
        import uuid
        from utils.auth_helpers import create_jwt
        from utils.db import user_keys_col

        user_alice = f"alice_{uuid.uuid4().hex[:8]}@example.com"
        user_bob = f"bob_{uuid.uuid4().hex[:8]}@example.com"
        token_alice = create_jwt("000000000000000000000065", user_alice)
        token_bob = create_jwt("000000000000000000000064", user_bob)

        try:
            # Bob registers key with backup
            payload = {
                "public_key": TEST_RSA_PUBLIC_KEY_PEM,
                "fingerprint": TEST_RSA_FINGERPRINT,
                "encrypted_private_key": base64.b64encode(b"bob_secret_private_backup").decode(),
                "iv": base64.b64encode(b"a" * 12).decode(),
                "salt": base64.b64encode(b"b" * 16).decode(),
            }
            client.post("/api/keys/register", json=payload, headers={"Authorization": f"Bearer {token_bob}"})

            # Alice looks up Bob's public key (for Phase 7 sharing)
            res = client.get(f"/api/keys/{user_bob}", headers={"Authorization": f"Bearer {token_alice}"})
            assert res.status_code == 200
            data = res.get_json()
            assert data["success"] is True
            assert data["user_email"] == user_bob
            assert data["fingerprint"] == TEST_RSA_FINGERPRINT
            assert data["public_key"] == TEST_RSA_PUBLIC_KEY_PEM

            # CRITICAL SECURITY CHECK: Bob's private key backup MUST NOT be returned to Alice!
            assert "encrypted_private_key" not in data
            assert "salt" not in data
            assert "iv" not in data

        finally:
            user_keys_col.delete_one({"user_email": user_bob})

    def test_keys_lookup_nonexistent_returns_404(self, client, valid_token):
        res = client.get("/api/keys/definitely_not_registered@example.com", headers={"Authorization": f"Bearer {valid_token}"})
        assert res.status_code == 404
        assert res.get_json()["success"] is False

    def test_keys_delete_me_revokes_keypair(self, client):
        import uuid
        from utils.auth_helpers import create_jwt
        from utils.db import user_keys_col

        email = f"revoke_key_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000063", email)

        try:
            client.post(
                "/api/keys/register",
                json={"public_key": TEST_RSA_PUBLIC_KEY_PEM, "fingerprint": TEST_RSA_FINGERPRINT},
                headers={"Authorization": f"Bearer {token}"},
            )

            # Revoke
            res_del = client.delete("/api/keys/me", headers={"Authorization": f"Bearer {token}"})
            assert res_del.status_code == 200

            # Lookup should now return 404
            res_lookup = client.get("/api/keys/me", headers={"Authorization": f"Bearer {token}"})
            assert res_lookup.status_code == 404

        finally:
            user_keys_col.delete_one({"user_email": email})

# =============================================================================
# 24. Hybrid Encryption (AES-GCM-256 + RSA-OAEP) (Phase 7)
# =============================================================================

TEST_WRAPPED_KEY_B64 = base64.b64encode(b"W" * 256).decode()  # 256-byte wrapped AES data key
TEST_RSA_KEY_FINGERPRINT = "SHA256:5E:E7:1A:22:F2:15:86:6D:98:EC:9F:E1:7E:77:28:73:1C:4B:F3:B3:CA:7C:22:D8:4F:05:62:E3:F2:2F:CD:0D"


class TestHybridEncryption:
    def test_hybrid_upload_success_and_metadata_persisted(self, client):
        """Upload hybrid encrypted file with wrapped_key and key_fingerprint (no salt needed)."""
        import uuid
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        email = f"hybrid_uploader_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000055", email)

        iv_b64 = base64.b64encode(b"0123456789ab").decode()  # 12-byte IV
        cipher_b64 = base64.b64encode(b"mock_aes_gcm_ciphertext_payload").decode()

        payload = {
            "filename": "hybrid_secret.pdf",
            "encrypted_content": cipher_b64,
            "mime_type": "application/pdf",
            "size": 32,
            "iv": iv_b64,
            "wrapped_key": TEST_WRAPPED_KEY_B64,
            "key_fingerprint": TEST_RSA_KEY_FINGERPRINT,
            "integrity_hash": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            "algorithm": "AES-GCM-256+RSA-OAEP",
            "version": "2.0",
        }

        with patch("routes.file.upload_bytes_to_s3", return_value="encrypted/hybrid_secret.pdf"):
            res = client.post(
                "/api/upload",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )

        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert data["wrapped_key"] == TEST_WRAPPED_KEY_B64
        assert data["key_fingerprint"] == TEST_RSA_KEY_FINGERPRINT
        assert data["algorithm"] == "AES-GCM-256+RSA-OAEP"

        file_id = data["file_id"]
        try:
            # Check DB record directly
            doc = files_col.find_one({"_id": ObjectId(file_id)})
            assert doc is not None
            assert doc["wrapped_key"] == TEST_WRAPPED_KEY_B64
            assert doc["key_fingerprint"] == TEST_RSA_KEY_FINGERPRINT
            assert doc["algorithm"] == "AES-GCM-256+RSA-OAEP"
            assert doc["version"] == "2.0"
        finally:
            files_col.delete_one({"_id": ObjectId(file_id)})

    def test_hybrid_download_headers_exposed(self, client):
        """GET /download/<id> exposes X-Wrapped-Key and X-Key-Fingerprint in headers and CORS."""
        import uuid
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        email = f"hybrid_dl_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000056", email)

        doc = {
            "user_email": email,
            "filename": "confidential_hybrid.bin",
            "file_hash": "hash123",
            "s3_key": "encrypted/confidential_hybrid.bin",
            "size": 64,
            "mime_type": "application/octet-stream",
            "iv": base64.b64encode(b"0123456789ab").decode(),
            "wrapped_key": TEST_WRAPPED_KEY_B64,
            "key_fingerprint": TEST_RSA_KEY_FINGERPRINT,
            "integrity_hash": "integrity_digest_hex",
            "algorithm": "AES-GCM-256+RSA-OAEP",
            "version": "2.0",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            with patch("routes.file.download_from_s3_stream", return_value=b"mock-cipher-bytes"):
                res = client.get(f"/api/download/{fid}", headers={"Authorization": f"Bearer {token}"})
                assert res.status_code == 200
                assert res.headers.get("X-Wrapped-Key") == TEST_WRAPPED_KEY_B64
                assert res.headers.get("X-Key-Fingerprint") == TEST_RSA_KEY_FINGERPRINT
                assert res.headers.get("X-Algorithm") == "AES-GCM-256+RSA-OAEP"
                assert res.headers.get("X-Integrity-Hash") == "integrity_digest_hex"
                expose_headers = res.headers.get("Access-Control-Expose-Headers", "")
                assert "X-Wrapped-Key" in expose_headers
                assert "X-Key-Fingerprint" in expose_headers
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})

    def test_hybrid_upload_missing_iv_or_keys_rejected(self, client, valid_token):
        """Reject upload if IV is missing, or if both salt and wrapped_key are missing."""
        cipher_b64 = base64.b64encode(b"sample_content").decode()

        # Missing IV
        res_no_iv = client.post(
            "/api/upload",
            json={"filename": "doc.txt", "encrypted_content": cipher_b64, "wrapped_key": TEST_WRAPPED_KEY_B64},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res_no_iv.status_code == 400

        # Missing both salt and wrapped_key
        res_no_keys = client.post(
            "/api/upload",
            json={"filename": "doc.txt", "encrypted_content": cipher_b64, "iv": "valid_iv"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res_no_keys.status_code == 400
        assert "either salt or wrapped_key" in res_no_keys.get_json()["msg"]

    def test_hybrid_upload_invalid_wrapped_key_rejected(self, client, valid_token):
        """Reject upload with malformed or invalid-length wrapped_key."""
        cipher_b64 = base64.b64encode(b"sample_content").decode()
        iv_b64 = base64.b64encode(b"0123456789ab").decode()

        # Not base64
        res_bad_b64 = client.post(
            "/api/upload",
            json={"filename": "doc.txt", "encrypted_content": cipher_b64, "iv": iv_b64, "wrapped_key": "not-base64!"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res_bad_b64.status_code == 400

        # Too short (<128 bytes)
        short_key = base64.b64encode(b"too_short_key").decode()
        res_short = client.post(
            "/api/upload",
            json={"filename": "doc.txt", "encrypted_content": cipher_b64, "iv": iv_b64, "wrapped_key": short_key},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res_short.status_code == 400
        assert "length" in res_short.get_json()["msg"].lower()

    def test_hybrid_download_url_and_files_list_metadata(self, client):
        """Presigned URL and file list endpoints return wrapped_key and key_fingerprint."""
        import uuid
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        email = f"meta_user_{uuid.uuid4().hex[:8]}@example.com"
        token = create_jwt("000000000000000000000057", email)

        doc = {
            "user_email": email,
            "filename": "meta_file.dat",
            "file_hash": "hash456",
            "s3_key": "encrypted/meta_file.dat",
            "size": 128,
            "mime_type": "application/octet-stream",
            "iv": base64.b64encode(b"0123456789ab").decode(),
            "wrapped_key": TEST_WRAPPED_KEY_B64,
            "key_fingerprint": TEST_RSA_KEY_FINGERPRINT,
            "integrity_hash": "hash_val",
            "algorithm": "AES-GCM-256+RSA-OAEP",
            "version": "2.0",
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            # 1. Check /files listing
            res_list = client.get("/api/files", headers={"Authorization": f"Bearer {token}"})
            assert res_list.status_code == 200
            file_items = res_list.get_json()["files"]
            target = next((f for f in file_items if f["id"] == fid), None)
            assert target is not None
            assert target["wrapped_key"] == TEST_WRAPPED_KEY_B64
            assert target["key_fingerprint"] == TEST_RSA_KEY_FINGERPRINT

            # 2. Check /download-url/<fid>
            with patch("routes.file.generate_presigned_url", return_value="https://b2.mock/presigned_url"):
                res_url = client.get(f"/api/download-url/{fid}", headers={"Authorization": f"Bearer {token}"})
                assert res_url.status_code == 200
                data_url = res_url.get_json()
                assert data_url["wrapped_key"] == TEST_WRAPPED_KEY_B64
                assert data_url["key_fingerprint"] == TEST_RSA_KEY_FINGERPRINT

        finally:
            files_col.delete_one({"_id": ObjectId(fid)})

    def test_hybrid_download_unauthorized_user_forbidden(self, client):
        """Unauthorized user attempting to download hybrid file gets 403 Forbidden."""
        import uuid
        from utils.auth_helpers import create_jwt
        from utils.db import files_col
        from bson.objectid import ObjectId

        owner_email = f"owner_{uuid.uuid4().hex[:8]}@example.com"
        attacker_email = f"attacker_{uuid.uuid4().hex[:8]}@example.com"
        attacker_token = create_jwt("000000000000000000000058", attacker_email)

        doc = {
            "user_email": owner_email,
            "filename": "private_hybrid.txt",
            "file_hash": "hash789",
            "s3_key": "encrypted/private_hybrid.txt",
            "size": 50,
            "mime_type": "text/plain",
            "iv": "iv",
            "wrapped_key": TEST_WRAPPED_KEY_B64,
            "key_fingerprint": TEST_RSA_KEY_FINGERPRINT,
            "upload_date": datetime.now(timezone.utc),
        }
        inserted = files_col.insert_one(doc)
        fid = str(inserted.inserted_id)

        try:
            res = client.get(f"/api/download/{fid}", headers={"Authorization": f"Bearer {attacker_token}"})
            assert res.status_code == 403
            assert res.get_json()["success"] is False
        finally:
            files_col.delete_one({"_id": ObjectId(fid)})
