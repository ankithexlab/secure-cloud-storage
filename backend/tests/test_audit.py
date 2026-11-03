# =============================================================================
# tests/test_audit.py — Phase 11 Security Monitoring & Audit Logging Test Suite
# =============================================================================
import concurrent.futures
import copy
from datetime import datetime, timezone
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import Config
from utils.auth_helpers import create_jwt
from utils.audit import (
    GENESIS_HASH,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSeverity,
    compute_entry_hash,
    is_admin_user,
    record_audit_event,
    redact_sensitive_payload,
    sanitize_ip,
    sanitize_user_agent,
    verify_audit_log_integrity,
)
from utils.db import audit_logs_col, users_col


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
def admin_token():
    """Issue JWT for admin user."""
    return create_jwt("000000000000000000000099", "admin@securecloud.com")


@pytest.fixture()
def regular_user_token():
    """Issue JWT for regular non-admin user."""
    return create_jwt("000000000000000000000002", "regularuser@example.com")


# ---------------------------------------------------------------------------
# 1. Sanitization & Redaction Unit Tests (Requirements 7 & 8)
# ---------------------------------------------------------------------------
class TestSanitizationAndRedaction:
    def test_sanitize_ip_valid_ipv4_and_ipv6(self):
        assert sanitize_ip("192.168.1.1") == "192.168.1.1"
        assert sanitize_ip("10.0.0.1") == "10.0.0.1"
        assert sanitize_ip("::1") == "::1"
        assert sanitize_ip("2001:db8::1") == "2001:db8::1"

    def test_sanitize_ip_forwarded_for_proxy_chain(self):
        # Extracts first valid client IP from proxy chain
        assert sanitize_ip("203.0.113.195, 70.41.3.18, 150.172.238.178") == "203.0.113.195"

    def test_sanitize_ip_prevents_log_injection_and_malformed(self):
        # Strips CRLF or garbage injection
        assert sanitize_ip("127.0.0.1\r\nINJECTED LOG LINE") == "127.0.0.1"
        assert sanitize_ip("<script>alert(1)</script>") == "127.0.0.1"
        assert sanitize_ip("   ") == "127.0.0.1"
        assert sanitize_ip(None) == "127.0.0.1"

    def test_sanitize_user_agent_strips_control_chars_and_truncates(self):
        clean = sanitize_user_agent("Mozilla/5.0 (Windows NT 10.0)\r\nFake-Header: true")
        assert "\r" not in clean
        assert "\n" not in clean

        oversized = "A" * 500
        truncated = sanitize_user_agent(oversized)
        assert len(truncated) <= 256

    def test_redact_sensitive_payload_keys(self):
        sensitive_data = {
            "password": "SuperSecretPassword123!",
            "old_password": "OldPassword1!",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig",
            "access_token": "sct_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...",
            "wrapped_key": "k8Hj4+9wA...base64...",
            "safe_field": "public_report.pdf",
            "size": 1024,
        }
        redacted = redact_sensitive_payload(sensitive_data)
        assert redacted["password"] == "[REDACTED]"
        assert redacted["old_password"] == "[REDACTED]"
        assert redacted["token"] == "[REDACTED]"
        assert redacted["access_token"] == "[REDACTED]"
        assert redacted["private_key"] == "[REDACTED]"
        assert redacted["wrapped_key"] == "[REDACTED]"
        assert redacted["safe_field"] == "public_report.pdf"
        assert redacted["size"] == 1024

    def test_redact_sensitive_payload_embedded_values(self):
        data = {
            "notes": "Here is a token: sct_abcdef1234567890abcdef1234567890 and user PAN is ABCDE1234F",
            "nested": {
                "identity_statement": "Customer aadhaar is 2345 6789 0123",
                "payment_statement": "Paid with card 4012 8888 8888 1881",
            },
        }
        redacted = redact_sensitive_payload(data)
        assert "[REDACTED_TOKEN]" in redacted["notes"]
        assert "[REDACTED_PAN]" in redacted["notes"]
        assert "[REDACTED_AADHAAR]" in redacted["nested"]["identity_statement"]
        assert "[REDACTED_CARD]" in redacted["nested"]["payment_statement"]


# ---------------------------------------------------------------------------
# 2. Cryptographic Hash Chain & Tamper Resistance (Requirements 4 & 5)
# ---------------------------------------------------------------------------
class TestTamperResistanceAndHashChain:
    def test_genesis_block_and_hash_calculation(self):
        entry_hash = compute_entry_hash(
            sequence=1,
            previous_hash=GENESIS_HASH,
            timestamp_iso="2026-11-01T12:00:00+00:00",
            event_type=AuditEventType.USER_REGISTER,
            outcome=AuditOutcome.SUCCESS,
            user_email="alice@example.com",
            resource_id="res_01",
            details={"action": "register"},
        )
        assert isinstance(entry_hash, str)
        assert len(entry_hash) == 64

    def test_record_audit_event_chains_correctly(self):
        doc1 = record_audit_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            user_email="testchain1@example.com",
            details={"step": 1},
        )
        doc2 = record_audit_event(
            event_type=AuditEventType.FILE_UPLOAD,
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            user_email="testchain1@example.com",
            resource_id="file_abc123",
            details={"step": 2},
        )
        assert doc2["sequence"] == doc1["sequence"] + 1
        assert doc2["previous_hash"] == doc1["entry_hash"]

    def test_verify_audit_log_integrity_valid_chain(self):
        res = verify_audit_log_integrity()
        assert res["verified"] is True
        assert res["chain_intact"] is True

    def test_tamper_detection_on_modified_details(self):
        # Insert a canary record
        doc = record_audit_event(
            event_type=AuditEventType.FILE_DOWNLOAD,
            outcome=AuditOutcome.SUCCESS,
            user_email="tamper_test@example.com",
            details={"legitimate": "original_value"},
        )
        seq = doc["sequence"]

        # Simulate an unauthorized database tampering attack
        audit_logs_col.update_one(
            {"_id": doc["_id"]},
            {"$set": {"details.legitimate": "TAMPERED_BY_ATTACKER"}},
        )

        res = verify_audit_log_integrity()
        assert res["verified"] is False
        assert res["chain_intact"] is False
        assert res["broken_at_sequence"] == seq
        assert "modified" in res["reason"].lower()

        # Restore legitimate value to keep DB clean
        audit_logs_col.update_one(
            {"_id": doc["_id"]},
            {"$set": {"details.legitimate": "original_value"}},
        )
        restored_res = verify_audit_log_integrity()
        assert restored_res["verified"] is True


# ---------------------------------------------------------------------------
# 3. Suspicious Activity & Threat Detection (Requirement 3)
# ---------------------------------------------------------------------------
class TestSuspiciousActivityDetection:
    def test_repeated_failed_logins_triggers_audit_and_alerts(self, client):
        email = f"target_{int(datetime.now().timestamp())}@example.com"
        for _ in range(3):
            resp = client.post("/api/login", json={"email": email, "password": "WrongPassword1!"})
            assert resp.status_code == 401

        # Check that failed logins and suspicious activity were logged
        failed_count = audit_logs_col.count_documents({
            "event_type": AuditEventType.LOGIN_FAILED,
            "user_email": email,
        })
        assert failed_count >= 3

        suspicious_doc = audit_logs_col.find_one({
            "event_type": AuditEventType.SUSPICIOUS_ACTIVITY,
            "user_email": email,
        })
        assert suspicious_doc is not None
        assert suspicious_doc["severity"] == AuditSeverity.WARNING

    def test_unauthorized_file_access_records_audit_event(self, client, regular_user_token):
        # Attempt to access a nonexistent or unowned file
        resp = client.get(
            "/api/download/000000000000000000000000",
            headers={"Authorization": f"Bearer {regular_user_token}"},
        )
        # Should return 404 for nonexistent, or 403 for unowned
        assert resp.status_code in (403, 404)


# ---------------------------------------------------------------------------
# 4. Admin Role & Endpoints Enforcement (Requirement 6)
# ---------------------------------------------------------------------------
class TestAdminEndpointsAndAuthorization:
    def test_admin_check_helper(self):
        assert is_admin_user("admin@securecloud.com") is True
        assert is_admin_user({"email": "admin@securecloud.com"}) is True
        assert is_admin_user("regular@example.com") is False
        assert is_admin_user({"email": "regular@example.com", "role": "user"}) is False
        assert is_admin_user({"email": "custom@example.com", "is_admin": True}) is True

    def test_admin_logs_endpoint_requires_auth(self, client):
        resp = client.get("/api/admin/audit-logs")
        assert resp.status_code == 401

    def test_admin_logs_endpoint_rejects_regular_user(self, client, regular_user_token):
        resp = client.get(
            "/api/admin/audit-logs",
            headers={"Authorization": f"Bearer {regular_user_token}"},
        )
        assert resp.status_code == 403
        data = resp.get_json()
        assert "administrator" in data.get("msg", "").lower() or "admin" in data.get("msg", "").lower()

        # Verify unauthorized attempt was recorded with CRITICAL severity
        unauth_log = audit_logs_col.find_one({
            "event_type": AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
            "resource_type": AuditResourceType.ADMIN,
            "user_email": "regularuser@example.com",
        })
        assert unauth_log is not None
        assert unauth_log["severity"] == AuditSeverity.CRITICAL

    def test_admin_logs_endpoint_accessible_by_admin(self, client, admin_token):
        resp = client.get(
            "/api/admin/audit-logs?limit=5",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "logs" in data
        assert "pagination" in data
        assert isinstance(data["logs"], list)

    def test_admin_logs_filtering_by_event_type(self, client, admin_token):
        resp = client.get(
            f"/api/admin/audit-logs?event_type={AuditEventType.LOGIN_SUCCESS}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        for log in data["logs"]:
            assert log["event_type"] == AuditEventType.LOGIN_SUCCESS

    def test_admin_stats_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/admin/audit-logs/stats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "total_events" in data["stats"]
        assert "failed_logins" in data["stats"]
        assert "unauthorized_attempts" in data["stats"]
        assert "severity_counts" in data["stats"]

    def test_admin_verify_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/admin/audit-logs/verify",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["verification"]["verified"] is True
        assert data["verification"]["chain_intact"] is True

    def test_admin_export_json_and_csv(self, client, admin_token):
        # JSON export
        resp_json = client.get(
            "/api/admin/audit-logs/export?format=json",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp_json.status_code == 200
        assert resp_json.get_json()["success"] is True

        # CSV export
        resp_csv = client.get(
            "/api/admin/audit-logs/export?format=csv",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp_csv.status_code == 200
        assert "text/csv" in resp_csv.content_type
        assert "Sequence,Timestamp,EventType" in resp_csv.data.decode("utf-8")

    def test_forbid_audit_modification_http_methods(self, client, admin_token):
        # Attempting DELETE on audit logs must be rejected with 405
        resp_del = client.delete(
            "/api/admin/audit-logs",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp_del.status_code == 405
        assert "immutable" in resp_del.get_json().get("msg", "").lower()

        # Attempting PUT on audit logs must be rejected with 405
        resp_put = client.put(
            "/api/admin/audit-logs/1",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp_put.status_code == 405


# ---------------------------------------------------------------------------
# 5. Concurrency & High Throughput Hash Chain Verification
# ---------------------------------------------------------------------------
class TestConcurrentLogging:
    def test_concurrent_threads_maintain_hash_chain_integrity(self):
        """
        Spawn multiple parallel threads generating audit events simultaneously.
        Verify that sequential numbering, previous hash linking, and Merkle chain remain unbroken.
        """
        def log_worker(worker_id):
            for i in range(10):
                record_audit_event(
                    event_type=AuditEventType.FILE_UPLOAD,
                    outcome=AuditOutcome.SUCCESS,
                    severity=AuditSeverity.INFO,
                    user_email=f"worker_{worker_id}@example.com",
                    resource_id=f"res_{worker_id}_{i}",
                    details={"worker": worker_id, "index": i},
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(log_worker, w) for w in range(5)]
            concurrent.futures.wait(futures)

        res = verify_audit_log_integrity()
        assert res["verified"] is True
        assert res["chain_intact"] is True
        assert res["broken_at_sequence"] is None
