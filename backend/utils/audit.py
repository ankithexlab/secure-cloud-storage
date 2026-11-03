# =============================================================================
# utils/audit.py — Tamper-Resistant Security Monitoring & Audit Logging Subsystem
# =============================================================================
from datetime import datetime, timezone
from functools import wraps
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import threading
from typing import Any

from bson.objectid import ObjectId
from flask import jsonify, request

from config import Config
from utils.auth_helpers import jwt_required
from utils.db import audit_logs_col, get_user_by_email

logger = logging.getLogger("securecloud.audit")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

class AuditEventType:
    # Authentication
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    USER_REGISTER = "USER_REGISTER"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGE_SUCCESS = "PASSWORD_CHANGE_SUCCESS"
    PASSWORD_CHANGE_FAILED = "PASSWORD_CHANGE_FAILED"

    # File Operations
    FILE_UPLOAD = "FILE_UPLOAD"
    FILE_UPLOAD_FAILED = "FILE_UPLOAD_FAILED"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    FILE_DOWNLOAD_URL_GENERATED = "FILE_DOWNLOAD_URL_GENERATED"
    FILE_DELETE = "FILE_DELETE"

    # File Sharing
    SHARE_CREATE = "SHARE_CREATE"
    SHARE_REVOKE = "SHARE_REVOKE"
    SHARE_ACCESS_VIEW = "SHARE_ACCESS_VIEW"
    SHARE_ACCESS_DOWNLOAD = "SHARE_ACCESS_DOWNLOAD"

    # Access Tokens
    TOKEN_CREATE = "TOKEN_CREATE"
    TOKEN_REVOKE = "TOKEN_REVOKE"
    TOKEN_VALIDATE = "TOKEN_VALIDATE"
    TOKEN_DOWNLOAD = "TOKEN_DOWNLOAD"

    # RSA Keys
    KEY_REGISTER = "KEY_REGISTER"
    KEY_DELETE = "KEY_DELETE"

    # Security & Threat Detection
    UNAUTHORIZED_ACCESS_ATTEMPT = "UNAUTHORIZED_ACCESS_ATTEMPT"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"

    # Admin Operations
    AUDIT_LOG_ACCESSED = "AUDIT_LOG_ACCESSED"
    AUDIT_VERIFY_TRIGGERED = "AUDIT_VERIFY_TRIGGERED"
    AUDIT_EXPORT = "AUDIT_EXPORT"


class AuditSeverity:
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AuditOutcome:
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    BLOCKED = "BLOCKED"
    WARNING = "WARNING"


class AuditResourceType:
    AUTH = "auth"
    FILE = "file"
    SHARE = "share"
    TOKEN = "token"
    KEY = "key"
    SECURITY = "security"
    ADMIN = "admin"
    SYSTEM = "system"


# Thread lock to guarantee atomic monotonic sequence numbers and hash linking
_chain_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Sanitization & Log-Injection Prevention (Requirement 8)
# ---------------------------------------------------------------------------
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f\r\n]")
_IP_CANDIDATE_RE = re.compile(r"^[0-9a-fA-F:.]+$")


def sanitize_ip(raw_ip: str | None) -> str:
    """
    Sanitize and validate client IP address.
    Strips whitespace, CRLF, control characters, and validates IPv4 or IPv6 syntax.
    """
    if not raw_ip or not isinstance(raw_ip, str):
        return "127.0.0.1"

    # Handle comma-separated proxy chains (take the first client IP)
    candidate = raw_ip.split(",")[0].strip()
    candidate = _CONTROL_CHAR_RE.sub("", candidate)

    if not candidate or len(candidate) > 45 or not _IP_CANDIDATE_RE.match(candidate):
        return "127.0.0.1"

    try:
        parsed = ipaddress.ip_address(candidate)
        return str(parsed)
    except ValueError:
        return "127.0.0.1"


def sanitize_user_agent(raw_ua: str | None) -> str:
    """
    Sanitize and truncate User-Agent string to prevent log injection or buffer bloat.
    """
    if not raw_ua or not isinstance(raw_ua, str):
        return "Unknown"

    cleaned = _CONTROL_CHAR_RE.sub(" ", raw_ua).strip()
    return cleaned[:256] if cleaned else "Unknown"


def sanitize_log_text(text: Any) -> str:
    """
    Strip CRLF and control characters from arbitrary strings to prevent log forging.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return _CONTROL_CHAR_RE.sub(" ", text).strip()


# ---------------------------------------------------------------------------
# Redaction Engine — Strict Non-Disclosure of Secrets & PII (Requirement 7)
# ---------------------------------------------------------------------------
_SENSITIVE_KEY_PATTERNS = {
    "password",
    "old_password",
    "new_password",
    "current_password",
    "pass",
    "pwd",
    "token",
    "raw_token",
    "access_token",
    "share_token",
    "jwt",
    "authorization",
    "secret",
    "secret_key",
    "key",
    "private_key",
    "privkey",
    "aes_key",
    "wrapped_key",
    "keypair",
    "backup",
    "content",
    "encrypted_content",
    "file_content",
    "plaintext",
    "decrypted",
    "credit_card",
    "card",
    "pan",
    "aadhaar",
    "ssn",
    "national_id",
}

_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
_TOKEN_PREFIX_RE = re.compile(r"\bsct_[a-zA-Z0-9_-]{16,}\b")
_PEM_PRIVATE_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----")
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b(?!\d)")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")


def _is_luhn_valid(num_str: str) -> bool:
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    if len(set(digits)) == 1:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact_string_value(val: str) -> str:
    """Inspect string value and redact any embedded secrets, tokens, keys or PII."""
    if not val:
        return val

    # Token and Key redaction
    if _JWT_RE.search(val):
        val = _JWT_RE.sub("[REDACTED_JWT]", val)
    if _TOKEN_PREFIX_RE.search(val):
        val = _TOKEN_PREFIX_RE.sub("[REDACTED_TOKEN]", val)
    if _PEM_PRIVATE_RE.search(val):
        val = _PEM_PRIVATE_RE.sub("[REDACTED_PRIVATE_KEY]", val)

    # PII matches (Card first as it has longer 13-19 digit span with Luhn validation)
    card_matches = _CREDIT_CARD_RE.findall(val)
    for match in card_matches:
        clean = "".join(c for c in match if c.isdigit())
        if _is_luhn_valid(clean):
            val = val.replace(match, "[REDACTED_CARD]")

    if _PAN_RE.search(val):
        val = _PAN_RE.sub("[REDACTED_PAN]", val)
    if _AADHAAR_RE.search(val):
        val = _AADHAAR_RE.sub("[REDACTED_AADHAAR]", val)

    return sanitize_log_text(val)


def redact_sensitive_payload(obj: Any) -> Any:
    """
    Recursively sanitize dictionaries, lists and primitives.
    Guarantees no raw tokens, passwords, private keys, AES keys or PII enter logs.
    """
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            key_clean = str(k).strip()
            key_lower = key_clean.lower()
            if any(sens in key_lower for sens in _SENSITIVE_KEY_PATTERNS):
                sanitized[key_clean] = "[REDACTED]"
            else:
                sanitized[key_clean] = redact_sensitive_payload(v)
        return sanitized
    elif isinstance(obj, list):
        return [redact_sensitive_payload(item) for item in obj]
    elif isinstance(obj, str):
        return _redact_string_value(obj)
    elif isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, ObjectId):
        return str(obj)
    else:
        return sanitize_log_text(str(obj))


# ---------------------------------------------------------------------------
# Cryptographic Tamper-Resistant Hash Chaining (Requirement 5)
# ---------------------------------------------------------------------------
def compute_entry_hash(
    sequence: int,
    previous_hash: str,
    timestamp_iso: str,
    event_type: str,
    outcome: str,
    user_email: str | None,
    resource_id: str | None,
    details: dict,
) -> str:
    """
    Compute deterministic SHA-256 hash linking the previous entry hash, sequence,
    timestamp, core event attributes, and canonical JSON representation of details.
    """
    canonical_details = json.dumps(details or {}, sort_keys=True, separators=(",", ":"), default=str)
    chain_payload = (
        f"{sequence}|"
        f"{previous_hash}|"
        f"{timestamp_iso}|"
        f"{event_type}|"
        f"{outcome}|"
        f"{(user_email or '').strip().lower()}|"
        f"{str(resource_id or '').strip()}|"
        f"{canonical_details}"
    )
    return hashlib.sha256(chain_payload.encode("utf-8")).hexdigest()


def record_audit_event(
    event_type: str,
    outcome: str = AuditOutcome.SUCCESS,
    severity: str = AuditSeverity.INFO,
    user_id: str | None = None,
    user_email: str | None = None,
    resource_id: str | None = None,
    resource_type: str = AuditResourceType.SYSTEM,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_obj: Any = None,
) -> dict:
    """
    Record an immutable, cryptographically chained audit log entry into MongoDB.
    Thread-safe and tamper-resistant.
    """
    # Context extraction if request_obj provided or active in Flask context
    req = request_obj
    if req is None:
        try:
            if request:
                req = request
        except RuntimeError:
            req = None

    if req is not None:
        if ip_address is None:
            ip_address = req.headers.get("X-Forwarded-For") or req.remote_addr
        if user_agent is None:
            user_agent = req.headers.get("User-Agent", "")
        if user_id is None:
            user_id = getattr(req, "user_id", None)
        if user_email is None:
            user_email = getattr(req, "user_email", None)

    # Sanitize inputs
    clean_ip = sanitize_ip(ip_address)
    clean_ua = sanitize_user_agent(user_agent)
    clean_email = (user_email or "").strip().lower() if user_email else None
    clean_user_id = str(user_id) if user_id else None
    clean_resource_id = str(resource_id) if resource_id else None
    clean_details = redact_sensitive_payload(details or {})

    now_utc = datetime.now(timezone.utc)
    timestamp_iso = now_utc.isoformat()

    with _chain_lock:
        try:
            latest = audit_logs_col.find_one(sort=[("sequence", -1)])
        except Exception as e:
            logger.error(f"Error querying latest audit record: {e}")
            latest = None

        if latest and "sequence" in latest and "entry_hash" in latest:
            sequence = int(latest["sequence"]) + 1
            previous_hash = str(latest["entry_hash"])
        else:
            sequence = 1
            previous_hash = GENESIS_HASH

        entry_hash = compute_entry_hash(
            sequence=sequence,
            previous_hash=previous_hash,
            timestamp_iso=timestamp_iso,
            event_type=event_type,
            outcome=outcome,
            user_email=clean_email,
            resource_id=clean_resource_id,
            details=clean_details,
        )

        log_doc = {
            "sequence": sequence,
            "timestamp": now_utc,
            "timestamp_iso": timestamp_iso,
            "event_type": event_type,
            "severity": severity,
            "outcome": outcome,
            "user_id": clean_user_id,
            "user_email": clean_email,
            "resource_id": clean_resource_id,
            "resource_type": resource_type,
            "ip_address": clean_ip,
            "user_agent": clean_ua,
            "details": clean_details,
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
        }

        try:
            res = audit_logs_col.insert_one(log_doc)
            log_doc["_id"] = res.inserted_id
        except Exception as exc:
            logger.error(f"CRITICAL: Failed to write audit log to MongoDB: {exc}")

    # Structured local log
    logger.info(
        f"AUDIT_LOG seq={sequence} type={event_type} outcome={outcome} "
        f"severity={severity} user={clean_email or 'anon'} resource={clean_resource_id or 'none'} "
        f"hash={entry_hash[:12]}..."
    )

    return log_doc


def verify_audit_log_integrity(limit: int | None = None, start_sequence: int = 1) -> dict:
    """
    Cryptographically verify the integrity of the audit log hash chain.
    Detects any modification, insertion, deletion or reordering of audit records.
    """
    query = {"sequence": {"$gte": start_sequence}}
    cursor = audit_logs_col.find(query).sort("sequence", 1)
    if limit:
        cursor = cursor.limit(limit)

    records = list(cursor)
    if not records:
        return {
            "verified": True,
            "total_records": 0,
            "chain_intact": True,
            "broken_at_sequence": None,
            "reason": None,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    expected_seq = start_sequence
    expected_prev_hash = GENESIS_HASH if start_sequence == 1 else None

    for idx, doc in enumerate(records):
        current_seq = doc.get("sequence")
        if current_seq != expected_seq:
            return {
                "verified": False,
                "chain_intact": False,
                "broken_at_sequence": expected_seq,
                "reason": f"Sequence break: expected {expected_seq}, found {current_seq}",
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }

        prev_hash = doc.get("previous_hash")
        if idx == 0 and start_sequence == 1:
            if not hmac.compare_digest(str(prev_hash or ""), GENESIS_HASH):
                return {
                    "verified": False,
                    "chain_intact": False,
                    "broken_at_sequence": current_seq,
                    "reason": f"Invalid genesis previous_hash: expected {GENESIS_HASH}, found {prev_hash}",
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }
        elif expected_prev_hash is not None and not hmac.compare_digest(str(prev_hash or ""), str(expected_prev_hash)):
            return {
                "verified": False,
                "chain_intact": False,
                "broken_at_sequence": current_seq,
                "reason": f"Previous hash mismatch at seq {current_seq}: expected {expected_prev_hash}, found {prev_hash}",
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }

        timestamp_iso = doc.get("timestamp_iso")
        if not timestamp_iso:
            ts = doc.get("timestamp")
            timestamp_iso = ts.isoformat() if isinstance(ts, datetime) else str(ts)

        recomputed_hash = compute_entry_hash(
            sequence=current_seq,
            previous_hash=prev_hash,
            timestamp_iso=timestamp_iso,
            event_type=doc.get("event_type", ""),
            outcome=doc.get("outcome", ""),
            user_email=doc.get("user_email"),
            resource_id=doc.get("resource_id"),
            details=doc.get("details", {}),
        )

        if not hmac.compare_digest(recomputed_hash, str(doc.get("entry_hash") or "")):
            return {
                "verified": False,
                "chain_intact": False,
                "broken_at_sequence": current_seq,
                "reason": f"Entry hash mismatch at seq {current_seq}. Record content has been modified.",
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }

        expected_prev_hash = doc.get("entry_hash")
        expected_seq += 1

    return {
        "verified": True,
        "chain_intact": True,
        "total_records": len(records),
        "latest_sequence": expected_seq - 1,
        "latest_hash": expected_prev_hash,
        "broken_at_sequence": None,
        "reason": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Suspicious Activity Detection Engine (Requirement 3)
# ---------------------------------------------------------------------------
def check_suspicious_login_activity(ip: str, email: str | None = None, request_obj: Any = None) -> None:
    """
    Inspect failed login attempts and trigger real-time threat detection alerts.
    """
    from utils.rate_limit import login_rate_limiter

    ip_key = f"ip:{ip}"
    email_key = f"email:{email.strip().lower()}" if email else None

    ip_failures = login_rate_limiter.get_failure_count(ip_key)
    email_failures = login_rate_limiter.get_failure_count(email_key) if email_key else 0
    max_failures = max(ip_failures, email_failures)

    if max_failures >= 5:
        # Rate limit lockout threshold exceeded
        record_audit_event(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            outcome=AuditOutcome.BLOCKED,
            severity=AuditSeverity.CRITICAL,
            user_email=email,
            resource_type=AuditResourceType.SECURITY,
            details={
                "alert": "Account brute-force attempt blocked by rate limiter",
                "ip_failures": ip_failures,
                "email_failures": email_failures,
                "threshold": 5,
            },
            request_obj=request_obj,
        )
    elif max_failures >= 3:
        # Repeated failed logins warning
        record_audit_event(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            outcome=AuditOutcome.WARNING,
            severity=AuditSeverity.WARNING,
            user_email=email,
            resource_type=AuditResourceType.SECURITY,
            details={
                "alert": "Repeated failed logins detected",
                "ip_failures": ip_failures,
                "email_failures": email_failures,
                "threshold": 3,
            },
            request_obj=request_obj,
        )


def record_unauthorized_access(
    resource_type: str,
    resource_id: str | None = None,
    reason: str = "Access denied",
    severity: str = AuditSeverity.WARNING,
    request_obj: Any = None,
    extra_details: dict | None = None,
) -> dict:
    """
    Record an unauthorized access attempt.
    """
    d = {"reason": reason}
    if extra_details:
        d.update(extra_details)

    return record_audit_event(
        event_type=AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
        outcome=AuditOutcome.DENIED,
        severity=severity,
        resource_id=resource_id,
        resource_type=resource_type,
        details=d,
        request_obj=request_obj,
    )


# ---------------------------------------------------------------------------
# Admin Authorization & Security Role Checks (Requirement 6)
# ---------------------------------------------------------------------------
def is_admin_user(user_email_or_doc: str | dict | None) -> bool:
    """
    Determine if a user has admin privileges.
    Evaluates:
      1. Config.ADMIN_EMAILS match
      2. User document is_admin flag or role == 'admin'
    """
    if not user_email_or_doc:
        return False

    if isinstance(user_email_or_doc, str):
        email = user_email_or_doc.strip().lower()
        if email in getattr(Config, "ADMIN_EMAILS", []):
            return True
        user = get_user_by_email(email)
        if user and (user.get("is_admin") is True or user.get("role") == "admin"):
            return True
        return False

    if isinstance(user_email_or_doc, dict):
        email = (user_email_or_doc.get("email") or "").strip().lower()
        if email in getattr(Config, "ADMIN_EMAILS", []):
            return True
        if user_email_or_doc.get("is_admin") is True or user_email_or_doc.get("role") == "admin":
            return True
        return False

    return False


def admin_required(f):
    """
    Decorator that enforces:
      1. Valid JWT authentication via @jwt_required
      2. Server-side verification of administrator privileges
      3. Strict audit logging of any unauthorized admin panel attempts
    """
    @wraps(f)
    @jwt_required
    def decorated(*args, **kwargs):
        req_email = getattr(request, "user_email", "")
        if not is_admin_user(req_email):
            record_unauthorized_access(
                resource_type=AuditResourceType.ADMIN,
                resource_id="admin_security_panel",
                reason="Non-admin user attempted to access restricted admin/security endpoint",
                severity=AuditSeverity.CRITICAL,
                request_obj=request,
            )
            return jsonify({"success": False, "msg": "Access denied: Administrator privileges required"}), 403

        return f(*args, **kwargs)

    return decorated
