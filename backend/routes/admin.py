# =============================================================================
# routes/admin.py — Authenticated Admin & Security Monitoring Endpoints (Phase 11)
# =============================================================================
from datetime import datetime, timezone
import csv
import io
import re
from bson.objectid import ObjectId
from flask import Blueprint, jsonify, request, Response

from utils.audit import (
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSeverity,
    admin_required,
    record_audit_event,
    verify_audit_log_integrity,
)
from utils.db import audit_logs_col

admin_bp = Blueprint("admin", __name__)


# ---------------------------------------------------------------------------
# GET /admin/audit-logs — Paginated & Filtered Audit Logs Listing
# ---------------------------------------------------------------------------
@admin_bp.route("/audit-logs", methods=["GET"])
@admin_required
def list_audit_logs():
    """
    Retrieve paginated audit logs with dynamic filtering.
    Enforces server-side administrator authorization.
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        limit = min(100, max(1, int(request.args.get("limit", 20))))
    except (ValueError, TypeError):
        limit = 20

    event_type = request.args.get("event_type", "").strip()
    severity = request.args.get("severity", "").strip().upper()
    outcome = request.args.get("outcome", "").strip().upper()
    user_email = request.args.get("user_email", "").strip().lower()
    resource_id = request.args.get("resource_id", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()
    search = request.args.get("search", "").strip()

    filter_query: dict = {}

    if event_type:
        filter_query["event_type"] = event_type
    if severity:
        filter_query["severity"] = severity
    if outcome:
        filter_query["outcome"] = outcome
    if user_email:
        filter_query["user_email"] = {"$regex": re.escape(user_email), "$options": "i"}
    if resource_id:
        filter_query["resource_id"] = resource_id

    # Date range filtering
    if start_date or end_date:
        ts_filter = {}
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                ts_filter["$gte"] = start_dt
            except Exception:
                pass
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                ts_filter["$lte"] = end_dt
            except Exception:
                pass
        if ts_filter:
            filter_query["timestamp"] = ts_filter

    # Generic search across event_type, user_email, resource_id, or IP
    if search:
        search_escaped = re.escape(search)
        filter_query["$or"] = [
            {"event_type": {"$regex": search_escaped, "$options": "i"}},
            {"user_email": {"$regex": search_escaped, "$options": "i"}},
            {"resource_id": {"$regex": search_escaped, "$options": "i"}},
            {"ip_address": {"$regex": search_escaped, "$options": "i"}},
        ]

    total = audit_logs_col.count_documents(filter_query)
    total_pages = max(1, (total + limit - 1) // limit)
    skip = (page - 1) * limit

    cursor = audit_logs_col.find(filter_query).sort("sequence", -1).skip(skip).limit(limit)

    logs = []
    for doc in cursor:
        ts = doc.get("timestamp")
        logs.append({
            "id": str(doc["_id"]),
            "sequence": doc.get("sequence"),
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
            "event_type": doc.get("event_type"),
            "severity": doc.get("severity", AuditSeverity.INFO),
            "outcome": doc.get("outcome", AuditOutcome.SUCCESS),
            "user_id": doc.get("user_id"),
            "user_email": doc.get("user_email"),
            "resource_id": doc.get("resource_id"),
            "resource_type": doc.get("resource_type"),
            "ip_address": doc.get("ip_address"),
            "user_agent": doc.get("user_agent"),
            "details": doc.get("details", {}),
            "previous_hash": doc.get("previous_hash"),
            "entry_hash": doc.get("entry_hash"),
        })

    # Log the access itself
    record_audit_event(
        event_type=AuditEventType.AUDIT_LOG_ACCESSED,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        resource_type=AuditResourceType.ADMIN,
        resource_id="audit_logs_listing",
        details={"page": page, "limit": limit, "filtered_count": total},
        request_obj=request,
    )

    return jsonify({
        "success": True,
        "logs": logs,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        },
    }), 200


# ---------------------------------------------------------------------------
# GET /admin/audit-logs/stats — Security Monitoring Metrics & Dashboard Aggregates
# ---------------------------------------------------------------------------
@admin_bp.route("/audit-logs/stats", methods=["GET"])
@admin_required
def get_audit_stats():
    """
    Return high-level security metrics, event breakdowns, and recent threat alerts.
    """
    total_events = audit_logs_col.count_documents({})
    failed_logins = audit_logs_col.count_documents({"event_type": AuditEventType.LOGIN_FAILED})
    unauthorized_attempts = audit_logs_col.count_documents({
        "event_type": {"$in": [AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT, AuditEventType.RATE_LIMIT_EXCEEDED]}
    })
    suspicious_events = audit_logs_col.count_documents({
        "severity": {"$in": [AuditSeverity.WARNING, AuditSeverity.CRITICAL]}
    })

    # Severity distribution
    severity_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]
    severity_counts = {item["_id"]: item["count"] for item in audit_logs_col.aggregate(severity_pipeline) if item.get("_id")}

    # Outcome distribution
    outcome_pipeline = [
        {"$group": {"_id": "$outcome", "count": {"$sum": 1}}}
    ]
    outcome_counts = {item["_id"]: item["count"] for item in audit_logs_col.aggregate(outcome_pipeline) if item.get("_id")}

    # Top event types
    event_type_pipeline = [
        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 8},
    ]
    top_events = [{"event_type": item["_id"], "count": item["count"]} for item in audit_logs_col.aggregate(event_type_pipeline) if item.get("_id")]

    # Recent alerts (WARNING and CRITICAL)
    recent_alerts_cursor = audit_logs_col.find(
        {"severity": {"$in": [AuditSeverity.WARNING, AuditSeverity.CRITICAL]}}
    ).sort("sequence", -1).limit(6)

    recent_alerts = []
    for doc in recent_alerts_cursor:
        ts = doc.get("timestamp")
        recent_alerts.append({
            "id": str(doc["_id"]),
            "sequence": doc.get("sequence"),
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
            "event_type": doc.get("event_type"),
            "severity": doc.get("severity"),
            "outcome": doc.get("outcome"),
            "user_email": doc.get("user_email"),
            "resource_id": doc.get("resource_id"),
            "ip_address": doc.get("ip_address"),
            "details": doc.get("details", {}),
        })

    return jsonify({
        "success": True,
        "stats": {
            "total_events": total_events,
            "failed_logins": failed_logins,
            "unauthorized_attempts": unauthorized_attempts,
            "suspicious_events": suspicious_events,
            "severity_counts": {
                "INFO": severity_counts.get("INFO", 0),
                "WARNING": severity_counts.get("WARNING", 0),
                "CRITICAL": severity_counts.get("CRITICAL", 0),
            },
            "outcome_counts": outcome_counts,
            "top_events": top_events,
            "recent_alerts": recent_alerts,
        },
    }), 200


# ---------------------------------------------------------------------------
# GET /admin/audit-logs/verify — Cryptographic Tamper-Resistance Chain Verification
# ---------------------------------------------------------------------------
@admin_bp.route("/audit-logs/verify", methods=["GET"])
@admin_required
def verify_audit_chain():
    """
    Run cryptographic verification over the audit log hash chain.
    Returns whether the chain is unbroken and free of tampering.
    """
    result = verify_audit_log_integrity()

    record_audit_event(
        event_type=AuditEventType.AUDIT_VERIFY_TRIGGERED,
        outcome=AuditOutcome.SUCCESS if result.get("verified") else AuditOutcome.FAILURE,
        severity=AuditSeverity.INFO if result.get("verified") else AuditSeverity.CRITICAL,
        resource_type=AuditResourceType.ADMIN,
        resource_id="audit_chain_verifier",
        details={
            "verified": result.get("verified"),
            "total_checked": result.get("total_records"),
            "broken_at_sequence": result.get("broken_at_sequence"),
        },
        request_obj=request,
    )

    return jsonify({
        "success": True,
        "verification": result,
    }), 200


# ---------------------------------------------------------------------------
# GET /admin/audit-logs/<log_id> — Fetch Single Audit Log Detail
# ---------------------------------------------------------------------------
@admin_bp.route("/audit-logs/<log_id>", methods=["GET"])
@admin_required
def get_audit_log_detail(log_id: str):
    """
    Retrieve full sanitized details of a specific audit log entry.
    """
    try:
        oid = ObjectId(log_id)
        doc = audit_logs_col.find_one({"_id": oid})
    except Exception:
        doc = None

    if not doc:
        return jsonify({"success": False, "msg": "Audit log entry not found"}), 404

    ts = doc.get("timestamp")
    log_detail = {
        "id": str(doc["_id"]),
        "sequence": doc.get("sequence"),
        "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        "event_type": doc.get("event_type"),
        "severity": doc.get("severity"),
        "outcome": doc.get("outcome"),
        "user_id": doc.get("user_id"),
        "user_email": doc.get("user_email"),
        "resource_id": doc.get("resource_id"),
        "resource_type": doc.get("resource_type"),
        "ip_address": doc.get("ip_address"),
        "user_agent": doc.get("user_agent"),
        "details": doc.get("details", {}),
        "previous_hash": doc.get("previous_hash"),
        "entry_hash": doc.get("entry_hash"),
    }

    return jsonify({"success": True, "log": log_detail}), 200


# ---------------------------------------------------------------------------
# GET /admin/audit-logs/export — SIEM / Compliance Read-Only Export
# ---------------------------------------------------------------------------
@admin_bp.route("/audit-logs/export", methods=["GET"])
@admin_required
def export_audit_logs():
    """
    Export audit logs in CSV or JSON format for compliance archiving.
    """
    export_format = request.args.get("format", "json").strip().lower()
    event_type = request.args.get("event_type", "").strip()
    severity = request.args.get("severity", "").strip().upper()
    outcome = request.args.get("outcome", "").strip().upper()

    filter_query = {}
    if event_type:
        filter_query["event_type"] = event_type
    if severity:
        filter_query["severity"] = severity
    if outcome:
        filter_query["outcome"] = outcome

    cursor = audit_logs_col.find(filter_query).sort("sequence", 1).limit(1000)

    record_audit_event(
        event_type=AuditEventType.AUDIT_EXPORT,
        outcome=AuditOutcome.SUCCESS,
        severity=AuditSeverity.INFO,
        resource_type=AuditResourceType.ADMIN,
        details={"format": export_format, "filter": filter_query},
        request_obj=request,
    )

    if export_format == "csv":
        si = io.StringIO()
        writer = csv.writer(si)
        writer.writerow([
            "Sequence", "Timestamp", "EventType", "Severity", "Outcome",
            "UserEmail", "ResourceID", "ResourceType", "IPAddress", "PreviousHash", "EntryHash"
        ])
        for doc in cursor:
            ts = doc.get("timestamp")
            writer.writerow([
                doc.get("sequence"),
                ts.isoformat() if isinstance(ts, datetime) else str(ts),
                doc.get("event_type"),
                doc.get("severity"),
                doc.get("outcome"),
                doc.get("user_email") or "",
                doc.get("resource_id") or "",
                doc.get("resource_type") or "",
                doc.get("ip_address") or "",
                doc.get("previous_hash") or "",
                doc.get("entry_hash") or "",
            ])
        csv_output = si.getvalue()
        return Response(
            csv_output,
            mimetype="text/csv",
            headers={"Content-Disposition": 'attachment; filename="audit_logs.csv"'}
        )
    else:
        logs = []
        for doc in cursor:
            ts = doc.get("timestamp")
            logs.append({
                "id": str(doc["_id"]),
                "sequence": doc.get("sequence"),
                "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                "event_type": doc.get("event_type"),
                "severity": doc.get("severity"),
                "outcome": doc.get("outcome"),
                "user_id": doc.get("user_id"),
                "user_email": doc.get("user_email"),
                "resource_id": doc.get("resource_id"),
                "resource_type": doc.get("resource_type"),
                "ip_address": doc.get("ip_address"),
                "user_agent": doc.get("user_agent"),
                "details": doc.get("details", {}),
                "previous_hash": doc.get("previous_hash"),
                "entry_hash": doc.get("entry_hash"),
            })
        return jsonify({"success": True, "logs": logs, "count": len(logs)}), 200


# ---------------------------------------------------------------------------
# Immutability Enforcement — Reject all Modification / Deletion Attempts
# ---------------------------------------------------------------------------
@admin_bp.route("/audit-logs", methods=["POST", "PUT", "PATCH", "DELETE"])
@admin_bp.route("/audit-logs/<path:subpath>", methods=["POST", "PUT", "PATCH", "DELETE"])
@admin_required
def forbid_audit_modification(subpath=""):
    """
    Explicitly reject modification or deletion of audit logs (Requirement 5).
    Audit logs are strictly append-only and cryptographically immutable.
    """
    record_audit_event(
        event_type=AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
        outcome=AuditOutcome.DENIED,
        severity=AuditSeverity.CRITICAL,
        resource_type=AuditResourceType.ADMIN,
        resource_id=f"audit_logs_tamper_attempt_{request.method}",
        details={
            "attempted_method": request.method,
            "path": request.path,
            "warning": "Attempt to modify or delete immutable audit logs rejected",
        },
        request_obj=request,
    )
    return jsonify({
        "success": False,
        "msg": "Audit logs are cryptographically immutable. Modification and deletion are strictly prohibited.",
    }), 405
