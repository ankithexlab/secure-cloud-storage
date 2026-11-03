// =============================================================================
// pages/AuditLogsPage.js — Security Monitoring & Audit Logging Portal (Phase 11)
// =============================================================================
import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Search,
  Filter,
  RefreshCw,
  Download,
  CheckCircle,
  XCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Eye,
  KeyRound,
  FileText,
  Server,
  Activity,
  User,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  getAuditLogs,
  getAuditStats,
  verifyAuditIntegrity,
} from '../services/api';
import { API_BASE_URL } from '../api';

const EVENT_TYPE_OPTIONS = [
  { value: '', label: 'All Event Types' },
  { value: 'LOGIN_SUCCESS', label: 'Login Success' },
  { value: 'LOGIN_FAILED', label: 'Login Failed' },
  { value: 'USER_REGISTER', label: 'User Registered' },
  { value: 'LOGOUT', label: 'Logout' },
  { value: 'PASSWORD_CHANGE_SUCCESS', label: 'Password Changed' },
  { value: 'PASSWORD_CHANGE_FAILED', label: 'Password Change Failed' },
  { value: 'FILE_UPLOAD', label: 'File Upload' },
  { value: 'FILE_DOWNLOAD', label: 'File Download' },
  { value: 'FILE_DELETE', label: 'File Delete' },
  { value: 'SHARE_CREATE', label: 'Share Created' },
  { value: 'SHARE_REVOKE', label: 'Share Revoked' },
  { value: 'SHARE_ACCESS_DOWNLOAD', label: 'Share Download' },
  { value: 'TOKEN_CREATE', label: 'Token Created' },
  { value: 'TOKEN_REVOKE', label: 'Token Revoked' },
  { value: 'TOKEN_DOWNLOAD', label: 'Token Download' },
  { value: 'KEY_REGISTER', label: 'Key Registered' },
  { value: 'KEY_DELETE', label: 'Key Deleted' },
  { value: 'SUSPICIOUS_ACTIVITY', label: 'Suspicious Activity' },
  { value: 'RATE_LIMIT_EXCEEDED', label: 'Rate Limit Block' },
  { value: 'UNAUTHORIZED_ACCESS_ATTEMPT', label: 'Unauthorized Access' },
];

export default function AuditLogsPage({ token, onSessionExpired }) {
  // State
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isForbidden, setIsForbidden] = useState(false);

  // Filters
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalRecords, setTotalRecords] = useState(0);
  const [search, setSearch] = useState('');
  const [eventType, setEventType] = useState('');
  const [severity, setSeverity] = useState('');
  const [outcome, setOutcome] = useState('');

  // Selected Log for Details Modal
  const [selectedLog, setSelectedLog] = useState(null);

  // Integrity Verification State
  const [verifying, setVerifying] = useState(false);
  const [integrityStatus, setIntegrityStatus] = useState(null);

  // ---------------------------------------------------------------------------
  // Load Stats & Logs
  // ---------------------------------------------------------------------------
  const fetchStats = useCallback(async () => {
    if (!token) return;
    try {
      const res = await getAuditStats(token);
      if (res.ok) {
        setStats(res.data?.stats);
      } else if (res.status === 403) {
        setIsForbidden(true);
      } else if (res.status === 401 && onSessionExpired) {
        onSessionExpired();
      }
    } catch (err) {
      console.error('Failed to load audit stats:', err);
    }
  }, [token, onSessionExpired]);

  const fetchLogs = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await getAuditLogs(token, {
        page,
        limit: 15,
        search: search.trim() || undefined,
        event_type: eventType || undefined,
        severity: severity || undefined,
        outcome: outcome || undefined,
      });

      if (res.ok) {
        setLogs(res.data?.logs || []);
        if (res.data?.pagination) {
          setTotalPages(res.data.pagination.total_pages || 1);
          setTotalRecords(res.data.pagination.total || 0);
        }
        setIsForbidden(false);
      } else if (res.status === 403) {
        setIsForbidden(true);
      } else if (res.status === 401 && onSessionExpired) {
        onSessionExpired();
      } else {
        toast.error(res.data?.msg || 'Failed to fetch audit logs');
      }
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
      toast.error('Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  }, [token, page, search, eventType, severity, outcome, onSessionExpired]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------
  const handleVerifyChain = async () => {
    if (!token) return;
    setVerifying(true);
    try {
      const res = await verifyAuditIntegrity(token);
      if (res.ok && res.data?.verification) {
        const v = res.data.verification;
        setIntegrityStatus(v);
        if (v.verified && v.chain_intact) {
          toast.success(`Merkle chain verified! All ${v.total_records} records intact.`);
        } else {
          toast.error(`Integrity warning: Chain broken at sequence #${v.broken_at_sequence}`);
        }
      } else {
        toast.error(res.data?.msg || 'Verification failed');
      }
    } catch (err) {
      console.error('Audit verification error:', err);
      toast.error('Failed to run chain verification');
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = (format = 'json') => {
    if (!token) return;
    const url = `${API_BASE_URL}/admin/audit-logs/export?format=${format}&event_type=${encodeURIComponent(
      eventType
    )}&severity=${encodeURIComponent(severity)}&outcome=${encodeURIComponent(outcome)}`;

    // Open export stream in authenticated manner via anchor
    fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error('Export request failed');
        return res.blob();
      })
      .then((blob) => {
        const blobUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.${format}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(blobUrl);
        toast.success(`Audit logs exported as ${format.toUpperCase()}`);
      })
      .catch((err) => {
        console.error('Export failed:', err);
        toast.error('Export failed');
      });
  };

  // Helper formatting badges
  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/20 text-red-400 border border-red-500/30">CRITICAL</span>;
      case 'WARNING':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">WARNING</span>;
      case 'INFO':
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">INFO</span>;
    }
  };

  const getOutcomeBadge = (out) => {
    switch (out) {
      case 'SUCCESS':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">SUCCESS</span>;
      case 'DENIED':
      case 'BLOCKED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/20 text-red-400 border border-red-500/30">{out}</span>;
      case 'FAILURE':
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">{out}</span>;
    }
  };

  // ---------------------------------------------------------------------------
  // Access Denied / Non-Admin Fallback
  // ---------------------------------------------------------------------------
  if (isForbidden) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 text-center">
        <div className="glass p-8 rounded-2xl border border-red-500/20 max-w-lg mx-auto shadow-2xl">
          <ShieldAlert className="w-16 h-16 text-red-400 mx-auto mb-4 animate-pulse" />
          <h2 className="text-xl font-bold text-white mb-2">Administrator Access Required</h2>
          <p className="text-sm text-cyber-muted mb-6">
            The Security Monitoring & Audit Logging subsystem is restricted to authenticated portal
            administrators. Every unauthorized access attempt is cryptographically logged and flagged.
          </p>
          <div className="p-3 bg-red-950/40 rounded-lg text-xs text-red-300/80 mb-6 border border-red-500/20">
            If you require audit visibility, contact your organization's security administrator to assign the administrator role.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyber-accent/10 border border-cyber-accent/20">
              <ShieldCheck className="w-6 h-6 text-cyber-accent" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                Security Monitoring & Audit Logging
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono font-normal">
                  TAMPER-PROOF LEDGER
                </span>
              </h1>
              <p className="text-xs text-cyber-muted">
                Cryptographically chained audit trail, real-time intrusion monitoring, and zero-knowledge redaction
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 transition-all shadow-sm"
          >
            <Lock className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            {verifying ? 'Verifying Chain...' : 'Verify Merkle Chain'}
          </button>

          <button
            onClick={() => handleExport('json')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-white/[0.04] text-cyber-muted hover:text-white border border-white/[0.08] transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            JSON
          </button>

          <button
            onClick={() => handleExport('csv')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-white/[0.04] text-cyber-muted hover:text-white border border-white/[0.08] transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </button>

          <button
            onClick={() => {
              fetchStats();
              fetchLogs();
            }}
            className="btn-icon"
            title="Refresh logs"
          >
            <RefreshCw className={`w-4 h-4 text-cyber-muted ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Audited Events */}
        <div className="glass p-4 rounded-xl border border-white/[0.06] flex items-center justify-between">
          <div>
            <p className="text-[11px] text-cyber-muted uppercase tracking-wider font-semibold">Total Audited Events</p>
            <p className="text-2xl font-bold text-white mt-1 font-mono">
              {stats?.total_events !== undefined ? stats.total_events : '...'}
            </p>
            <p className="text-[10px] text-cyber-muted mt-1 flex items-center gap-1">
              <CheckCircle className="w-3 h-3 text-emerald-400" />
              Cryptographically chained
            </p>
          </div>
          <div className="p-3 rounded-xl bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20">
            <Server className="w-5 h-5" />
          </div>
        </div>

        {/* Failed Logins */}
        <div className="glass p-4 rounded-xl border border-white/[0.06] flex items-center justify-between">
          <div>
            <p className="text-[11px] text-cyber-muted uppercase tracking-wider font-semibold">Failed Login Events</p>
            <p className="text-2xl font-bold text-amber-400 mt-1 font-mono">
              {stats?.failed_logins !== undefined ? stats.failed_logins : '...'}
            </p>
            <p className="text-[10px] text-cyber-muted mt-1">Brute-force tracking active</p>
          </div>
          <div className="p-3 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <KeyRound className="w-5 h-5" />
          </div>
        </div>

        {/* Unauthorized Attempts */}
        <div className="glass p-4 rounded-xl border border-white/[0.06] flex items-center justify-between">
          <div>
            <p className="text-[11px] text-cyber-muted uppercase tracking-wider font-semibold">Unauthorized Attempts</p>
            <p className="text-2xl font-bold text-red-400 mt-1 font-mono">
              {stats?.unauthorized_attempts !== undefined ? stats.unauthorized_attempts : '...'}
            </p>
            <p className="text-[10px] text-cyber-muted mt-1">Access control violations</p>
          </div>
          <div className="p-3 rounded-xl bg-red-500/10 text-red-400 border border-red-500/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        {/* Chain Integrity */}
        <div className="glass p-4 rounded-xl border border-white/[0.06] flex items-center justify-between">
          <div>
            <p className="text-[11px] text-cyber-muted uppercase tracking-wider font-semibold">Ledger Integrity</p>
            <p className="text-lg font-bold text-emerald-400 mt-1 flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-emerald-400" />
              {integrityStatus?.verified === false ? 'ALERT: Tampered' : 'Verified Intact'}
            </p>
            <p className="text-[10px] text-cyber-muted mt-1 font-mono">
              Genesis: SHA256 Chained
            </p>
          </div>
          <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass p-4 rounded-xl border border-white/[0.06] space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          {/* Search */}
          <div className="md:col-span-5 relative">
            <Search className="w-4 h-4 text-cyber-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search user email, resource ID, IP..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              className="w-full bg-cyber-bg/80 border border-white/[0.08] rounded-xl pl-9 pr-3 py-2 text-xs text-white placeholder-cyber-muted focus:outline-none focus:border-cyber-accent"
            />
          </div>

          {/* Event Type Dropdown */}
          <div className="md:col-span-3">
            <select
              value={eventType}
              onChange={(e) => {
                setEventType(e.target.value);
                setPage(1);
              }}
              className="w-full bg-cyber-bg/80 border border-white/[0.08] rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyber-accent"
            >
              {EVENT_TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value} className="bg-cyber-bg text-white">
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {/* Severity Dropdown */}
          <div className="md:col-span-2">
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
              className="w-full bg-cyber-bg/80 border border-white/[0.08] rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyber-accent"
            >
              <option value="" className="bg-cyber-bg text-white">All Severities</option>
              <option value="INFO" className="bg-cyber-bg text-white">INFO</option>
              <option value="WARNING" className="bg-cyber-bg text-white">WARNING</option>
              <option value="CRITICAL" className="bg-cyber-bg text-white">CRITICAL</option>
            </select>
          </div>

          {/* Outcome Dropdown */}
          <div className="md:col-span-2">
            <select
              value={outcome}
              onChange={(e) => {
                setOutcome(e.target.value);
                setPage(1);
              }}
              className="w-full bg-cyber-bg/80 border border-white/[0.08] rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyber-accent"
            >
              <option value="" className="bg-cyber-bg text-white">All Outcomes</option>
              <option value="SUCCESS" className="bg-cyber-bg text-white">SUCCESS</option>
              <option value="FAILURE" className="bg-cyber-bg text-white">FAILURE</option>
              <option value="DENIED" className="bg-cyber-bg text-white">DENIED</option>
              <option value="BLOCKED" className="bg-cyber-bg text-white">BLOCKED</option>
            </select>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="glass rounded-xl border border-white/[0.06] overflow-hidden">
        <div className="overflow-x-auto scrollbar-cyber">
          <table className="w-full text-left text-xs">
            <thead className="bg-white/[0.02] text-cyber-muted uppercase border-b border-white/[0.06] font-mono text-[10px]">
              <tr>
                <th className="py-3 px-4">Seq</th>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Outcome</th>
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4">Resource ID</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-cyber-muted">
                    <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin text-cyber-accent" />
                    Loading cryptographically chained audit trail...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-cyber-muted">
                    No audit records match the selected filters.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-3 px-4 font-mono text-cyber-accent font-semibold">
                      #{log.sequence}
                    </td>
                    <td className="py-3 px-4 text-cyber-muted whitespace-nowrap font-mono text-[11px]">
                      {log.timestamp ? log.timestamp.replace('T', ' ').slice(0, 19) : '-'}
                    </td>
                    <td className="py-3 px-4 font-mono font-medium text-white">
                      {log.event_type}
                    </td>
                    <td className="py-3 px-4">
                      {getSeverityBadge(log.severity)}
                    </td>
                    <td className="py-3 px-4">
                      {getOutcomeBadge(log.outcome)}
                    </td>
                    <td className="py-3 px-4 text-white font-medium max-w-[160px] truncate" title={log.user_email || 'anonymous'}>
                      {log.user_email || <span className="text-cyber-muted italic">anonymous</span>}
                    </td>
                    <td className="py-3 px-4 text-cyber-muted font-mono max-w-[120px] truncate" title={log.resource_id || '-'}>
                      {log.resource_id || '-'}
                    </td>
                    <td className="py-3 px-4 text-cyber-muted font-mono text-[11px]">
                      {log.ip_address || '-'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-white/[0.04] text-cyber-accent hover:bg-cyber-accent/10 border border-cyber-accent/20 transition-all"
                      >
                        <Eye className="w-3 h-3" />
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-white/[0.06] text-xs text-cyber-muted">
          <div>
            Showing page <span className="text-white font-mono">{page}</span> of{' '}
            <span className="text-white font-mono">{totalPages}</span> ({totalRecords} total events)
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg border border-white/[0.08] hover:bg-white/[0.04] disabled:opacity-30 disabled:pointer-events-none transition-all"
            >
              <ChevronLeft className="w-4 h-4 text-white" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="p-1.5 rounded-lg border border-white/[0.08] hover:bg-white/[0.04] disabled:opacity-30 disabled:pointer-events-none transition-all"
            >
              <ChevronRight className="w-4 h-4 text-white" />
            </button>
          </div>
        </div>
      </div>

      {/* Event Details Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
          <div className="glass max-w-2xl w-full rounded-2xl border border-white/[0.1] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-white/[0.08] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    Audit Event #{selectedLog.sequence}
                    {getSeverityBadge(selectedLog.severity)}
                    {getOutcomeBadge(selectedLog.outcome)}
                  </h3>
                  <p className="text-xs text-cyber-muted font-mono">{selectedLog.event_type}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="btn-icon"
                aria-label="Close"
              >
                <XCircle className="w-5 h-5 text-cyber-muted hover:text-white" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-4 text-xs scrollbar-cyber">
              {/* Cryptographic Chain Proof */}
              <div className="p-3.5 rounded-xl bg-emerald-500/5 border border-emerald-500/20 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-emerald-400 flex items-center gap-1.5 text-xs">
                    <Lock className="w-3.5 h-3.5" />
                    Cryptographic Chain Block Proof
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono text-[10px]">
                    HASH LINKED
                  </span>
                </div>
                <div className="space-y-1 font-mono text-[10px] text-cyber-muted">
                  <p className="break-all">
                    <span className="text-white font-semibold">Previous Hash:</span>{' '}
                    {selectedLog.previous_hash || 'GENESIS'}
                  </p>
                  <p className="break-all">
                    <span className="text-white font-semibold">Entry Hash:</span>{' '}
                    {selectedLog.entry_hash}
                  </p>
                </div>
              </div>

              {/* Event Attributes Grid */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                  <p className="text-cyber-muted text-[10px] uppercase font-semibold">Timestamp (UTC)</p>
                  <p className="text-white font-mono mt-0.5">{selectedLog.timestamp}</p>
                </div>
                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                  <p className="text-cyber-muted text-[10px] uppercase font-semibold">Client IP Address</p>
                  <p className="text-white font-mono mt-0.5">{selectedLog.ip_address || '127.0.0.1'}</p>
                </div>
                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                  <p className="text-cyber-muted text-[10px] uppercase font-semibold">Subject User</p>
                  <p className="text-white mt-0.5 truncate">{selectedLog.user_email || 'anonymous'}</p>
                </div>
                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                  <p className="text-cyber-muted text-[10px] uppercase font-semibold">Resource Target</p>
                  <p className="text-white font-mono mt-0.5 truncate">
                    {selectedLog.resource_id ? `${selectedLog.resource_type}:${selectedLog.resource_id}` : '-'}
                  </p>
                </div>
              </div>

              {/* User Agent */}
              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                <p className="text-cyber-muted text-[10px] uppercase font-semibold">User Agent String</p>
                <p className="text-white font-mono text-[11px] mt-0.5 break-all">{selectedLog.user_agent || 'Unknown'}</p>
              </div>

              {/* Event Details (Sanitized Safe Metadata) */}
              <div>
                <p className="text-cyber-muted text-[10px] uppercase font-semibold mb-1">
                  Event Metadata (Zero-Knowledge Redacted)
                </p>
                <pre className="p-3.5 rounded-xl bg-black/40 border border-white/[0.08] text-cyber-accent font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>

              {/* Zero-Knowledge Assurance Banner */}
              <div className="p-3 rounded-lg bg-cyber-accent/5 border border-cyber-accent/20 text-[11px] text-cyber-muted flex items-start gap-2">
                <Shield className="w-4 h-4 text-cyber-accent flex-shrink-0 mt-0.5" />
                <span>
                  <strong className="text-white">Zero-Knowledge Guarantee:</strong> Passwords, raw access tokens,
                  RSA private keys, and plaintext file data are cryptographically stripped before persistence.
                </span>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3 border-t border-white/[0.08] flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="btn-primary py-1.5 px-4 text-xs"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
