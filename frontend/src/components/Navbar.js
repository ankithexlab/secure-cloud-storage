// =============================================================================
// components/Navbar.js — Top navigation bar with live security & share alerts
// =============================================================================
import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Menu,
  Bell,
  CheckCheck,
  Share2,
  ShieldAlert,
  RefreshCw,
  X,
  ExternalLink,
  Loader2,
} from 'lucide-react';
import { getReceivedShares, getAuditLogs } from '../services/api';

function formatTimeAgo(isoString) {
  if (!isoString) return 'Recently';
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
    if (diffSec < 60) return 'Just now';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    if (diffSec < 604800) return `${Math.floor(diffSec / 86400)}d ago`;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch {
    return 'Recently';
  }
}

export default function Navbar({
  user,
  onMenuToggle,
  pageTitle,
  token: propToken,
  onNavigate,
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [readIds, setReadIds] = useState([]);
  const [loading, setLoading] = useState(false);
  const dropdownRef = useRef(null);

  const storageKey = user?.email
    ? `sc_read_notifications_${user.email.toLowerCase()}`
    : 'sc_read_notifications_guest';

  // Load read notification IDs from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        setReadIds(JSON.parse(saved));
      } else {
        setReadIds([]);
      }
    } catch {
      setReadIds([]);
    }
  }, [storageKey]);

  // Fetch real alerts and shares from existing backend APIs
  const fetchNotifications = useCallback(async () => {
    const authToken =
      propToken ||
      (typeof window !== 'undefined' ? localStorage.getItem('sc_token') : null);

    if (!authToken || !user) {
      setNotifications([]);
      return;
    }

    setLoading(true);
    try {
      const items = [];

      // 1. Fetch file shares received by the authenticated user
      try {
        const shareRes = await getReceivedShares(authToken);
        if (shareRes?.ok && Array.isArray(shareRes.data?.shares)) {
          shareRes.data.shares.forEach((share) => {
            items.push({
              id: `share_${share.id || share._id}`,
              type: 'share',
              title: 'Encrypted File Shared',
              message: `${share.owner_email || 'A user'} shared "${share.filename || 'file'}"`,
              details: `Permission: ${share.permission || 'download'} • Status: ${share.status || 'active'}`,
              timestamp: share.created_at || new Date().toISOString(),
              severity: 'info',
              linkPage: 'shared',
              raw: share,
            });
          });
        }
      } catch {
        // Continue if share fetch encounters an issue
      }

      // 2. If user has admin privileges, fetch recent security alerts
      const isAdmin = user.is_admin || user.role === 'admin';
      if (isAdmin) {
        try {
          const auditRes = await getAuditLogs(authToken, { limit: 10 });
          if (auditRes?.ok && Array.isArray(auditRes.data?.logs)) {
            auditRes.data.logs.forEach((log) => {
              const isWarningOrCrit =
                log.severity === 'CRITICAL' ||
                log.severity === 'WARNING' ||
                log.outcome === 'FAILURE' ||
                log.outcome === 'BLOCKED';

              items.push({
                id: `audit_${log.id || log.sequence}`,
                type: 'security',
                title:
                  log.severity === 'CRITICAL'
                    ? 'Critical Security Alert'
                    : log.severity === 'WARNING'
                    ? 'Security Warning'
                    : `Security Event: ${log.event_type || 'Audit Log'}`,
                message:
                  log.details?.reason ||
                  log.details?.action ||
                  `${log.event_type || 'Event'} (${log.outcome || 'RECORDED'})`,
                details: `IP: ${log.ip_address || 'masked'} • Outcome: ${log.outcome || 'OK'}`,
                timestamp:
                  log.timestamp || log.timestamp_iso || new Date().toISOString(),
                severity:
                  log.severity === 'CRITICAL'
                    ? 'critical'
                    : isWarningOrCrit
                    ? 'warning'
                    : 'info',
                linkPage: 'audit',
                raw: log,
              });
            });
          }
        } catch {
          // Gracefully continue
        }
      }

      // Sort newest first
      items.sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );

      setNotifications(items);
    } catch {
      setNotifications([]);
    } finally {
      setLoading(false);
    }
  }, [propToken, user]);

  // Initial fetch and when user/token changes + periodic refresh every 60s
  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(() => {
      fetchNotifications();
    }, 60000);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  // Click-outside and Escape key listener to close dropdown
  useEffect(() => {
    if (!isOpen) return;

    function handleClickOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    }

    function handleKeyDown(e) {
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const unreadCount = notifications.filter((n) => !readIds.includes(n.id)).length;

  // Mark single notification as read
  const handleMarkRead = (id, e) => {
    if (e) e.stopPropagation();
    if (!readIds.includes(id)) {
      const updated = [...readIds, id];
      setReadIds(updated);
      try {
        localStorage.setItem(storageKey, JSON.stringify(updated));
      } catch {
        // localStorage full or unavailable
      }
    }
  };

  // Mark all notifications as read
  const handleMarkAllRead = (e) => {
    if (e) e.stopPropagation();
    const allIds = Array.from(new Set([...readIds, ...notifications.map((n) => n.id)]));
    setReadIds(allIds);
    try {
      localStorage.setItem(storageKey, JSON.stringify(allIds));
    } catch {
      // localStorage full or unavailable
    }
  };

  // Click notification item
  const handleItemClick = (item) => {
    handleMarkRead(item.id);
    if (onNavigate && item.linkPage) {
      onNavigate(item.linkPage);
      setIsOpen(false);
    }
  };

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between
                        px-4 sm:px-8 h-16
                        bg-cyber-bg/80 backdrop-blur-xl
                        border-b border-white/[0.05]">
      {/* Left — menu + title */}
      <div className="flex items-center gap-4">
        <button
          onClick={onMenuToggle}
          className="btn-icon lg:hidden"
          aria-label="Toggle sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>
        <h2 className="text-lg font-semibold text-white hidden sm:block">
          {pageTitle}
        </h2>
      </div>

      {/* Right — notifications + user */}
      <div className="flex items-center gap-3">
        {/* Notification bell & dropdown container */}
        <div className="relative" ref={dropdownRef}>
          <button
            type="button"
            onClick={() => {
              setIsOpen((prev) => !prev);
              if (!isOpen) {
                fetchNotifications();
              }
            }}
            className={`btn-icon relative transition-colors ${
              isOpen ? 'text-cyber-accent bg-cyber-accent/10' : ''
            }`}
            aria-label="Notifications"
            aria-expanded={isOpen}
            aria-haspopup="true"
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span
                data-testid="unread-indicator"
                className="absolute top-1 right-1 w-2.5 h-2.5 rounded-full
                           bg-cyber-green animate-pulse shadow-[0_0_8px_rgba(0,255,136,0.8)]"
              />
            )}
          </button>

          {/* Notification dropdown panel */}
          {isOpen && (
            <div
              data-testid="notifications-panel"
              className="absolute right-0 top-full mt-2 w-80 sm:w-96
                         bg-cyber-surface/95 backdrop-blur-2xl
                         border border-white/10 rounded-2xl
                         shadow-[0_20px_50px_rgba(0,0,0,0.6)]
                         overflow-hidden z-50 animate-slide-down"
              role="region"
              aria-label="Notifications panel"
            >
              {/* Header */}
              <div className="p-3.5 px-4 border-b border-white/[0.06] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-white">Notifications</h3>
                  {unreadCount > 0 ? (
                    <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-cyber-green/20 text-cyber-green border border-cyber-green/30 font-mono">
                      {unreadCount} new
                    </span>
                  ) : (
                    <span className="text-[11px] text-cyber-muted font-mono">All read</span>
                  )}
                </div>

                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={handleMarkAllRead}
                    disabled={unreadCount === 0}
                    title="Mark all as read"
                    className="p-1.5 rounded-lg text-cyber-muted hover:text-cyber-accent hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                    aria-label="Mark all as read"
                  >
                    <CheckCheck className="w-4 h-4" />
                  </button>

                  <button
                    type="button"
                    onClick={fetchNotifications}
                    title="Refresh notifications"
                    className="p-1.5 rounded-lg text-cyber-muted hover:text-cyber-accent hover:bg-white/5 transition-colors"
                    aria-label="Refresh notifications"
                  >
                    <RefreshCw
                      className={`w-4 h-4 ${loading ? 'animate-spin text-cyber-accent' : ''}`}
                    />
                  </button>

                  <button
                    type="button"
                    onClick={() => setIsOpen(false)}
                    title="Close notifications"
                    className="p-1.5 rounded-lg text-cyber-muted hover:text-white hover:bg-white/5 transition-colors"
                    aria-label="Close notifications"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Notification list / state */}
              <div className="max-h-80 overflow-y-auto scrollbar-cyber divide-y divide-white/[0.04]">
                {loading && notifications.length === 0 ? (
                  <div className="py-8 flex flex-col items-center justify-center text-center gap-2">
                    <Loader2 className="w-6 h-6 animate-spin text-cyber-accent" />
                    <p className="text-xs text-cyber-muted">Loading alerts...</p>
                  </div>
                ) : notifications.length === 0 ? (
                  <div
                    data-testid="notifications-empty"
                    className="py-10 px-4 flex flex-col items-center justify-center text-center"
                  >
                    <div className="w-12 h-12 rounded-full bg-white/[0.03] border border-white/10 flex items-center justify-center mb-3">
                      <Bell className="w-5 h-5 text-cyber-muted/60" />
                    </div>
                    <p className="text-sm font-medium text-white">No notifications</p>
                    <p className="text-xs text-cyber-muted mt-1 max-w-[220px]">
                      You're all caught up! Encrypted file shares and security alerts will appear here.
                    </p>
                  </div>
                ) : (
                  notifications.map((item) => {
                    const isRead = readIds.includes(item.id);
                    return (
                      <div
                        key={item.id}
                        data-testid="notification-item"
                        onClick={() => handleItemClick(item)}
                        className={`group px-4 py-3 cursor-pointer transition-colors
                                    hover:bg-white/[0.04] flex items-start gap-3
                                    ${!isRead ? 'bg-cyber-accent/[0.03]' : 'opacity-65 hover:opacity-100'}`}
                      >
                        {/* Type Icon */}
                        <div
                          className={`mt-0.5 w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                            item.type === 'share'
                              ? 'bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20'
                              : item.severity === 'critical'
                              ? 'bg-cyber-danger/10 text-cyber-danger border border-cyber-danger/20'
                              : 'bg-cyber-violet/10 text-cyber-violet border border-cyber-violet/20'
                          }`}
                        >
                          {item.type === 'share' ? (
                            <Share2 className="w-4 h-4" />
                          ) : (
                            <ShieldAlert className="w-4 h-4" />
                          )}
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-1">
                            <p className="text-xs font-semibold text-white truncate">
                              {item.title}
                            </p>
                            <span className="text-[10px] text-cyber-muted font-mono whitespace-nowrap">
                              {formatTimeAgo(item.timestamp)}
                            </span>
                          </div>
                          <p className="text-xs text-cyber-muted mt-0.5 line-clamp-2">
                            {item.message}
                          </p>
                          {item.details && (
                            <p className="text-[11px] text-cyber-muted/60 mt-1 font-mono truncate">
                              {item.details}
                            </p>
                          )}
                        </div>

                        {/* Read/Unread Status Indicator */}
                        <div className="flex-shrink-0 mt-1">
                          {!isRead ? (
                            <button
                              type="button"
                              onClick={(e) => handleMarkRead(item.id, e)}
                              title="Mark as read"
                              className="p-1 rounded hover:bg-white/10 text-cyber-accent hover:text-white transition-colors"
                              aria-label="Mark as read"
                            >
                              <span className="w-2 h-2 rounded-full bg-cyber-green block" />
                            </button>
                          ) : (
                            <span className="w-2 h-2 rounded-full bg-white/10 block my-1" />
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Footer */}
              <div className="px-4 py-2.5 bg-black/30 border-t border-white/[0.06] flex items-center justify-between text-[11px] text-cyber-muted">
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-green inline-block" />
                  Live security feed
                </span>
                {onNavigate && (
                  <button
                    type="button"
                    onClick={() => {
                      onNavigate('shared');
                      setIsOpen(false);
                    }}
                    className="text-cyber-accent hover:underline flex items-center gap-1 font-mono"
                  >
                    View shared files <ExternalLink className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* User avatar */}
        <div className="flex items-center gap-3 pl-3 border-l border-white/[0.06]">
          <div className="w-9 h-9 rounded-full bg-gradient-to-br from-cyber-violet to-cyber-accent
                          flex items-center justify-center text-sm font-bold text-white shadow-lg">
            {(user?.email || 'U')[0].toUpperCase()}
          </div>
          <div className="hidden sm:block">
            <div className="flex items-center gap-1.5">
              <p className="text-sm font-medium text-white leading-tight">
                {user?.email || 'User'}
              </p>
              {(user?.is_admin || user?.role === 'admin') && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/30 font-mono">
                  ADMIN
                </span>
              )}
            </div>
            <p className="text-[11px] text-cyber-muted leading-tight">Secure account</p>
          </div>
        </div>
      </div>
    </header>
  );
}
