// =============================================================================
// pages/SharedPage.js — View & Decrypt Files Shared With Me (Phase 9)
// ZERO-KNOWLEDGE: Recipient unprotects private key and unwraps AES key client-side.
// =============================================================================
import { useState, useEffect } from 'react';
import {
  Share2, Download, Lock, Eye, EyeOff, Loader2,
  LayoutGrid, List, Search, Calendar, HardDrive,
  ShieldCheck, RefreshCw, FolderOpen, AlertTriangle, X,
  User, Info, Key, ShieldAlert,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { getReceivedShares, downloadSharedFile, getMyKeys } from '../services/api';
import { unprotectPrivateKey, unwrapDataKey } from '../services/rsa';
import { decryptWithDataKey } from '../services/crypto';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatDate(dateStr, options) {
  if (!dateStr) return 'No expiry';
  try {
    const d = new Date(dateStr);
    return isNaN(d.getTime())
      ? 'No expiry'
      : d.toLocaleDateString('en-US', options || { month: 'short', day: 'numeric', year: 'numeric' });
  } catch {
    return 'No expiry';
  }
}

function getFileIcon(filename) {
  const ext = filename?.split('.').pop()?.toLowerCase();
  const icons = {
    pdf: '📄', doc: '📝', docx: '📝', xls: '📊', xlsx: '📊',
    png: '🖼️', jpg: '🖼️', jpeg: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️',
    mp4: '🎬', mov: '🎬', avi: '🎬', mp3: '🎵', wav: '🎵',
    zip: '📦', rar: '📦', '7z': '📦', tar: '📦',
    js: '⚡', py: '🐍', html: '🌐', css: '🎨',
    txt: '📃', md: '📃', json: '📃',
  };
  return icons[ext] || '📁';
}

export default function SharedPage({ token, user, onSessionExpired }) {
  const [shares, setShares] = useState([]);
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState('list');
  const [search, setSearch] = useState('');
  const [downloadingId, setDownloadingId] = useState(null);

  // Decryption password modal
  const [showPwModal, setShowPwModal] = useState(false);
  const [selectedShare, setSelectedShare] = useState(null);
  const [decryptPw, setDecryptPw] = useState('');
  const [pwVisible, setPwVisible] = useState(false);

  // View details modal
  const [viewModalShare, setViewModalShare] = useState(null);

  const loadShares = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await getReceivedShares(token);
      if (res.ok) {
        setShares(res.data?.shares || []);
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else {
        toast.error(res.data?.msg || 'Failed to load shared files');
      }
    } catch (err) {
      console.error(err);
      toast.error('Network error loading shared files');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadShares();
  }, [token]);

  // Dismiss modals on Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        if (showPwModal) closePwModal();
        if (viewModalShare) setViewModalShare(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showPwModal, viewModalShare]);

  const filtered = (shares || []).filter((s) =>
    (s.filename || '').toLowerCase().includes(search.toLowerCase()) ||
    (s.owner_email || '').toLowerCase().includes(search.toLowerCase())
  );

  const openPwModal = (share) => {
    setSelectedShare(share);
    setDecryptPw('');
    setPwVisible(false);
    setShowPwModal(true);
  };

  const closePwModal = () => {
    setShowPwModal(false);
    setSelectedShare(null);
    setDecryptPw('');
  };

  /**
   * Handle Secure Decrypt & Download of Shared File
   * ZERO-KNOWLEDGE:
   *   1. Recipient password unprotects recipient's private key in browser.
   *   2. Server delivers ciphertext and recipient's specific wrapped AES key.
   *   3. Recipient unwraps the AES data key client-side.
   *   4. Decrypts file in memory and verifies SHA-256 integrity hash.
   */
  const confirmDownload = async () => {
    if (!selectedShare || !decryptPw) {
      toast.error('Enter your account password to decrypt the file');
      return;
    }

    const share = selectedShare;
    const password = decryptPw;
    closePwModal();
    setDownloadingId(share.id);

    try {
      // 1. Fetch recipient's protected private key from /keys/me
      const keyRes = await getMyKeys(token);
      if (keyRes.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
        return;
      }
      if (!keyRes.ok || !keyRes.data?.encrypted_private_key) {
        throw new Error(keyRes.data?.msg || 'No registered private key found for your account. Please check your key settings.');
      }

      // Check RSA key fingerprint match before decapsulation
      const myFp = keyRes.data.fingerprint;
      const shareFp = share.key_fingerprint;
      if (shareFp && myFp) {
        const normShareFp = shareFp.replace(/^SHA256:/i, '').replace(/:/g, '').toUpperCase();
        const normMyFp = myFp.replace(/^SHA256:/i, '').replace(/:/g, '').toUpperCase();
        if (normShareFp !== normMyFp) {
          toast.error('RSA key fingerprint mismatch: this share was encrypted for a different key');
          return;
        }
      }

      // 2. Unprotect private key client-side with user password
      let privateKey;
      try {
        privateKey = await unprotectPrivateKey(
          {
            encrypted_private_key: keyRes.data.encrypted_private_key,
            iv: keyRes.data.iv,
            salt: keyRes.data.salt,
            integrity_hash: keyRes.data.integrity_hash,
          },
          password
        );
      } catch {
        toast.error('Incorrect password — could not unlock your private key');
        return;
      }

      // 3. Download encrypted bytes and recipient-wrapped key from backend
      const {
        encryptedBytes,
        iv,
        wrappedKey,
        mimeType,
        integrityHash,
      } = await downloadSharedFile(token, share.id);

      const targetWrappedKey = wrappedKey || share.wrapped_key;
      if (!targetWrappedKey) {
        throw new Error('Missing wrapped AES key for this share');
      }

      // 4. Unwrap the file's AES data key using recipient's unlocked private key
      let dataKey;
      try {
        dataKey = await unwrapDataKey(targetWrappedKey, privateKey);
      } catch {
        toast.error('Key decapsulation failed: your private key does not match this share');
        return;
      }

      // 5. Decrypt ciphertext using AES-256-GCM and verify integrity hash
      let plainBuffer;
      try {
        plainBuffer = await decryptWithDataKey(
          encryptedBytes,
          dataKey,
          iv || share.iv,
          integrityHash || share.integrity_hash
        );
      } catch (decErr) {
        if (decErr.message && decErr.message.includes('Integrity verification failed')) {
          toast.error('Integrity error: file payload has been tampered with!');
        } else {
          toast.error('Decryption failed: corrupted ciphertext or authentication tag mismatch');
        }
        return;
      }

      // 6. Trigger plaintext browser download
      const blob = new Blob([plainBuffer], { type: mimeType || share.mime_type || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = share.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      toast.success(`"${share.filename}" successfully decrypted & downloaded!`);
      // Refresh share list to update download count
      loadShares();
    } catch (err) {
      console.error(err);
      if (err.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else if (err.status === 403) {
        toast.error(err.message || 'Access denied to this shared file');
        loadShares();
      } else if (err.status === 404) {
        toast.error(err.message || 'Shared file or cloud payload not found');
        loadShares();
      } else if (err.message && err.message.toLowerCase().includes('failed to fetch')) {
        toast.error('Network error: unable to connect to server');
      } else {
        toast.error(`Download error: ${err.message}`);
      }
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="page-enter space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1 flex items-center gap-2">
            <Share2 className="w-6 h-6 text-cyber-accent" />
            Shared With Me
          </h1>
          <p className="text-sm text-cyber-muted">
            {filtered.length} encrypted file{filtered.length !== 1 ? 's' : ''} shared with your account
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadShares}
            disabled={loading}
            className="btn-ghost text-xs py-2 px-3 disabled:opacity-50 flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Search & Info Banner */}
      <div className="glass p-4 space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by file name or owner email..."
              className="input-field pl-10 pr-10 py-2.5 text-sm"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-white p-1"
                title="Clear search"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* View toggle */}
          <div className="flex bg-black/30 rounded-xl p-1 self-start">
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded-lg transition-all ${
                viewMode === 'list'
                  ? 'bg-cyber-accent/15 text-cyber-accent'
                  : 'text-cyber-muted hover:text-white'
              }`}
              title="List view"
            >
              <List className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded-lg transition-all ${
                viewMode === 'grid'
                  ? 'bg-cyber-accent/15 text-cyber-accent'
                  : 'text-cyber-muted hover:text-white'
              }`}
              title="Grid view"
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3 p-3 bg-cyber-border/40 rounded-xl text-xs text-cyber-muted">
          <Key className="w-4 h-4 text-cyber-accent flex-shrink-0" />
          <span>
            Shared files are encrypted with unique AES keys wrapped specifically for your RSA public key.
            Decryption happens strictly in your browser.
          </span>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-20">
          <Loader2 className="w-8 h-8 text-cyber-accent animate-spin mb-3" />
          <p className="text-sm text-cyber-muted">Loading shared files...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass text-center py-16 px-6">
          <FolderOpen className="w-16 h-16 text-white/10 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">
            {search ? 'No matching shared files' : 'No files shared with you yet'}
          </h3>
          <p className="text-sm text-cyber-muted mb-4 max-w-md mx-auto">
            {search
              ? 'Try adjusting your search criteria'
              : 'When other users share files with your email address, they will appear here with zero-knowledge cryptographic access.'}
          </p>
          {search && (
            <button
              onClick={() => setSearch('')}
              className="btn-ghost text-xs py-2 px-4"
            >
              Clear search
            </button>
          )}
        </div>
      ) : viewMode === 'list' ? (
        /* List View */
        <div className="glass overflow-hidden">
          <div className="hidden sm:grid grid-cols-12 gap-4 px-5 py-3 border-b border-white/[0.05] text-xs text-cyber-muted font-medium uppercase tracking-wider">
            <div className="col-span-4">File</div>
            <div className="col-span-3">Shared By</div>
            <div className="col-span-2">Permission</div>
            <div className="col-span-3 text-right">Actions</div>
          </div>

          <div className="divide-y divide-white/[0.04]">
            {filtered.map((s, idx) => {
              const isActive = s.status === 'active';
              const isDownloadAllowed = s.permission === 'download' && isActive;

              return (
                <div
                  key={s.id}
                  className="grid grid-cols-1 sm:grid-cols-12 gap-2 sm:gap-4 items-center px-5 py-4 hover:bg-white/[0.02] transition-colors animate-slide-up"
                  style={{ animationDelay: `${idx * 40}ms` }}
                >
                  {/* File name & size */}
                  <div className="sm:col-span-4 flex items-center gap-3 min-w-0">
                    <span className="text-xl flex-shrink-0">{getFileIcon(s.filename)}</span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">{s.filename}</p>
                      <div className="flex items-center gap-2 text-[11px] text-cyber-muted mt-0.5">
                        <span>{formatBytes(s.size)}</span>
                        <span>·</span>
                        <span>Expires {formatDate(s.expires_at)}</span>
                      </div>
                    </div>
                  </div>

                  {/* Shared By */}
                  <div className="sm:col-span-3 flex items-center gap-1.5 text-xs text-cyber-muted truncate">
                    <User className="w-3.5 h-3.5 text-cyber-accent flex-shrink-0" />
                    <span className="truncate" title={s.owner_email}>{s.owner_email}</span>
                  </div>

                  {/* Permission badge */}
                  <div className="sm:col-span-2 flex items-center gap-1.5">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                        s.permission === 'download'
                          ? 'bg-cyber-accent/15 text-cyber-accent border border-cyber-accent/30'
                          : 'bg-amber-400/15 text-amber-400 border border-amber-400/30'
                      }`}
                    >
                      {s.permission === 'download' ? 'Download' : 'View Only'}
                    </span>
                    {!isActive && (
                      <span className="px-1.5 py-0.2 rounded text-[9px] uppercase font-mono bg-cyber-danger/15 text-cyber-danger">
                        {s.status}
                      </span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="sm:col-span-3 flex items-center gap-2 justify-end">
                    <button
                      onClick={() => setViewModalShare(s)}
                      className="btn-ghost text-xs py-1.5 px-2.5 flex items-center gap-1"
                      title="Inspect share metadata"
                    >
                      <Info className="w-3.5 h-3.5" />
                      <span>Details</span>
                    </button>

                    {isDownloadAllowed ? (
                      <button
                        onClick={() => openPwModal(s)}
                        disabled={downloadingId === s.id}
                        className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
                        title="Download and decrypt file"
                      >
                        {downloadingId === s.id ? (
                          <>
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            <span>Decrypting</span>
                          </>
                        ) : (
                          <>
                            <Download className="w-3.5 h-3.5" />
                            <span>Download</span>
                          </>
                        )}
                      </button>
                    ) : (
                      <span className="text-[11px] text-cyber-muted/60 italic">
                        {s.permission === 'view' ? 'View only' : s.status}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        /* Grid View */
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((s, idx) => {
            const isActive = s.status === 'active';
            const isDownloadAllowed = s.permission === 'download' && isActive;

            return (
              <div
                key={s.id}
                className="glass glass-hover p-5 space-y-4 animate-slide-up flex flex-col justify-between"
                style={{ animationDelay: `${idx * 60}ms` }}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between">
                    <span className="text-3xl">{getFileIcon(s.filename)}</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${
                        s.permission === 'download'
                          ? 'bg-cyber-accent/15 text-cyber-accent border border-cyber-accent/30'
                          : 'bg-amber-400/15 text-amber-400 border border-amber-400/30'
                      }`}
                    >
                      {s.permission}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold text-white truncate" title={s.filename}>
                      {s.filename}
                    </h3>
                    <p className="text-xs text-cyber-muted mt-1">
                      {formatBytes(s.size)} · By <span className="text-white/80">{s.owner_email}</span>
                    </p>
                    <p className="text-[11px] text-cyber-muted/70 mt-1">
                      Expires: {formatDate(s.expires_at)}
                    </p>
                  </div>

                  {s.note && (
                    <p className="text-xs italic text-cyber-muted bg-black/20 p-2 rounded-lg">
                      "{s.note}"
                    </p>
                  )}
                </div>

                <div className="flex gap-2 pt-2 border-t border-white/[0.04]">
                  <button
                    onClick={() => setViewModalShare(s)}
                    className="btn-ghost text-xs py-2 px-3 flex items-center justify-center gap-1"
                  >
                    <Info className="w-3.5 h-3.5" />
                    Details
                  </button>

                  {isDownloadAllowed ? (
                    <button
                      onClick={() => openPwModal(s)}
                      disabled={downloadingId === s.id}
                      className="btn-primary flex-1 text-xs py-2 flex items-center justify-center gap-1.5"
                    >
                      {downloadingId === s.id ? (
                        <>
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          Decrypting...
                        </>
                      ) : (
                        <>
                          <Download className="w-3.5 h-3.5" />
                          Download
                        </>
                      )}
                    </button>
                  ) : (
                    <button disabled className="btn-ghost flex-1 text-xs py-2 opacity-50 cursor-not-allowed">
                      {s.permission === 'view' ? 'View Only' : s.status}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Decrypt & Download Modal */}
      {showPwModal && selectedShare && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) closePwModal(); }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <div className="glass max-w-md w-full rounded-2xl p-8 space-y-6">
            <div className="text-center">
              <Lock className="w-14 h-14 text-cyber-accent mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">Decrypt Shared File</h2>
              <p className="text-cyber-muted text-sm">
                Enter your account password to unlock your RSA private key and decrypt{' '}
                <strong className="text-white">{selectedShare.filename}</strong>
              </p>
              <p className="text-xs text-cyber-muted/70 mt-2">
                Decryption takes place entirely in your browser using Web Crypto RSA-OAEP and AES-GCM.
              </p>
            </div>

            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-cyber-accent" />
              <input
                ref={(input) => input && input.focus()}
                type={pwVisible ? 'text' : 'password'}
                value={decryptPw}
                onChange={(e) => setDecryptPw(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && decryptPw.trim() && confirmDownload()}
                placeholder="Your account password"
                className="input-field pl-12 pr-12 py-3 w-full text-base"
                autoComplete="off"
              />
              <button
                type="button"
                onClick={() => setPwVisible(!pwVisible)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-white p-1 rounded-full transition-all"
              >
                {pwVisible ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>

            <div className="flex gap-3">
              <button onClick={closePwModal} className="flex-1 btn-ghost">
                Cancel
              </button>
              <button
                onClick={confirmDownload}
                disabled={!decryptPw.trim()}
                className="flex-1 btn-primary disabled:opacity-50"
              >
                Decrypt &amp; Download
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Details Modal */}
      {viewModalShare && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) setViewModalShare(null); }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <div className="glass max-w-lg w-full rounded-2xl p-6 sm:p-8 space-y-5">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-cyber-accent/15 text-cyber-accent">
                  <Info className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Share Details</h2>
                  <p className="text-xs text-cyber-muted truncate max-w-xs">
                    {viewModalShare.filename}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setViewModalShare(null)}
                className="text-cyber-muted hover:text-white p-1 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 bg-black/30 p-4 rounded-xl text-xs space-y-2">
              <div className="flex justify-between">
                <span className="text-cyber-muted">Owner / Shared By:</span>
                <span className="font-semibold text-white">{viewModalShare.owner_email}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-cyber-muted">File Size:</span>
                <span className="font-semibold text-white">{formatBytes(viewModalShare.size)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-cyber-muted">MIME Type:</span>
                <span className="font-mono text-white/80">{viewModalShare.mime_type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-cyber-muted">Permission:</span>
                <span className="font-semibold uppercase text-cyber-accent">{viewModalShare.permission}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-cyber-muted">Status:</span>
                <span className="font-semibold uppercase text-cyber-green">{viewModalShare.status}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-cyber-muted">Quota Remaining:</span>
                <span className="font-semibold text-white">{viewModalShare.downloads_remaining || 'N/A'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-cyber-muted">Expires:</span>
                <span className="font-semibold text-white">{formatDate(viewModalShare.expires_at)}</span>
              </div>
              {viewModalShare.note && (
                <div className="pt-2 border-t border-white/[0.04]">
                  <span className="text-cyber-muted block mb-1">Note from Owner:</span>
                  <p className="italic text-white bg-black/40 p-2 rounded">{viewModalShare.note}</p>
                </div>
              )}
            </div>

            {viewModalShare.permission === 'view' && (
              <div className="p-3 bg-amber-400/10 border border-amber-400/20 rounded-xl text-xs text-amber-300">
                ⚠️ This file has view-only permissions. You can inspect its metadata, but download access has not been granted.
              </div>
            )}

            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => setViewModalShare(null)}
                className="btn-ghost text-xs py-2 px-4"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
