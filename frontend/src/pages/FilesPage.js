// =============================================================================
// pages/FilesPage.js — File listing with download & decryption
// =============================================================================
import { useState } from 'react';
import {
  Files, Download, Lock, Eye, EyeOff, Loader2,
  LayoutGrid, List, Search, Calendar, HardDrive,
  ShieldCheck, RefreshCw, FolderOpen,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { downloadEncryptedFile } from '../services/api';
import { decryptFile } from '../services/crypto';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function getFileIcon(filename) {
  const ext = filename.split('.').pop()?.toLowerCase();
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

export default function FilesPage({ files, loading, token, onRefresh, setActivePage }) {
  const [viewMode, setViewMode] = useState('list'); // list | grid
  const [search, setSearch] = useState('');
  const [downloadingId, setDownloadingId] = useState(null);
  // Per-file password modal
  const [showPwModal, setShowPwModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [downloadPw, setDownloadPw] = useState('');
  const [pwVisible, setPwVisible] = useState(false);


  const filtered = (files || []).filter((f) =>
    (f.filename || '').toLowerCase().includes(search.toLowerCase())
  );

  // ---------------------------------------------------------------------------
  // Password modal handlers
  // ---------------------------------------------------------------------------
  const openPwModal = (file) => {
    setSelectedFile(file);
    setDownloadPw('');
    setShowPwModal(true);
  };

  const closePwModal = () => {
    setShowPwModal(false);
    setSelectedFile(null);
    setDownloadPw('');
  };

  const confirmDownload = async () => {
    if (!selectedFile || !downloadPw) {
      toast.error('Enter file password');
      return;
    }

    closePwModal();
    await handleSecureDownload(selectedFile, downloadPw);
  };

  // ---------------------------------------------------------------------------
  // Secure download & decrypt (with server pw check)
  // ---------------------------------------------------------------------------
  const handleSecureDownload = async (fileEntry, password) => {
    setDownloadingId(fileEntry.id);
    try {
      // 1. POST password to server for validation & file stream
      const { encryptedBytes, iv, salt, mimeType } = await downloadEncryptedFile(
        token,
        fileEntry.id,
        password
      );

      // 2. Decrypt in browser (same pw used for file encryption)
      const plainBuffer = await decryptFile(
        encryptedBytes,
        password,
        iv || fileEntry.iv,
        salt || fileEntry.salt
      );

      // 3. Trigger download
      const blob = new Blob([plainBuffer], { type: mimeType || fileEntry.mime_type });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileEntry.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      toast.success(`"${fileEntry.filename}" downloaded & decrypted!`);
    } catch (err) {
      console.error(err);
      if (err.status === 401 && err.data?.code === 'token_expired') {
        toast.error('Session expired. Please login again.');
      } else if (err.status === 401 && err.message.includes('Incorrect password')) {
        toast.error('Wrong file password');
      } else if (err.message.includes('Decryption failed')) {
        toast.error('Decryption failed — password mismatch');
      } else {
        toast.error(`Download error: ${err.message}`);
      }
    } finally {
      setDownloadingId(null);
    }
  };

  // Legacy download button handler (opens modal)
  const handleDownload = (fileEntry) => {
    openPwModal(fileEntry);
  };


  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="page-enter space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">My Files</h1>
          <p className="text-sm text-cyber-muted">
            {filtered.length} encrypted file{filtered.length !== 1 ? 's' : ''} in your vault
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={onRefresh} className="btn-ghost text-xs py-2 px-3">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <button
            onClick={() => setActivePage('upload')}
            className="btn-primary text-xs py-2 px-3"
          >
            Upload new
          </button>
        </div>
      </div>

      {/* Search + view toggle + decrypt password */}
      <div className="glass p-4 space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search files..."
              className="input-field pl-10 py-2.5 text-sm"
            />
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
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Note: Per-file passwords now prompted on download */}
        <div className="flex items-center gap-3 p-3 bg-cyber-border/50 rounded-xl text-sm text-cyber-muted">
          <Lock className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>🔐 File-specific passwords required on download (server-validated)</span>
        </div>

      </div>

      {/* File list */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-20">
          <Loader2 className="w-8 h-8 text-cyber-accent animate-spin mb-3" />
          <p className="text-sm text-cyber-muted">Loading your files...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass text-center py-16 px-6">
          <FolderOpen className="w-16 h-16 text-white/10 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">
            {search ? 'No matching files' : 'Your vault is empty'}
          </h3>
          <p className="text-sm text-cyber-muted mb-4">
            {search
              ? 'Try a different search term'
              : 'Upload files to start securing them with AES-256 encryption'}
          </p>
          {!search && (
            <button
              onClick={() => setActivePage('upload')}
              className="btn-primary text-sm"
            >
              Upload first file
            </button>
          )}
        </div>
      ) : viewMode === 'list' ? (
        /* ---- List view ---- */
        <div className="glass overflow-hidden">
          {/* Table header */}
          <div className="hidden sm:grid grid-cols-12 gap-4 px-5 py-3
                          border-b border-white/[0.05] text-xs text-cyber-muted
                          font-medium uppercase tracking-wider">
            <div className="col-span-5">File</div>
            <div className="col-span-2">Size</div>
            <div className="col-span-3">Date</div>
            <div className="col-span-2 text-right">Actions</div>
          </div>

          {/* Rows */}
          <div className="divide-y divide-white/[0.04]">
            {filtered.map((f, idx) => (
              <div
                key={f.id}
                className="grid grid-cols-1 sm:grid-cols-12 gap-2 sm:gap-4 items-center
                           px-5 py-4 hover:bg-white/[0.02] transition-colors
                           animate-slide-up"
                style={{ animationDelay: `${idx * 40}ms` }}
              >
                {/* File name */}
                <div className="sm:col-span-5 flex items-center gap-3 min-w-0">
                  <span className="text-xl flex-shrink-0">{getFileIcon(f.filename)}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-white truncate">{f.filename}</p>
                    <div className="flex items-center gap-1.5 sm:hidden text-[11px] text-cyber-muted mt-0.5">
                      <span>{formatBytes(f.size)}</span>
                      <span>·</span>
                      <span>{new Date(f.upload_date).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>

                {/* Size */}
                <div className="hidden sm:flex sm:col-span-2 items-center gap-1.5 text-sm text-cyber-muted">
                  <HardDrive className="w-3.5 h-3.5" />
                  {formatBytes(f.size)}
                </div>

                {/* Date */}
                <div className="hidden sm:flex sm:col-span-3 items-center gap-1.5 text-sm text-cyber-muted">
                  <Calendar className="w-3.5 h-3.5" />
                  {new Date(f.upload_date).toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric',
                  })}
                </div>

                {/* Download button */}
                <div className="sm:col-span-2 flex justify-end">
                  <button
                    onClick={() => handleDownload(f)}
                    disabled={downloadingId === f.id}
                    className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
                    title="Password protected"
                  >
                    {downloadingId === f.id ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5" />
                        <Lock className="w-3 h-3 text-amber-400" />
                      </>
                    )}
                    {downloadingId === f.id ? 'Decrypting' : 'Secure Download'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

      ) : (
        /* ---- Grid view ---- */
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((f, idx) => (
            <div
              key={f.id}
              className="glass glass-hover p-5 space-y-4 animate-slide-up"
              style={{ animationDelay: `${idx * 60}ms` }}
            >
              <div className="flex items-start justify-between">
                <span className="text-3xl">{getFileIcon(f.filename)}</span>
                <span className="text-[10px] text-cyber-green font-mono
                                 bg-cyber-green/10 px-2 py-0.5 rounded-md
                                 flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3" /> Encrypted
                </span>
              </div>
              <div>
                <p className="text-sm font-semibold text-white truncate" title={f.filename}>
                  {f.filename}
                </p>
                <p className="text-xs text-cyber-muted mt-1">
                  {formatBytes(f.size)} · {new Date(f.upload_date).toLocaleDateString()}
                </p>
              </div>
              <button
                onClick={() => handleDownload(f)}
                disabled={downloadingId === f.id}
                className="btn-ghost w-full text-xs py-2 flex items-center gap-1.5"
                title="Password protected"
              >
                {downloadingId === f.id ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    Decrypting...
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" />
                    <Lock className="w-3 h-3 text-amber-400" />
                    Secure Download
                  </>
                )}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Password Modal */}
      {showPwModal && selectedFile && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-slide-down">
          <div className="glass max-w-md w-full max-h-[90vh] overflow-y-auto rounded-2xl p-8 space-y-6">
            <div className="text-center">
              <Lock className="w-16 h-16 text-amber-400 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">Unlock File</h2>
              <p className="text-cyber-muted">
                Enter the password for <strong>{selectedFile.filename}</strong>
              </p>
            </div>

            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-amber-400" />
              <input
                ref={(input) => input && input.focus()}
                type={pwVisible ? 'text' : 'password'}
                value={downloadPw}
                onChange={(e) => setDownloadPw(e.target.value)}
                placeholder="File password"
                className="input-field pl-12 pr-12 py-3 w-full text-lg"
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => setPwVisible(!pwVisible)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-white p-1 rounded-full transition-all"
              >
                {pwVisible ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={closePwModal}
                className="flex-1 btn-ghost"
              >
                Cancel
              </button>
              <button
                onClick={confirmDownload}
                disabled={!downloadPw.trim()}
                className="flex-1 btn-primary disabled:opacity-50"
              >
                Unlock & Download
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
