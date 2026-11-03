// =============================================================================
// pages/FilesPage.js — File listing with download, decryption & deletion
// ZERO-KNOWLEDGE: Password is used only for local AES-256-GCM decryption.
// =============================================================================
import { useState, useEffect } from 'react';
import {
  Files, Download, Lock, Eye, EyeOff, Loader2,
  LayoutGrid, List, Search, Calendar, HardDrive,
  ShieldCheck, RefreshCw, FolderOpen, Trash2, AlertTriangle, X,
  Share2, Copy, Check, Key, Clock, ShieldAlert,
  Users, Link2, User,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  downloadEncryptedFile,
  deleteFile,
  getMyKeys,
  getUserPublicKey,
  createAccessToken,
  getFileAccessTokens,
  revokeAccessToken,
  createFileShare,
  getFileShares,
  revokeFileShare,
} from '../services/api';
import { decryptFile, deriveKey } from '../services/crypto';
import { unprotectPrivateKey, hybridDecryptFile, unwrapDataKey, wrapDataKey, verifyPublicKeyFingerprint } from '../services/rsa';
import { extractTextFromFile, scanPii } from '../services/pii';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatDate(dateStr, options) {
  if (!dateStr) return 'Recently';
  try {
    const d = new Date(dateStr);
    return isNaN(d.getTime())
      ? 'Recently'
      : d.toLocaleDateString('en-US', options || { month: 'short', day: 'numeric', year: 'numeric' });
  } catch {
    return 'Recently';
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

export default function FilesPage({ files, loading, token, user, onRefresh, setActivePage, onSessionExpired }) {
  const [viewMode, setViewMode] = useState('list');
  const [search, setSearch] = useState('');
  const [downloadingId, setDownloadingId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  // Download password modal state
  const [showPwModal, setShowPwModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [downloadPw, setDownloadPw] = useState('');
  const [pwVisible, setPwVisible] = useState(false);

  // Delete confirmation modal state
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [fileToDelete, setFileToDelete] = useState(null);

  // Access token modal state (Phase 8)
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [fileForTokens, setFileForTokens] = useState(null);
  const [fileTokens, setFileTokens] = useState([]);
  const [loadingTokens, setLoadingTokens] = useState(false);
  const [creatingToken, setCreatingToken] = useState(false);
  const [revokingTokenId, setRevokingTokenId] = useState(null);
  const [tokenExpiry, setTokenExpiry] = useState(86400); // 24 hours
  const [tokenMaxDownloads, setTokenMaxDownloads] = useState(1); // single-use default
  const [tokenScope, setTokenScope] = useState('download');
  const [tokenLabel, setTokenLabel] = useState('');
  const [newlyCreatedToken, setNewlyCreatedToken] = useState(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);

  // Phase 9: Secure File Sharing state
  const [shareTab, setShareTab] = useState('user'); // 'user' | 'token'
  const [recipientEmail, setRecipientEmail] = useState('');
  const [shareOwnerPassword, setShareOwnerPassword] = useState('');
  const [shareOwnerPwVisible, setShareOwnerPwVisible] = useState(false);
  const [sharePermission, setSharePermission] = useState('download');
  const [shareNote, setShareNote] = useState('');
  const [sharingUser, setSharingUser] = useState(false);
  const [fileShares, setFileShares] = useState([]);
  const [loadingShares, setLoadingShares] = useState(false);
  const [revokingShareId, setRevokingShareId] = useState(null);

  // Phase 10: Client-Side Privacy Pre-Check State
  const [isScanningPiiForShare, setIsScanningPiiForShare] = useState(false);
  const [piiScanResult, setPiiScanResult] = useState(null);

  // Dismiss modals on Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        if (showPwModal) closePwModal();
        if (showDeleteModal) closeDeleteModal();
        if (showTokenModal) closeTokenModal();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showPwModal, showDeleteModal, showTokenModal]);

  const filtered = (files || []).filter((f) =>
    (f.filename || '').toLowerCase().includes(search.toLowerCase())
  );

  // ---------------------------------------------------------------------------
  // Download — password modal
  // ---------------------------------------------------------------------------
  const openPwModal = (file) => {
    setSelectedFile(file);
    setDownloadPw('');
    setPwVisible(false);
    setShowPwModal(true);
  };

  const closePwModal = () => {
    setShowPwModal(false);
    setSelectedFile(null);
    setDownloadPw('');
  };

  const confirmDownload = async () => {
    if (!selectedFile || !downloadPw) {
      toast.error('Enter the file encryption password');
      return;
    }
    closePwModal();
    await handleSecureDownload(selectedFile, downloadPw);
  };

  /**
   * Secure download & client-side decrypt.
   * ZERO-KNOWLEDGE: password is used only in browser to run AES-256-GCM.
   * The server receives only the JWT; it never sees the password.
   */
  const handleSecureDownload = async (fileEntry, password) => {
    setDownloadingId(fileEntry.id);
    try {
      // 1. GET encrypted bytes and cryptographic metadata from server (no password sent)
      const {
        encryptedBytes,
        iv,
        salt,
        mimeType,
        integrityHash,
        wrappedKey,
        keyFingerprint,
      } = await downloadEncryptedFile(token, fileEntry.id);

      // 2. Decrypt in browser with the user-supplied password and verify integrity
      let plainBuffer;
      try {
        const fileWrappedKey = wrappedKey || fileEntry.wrapped_key;

        if (fileWrappedKey) {
          // Hybrid Encryption flow: unprotect private key, unwrap AES data key, decrypt file
          const keyRes = await getMyKeys(token);
          if (!keyRes.ok || !keyRes.data?.encrypted_private_key) {
            throw new Error('No registered private key found to decrypt this hybrid encrypted file');
          }

          const privateKey = await unprotectPrivateKey(
            {
              encrypted_private_key: keyRes.data.encrypted_private_key,
              iv: keyRes.data.iv,
              salt: keyRes.data.salt,
              integrity_hash: keyRes.data.integrity_hash,
            },
            password
          );

          plainBuffer = await hybridDecryptFile(
            encryptedBytes,
            fileWrappedKey,
            privateKey,
            iv || fileEntry.iv,
            integrityHash || fileEntry.integrity_hash
          );
        } else {
          // Backwards compatibility: Phase 5 password-based AES-256-GCM
          plainBuffer = await decryptFile(
            encryptedBytes,
            password,
            iv || fileEntry.iv,
            salt || fileEntry.salt,
            integrityHash || fileEntry.integrity_hash
          );
        }
      } catch (decErr) {
        if (decErr.message && decErr.message.includes('Integrity verification failed')) {
          toast.error('File integrity verification failed: decrypted content has been tampered with!');
        } else {
          toast.error('Decryption failed — wrong password or corrupted file');
        }
        return;
      }

      // 3. Trigger browser download of plaintext
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
      if (err.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else if (err.status === 403) {
        toast.error('Access denied to this file.');
      } else {
        toast.error(`Download error: ${err.message}`);
      }
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDownload = (fileEntry) => {
    openPwModal(fileEntry);
  };

  // ---------------------------------------------------------------------------
  // Delete — confirmation modal
  // ---------------------------------------------------------------------------
  const openDeleteModal = (file) => {
    setFileToDelete(file);
    setShowDeleteModal(true);
  };

  const closeDeleteModal = () => {
    setShowDeleteModal(false);
    setFileToDelete(null);
  };

  const confirmDelete = async () => {
    if (!fileToDelete) return;
    const target = fileToDelete;
    closeDeleteModal();

    setDeletingId(target.id);
    try {
      const res = await deleteFile(token, target.id);
      if (res.ok) {
        toast.success(`"${target.filename}" deleted successfully`);
        onRefresh?.();
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else if (res.status === 403) {
        toast.error('Permission denied — cannot delete this file');
      } else {
        toast.error(res.data?.msg || 'Failed to delete file');
      }
    } catch (err) {
      toast.error('Delete failed: network error');
      console.error(err);
    } finally {
      setDeletingId(null);
    }
  };

  // ---------------------------------------------------------------------------
  // Access Tokens (Phase 8) & File Sharing (Phase 9) — Modal & Management
  // ---------------------------------------------------------------------------
  const openTokenModal = (file) => {
    setFileForTokens(file);
    setShareTab('user'); // Default to Phase 9 User Sharing
    setNewlyCreatedToken(null);
    setCopiedToken(false);
    setCopiedLink(false);
    setRecipientEmail('');
    setShareOwnerPassword('');
    setShareOwnerPwVisible(false);
    setShareNote('');
    setSharePermission('download');
    setTokenLabel('');
    setTokenExpiry(86400);
    setTokenMaxDownloads(1);
    setTokenScope('download');
    setPiiScanResult(null);
    setIsScanningPiiForShare(false);
    setShowTokenModal(true);
    loadTokensForFile(file.id);
    loadSharesForFile(file.id);
  };

  const closeTokenModal = () => {
    setShowTokenModal(false);
    setFileForTokens(null);
    setNewlyCreatedToken(null);
    setFileTokens([]);
    setFileShares([]);
    setRecipientEmail('');
    setShareOwnerPassword('');
    setPiiScanResult(null);
    setIsScanningPiiForShare(false);
  };

  const handleScanPiiBeforeShare = async () => {
    if (!fileForTokens) return;
    if (!shareOwnerPassword) {
      toast.error('Enter your master password above to decrypt the file locally for PII scanning');
      return;
    }

    setIsScanningPiiForShare(true);
    setPiiScanResult(null);

    try {
      // 1. Download encrypted ciphertext from server
      const downloadData = await downloadEncryptedFile(token, fileForTokens.id);
      const { encryptedBytes, iv, salt, wrappedKey, integrityHash, isLegacy } = downloadData;

      // 2. Decrypt file client-side (Zero-Knowledge)
      let plainBuffer;
      if (!isLegacy && wrappedKey) {
        const myKeyRes = await getMyKeys(token);
        if (myKeyRes.status === 401) {
          toast.error('Session expired. Please login again.');
          onSessionExpired?.();
          return;
        }
        if (!myKeyRes.ok || !myKeyRes.data?.encrypted_private_key) {
          throw new Error('No registered private key found for your account');
        }
        const privateKey = await unprotectPrivateKey(
          {
            encrypted_private_key: myKeyRes.data.encrypted_private_key,
            iv: myKeyRes.data.iv,
            salt: myKeyRes.data.salt,
            integrity_hash: myKeyRes.data.integrity_hash,
          },
          shareOwnerPassword
        );
        plainBuffer = await hybridDecryptFile(
          encryptedBytes,
          wrappedKey,
          privateKey,
          iv || fileForTokens.iv,
          integrityHash || fileForTokens.integrity_hash
        );
      } else {
        plainBuffer = await decryptFile(
          encryptedBytes,
          shareOwnerPassword,
          iv || fileForTokens.iv,
          salt || fileForTokens.salt,
          integrityHash || fileForTokens.integrity_hash
        );
      }

      // 3. Extract text from decrypted payload
      const mockFile = {
        name: fileForTokens.filename,
        size: plainBuffer.byteLength,
        arrayBuffer: async () => plainBuffer,
      };

      const extractRes = await extractTextFromFile(mockFile);
      if (!extractRes.supported) {
        setPiiScanResult({
          supported: false,
          isScannedPdf: extractRes.isScannedPdf,
          reason: extractRes.reason,
        });
        toast.error(extractRes.reason || 'Document format unsupported for PII extraction');
        return;
      }

      // 4. Run PII scan
      const scan = scanPii(extractRes.text);
      setPiiScanResult({
        supported: true,
        scan,
      });

      if (scan.totalCount > 0) {
        toast.error(`Privacy Warning: Found ${scan.totalCount} sensitive PII item(s) in this file!`, { duration: 4000 });
      } else {
        toast.success('Privacy Check Passed: 0 sensitive items detected in file!');
      }
    } catch (err) {
      console.error(err);
      if (err.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else if (err.message && err.message.toLowerCase().includes('decryption failed')) {
        toast.error('Incorrect password — could not decrypt file for PII scanning');
      } else {
        toast.error(`Privacy check failed: ${err.message || 'Decryption error'}`);
      }
    } finally {
      setIsScanningPiiForShare(false);
    }
  };

  const loadSharesForFile = async (fileId) => {
    setLoadingShares(true);
    try {
      const res = await getFileShares(token, fileId);
      if (res.ok) {
        setFileShares(res.data?.shares || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingShares(false);
    }
  };

  const handleShareWithUser = async () => {
    if (!fileForTokens || !recipientEmail.trim()) {
      toast.error('Enter recipient email');
      return;
    }
    const cleanEmail = recipientEmail.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      toast.error('Please enter a valid recipient email address');
      return;
    }

    // Prevent sharing with oneself
    let currentEmail = (user?.email || '').trim().toLowerCase();
    if (!currentEmail) {
      try {
        const savedUser = localStorage.getItem('sc_user');
        if (savedUser) {
          currentEmail = JSON.parse(savedUser)?.email?.trim()?.toLowerCase() || '';
        }
      } catch {}
    }
    if (!currentEmail && fileForTokens?.user_email) {
      currentEmail = fileForTokens.user_email.trim().toLowerCase();
    }
    if (currentEmail && cleanEmail === currentEmail) {
      toast.error('Cannot share a file with yourself');
      return;
    }

    if (!shareOwnerPassword) {
      toast.error('Enter your file password to unwrap the AES key');
      return;
    }

    setSharingUser(true);
    try {
      // 1. Lookup recipient's registered public key
      const recipRes = await getUserPublicKey(token, cleanEmail);
      if (recipRes.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
        return;
      }
      if (!recipRes.ok || !recipRes.data?.public_key) {
        throw new Error(recipRes.data?.msg || 'Recipient has not registered an RSA public key');
      }

      const recipientPubKey = recipRes.data.public_key;
      const recipientFp = recipRes.data.fingerprint;

      // Cryptographic verification: verify public key fingerprint match to prevent substitution
      if (recipientFp) {
        const isFpValid = await verifyPublicKeyFingerprint(recipientFp, recipientPubKey);
        if (!isFpValid) {
          throw new Error('Recipient RSA public key fingerprint mismatch — key substitution detected');
        }
      }

      // 2. Client-side key unwrapping
      let dataKey;
      if (fileForTokens.wrapped_key) {
        // Hybrid file: unprotect owner's private key and unwrap AES key
        const myKeyRes = await getMyKeys(token);
        if (myKeyRes.status === 401) {
          toast.error('Session expired. Please login again.');
          onSessionExpired?.();
          return;
        }
        if (!myKeyRes.ok || !myKeyRes.data?.encrypted_private_key) {
          throw new Error('No registered private key found for your account');
        }

        const ownerPrivateKey = await unprotectPrivateKey(
          {
            encrypted_private_key: myKeyRes.data.encrypted_private_key,
            iv: myKeyRes.data.iv,
            salt: myKeyRes.data.salt,
            integrity_hash: myKeyRes.data.integrity_hash,
          },
          shareOwnerPassword
        );

        dataKey = await unwrapDataKey(fileForTokens.wrapped_key, ownerPrivateKey);
      } else {
        // Legacy file: derive key with password & salt
        dataKey = await deriveKey(shareOwnerPassword, fileForTokens.salt);
      }

      // 3. Wrap the file's existing AES data key using recipient's public key
      const wrapResult = await wrapDataKey(dataKey, recipientPubKey);

      // 4. Submit to backend
      const res = await createFileShare(token, {
        file_id: fileForTokens.id,
        recipient_email: cleanEmail,
        wrapped_key: wrapResult.wrappedKeyB64,
        key_fingerprint: recipientFp,
        permission: sharePermission,
        expires_in_seconds: Number(tokenExpiry),
        max_downloads: Number(tokenMaxDownloads),
        note: shareNote.trim(),
      });

      if (res.ok) {
        toast.success(`File shared with ${cleanEmail}!`);
        setRecipientEmail('');
        setShareNote('');
        loadSharesForFile(fileForTokens.id);
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else {
        const errorDetail = (res.data?.errors && res.data.errors.length > 0)
          ? res.data.errors[0].replace(/^Share item #\d+:\s*/, '')
          : (res.data?.msg || 'Failed to share file');
        toast.error(errorDetail);
      }
    } catch (err) {
      console.error(err);
      if (err.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else if (err.message && err.message.toLowerCase().includes('decryption failed')) {
        toast.error('Incorrect account password — could not unlock your private key');
      } else {
        toast.error(err.message || 'Error sharing file');
      }
    } finally {
      setSharingUser(false);
    }
  };

  const handleRevokeShare = async (shareId) => {
    setRevokingShareId(shareId);
    try {
      const res = await revokeFileShare(token, shareId);
      if (res.ok) {
        toast.success('Share revoked successfully');
        if (fileForTokens) loadSharesForFile(fileForTokens.id);
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else {
        toast.error(res.data?.msg || 'Failed to revoke share');
      }
    } catch (err) {
      console.error(err);
      toast.error('Error revoking share');
    } finally {
      setRevokingShareId(null);
    }
  };

  const loadTokensForFile = async (fileId) => {
    setLoadingTokens(true);
    try {
      const res = await getFileAccessTokens(token, fileId);
      if (res.ok) {
        setFileTokens(res.data?.tokens || []);
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else {
        toast.error(res.data?.msg || 'Failed to load tokens');
      }
    } catch (err) {
      console.error(err);
      toast.error('Network error loading access tokens');
    } finally {
      setLoadingTokens(false);
    }
  };

  const handleCreateToken = async () => {
    if (!fileForTokens) return;
    setCreatingToken(true);
    try {
      const res = await createAccessToken(token, fileForTokens.id, {
        expiresInSeconds: Number(tokenExpiry),
        maxDownloads: Number(tokenMaxDownloads),
        scope: tokenScope,
        label: tokenLabel.trim(),
      });

      if (res.ok && res.data?.token) {
        setNewlyCreatedToken(res.data.token);
        toast.success('Access token generated successfully!');
        loadTokensForFile(fileForTokens.id);
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else {
        toast.error(res.data?.msg || 'Failed to generate token');
      }
    } catch (err) {
      console.error(err);
      toast.error(err.message || 'Error generating token');
    } finally {
      setCreatingToken(false);
    }
  };

  const handleRevokeToken = async (tokenId) => {
    setRevokingTokenId(tokenId);
    try {
      const res = await revokeAccessToken(token, tokenId);
      if (res.ok) {
        toast.success('Access token revoked immediately');
        if (fileForTokens) {
          loadTokensForFile(fileForTokens.id);
        }
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else {
        toast.error(res.data?.msg || 'Failed to revoke token');
      }
    } catch (err) {
      console.error(err);
      toast.error('Error revoking token');
    } finally {
      setRevokingTokenId(null);
    }
  };

  const copyToClipboard = async (text, type = 'token') => {
    try {
      await navigator.clipboard.writeText(text);
      if (type === 'token') {
        setCopiedToken(true);
        setTimeout(() => setCopiedToken(false), 2500);
      } else {
        setCopiedLink(true);
        setTimeout(() => setCopiedLink(false), 2500);
      }
      toast.success('Copied to clipboard!');
    } catch {
      toast.error('Failed to copy to clipboard');
    }
  };

  // ---------------------------------------------------------------------------
  // Render helpers
  // ---------------------------------------------------------------------------
  const renderActions = (f) => (
    <div className="flex items-center gap-1.5 justify-end">
      <button
        onClick={() => setActivePage?.('privacy')}
        className="btn-ghost text-xs py-1.5 px-2 flex items-center gap-1 text-cyber-muted hover:text-cyber-accent"
        title="Privacy & PII Scanner Studio"
      >
        <ShieldAlert className="w-3.5 h-3.5" />
        <span className="hidden xl:inline">Privacy</span>
      </button>
      <button
        onClick={() => openTokenModal(f)}
        disabled={downloadingId === f.id || deletingId === f.id}
        className="btn-ghost text-xs py-1.5 px-2.5 flex items-center gap-1 text-cyber-accent hover:text-white"
        title="Share & manage access tokens"
      >
        <Share2 className="w-3.5 h-3.5" />
        <span>Share</span>
      </button>
      <button
        onClick={() => handleDownload(f)}
        disabled={downloadingId === f.id || deletingId === f.id}
        className="btn-ghost text-xs py-1.5 px-2.5 flex items-center gap-1"
        title="Download & decrypt"
      >
        {downloadingId === f.id ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        ) : (
          <>
            <Download className="w-3.5 h-3.5" />
            <Lock className="w-3 h-3 text-amber-400" />
          </>
        )}
        {downloadingId === f.id ? 'Decrypting' : 'Download'}
      </button>
      <button
        onClick={() => openDeleteModal(f)}
        disabled={deletingId === f.id || downloadingId === f.id}
        className="btn-ghost text-xs py-1.5 px-2.5 flex items-center gap-1 text-cyber-danger/70 hover:text-cyber-danger hover:bg-cyber-danger/10"
        title="Delete file"
      >
        {deletingId === f.id ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        ) : (
          <Trash2 className="w-3.5 h-3.5" />
        )}
      </button>
    </div>
  );

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
          <button
            onClick={onRefresh}
            disabled={loading}
            className="btn-ghost text-xs py-2 px-3 disabled:opacity-50 flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button
            onClick={() => setActivePage('upload')}
            className="btn-primary text-xs py-2 px-3"
          >
            Upload new
          </button>
        </div>
      </div>

      {/* Search + view toggle */}
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

        <div className="flex items-center gap-3 p-3 bg-cyber-border/50 rounded-xl text-sm text-cyber-muted">
          <Lock className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>🔐 Password used only in your browser for decryption — never sent to server</span>
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
          {search ? (
            <button
              onClick={() => setSearch('')}
              className="btn-ghost text-xs py-2 px-4"
            >
              Clear search
            </button>
          ) : (
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
          <div className="hidden sm:grid grid-cols-12 gap-4 px-5 py-3
                          border-b border-white/[0.05] text-xs text-cyber-muted
                          font-medium uppercase tracking-wider">
            <div className="col-span-5">File</div>
            <div className="col-span-2">Size</div>
            <div className="col-span-2">Date</div>
            <div className="col-span-3 text-right">Actions</div>
          </div>

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
                      <span>{formatDate(f.upload_date)}</span>
                      {f.is_legacy && (
                        <span className="text-amber-400/70 text-[10px]">· legacy</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Size */}
                <div className="hidden sm:flex sm:col-span-2 items-center gap-1.5 text-sm text-cyber-muted">
                  <HardDrive className="w-3.5 h-3.5" />
                  {formatBytes(f.size)}
                </div>

                {/* Date */}
                <div className="hidden sm:flex sm:col-span-2 items-center gap-1.5 text-sm text-cyber-muted">
                  <Calendar className="w-3.5 h-3.5" />
                  {formatDate(f.upload_date)}
                </div>

                {/* Actions */}
                <div className="sm:col-span-3">
                  {renderActions(f)}
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
                  {formatBytes(f.size)} · {formatDate(f.upload_date)}
                  {f.is_legacy && <span className="text-amber-400/70"> · legacy</span>}
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setActivePage?.('privacy')}
                  className="btn-ghost text-xs py-2 px-2 flex items-center justify-center text-cyber-muted hover:text-cyber-accent"
                  title="Privacy & PII Scanner Studio"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => openTokenModal(f)}
                  disabled={downloadingId === f.id || deletingId === f.id}
                  className="btn-ghost text-xs py-2 px-2.5 flex items-center gap-1 text-cyber-accent hover:text-white"
                  title="Share & access tokens"
                >
                  <Share2 className="w-3.5 h-3.5" />
                  Share
                </button>
                <button
                  onClick={() => handleDownload(f)}
                  disabled={downloadingId === f.id || deletingId === f.id}
                  className="btn-ghost flex-1 text-xs py-2 flex items-center justify-center gap-1.5"
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
                      Download
                    </>
                  )}
                </button>
                <button
                  onClick={() => openDeleteModal(f)}
                  disabled={deletingId === f.id || downloadingId === f.id}
                  className="btn-ghost text-xs py-2 px-3 flex items-center text-cyber-danger/70 hover:text-cyber-danger hover:bg-cyber-danger/10"
                  title="Delete file"
                >
                  {deletingId === f.id ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Trash2 className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ---- Download Password Modal ---- */}
      {showPwModal && selectedFile && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) closePwModal(); }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <div className="glass max-w-md w-full rounded-2xl p-8 space-y-6">
            <div className="text-center">
              <Lock className="w-14 h-14 text-amber-400 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">Decrypt File</h2>
              <p className="text-cyber-muted text-sm">
                Enter the encryption password for <strong>{selectedFile.filename}</strong>
              </p>
              <p className="text-xs text-cyber-muted/70 mt-2">
                Your password is used only in your browser — it is never sent to the server.
              </p>
            </div>

            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-amber-400" />
              <input
                ref={(input) => input && input.focus()}
                type={pwVisible ? 'text' : 'password'}
                value={downloadPw}
                onChange={(e) => setDownloadPw(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && downloadPw.trim() && confirmDownload()}
                placeholder="File encryption password"
                className="input-field pl-12 pr-12 py-3 w-full text-lg"
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
                disabled={!downloadPw.trim()}
                className="flex-1 btn-primary disabled:opacity-50"
              >
                Decrypt &amp; Download
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- Delete Confirmation Modal ---- */}
      {showDeleteModal && fileToDelete && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) closeDeleteModal(); }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <div className="glass max-w-md w-full rounded-2xl p-8 space-y-6">
            <div className="text-center">
              <AlertTriangle className="w-14 h-14 text-cyber-danger mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-white mb-2">Delete File?</h2>
              <p className="text-cyber-muted">
                Are you sure you want to permanently delete{' '}
                <strong className="text-white">{fileToDelete.filename}</strong>?
              </p>
              <p className="text-xs text-cyber-danger/80 mt-3">
                This action cannot be undone. The file will be removed from storage and cannot be recovered.
              </p>
            </div>

            <div className="flex gap-3">
              <button onClick={closeDeleteModal} className="flex-1 btn-ghost">
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                className="flex-1 btn-primary bg-cyber-danger/20 border-cyber-danger/30 hover:bg-cyber-danger/30 text-cyber-danger"
              >
                <Trash2 className="w-4 h-4" />
                Delete Permanently
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- Access Token Management Modal (Phase 8) ---- */}
      {showTokenModal && fileForTokens && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) closeTokenModal(); }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <div className="glass max-w-xl w-full rounded-2xl p-6 sm:p-8 space-y-6 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-cyber-accent/15 text-cyber-accent">
                  <Key className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Share &amp; Access Tokens</h2>
                  <p className="text-xs text-cyber-muted truncate max-w-xs sm:max-w-md">
                    {fileForTokens.filename} ({formatBytes(fileForTokens.size)})
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={closeTokenModal}
                className="text-cyber-muted hover:text-white p-1 rounded-lg transition-colors"
                title="Close modal"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Tabs */}
            <div className="flex border-b border-white/[0.08] gap-2">
              <button
                type="button"
                onClick={() => setShareTab('user')}
                className={`flex items-center gap-2 pb-3 px-3 text-xs font-semibold border-b-2 transition-colors ${
                  shareTab === 'user'
                    ? 'border-cyber-accent text-cyber-accent'
                    : 'border-transparent text-cyber-muted hover:text-white'
                }`}
              >
                <Users className="w-4 h-4" />
                <span>Share with User (RSA)</span>
              </button>
              <button
                type="button"
                onClick={() => setShareTab('token')}
                className={`flex items-center gap-2 pb-3 px-3 text-xs font-semibold border-b-2 transition-colors ${
                  shareTab === 'token'
                    ? 'border-cyber-accent text-cyber-accent'
                    : 'border-transparent text-cyber-muted hover:text-white'
                }`}
              >
                <Link2 className="w-4 h-4" />
                <span>Temporary Token Link</span>
              </button>
            </div>

            {/* TAB 1: Share with Registered User (RSA Hybrid) */}
            {shareTab === 'user' && (
              <>
                {/* Security Explanation */}
                <div className="flex items-start gap-3 p-3 bg-cyber-border/40 rounded-xl text-xs text-cyber-muted">
                  <ShieldCheck className="w-4 h-4 text-cyber-accent flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold text-white/90">Zero-Knowledge RSA Hybrid Sharing</p>
                    <p className="mt-0.5">
                      The file payload in cloud storage is <strong>never re-encrypted or duplicated</strong>.
                      Your browser unwraps the file's AES-256 data key client-side and wraps it with the recipient's verified RSA public key.
                    </p>
                  </div>
                </div>

                {/* Sharing Form */}
                <div className="space-y-4">
                  <h3 className="text-sm font-semibold text-white">Share with Registered User</h3>

                  <div>
                    <label className="text-xs text-cyber-muted block mb-1">Recipient Account Email</label>
                    <div className="relative">
                      <input
                        type="email"
                        value={recipientEmail}
                        onChange={(e) => setRecipientEmail(e.target.value)}
                        placeholder="recipient@example.com"
                        className="input-field text-xs py-2 w-full pl-9"
                      />
                      <User className="w-4 h-4 text-cyber-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-cyber-muted block mb-1">
                      Your Account Password <span className="text-cyber-muted/60">(required to unwrap AES key in your browser)</span>
                    </label>
                    <div className="relative">
                      <input
                        type={shareOwnerPwVisible ? 'text' : 'password'}
                        value={shareOwnerPassword}
                        onChange={(e) => setShareOwnerPassword(e.target.value)}
                        placeholder="Enter your account / encryption password"
                        className="input-field text-xs py-2 w-full pl-9 pr-9"
                      />
                      <Lock className="w-4 h-4 text-cyber-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <button
                        type="button"
                        onClick={() => setShareOwnerPwVisible(!shareOwnerPwVisible)}
                        className="text-cyber-muted hover:text-white absolute right-3 top-1/2 -translate-y-1/2 p-0.5"
                      >
                        {shareOwnerPwVisible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Permission Scope</label>
                      <select
                        value={sharePermission}
                        onChange={(e) => setSharePermission(e.target.value)}
                        className="input-field text-xs py-2 w-full"
                      >
                        <option value="download">Download &amp; Decrypt (Full Access)</option>
                        <option value="view">View Only (Metadata Inspection)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Expiration Period</label>
                      <select
                        value={tokenExpiry}
                        onChange={(e) => setTokenExpiry(Number(e.target.value))}
                        className="input-field text-xs py-2 w-full"
                      >
                        <option value={3600}>1 Hour (3,600s)</option>
                        <option value={86400}>24 Hours (1 Day)</option>
                        <option value={604800}>7 Days</option>
                        <option value={2592000}>30 Days (Maximum)</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Download Quota</label>
                      <select
                        value={tokenMaxDownloads}
                        onChange={(e) => setTokenMaxDownloads(Number(e.target.value))}
                        className="input-field text-xs py-2 w-full"
                      >
                        <option value={1}>1 Download (Single-Use, Atomic)</option>
                        <option value={5}>5 Downloads</option>
                        <option value={10}>10 Downloads</option>
                        <option value={0}>Unlimited (Within Expiry)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Optional Note / Message</label>
                      <input
                        type="text"
                        value={shareNote}
                        onChange={(e) => setShareNote(e.target.value)}
                        placeholder="e.g. Confidential Project Files"
                        className="input-field text-xs py-2 w-full"
                        maxLength={100}
                      />
                    </div>
                  </div>

                  {/* Privacy Pre-Check Card (Phase 10) */}
                  <div className="p-3.5 rounded-xl border border-white/[0.08] bg-black/40 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-cyber-accent" />
                        <span className="text-xs font-semibold text-white">Privacy Pre-Check (PII Scan)</span>
                      </div>
                      <button
                        type="button"
                        onClick={handleScanPiiBeforeShare}
                        disabled={isScanningPiiForShare || !shareOwnerPassword}
                        className="btn-ghost text-[11px] py-1 px-2.5 text-cyber-accent hover:bg-cyber-accent/10 flex items-center gap-1.5"
                      >
                        {isScanningPiiForShare ? (
                          <>
                            <Loader2 className="w-3 h-3 animate-spin" />
                            <span>Scanning File...</span>
                          </>
                        ) : (
                          <>
                            <Search className="w-3 h-3" />
                            <span>Scan File for PII</span>
                          </>
                        )}
                      </button>
                    </div>

                    {!piiScanResult && (
                      <p className="text-[11px] text-cyber-muted">
                        Verify whether this file contains unmasked payment cards, Aadhaar, PAN, emails, or phone numbers before sharing.
                      </p>
                    )}

                    {piiScanResult && !piiScanResult.supported && (
                      <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[11px] text-amber-300 space-y-1">
                        <div className="flex items-center gap-1.5 font-semibold">
                          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                          <span>Unsupported Format Warning</span>
                        </div>
                        <p>{piiScanResult.reason}</p>
                      </div>
                    )}

                    {piiScanResult && piiScanResult.supported && piiScanResult.scan.totalCount === 0 && (
                      <div className="p-2.5 rounded-lg bg-cyber-green/10 border border-cyber-green/20 text-[11px] text-cyber-green flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4 flex-shrink-0" />
                        <span>Clean Document: 0 sensitive PII items detected in file.</span>
                      </div>
                    )}

                    {piiScanResult && piiScanResult.supported && piiScanResult.scan.totalCount > 0 && (
                      <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs space-y-2">
                        <div className="flex items-center justify-between text-rose-300 font-semibold">
                          <span className="flex items-center gap-1.5">
                            <AlertTriangle className="w-4 h-4 text-rose-400" />
                            Privacy Risk: {piiScanResult.scan.totalCount} Sensitive Item(s) Detected!
                          </span>
                          <button
                            type="button"
                            onClick={() => {
                              closeTokenModal();
                              setActivePage('privacy');
                            }}
                            className="text-[11px] text-cyber-accent hover:underline flex items-center gap-1"
                          >
                            Open in Privacy Studio →
                          </button>
                        </div>

                        <div className="flex items-center gap-2 flex-wrap text-[11px]">
                          {piiScanResult.scan.countsByType.CARD > 0 && (
                            <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono">
                              Cards: {piiScanResult.scan.countsByType.CARD}
                            </span>
                          )}
                          {piiScanResult.scan.countsByType.AADHAAR > 0 && (
                            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
                              Aadhaar: {piiScanResult.scan.countsByType.AADHAAR}
                            </span>
                          )}
                          {piiScanResult.scan.countsByType.PAN > 0 && (
                            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                              PAN: {piiScanResult.scan.countsByType.PAN}
                            </span>
                          )}
                          {piiScanResult.scan.countsByType.EMAIL > 0 && (
                            <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">
                              Emails: {piiScanResult.scan.countsByType.EMAIL}
                            </span>
                          )}
                          {piiScanResult.scan.countsByType.PHONE > 0 && (
                            <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-mono">
                              Phones: {piiScanResult.scan.countsByType.PHONE}
                            </span>
                          )}
                        </div>

                        <p className="text-[11px] text-cyber-muted">
                          It is strongly advised to redact sensitive data before sharing.
                        </p>
                      </div>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={handleShareWithUser}
                    disabled={sharingUser || !recipientEmail.trim() || !shareOwnerPassword}
                    className="btn-primary w-full text-xs py-2.5 flex items-center justify-center gap-2"
                  >
                    {sharingUser ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Unwrapping &amp; Re-wrapping AES Key...
                      </>
                    ) : (
                      <>
                        <Users className="w-4 h-4" />
                        Share File with Recipient
                      </>
                    )}
                  </button>
                </div>

                {/* Existing Shares for this File */}
                <div className="space-y-3 border-t border-white/[0.08] pt-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white">
                      Active File Shares ({fileShares.length})
                    </h3>
                    {loadingShares && <Loader2 className="w-3.5 h-3.5 text-cyber-accent animate-spin" />}
                  </div>

                  {loadingShares && fileShares.length === 0 ? (
                    <div className="py-6 text-center text-xs text-cyber-muted">
                      Loading sharing records...
                    </div>
                  ) : fileShares.length === 0 ? (
                    <div className="py-6 text-center text-xs text-cyber-muted bg-black/20 rounded-xl">
                      No recipient shares created for this file yet.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {fileShares.map((s) => {
                        const isRevoked = s.is_revoked || s.status === 'revoked';
                        const isExhausted = s.status === 'exhausted';
                        const isExpired = s.status === 'expired';
                        const isActive = s.status === 'active';

                        let badgeColor = 'bg-cyber-green/15 text-cyber-green';
                        if (isRevoked) badgeColor = 'bg-cyber-danger/15 text-cyber-danger';
                        else if (isExhausted) badgeColor = 'bg-amber-400/15 text-amber-400';
                        else if (isExpired) badgeColor = 'bg-white/10 text-cyber-muted';

                        return (
                          <div
                            key={s.id}
                            className="p-3 bg-black/30 rounded-xl border border-white/[0.04] flex items-center justify-between gap-3 text-xs"
                          >
                            <div className="space-y-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-white truncate max-w-[140px] sm:max-w-xs">
                                  {s.recipient_email}
                                </span>
                                <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] uppercase ${badgeColor}`}>
                                  {s.status}
                                </span>
                                <span className="px-1.5 py-0.2 rounded font-mono text-[10px] bg-cyber-accent/15 text-cyber-accent uppercase">
                                  {s.permission}
                                </span>
                              </div>
                              <div className="text-[11px] text-cyber-muted flex items-center gap-2 flex-wrap">
                                <span>
                                  Downloads: {s.downloads_used} / {s.max_downloads === 0 ? '∞' : s.max_downloads}
                                </span>
                                <span>·</span>
                                <span>Expires: {formatDate(s.expires_at)}</span>
                                {s.note && (
                                  <>
                                    <span>·</span>
                                    <span className="italic truncate max-w-[120px]">"{s.note}"</span>
                                  </>
                                )}
                              </div>
                              {s.raw_token && (
                                <div className="pt-1 flex items-center gap-2">
                                  <span className="text-[10px] text-cyber-muted">Direct Link:</span>
                                  <button
                                    type="button"
                                    onClick={() =>
                                      copyToClipboard(
                                        `${window.location.origin}/api/shares/access/${s.raw_token}`,
                                        'link'
                                      )
                                    }
                                    className="text-[10px] text-cyber-accent hover:underline flex items-center gap-1"
                                  >
                                    <Copy className="w-2.5 h-2.5" />
                                    Copy Token Link
                                  </button>
                                </div>
                              )}
                            </div>

                            {isActive && (
                              <button
                                type="button"
                                onClick={() => handleRevokeShare(s.id)}
                                disabled={revokingShareId === s.id}
                                className="btn-ghost text-xs py-1 px-2.5 text-cyber-danger/80 hover:text-cyber-danger hover:bg-cyber-danger/10 flex-shrink-0"
                                title="Immediately revoke recipient access"
                              >
                                {revokingShareId === s.id ? (
                                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                ) : (
                                  'Revoke'
                                )}
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </>
            )}

            {/* TAB 2: Temporary Token Link (Phase 8) */}
            {shareTab === 'token' && (
              <>
                {/* Security Explanation */}
                <div className="flex items-start gap-3 p-3 bg-cyber-border/40 rounded-xl text-xs text-cyber-muted">
                  <ShieldAlert className="w-4 h-4 text-cyber-accent flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold text-white/90">Zero-Knowledge Token Security</p>
                    <p className="mt-0.5">
                      Only the <strong>SHA-256 hash</strong> of each token is stored in the database.
                      Single-use and download quotas are decremented atomically with zero race conditions.
                    </p>
                  </div>
                </div>

                {/* Newly Generated Token Alert */}
                {newlyCreatedToken && (
                  <div className="p-4 rounded-xl border border-cyber-accent/40 bg-cyber-accent/10 space-y-3">
                    <div className="flex items-center gap-2 text-cyber-accent text-sm font-semibold">
                      <Check className="w-4 h-4" />
                      <span>Token Generated Successfully!</span>
                    </div>
                    <p className="text-xs text-amber-300">
                      ⚠️ Copy this token now. It will never be displayed again, and cannot be recovered from the database.
                    </p>
                    
                    {/* Raw token box */}
                    <div>
                      <label className="text-[11px] font-medium text-cyber-muted uppercase tracking-wider block mb-1">
                        Raw Access Token
                      </label>
                      <div className="flex items-center gap-2">
                        <input
                          type="text"
                          readOnly
                          value={newlyCreatedToken}
                          className="input-field font-mono text-xs py-2 px-3 flex-1 select-all"
                        />
                        <button
                          type="button"
                          onClick={() => copyToClipboard(newlyCreatedToken, 'token')}
                          className="btn-primary text-xs py-2 px-3 flex items-center gap-1.5"
                        >
                          {copiedToken ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          {copiedToken ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    </div>

                    {/* Direct download link */}
                    <div>
                      <label className="text-[11px] font-medium text-cyber-muted uppercase tracking-wider block mb-1">
                        Direct Download URL
                      </label>
                      <div className="flex items-center gap-2">
                        <input
                          type="text"
                          readOnly
                          value={`${window.location.origin}/api/access/download/${newlyCreatedToken}`}
                          className="input-field font-mono text-xs py-2 px-3 flex-1 select-all"
                        />
                        <button
                          type="button"
                          onClick={() =>
                            copyToClipboard(`${window.location.origin}/api/access/download/${newlyCreatedToken}`, 'link')
                          }
                          className="btn-ghost text-xs py-2 px-3 flex items-center gap-1.5"
                        >
                          {copiedLink ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          {copiedLink ? 'Copied' : 'Copy Link'}
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Token Creation Form */}
                <div className="space-y-4 border-t border-white/[0.08] pt-4">
                  <h3 className="text-sm font-semibold text-white">Create New Access Token</h3>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {/* Expiration */}
                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Expiration Period</label>
                      <select
                        value={tokenExpiry}
                        onChange={(e) => setTokenExpiry(Number(e.target.value))}
                        className="input-field text-xs py-2 w-full"
                      >
                        <option value={3600}>1 Hour (3,600s)</option>
                        <option value={86400}>24 Hours (1 Day)</option>
                        <option value={604800}>7 Days</option>
                        <option value={2592000}>30 Days (Maximum)</option>
                      </select>
                    </div>

                    {/* Download Limit */}
                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Download Quota</label>
                      <select
                        value={tokenMaxDownloads}
                        onChange={(e) => setTokenMaxDownloads(Number(e.target.value))}
                        className="input-field text-xs py-2 w-full"
                      >
                        <option value={1}>1 Download (Single-Use, Atomic)</option>
                        <option value={5}>5 Downloads</option>
                        <option value={10}>10 Downloads</option>
                        <option value={0}>Unlimited (Within Expiry)</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {/* Scope */}
                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Permission Scope</label>
                      <select
                        value={tokenScope}
                        onChange={(e) => setTokenScope(e.target.value)}
                        className="input-field text-xs py-2 w-full"
                      >
                        <option value="download">Download (Stream Encrypted File)</option>
                        <option value="view">View Only (Metadata Inspection)</option>
                      </select>
                    </div>

                    {/* Optional Label */}
                    <div>
                      <label className="text-xs text-cyber-muted block mb-1">Optional Label / Note</label>
                      <input
                        type="text"
                        value={tokenLabel}
                        onChange={(e) => setTokenLabel(e.target.value)}
                        placeholder="e.g. External Audit Share"
                        className="input-field text-xs py-2 w-full"
                        maxLength={100}
                      />
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleCreateToken}
                    disabled={creatingToken}
                    className="btn-primary w-full text-xs py-2.5 flex items-center justify-center gap-2"
                  >
                    {creatingToken ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Generating Cryptographic Token...
                      </>
                    ) : (
                      <>
                        <Key className="w-4 h-4" />
                        Generate Scoped Access Token
                      </>
                    )}
                  </button>
                </div>

                {/* Existing Tokens for this File */}
                <div className="space-y-3 border-t border-white/[0.08] pt-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white">
                      Active &amp; Prior Tokens ({fileTokens.length})
                    </h3>
                    {loadingTokens && <Loader2 className="w-3.5 h-3.5 text-cyber-accent animate-spin" />}
                  </div>

                  {loadingTokens && fileTokens.length === 0 ? (
                    <div className="py-6 text-center text-xs text-cyber-muted">
                      Loading token status...
                    </div>
                  ) : fileTokens.length === 0 ? (
                    <div className="py-6 text-center text-xs text-cyber-muted bg-black/20 rounded-xl">
                      No access tokens created for this file yet.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {fileTokens.map((t) => {
                        const isRevoked = t.is_revoked || t.status === 'revoked';
                        const isExhausted = t.status === 'exhausted';
                        const isExpired = t.status === 'expired';
                        const isActive = t.status === 'active';

                        let badgeColor = 'bg-cyber-green/15 text-cyber-green';
                        if (isRevoked) badgeColor = 'bg-cyber-danger/15 text-cyber-danger';
                        else if (isExhausted) badgeColor = 'bg-amber-400/15 text-amber-400';
                        else if (isExpired) badgeColor = 'bg-white/10 text-cyber-muted';

                        return (
                          <div
                            key={t.id}
                            className="p-3 bg-black/30 rounded-xl border border-white/[0.04] flex items-center justify-between gap-3 text-xs"
                          >
                            <div className="space-y-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-white truncate max-w-[140px] sm:max-w-xs">
                                  {t.label || 'Unnamed Access Token'}
                                </span>
                                <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] uppercase ${badgeColor}`}>
                                  {t.status}
                                </span>
                                <span className="px-1.5 py-0.2 rounded font-mono text-[10px] bg-cyber-accent/15 text-cyber-accent">
                                  {t.scope}
                                </span>
                              </div>
                              <div className="text-[11px] text-cyber-muted flex items-center gap-2">
                                <span>
                                  Used: {t.downloads_used} / {t.max_downloads === 0 ? '∞' : t.max_downloads}
                                </span>
                                <span>·</span>
                                <span>Expires: {formatDate(t.expires_at)}</span>
                              </div>
                            </div>

                            {isActive && (
                              <button
                                type="button"
                                onClick={() => handleRevokeToken(t.id)}
                                disabled={revokingTokenId === t.id}
                                className="btn-ghost text-xs py-1 px-2.5 text-cyber-danger/80 hover:text-cyber-danger hover:bg-cyber-danger/10 flex-shrink-0"
                                title="Immediately revoke token"
                              >
                                {revokingTokenId === t.id ? (
                                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                ) : (
                                  'Revoke'
                                )}
                              </button>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Modal footer */}
            <div className="flex justify-end pt-2 border-t border-white/[0.08]">
              <button
                type="button"
                onClick={closeTokenModal}
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
