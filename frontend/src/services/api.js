// =============================================================================
// services/api.js — HTTP client for the Secure Cloud API
// ZERO-KNOWLEDGE: File encryption passwords are NEVER sent to the server.
// =============================================================================
import { API_BASE_URL, ApiError, apiFetch, buildApiUrl } from '../api';

function asObject(data) {
  return data && typeof data === 'object' ? data : {};
}

function getErrorMessage(data, fallback) {
  const payload = asObject(data);
  return payload.msg || payload.error || fallback;
}

function authHeaders(token) {
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function requestJson(path, options = {}, fallbackError = 'Request failed') {
  try {
    const res = await apiFetch(path, options);
    const payload = asObject(res.data);
    if (!res.ok && !payload.msg && !payload.error) {
      payload.msg = fallbackError;
    }
    return { ok: res.ok, status: res.status, data: payload };
  } catch (error) {
    return {
      ok: false,
      status: error instanceof ApiError ? error.status : 0,
      data: { success: false, msg: error.message || 'Network error' },
    };
  }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
export function registerRequest({ email, password }) {
  return requestJson(
    '/register',
    {
      method: 'POST',
      body: { email, password },
    },
    'Registration failed'
  );
}

export function loginRequest({ email, password }) {
  return requestJson(
    '/login',
    {
      method: 'POST',
      body: { email, password },
    },
    'Login failed'
  );
}

export function logoutRequest(token) {
  return requestJson(
    '/logout',
    {
      method: 'POST',
      token,
    },
    'Logout failed'
  );
}

export function getProfile(token) {
  return requestJson(
    '/me',
    {
      method: 'GET',
      token,
    },
    'Failed to load profile'
  );
}

export function changePasswordRequest({ token, old_password, new_password }) {
  return requestJson(
    '/change-password',
    {
      method: 'POST',
      token,
      body: { old_password, new_password },
    },
    'Failed to change password'
  );
}

// ---------------------------------------------------------------------------
// RSA Public Keys & Key Management (Phase 6)
// ---------------------------------------------------------------------------
export function registerPublicKey({
  token,
  publicKey,
  fingerprint,
  keyType,
  encryptedPrivateKey,
  iv,
  salt,
  integrityHash,
}) {
  return requestJson(
    '/keys/register',
    {
      method: 'POST',
      token,
      body: {
        public_key: publicKey,
        fingerprint,
        key_type: keyType || 'RSA-OAEP-2048',
        encrypted_private_key: encryptedPrivateKey || '',
        iv: iv || '',
        salt: salt || '',
        integrity_hash: integrityHash || '',
      },
    },
    'Failed to register public key'
  );
}

export function getMyKeys(token) {
  return requestJson(
    '/keys/me',
    {
      method: 'GET',
      token,
    },
    'Failed to load keys'
  );
}

export function getUserPublicKey(token, email) {
  return requestJson(
    `/keys/${encodeURIComponent(email)}`,
    {
      method: 'GET',
      token,
    },
    'Failed to load user public key'
  );
}

export function deleteMyKeys(token) {
  return requestJson(
    '/keys/me',
    {
      method: 'DELETE',
      token,
    },
    'Failed to revoke keypair'
  );
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
export async function healthCheck() {
  const result = await requestJson('/health', { method: 'GET' }, 'Backend unavailable');
  return {
    ok: result.ok,
    status: result.status,
    data: result.data,
    backendUrl: API_BASE_URL,
  };
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/**
 * Upload encrypted file to the server.
 * ZERO-KNOWLEDGE: Only ciphertext + iv + metadata (or wrapped_key) are sent. Password is NEVER included.
 * Supports both object signature ({ token, filename, ... }) and positional signature (token, file, encrypted).
 */
export function uploadEncryptedFile(tokenOrOptions, maybeFile, maybeEncrypted) {
  let opts = {};
  if (typeof tokenOrOptions === 'object' && tokenOrOptions !== null) {
    opts = tokenOrOptions;
  } else {
    // Positional signature: uploadEncryptedFile(token, file, encrypted)
    const token = tokenOrOptions;
    const file = maybeFile || {};
    const enc = maybeEncrypted || {};
    opts = {
      token,
      filename: file.name || 'encrypted_file.bin',
      mime_type: file.type || 'application/octet-stream',
      size: typeof file.size === 'number' ? file.size : 0,
      encrypted_content: enc.ciphertext,
      iv: enc.iv,
      salt: enc.salt || '',
      wrapped_key: enc.wrapped_key || '',
      key_fingerprint: enc.key_fingerprint || '',
      integrity_hash: enc.integrity_hash || enc.hash || '',
      algorithm: enc.algorithm || 'AES-GCM-256',
      kdf: enc.kdf || 'PBKDF2-SHA256',
      iterations: enc.iterations !== undefined ? enc.iterations : 100000,
      version: enc.version || '1.0',
    };
  }

  const {
    token,
    filename,
    mime_type,
    size,
    encrypted_content,
    iv,
    salt,
    wrapped_key,
    key_fingerprint,
    integrity_hash,
    algorithm,
    kdf,
    iterations,
    version,
  } = opts;

  return requestJson(
    '/upload',
    {
      method: 'POST',
      token,
      body: {
        filename,
        mime_type,
        size,
        encrypted_content,
        iv,
        salt: salt || '',
        wrapped_key: wrapped_key || '',
        key_fingerprint: key_fingerprint || '',
        integrity_hash: integrity_hash || '',
        algorithm: algorithm || 'AES-GCM-256',
        kdf: kdf || 'PBKDF2-SHA256',
        iterations: iterations !== undefined ? iterations : 100000,
        version: version || '1.0',
        // NOTE: file_password is intentionally NOT sent — zero-knowledge design
      },
    },
    'Upload failed'
  );
}

export function getFiles(token) {
  return requestJson(
    '/files',
    {
      method: 'GET',
      token,
    },
    'Failed to load files'
  );
}

export function deleteFile(token, fileId) {
  return requestJson(
    `/files/${fileId}`,
    {
      method: 'DELETE',
      token,
    },
    'Failed to delete file'
  );
}

/**
 * Download encrypted file bytes from the server using authenticated GET.
 * The encryption password is NEVER sent to the server.
 * Decryption happens entirely client-side using the Web Crypto API.
 *
 * @param {string} token - JWT Bearer token
 * @param {string} fileId - File ID to download
 * @returns {{ encryptedBytes: ArrayBuffer, iv: string, salt: string, mimeType: string, isLegacy: boolean, integrityHash: string, algorithm: string, wrappedKey: string, keyFingerprint: string }}
 */
export async function downloadEncryptedFile(token, fileId) {
  let res;
  try {
    res = await fetch(buildApiUrl(`/download/${fileId}`), {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    throw new ApiError('Failed to fetch', 0, null);
  }

  if (!res.ok) {
    let payload = {};
    try {
      payload = await res.json();
    } catch {
      payload = {};
    }
    throw new ApiError(getErrorMessage(payload, 'Download failed'), res.status, payload);
  }

  const encryptedBytes = await res.arrayBuffer();
  if (!encryptedBytes || encryptedBytes.byteLength === 0) {
    throw new ApiError('Downloaded file is empty', res.status, null);
  }

  const iv = res.headers.get('X-IV') || '';
  const salt = res.headers.get('X-Salt') || '';
  const wrappedKey = res.headers.get('X-Wrapped-Key') || '';
  const keyFingerprint = res.headers.get('X-Key-Fingerprint') || '';
  const mimeType = res.headers.get('X-Original-Mime') || 'application/octet-stream';
  const isLegacy = res.headers.get('X-Is-Legacy') === 'true';
  const integrityHash = res.headers.get('X-Integrity-Hash') || '';
  const algorithm = res.headers.get('X-Algorithm') || 'AES-GCM-256';

  return {
    encryptedBytes,
    iv,
    salt,
    wrappedKey,
    keyFingerprint,
    mimeType,
    isLegacy,
    integrityHash,
    algorithm,
  };
}

// ---------------------------------------------------------------------------
// Access Token Management (Phase 8)
// ---------------------------------------------------------------------------

/**
 * Generate a new secure access token for a file.
 * Returns raw token ONCE in the response body.
 * Supports both object signature ({ token, fileId, ... }) and positional (token, fileId, options).
 */
export function createAccessToken(
  tokenOrOptions,
  maybeFileId,
  maybeOptions = {}
) {
  let token, fileId, scope, expiresInSeconds, maxDownloads, label;

  if (typeof tokenOrOptions === 'object' && tokenOrOptions !== null) {
    ({
      token,
      fileId,
      scope = 'download',
      expiresInSeconds = 86400,
      maxDownloads = 1,
      label = '',
    } = tokenOrOptions);
  } else {
    token = tokenOrOptions;
    fileId = maybeFileId;
    ({
      scope = 'download',
      expiresInSeconds = 86400,
      maxDownloads = 1,
      label = '',
    } = maybeOptions || {});
  }

  return requestJson(
    '/tokens/create',
    {
      method: 'POST',
      token,
      body: {
        file_id: fileId,
        scope,
        expires_in_seconds: expiresInSeconds,
        max_downloads: maxDownloads,
        label,
      },
    },
    'Failed to create access token'
  );
}

/**
 * List all access tokens created for a specific file.
 */
export function getFileAccessTokens(token, fileId) {
  return requestJson(
    `/tokens/file/${fileId}`,
    {
      method: 'GET',
      token,
    },
    'Failed to load file access tokens'
  );
}

/**
 * List all access tokens created by the authenticated user.
 */
export function getUserAccessTokens(token) {
  return requestJson(
    '/tokens',
    {
      method: 'GET',
      token,
    },
    'Failed to load access tokens'
  );
}

/**
 * Revoke an access token immediately.
 */
export function revokeAccessToken(token, tokenId) {
  return requestJson(
    `/tokens/${tokenId}`,
    {
      method: 'DELETE',
      token,
    },
    'Failed to revoke access token'
  );
}

/**
 * Validate an access token (view-only inspection).
 */
export function validateAccessToken(rawToken) {
  return requestJson(
    '/tokens/validate',
    {
      method: 'GET',
      headers: {
        'X-Access-Token': rawToken,
      },
    },
    'Access token is invalid or expired'
  );
}

/**
 * Download encrypted file bytes using an access token.
 * Atomically consumes 1 download against token quota.
 */
export async function downloadFileWithAccessToken(rawToken) {
  let res;
  try {
    res = await fetch(buildApiUrl('/tokens/download'), {
      method: 'GET',
      headers: {
        'X-Access-Token': rawToken,
      },
    });
  } catch {
    throw new ApiError('Failed to fetch', 0, null);
  }

  if (!res.ok) {
    let payload = {};
    try {
      payload = await res.json();
    } catch {
      payload = {};
    }
    throw new ApiError(getErrorMessage(payload, 'Token download failed'), res.status, payload);
  }

  const encryptedBytes = await res.arrayBuffer();
  if (!encryptedBytes || encryptedBytes.byteLength === 0) {
    throw new ApiError('Downloaded file is empty', res.status, null);
  }

  const iv = res.headers.get('X-IV') || '';
  const salt = res.headers.get('X-Salt') || '';
  const wrappedKey = res.headers.get('X-Wrapped-Key') || '';
  const keyFingerprint = res.headers.get('X-Key-Fingerprint') || '';
  const mimeType = res.headers.get('X-Original-Mime') || 'application/octet-stream';
  const isLegacy = res.headers.get('X-Is-Legacy') === 'true';
  const integrityHash = res.headers.get('X-Integrity-Hash') || '';
  const algorithm = res.headers.get('X-Algorithm') || 'AES-GCM-256';
  const remaining = res.headers.get('X-Token-Downloads-Remaining') || '';

  return {
    encryptedBytes,
    iv,
    salt,
    wrappedKey,
    keyFingerprint,
    mimeType,
    isLegacy,
    integrityHash,
    algorithm,
    remaining,
  };
}

// ---------------------------------------------------------------------------
// Phase 9: Secure File Sharing API Methods
// ---------------------------------------------------------------------------

/**
 * Share a file with one or more registered users.
 * @param {string} token — Authenticated JWT
 * @param {object} shareData — { file_id, recipient_email, wrapped_key, key_fingerprint, permission, expires_in_seconds, max_downloads, note } or { file_id, shares: [...] }
 */
export function createFileShare(token, shareData) {
  return requestJson(
    '/shares',
    {
      method: 'POST',
      token,
      body: shareData,
    },
    'Failed to share file'
  );
}

/**
 * List all file shares created by the authenticated owner (Sharing History).
 */
export function getSentShares(token, fileId = null) {
  const query = fileId ? `?file_id=${encodeURIComponent(fileId)}` : '';
  return requestJson(
    `/shares/sent${query}`,
    {
      method: 'GET',
      token,
    },
    'Failed to load sharing history'
  );
}

/**
 * List shares for a specific file owned by caller.
 */
export function getFileShares(token, fileId) {
  return requestJson(
    `/shares/file/${fileId}`,
    {
      method: 'GET',
      token,
    },
    'Failed to load file shares'
  );
}

/**
 * List all files shared with the authenticated recipient.
 */
export function getReceivedShares(token) {
  return requestJson(
    '/shares/received',
    {
      method: 'GET',
      token,
    },
    'Failed to load received shares'
  );
}

/**
 * Inspect details of a specific share (recipient or owner).
 */
export function getShareDetails(token, shareId) {
  return requestJson(
    `/shares/${shareId}`,
    {
      method: 'GET',
      token,
    },
    'Failed to load share details'
  );
}

/**
 * Download a shared file as an authorized recipient.
 * Atomically consumes download quota and parses recipient's wrapped key.
 */
export async function downloadSharedFile(token, shareId) {
  let res;
  try {
    res = await fetch(buildApiUrl(`/shares/${shareId}/download`), {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    throw new ApiError('Failed to fetch', 0, null);
  }

  if (!res.ok) {
    let payload = {};
    try {
      payload = await res.json();
    } catch {
      payload = {};
    }
    throw new ApiError(getErrorMessage(payload, 'Shared file download failed'), res.status, payload);
  }

  const encryptedBytes = await res.arrayBuffer();
  if (!encryptedBytes || encryptedBytes.byteLength === 0) {
    throw new ApiError('Downloaded file is empty', res.status, null);
  }

  const iv = res.headers.get('X-IV') || '';
  const salt = res.headers.get('X-Salt') || '';
  const wrappedKey = res.headers.get('X-Wrapped-Key') || '';
  const keyFingerprint = res.headers.get('X-Key-Fingerprint') || '';
  const mimeType = res.headers.get('X-Original-Mime') || 'application/octet-stream';
  const integrityHash = res.headers.get('X-Integrity-Hash') || '';
  const algorithm = res.headers.get('X-Algorithm') || 'AES-GCM-256+RSA-OAEP';
  const remaining = res.headers.get('X-Share-Downloads-Remaining') || '';
  const permission = res.headers.get('X-Share-Permission') || 'download';

  return {
    encryptedBytes,
    iv,
    salt,
    wrappedKey,
    keyFingerprint,
    mimeType,
    integrityHash,
    algorithm,
    remaining,
    permission,
  };
}

/**
 * Immediately revoke a file share (owner only).
 */
export function revokeFileShare(token, shareId) {
  return requestJson(
    `/shares/${shareId}`,
    {
      method: 'DELETE',
      token,
    },
    'Failed to revoke file share'
  );
}

/**
 * Download shared file using direct access token link.
 */
export async function downloadSharedFileWithToken(rawToken) {
  let res;
  try {
    res = await fetch(buildApiUrl(`/shares/access/${rawToken}`), {
      method: 'GET',
    });
  } catch {
    throw new ApiError('Failed to fetch', 0, null);
  }

  if (!res.ok) {
    let payload = {};
    try {
      payload = await res.json();
    } catch {
      payload = {};
    }
    throw new ApiError(getErrorMessage(payload, 'Direct share download failed'), res.status, payload);
  }

  const encryptedBytes = await res.arrayBuffer();
  if (!encryptedBytes || encryptedBytes.byteLength === 0) {
    throw new ApiError('Downloaded file is empty', res.status, null);
  }

  const iv = res.headers.get('X-IV') || '';
  const salt = res.headers.get('X-Salt') || '';
  const wrappedKey = res.headers.get('X-Wrapped-Key') || '';
  const keyFingerprint = res.headers.get('X-Key-Fingerprint') || '';
  const mimeType = res.headers.get('X-Original-Mime') || 'application/octet-stream';
  const integrityHash = res.headers.get('X-Integrity-Hash') || '';
  const algorithm = res.headers.get('X-Algorithm') || 'AES-GCM-256+RSA-OAEP';
  const remaining = res.headers.get('X-Share-Downloads-Remaining') || '';

  return {
    encryptedBytes,
    iv,
    salt,
    wrappedKey,
    keyFingerprint,
    mimeType,
    integrityHash,
    algorithm,
    remaining,
  };
}

// ---------------------------------------------------------------------------
// Security Monitoring & Audit Logs (Phase 11)
// ---------------------------------------------------------------------------
export function getAuditLogs(token, params = {}) {
  const query = new URLSearchParams();
  if (params.page) query.set('page', params.page);
  if (params.limit) query.set('limit', params.limit);
  if (params.event_type) query.set('event_type', params.event_type);
  if (params.severity) query.set('severity', params.severity);
  if (params.outcome) query.set('outcome', params.outcome);
  if (params.user_email) query.set('user_email', params.user_email);
  if (params.resource_id) query.set('resource_id', params.resource_id);
  if (params.search) query.set('search', params.search);
  if (params.start_date) query.set('start_date', params.start_date);
  if (params.end_date) query.set('end_date', params.end_date);

  const qs = query.toString();
  const path = `/admin/audit-logs${qs ? `?${qs}` : ''}`;
  return requestJson(
    path,
    {
      method: 'GET',
      token,
    },
    'Failed to fetch audit logs'
  );
}

export function getAuditStats(token) {
  return requestJson(
    '/admin/audit-logs/stats',
    {
      method: 'GET',
      token,
    },
    'Failed to fetch security stats'
  );
}

export function verifyAuditIntegrity(token) {
  return requestJson(
    '/admin/audit-logs/verify',
    {
      method: 'GET',
      token,
    },
    'Failed to verify audit log integrity'
  );
}

export function getAuditLogDetails(token, logId) {
  return requestJson(
    `/admin/audit-logs/${encodeURIComponent(logId)}`,
    {
      method: 'GET',
      token,
    },
    'Failed to fetch audit log detail'
  );
}
