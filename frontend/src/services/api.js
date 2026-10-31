// =============================================================================
// services/api.js — HTTP client for the Secure Cloud API
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
export function uploadEncryptedFile({
  token,
  filename,
  mime_type,
  size,
  encrypted_content,
  iv,
  salt,
  file_password,
}) {
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
        salt,
        file_password,
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

export async function downloadEncryptedFile(token, fileId, password) {
  let res;
  try {
    res = await fetch(buildApiUrl(`/download/${fileId}`), {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify({ password }),
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
  const mimeType = res.headers.get('X-Original-Mime') || 'application/octet-stream';

  return { encryptedBytes, iv, salt, mimeType };
}
