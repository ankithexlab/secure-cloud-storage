// =============================================================================
// api.js — Shared API client primitives
// =============================================================================

// Safe local development default and relative production fallback (no third-party Render URL)
const SAFE_LOCAL_API_URL = 'http://127.0.0.1:5000/api';
const DEFAULT_BASE_URL = process.env.NODE_ENV === 'production' ? '/api' : SAFE_LOCAL_API_URL;

const fromEnv = (process.env.REACT_APP_API_URL || '').trim();
export const API_BASE_URL = (fromEnv || DEFAULT_BASE_URL).replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(message, status = 0, data = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
    this.isAuthError = status === 401;
  }
}

export function buildApiUrl(path) {
  if (!path) return API_BASE_URL;
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}

function buildHeaders({ token, headers, hasJsonBody }) {
  return {
    ...(hasJsonBody ? { 'Content-Type': 'application/json' } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(headers || {}),
  };
}

async function parsePayload(response) {
  const type = response.headers.get('content-type') || '';
  if (type.includes('application/json')) {
    try {
      return await response.json();
    } catch {
      return {};
    }
  }
  if (type.includes('text/')) {
    try {
      return await response.text();
    } catch {
      return '';
    }
  }
  return null;
}

export async function apiFetch(path, options = {}) {
  const {
    method = 'GET',
    token,
    headers,
    body,
    responseType = 'json',
  } = options;

  const hasJsonBody = body !== undefined && body !== null && !(body instanceof FormData);

  try {
    const response = await fetch(buildApiUrl(path), {
      method,
      headers: buildHeaders({ token, headers, hasJsonBody }),
      body: hasJsonBody ? JSON.stringify(body) : body,
    });

    if (responseType === 'arrayBuffer') {
      const buffer = await response.arrayBuffer();
      return {
        ok: response.ok,
        status: response.status,
        headers: response.headers,
        data: buffer,
      };
    }

    const data = await parsePayload(response);
    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      data,
    };
  } catch (error) {
    throw new ApiError('Failed to connect to backend API', 0, null);
  }
}
