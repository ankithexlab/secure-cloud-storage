// =============================================================================
// api.test.js — Frontend API client primitives and URL resolution tests
// =============================================================================
import { buildApiUrl, API_BASE_URL, ApiError } from './api';

describe('Frontend API configuration and primitives', () => {
  test('API_BASE_URL does not point to external third-party Render host', () => {
    expect(API_BASE_URL).not.toContain('onrender.com');
  });

  test('buildApiUrl builds normalized endpoint paths', () => {
    expect(buildApiUrl('/health')).toBe(`${API_BASE_URL}/health`);
    expect(buildApiUrl('health')).toBe(`${API_BASE_URL}/health`);
    expect(buildApiUrl('')).toBe(API_BASE_URL);
  });

  test('ApiError correctly captures status and auth error flag', () => {
    const authErr = new ApiError('Unauthorized', 401, { code: 'token_expired' });
    expect(authErr.status).toBe(401);
    expect(authErr.isAuthError).toBe(true);
    expect(authErr.data.code).toBe('token_expired');

    const networkErr = new ApiError('Network fail', 0, null);
    expect(networkErr.status).toBe(0);
    expect(networkErr.isAuthError).toBe(false);
  });
});
