// =============================================================================
// services/api.test.js — Frontend API service method integration tests (mocked)
// =============================================================================
import {
  loginRequest,
  registerRequest,
  logoutRequest,
  getProfile,
  changePasswordRequest,
  uploadEncryptedFile,
  getFiles,
  deleteFile,
  downloadEncryptedFile,
  healthCheck,
  createAccessToken,
  getFileAccessTokens,
  getUserAccessTokens,
  revokeAccessToken,
  validateAccessToken,
  downloadFileWithAccessToken,
  createFileShare,
  getSentShares,
  getFileShares,
  getReceivedShares,
  getShareDetails,
  downloadSharedFile,
  revokeFileShare,
  downloadSharedFileWithToken,
  getAuditLogs,
  getAuditStats,
  verifyAuditIntegrity,
  getAuditLogDetails,
} from './api';
import { encryptFile } from './crypto';

describe('Frontend API service integration', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    jest.resetAllMocks();
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  test('loginRequest sends POST to /login with JSON credentials', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true, token: 'mock-jwt-token', user: { email: 'user@test.com' } }),
    });

    const res = await loginRequest({ email: 'user@test.com', password: 'Password1' });
    expect(res.ok).toBe(true);
    expect(res.status).toBe(200);
    expect(res.data.token).toBe('mock-jwt-token');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/login'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ email: 'user@test.com', password: 'Password1' }),
      })
    );
  });

  test('registerRequest sends POST to /register', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true, token: 'new-token' }),
    });

    const res = await registerRequest({ email: 'new@test.com', password: 'Password1' });
    expect(res.ok).toBe(true);
    expect(res.status).toBe(201);
  });

  test('logoutRequest sends POST to /logout with Authorization header', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true, msg: 'Logged out successfully' }),
    });

    const res = await logoutRequest('test-token-123');
    expect(res.ok).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/logout'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer test-token-123',
        }),
      })
    );
  });

  test('getProfile sends authenticated GET to /me', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        user: { id: 'u123', email: 'user@test.com', created_at: '2026-11-01T00:00:00Z' },
      }),
    });

    const res = await getProfile('profile-token-123');
    expect(res.ok).toBe(true);
    expect(res.status).toBe(200);
    expect(res.data.user.email).toBe('user@test.com');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/me'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer profile-token-123',
        }),
      })
    );
  });

  test('changePasswordRequest sends authenticated POST to /change-password', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        token: 'new-jwt-token-456',
        msg: 'Password updated successfully',
      }),
    });

    const res = await changePasswordRequest({
      token: 'old-token-123',
      old_password: 'OldPassword1',
      new_password: 'NewPassword2',
    });
    expect(res.ok).toBe(true);
    expect(res.data.token).toBe('new-jwt-token-456');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/change-password'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer old-token-123',
        }),
        body: JSON.stringify({
          old_password: 'OldPassword1',
          new_password: 'NewPassword2',
        }),
      })
    );
  });

  test('uploadEncryptedFile sends ciphertext, IV, salt without any password field', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true, file_id: 'file123', s3_key: 'encrypted/file123' }),
    });

    const payload = {
      token: 'jwt-123',
      filename: 'document.txt',
      mime_type: 'text/plain',
      size: 1024,
      encrypted_content: 'base64ciphertext==',
      iv: 'base64iv==',
      salt: 'base64salt==',
    };

    const res = await uploadEncryptedFile(payload);
    expect(res.ok).toBe(true);

    const callArgs = global.fetch.mock.calls[0];
    const requestBody = JSON.parse(callArgs[1].body);

    expect(requestBody.filename).toBe('document.txt');
    expect(requestBody.encrypted_content).toBe('base64ciphertext==');
    expect(requestBody.iv).toBe('base64iv==');
    expect(requestBody.salt).toBe('base64salt==');
    // ZERO-KNOWLEDGE: Verify password is NEVER included in request payload
    expect(requestBody.password).toBeUndefined();
    expect(requestBody.file_password).toBeUndefined();
    expect(requestBody.encPassword).toBeUndefined();
  });

  test('uploadEncryptedFile supports positional arguments (token, file, encrypted)', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true, file_id: 'sanitized-456' }),
    });

    const mockFile = {
      name: 'confidential_masked.txt',
      type: 'text/plain',
      size: 512,
    };
    const mockEncrypted = {
      ciphertext: 'ciphertext==',
      iv: 'iv==',
      salt: 'salt==',
      hash: 'sha256hash==',
      integrity_hash: 'sha256hash==',
      algorithm: 'AES-GCM-256',
      kdf: 'PBKDF2-SHA256',
      iterations: 100000,
      version: '1.0',
    };

    const res = await uploadEncryptedFile('jwt-token-456', mockFile, mockEncrypted);
    expect(res.ok).toBe(true);

    const callArgs = global.fetch.mock.calls[0];
    expect(callArgs[1].headers.Authorization).toBe('Bearer jwt-token-456');

    const requestBody = JSON.parse(callArgs[1].body);
    expect(requestBody.filename).toBe('confidential_masked.txt');
    expect(requestBody.encrypted_content).toBe('ciphertext==');
    expect(requestBody.iv).toBe('iv==');
    expect(requestBody.salt).toBe('salt==');
    expect(requestBody.integrity_hash).toBe('sha256hash==');
  });

  test('regression: sanitized file upload from PrivacyPage preserves JWT authorization header and payload structure', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        file_id: 'sanitized-file-999',
        filename: 'customer_data_masked.txt',
      }),
    });

    const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.validSig';
    const plainMaskedText = 'Aadhaar: [REDACTED_AADHAAR], PAN: [REDACTED_PAN]';
    const enc = new TextEncoder();
    const plainBuffer = enc.encode(plainMaskedText).buffer;
    const encrypted = await encryptFile(plainBuffer, 'SanitizedFilePassword123!');

    const res = await uploadEncryptedFile({
      token: jwtToken,
      filename: 'customer_data_masked.txt',
      mime_type: 'text/plain',
      size: plainBuffer.byteLength,
      encrypted_content: encrypted.ciphertext,
      iv: encrypted.iv,
      salt: encrypted.salt || '',
      wrapped_key: '',
      key_fingerprint: '',
      integrity_hash: encrypted.integrity_hash || encrypted.hash || '',
      algorithm: encrypted.algorithm || 'AES-GCM-256',
      kdf: encrypted.kdf || 'PBKDF2-SHA256',
      iterations: encrypted.iterations || 100000,
      version: encrypted.version || '1.0',
    });

    expect(res.ok).toBe(true);
    expect(res.status).toBe(201);
    expect(res.data.file_id).toBe('sanitized-file-999');

    // Verify JWT was passed in Authorization header (preventing 401 Session Expired)
    const callArgs = global.fetch.mock.calls[0];
    expect(callArgs[1].headers.Authorization).toBe(`Bearer ${jwtToken}`);

    // Verify payload does not leak password
    const body = JSON.parse(callArgs[1].body);
    expect(body.filename).toBe('customer_data_masked.txt');
    expect(body.encrypted_content).toBe(encrypted.ciphertext);
    expect(body.iv).toBe(encrypted.iv);
    expect(body.salt).toBe(encrypted.salt);
    expect(body.integrity_hash).toBe(encrypted.integrity_hash);
    expect(body.password).toBeUndefined();
  });

  test('getFiles sends authenticated GET /files and returns file list with stats', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        files: [{ id: 'f1', filename: 'report.pdf', size: 2048, upload_date: '2026-11-01T00:00:00Z' }],
        stats: { total_files: 1, total_size: 2048 },
      }),
    });

    const res = await getFiles('jwt-123');
    expect(res.ok).toBe(true);
    expect(res.data.files).toHaveLength(1);
    expect(res.data.stats.total_files).toBe(1);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/files'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({ Authorization: 'Bearer jwt-123' }),
      })
    );
  });

  test('deleteFile sends authenticated DELETE to /files/:id', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true, msg: 'File deleted successfully' }),
    });

    const res = await deleteFile('jwt-123', 'file-id-abc');
    expect(res.ok).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/files/file-id-abc'),
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.objectContaining({ Authorization: 'Bearer jwt-123' }),
      })
    );
  });

  test('downloadEncryptedFile fetches arrayBuffer with encryption headers without sending password', async () => {
    const rawBuffer = new Uint8Array([1, 2, 3, 4, 5]).buffer;
    const mockHeaders = new Headers({
      'Content-Disposition': 'attachment; filename="secret.bin"',
      'X-IV': 'iv-sample',
      'X-Salt': 'salt-sample',
      'X-Original-Mime': 'application/octet-stream',
    });

    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: mockHeaders,
      arrayBuffer: async () => rawBuffer,
    });

    const result = await downloadEncryptedFile('jwt-123', 'file-id-abc');
    expect(result.encryptedBytes).toBe(rawBuffer);
    expect(result.iv).toBe('iv-sample');
    expect(result.salt).toBe('salt-sample');
    expect(result.mimeType).toBe('application/octet-stream');

    const callArgs = global.fetch.mock.calls[0];
    expect(callArgs[1].method).toBe('GET');
    expect(callArgs[1].headers.Authorization).toBe('Bearer jwt-123');
    // ZERO-KNOWLEDGE: Verify no request body was sent with download GET
    expect(callArgs[1].body).toBeUndefined();
  });

  test('healthCheck reports backend availability', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true, status: 'Backend running', mongo: 'connected', storage: 'connected' }),
    });

    const res = await healthCheck();
    expect(res.ok).toBe(true);
    expect(res.data.mongo).toBe('connected');
    expect(res.data.storage).toBe('connected');
  });

  test('handles 401 session expiration cleanly across API calls', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: false, code: 'token_expired', msg: 'Session expired' }),
    });

    const res = await getFiles('expired-token');
    expect(res.ok).toBe(false);
    expect(res.status).toBe(401);
    expect(res.data.msg).toBe('Session expired');
  });

  test('handles 429 rate limiting with retry message', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 429,
      headers: new Headers({ 'content-type': 'application/json', 'Retry-After': '60' }),
      json: async () => ({ success: false, msg: 'Too many requests. Please slow down.' }),
    });

    const res = await loginRequest({ email: 'user@test.com', password: 'wrong' });
    expect(res.ok).toBe(false);
    expect(res.status).toBe(429);
    expect(res.data.msg).toContain('Too many requests');
  });

  // ---------------------------------------------------------------------------
  // Phase 8: Access Token Management tests
  // ---------------------------------------------------------------------------
  test('createAccessToken sends POST to /tokens/create with token options', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        token: 'sct_random_test_token_123',
        token_id: 'tok123',
        scope: 'download',
        max_downloads: 1,
        expires_at: '2026-11-02T00:00:00Z',
      }),
    });

    const res = await createAccessToken('jwt-auth-token', 'file-456', {
      scope: 'download',
      expiresInSeconds: 3600,
      maxDownloads: 1,
      label: 'Audit Share',
    });

    expect(res.ok).toBe(true);
    expect(res.status).toBe(201);
    expect(res.data.token).toBe('sct_random_test_token_123');

    const callArgs = global.fetch.mock.calls[0];
    expect(callArgs[0]).toContain('/tokens/create');
    expect(callArgs[1].method).toBe('POST');
    expect(callArgs[1].headers.Authorization).toBe('Bearer jwt-auth-token');
    expect(JSON.parse(callArgs[1].body)).toEqual({
      file_id: 'file-456',
      scope: 'download',
      expires_in_seconds: 3600,
      max_downloads: 1,
      label: 'Audit Share',
    });
  });

  test('getFileAccessTokens sends GET to /tokens/file/:id', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        tokens: [
          { id: 't1', scope: 'download', status: 'active', downloads_used: 0, max_downloads: 1 },
        ],
      }),
    });

    const res = await getFileAccessTokens('jwt-auth-token', 'file-456');
    expect(res.ok).toBe(true);
    expect(res.data.tokens).toHaveLength(1);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/tokens/file/file-456'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer jwt-auth-token',
        }),
      })
    );
  });

  test('revokeAccessToken sends DELETE to /tokens/:id', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        msg: 'Access token revoked successfully',
      }),
    });

    const res = await revokeAccessToken('jwt-auth-token', 'tok-to-revoke');
    expect(res.ok).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/tokens/tok-to-revoke'),
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.objectContaining({
          Authorization: 'Bearer jwt-auth-token',
        }),
      })
    );
  });

  test('validateAccessToken sends GET with X-Access-Token header', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        valid: true,
        file: { filename: 'report.pdf', size: 1024 },
      }),
    });

    const res = await validateAccessToken('sct_test_token_abc');
    expect(res.ok).toBe(true);
    expect(res.data.valid).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/tokens/validate'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          'X-Access-Token': 'sct_test_token_abc',
        }),
      })
    );
  });

  test('downloadFileWithAccessToken fetches binary stream and parses crypto headers', async () => {
    const fakeCiphertext = new Uint8Array([1, 2, 3, 4, 5]).buffer;
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({
        'content-type': 'application/octet-stream',
        'X-IV': 'iv123',
        'X-Salt': 'salt123',
        'X-Original-Mime': 'application/pdf',
        'X-Integrity-Hash': 'hash123',
        'X-Wrapped-Key': 'wrappedKey123',
        'X-Key-Fingerprint': 'fp123',
        'X-Token-Downloads-Remaining': '0',
      }),
      arrayBuffer: async () => fakeCiphertext,
    });

    const res = await downloadFileWithAccessToken('sct_test_token_abc');
    expect(res.encryptedBytes.byteLength).toBe(5);
    expect(res.iv).toBe('iv123');
    expect(res.salt).toBe('salt123');
    expect(res.wrappedKey).toBe('wrappedKey123');
    expect(res.keyFingerprint).toBe('fp123');
    expect(res.remaining).toBe('0');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/tokens/download'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          'X-Access-Token': 'sct_test_token_abc',
        }),
      })
    );
  });

  // ---------------------------------------------------------------------------
  // Phase 9: Secure File Sharing API integration tests
  // ---------------------------------------------------------------------------
  test('createFileShare sends POST to /shares with recipient wrapped key and metadata', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        share: {
          id: 'share-123',
          file_id: 'file-abc',
          recipient_email: 'recip@test.com',
          permission: 'download',
          status: 'active',
        },
      }),
    });

    const payload = {
      file_id: 'file-abc',
      recipient_email: 'recip@test.com',
      wrapped_key: 'b64wrappedKey==',
      key_fingerprint: 'fp-sha256',
      permission: 'download',
      expires_in_seconds: 86400,
      max_downloads: 1,
    };

    const res = await createFileShare('owner-jwt-token', payload);
    expect(res.ok).toBe(true);
    expect(res.status).toBe(201);
    expect(res.data.share.id).toBe('share-123');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer owner-jwt-token',
        }),
        body: JSON.stringify(payload),
      })
    );
  });

  test('getSentShares sends authenticated GET to /shares/sent', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        shares: [{ id: 'share-123', recipient_email: 'recip@test.com' }],
      }),
    });

    const res = await getSentShares('owner-token', 'file-abc');
    expect(res.ok).toBe(true);
    expect(res.data.shares.length).toBe(1);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/sent?file_id=file-abc'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer owner-token',
        }),
      })
    );
  });

  test('getFileShares sends authenticated GET to /shares/file/:fileId', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        shares: [{ id: 'share-456' }],
      }),
    });

    const res = await getFileShares('owner-token', 'file-123');
    expect(res.ok).toBe(true);
    expect(res.data.shares.length).toBe(1);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/file/file-123'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer owner-token',
        }),
      })
    );
  });

  test('getReceivedShares sends authenticated GET to /shares/received', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        shares: [{ id: 'share-789', owner_email: 'owner@test.com' }],
      }),
    });

    const res = await getReceivedShares('recip-token');
    expect(res.ok).toBe(true);
    expect(res.data.shares.length).toBe(1);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/received'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer recip-token',
        }),
      })
    );
  });

  test('getShareDetails sends authenticated GET to /shares/:shareId', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        share: { id: 'share-999', filename: 'report.pdf' },
      }),
    });

    const res = await getShareDetails('caller-token', 'share-999');
    expect(res.ok).toBe(true);
    expect(res.data.share.filename).toBe('report.pdf');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/share-999'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer caller-token',
        }),
      })
    );
  });

  test('revokeFileShare sends authenticated DELETE to /shares/:shareId', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        msg: 'File share revoked successfully',
      }),
    });

    const res = await revokeFileShare('owner-token', 'share-123');
    expect(res.ok).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/share-123'),
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.objectContaining({
          Authorization: 'Bearer owner-token',
        }),
      })
    );
  });

  test('downloadSharedFile streams ciphertext and parses recipient wrapped-key headers', async () => {
    const fakeCiphertext = new Uint8Array([10, 20, 30, 40]).buffer;
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({
        'content-type': 'application/octet-stream',
        'X-IV': 'share-iv-123',
        'X-Salt': 'share-salt-123',
        'X-Original-Mime': 'application/pdf',
        'X-Integrity-Hash': 'integrity-hash-abc',
        'X-Wrapped-Key': 'recipient-wrapped-key-b64',
        'X-Key-Fingerprint': 'fp-recip-123',
        'X-Share-Downloads-Remaining': '0',
        'X-Share-Permission': 'download',
      }),
      arrayBuffer: async () => fakeCiphertext,
    });

    const res = await downloadSharedFile('recip-jwt-token', 'share-123');
    expect(res.encryptedBytes.byteLength).toBe(4);
    expect(res.iv).toBe('share-iv-123');
    expect(res.wrappedKey).toBe('recipient-wrapped-key-b64');
    expect(res.keyFingerprint).toBe('fp-recip-123');
    expect(res.remaining).toBe('0');
    expect(res.permission).toBe('download');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/share-123/download'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer recip-jwt-token',
        }),
      })
    );
  });

  test('downloadSharedFileWithToken downloads via direct token URL', async () => {
    const fakeCiphertext = new Uint8Array([7, 8, 9]).buffer;
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({
        'content-type': 'application/octet-stream',
        'X-IV': 'token-iv',
        'X-Wrapped-Key': 'wrapped-token-key',
        'X-Share-Downloads-Remaining': '4',
      }),
      arrayBuffer: async () => fakeCiphertext,
    });

    const res = await downloadSharedFileWithToken('sct_share_xyz');
    expect(res.encryptedBytes.byteLength).toBe(3);
    expect(res.iv).toBe('token-iv');
    expect(res.wrappedKey).toBe('wrapped-token-key');
    expect(res.remaining).toBe('4');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/access/sct_share_xyz'),
      expect.objectContaining({
        method: 'GET',
      })
    );
  });

  test('downloadSharedFile throws ApiError with status and message when access is denied or expired', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 403,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: false, msg: 'This share link has expired' }),
    });

    await expect(downloadSharedFile('test-token', 'share-expired-1')).rejects.toMatchObject({
      name: 'ApiError',
      status: 403,
      message: 'This share link has expired',
    });
  });

  test('downloadSharedFile handles network error and throws ApiError with status 0', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(downloadSharedFile('test-token', 'share-net-1')).rejects.toMatchObject({
      name: 'ApiError',
      status: 0,
      message: 'Failed to fetch',
    });
  });

  // ---------------------------------------------------------------------------
  // Phase 11: Security Monitoring & Audit Logging Tests
  // ---------------------------------------------------------------------------
  test('getAuditLogs sends GET to /admin/audit-logs with query params', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        logs: [{ sequence: 1, event_type: 'LOGIN_SUCCESS' }],
        pagination: { page: 1, total: 1 },
      }),
    });

    const res = await getAuditLogs('admin-jwt-token', {
      page: 2,
      limit: 10,
      event_type: 'LOGIN_SUCCESS',
      severity: 'INFO',
    });
    expect(res.ok).toBe(true);
    expect(res.data.logs).toHaveLength(1);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringMatching(/\/admin\/audit-logs\?page=2&limit=10&event_type=LOGIN_SUCCESS&severity=INFO/),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer admin-jwt-token',
        }),
      })
    );
  });

  test('getAuditStats sends GET to /admin/audit-logs/stats', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        stats: { total_events: 50, failed_logins: 2 },
      }),
    });

    const res = await getAuditStats('admin-jwt-token');
    expect(res.ok).toBe(true);
    expect(res.data.stats.total_events).toBe(50);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/admin/audit-logs/stats'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer admin-jwt-token',
        }),
      })
    );
  });

  test('verifyAuditIntegrity sends GET to /admin/audit-logs/verify', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        verification: { verified: true, chain_intact: true, total_records: 50 },
      }),
    });

    const res = await verifyAuditIntegrity('admin-jwt-token');
    expect(res.ok).toBe(true);
    expect(res.data.verification.chain_intact).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/admin/audit-logs/verify'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer admin-jwt-token',
        }),
      })
    );
  });

  test('getAuditLogDetails sends GET to /admin/audit-logs/:id', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        success: true,
        log: { sequence: 42, event_type: 'FILE_UPLOAD', outcome: 'SUCCESS' },
      }),
    });

    const res = await getAuditLogDetails('admin-jwt-token', 'log-12345');
    expect(res.ok).toBe(true);
    expect(res.data.log.sequence).toBe(42);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/admin/audit-logs/log-12345'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer admin-jwt-token',
        }),
      })
    );
  });
});
