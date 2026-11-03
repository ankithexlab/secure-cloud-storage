// =============================================================================
// pages/AuditLogsPage.test.js — Unit and integration tests for AuditLogsPage
// =============================================================================
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AuditLogsPage from './AuditLogsPage';
import * as api from '../services/api';

global.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('../services/api');

describe('AuditLogsPage Security Portal & Access Controls', () => {
  let container = null;
  let root = null;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    jest.clearAllMocks();
  });

  afterEach(() => {
    act(() => {
      if (root) {
        root.unmount();
      }
    });
    if (container) {
      container.remove();
      container = null;
    }
  });

  test('displays Administrator Access Required screen when API returns 403 Forbidden', async () => {
    api.getAuditStats.mockResolvedValue({ ok: false, status: 403, data: { msg: 'Forbidden' } });
    api.getAuditLogs.mockResolvedValue({ ok: false, status: 403, data: { msg: 'Forbidden' } });

    await act(async () => {
      root.render(<AuditLogsPage token="regular-user-token" onSessionExpired={() => {}} />);
    });

    expect(container.textContent).toContain('Administrator Access Required');
    expect(container.textContent).toContain('restricted to authenticated portal administrators');
  });

  test('renders security metrics cards and audit log entries for authorized admin', async () => {
    const mockStats = {
      total_events: 42,
      failed_logins: 3,
      unauthorized_attempts: 1,
      severity_breakdown: { INFO: 38, WARNING: 3, CRITICAL: 1 },
      top_events: [{ _id: 'FILE_UPLOAD', count: 20 }],
    };

    const mockLogs = [
      {
        id: 'log1234567890abcdef',
        sequence: 1,
        timestamp: '2026-11-01T12:00:00Z',
        event_type: 'FILE_UPLOAD',
        severity: 'INFO',
        outcome: 'SUCCESS',
        user_email: 'admin@securecloud.com',
        resource_id: 'file_999',
        details: { filename: 'test_doc.pdf', size: 1024 },
        entry_hash: 'abc123def456',
        prev_hash: 'GENESIS',
      },
    ];

    api.getAuditStats.mockResolvedValue({ ok: true, status: 200, data: { stats: mockStats } });
    api.getAuditLogs.mockResolvedValue({
      ok: true,
      status: 200,
      data: {
        logs: mockLogs,
        pagination: { total: 1, page: 1, total_pages: 1 },
      },
    });

    await act(async () => {
      root.render(<AuditLogsPage token="admin-token" onSessionExpired={() => {}} />);
    });

    expect(container.textContent).toContain('Security Monitoring & Audit Logging');
    expect(container.textContent).toContain('Total Audited Events');
    expect(container.textContent).toContain('42');
    expect(container.textContent).toContain('FILE_UPLOAD');
    expect(container.textContent).toContain('admin@securecloud.com');
  });

  test('clicking Verify Merkle Chain calls verifyAuditIntegrity API', async () => {
    api.getAuditStats.mockResolvedValue({ ok: true, status: 200, data: { stats: {} } });
    api.getAuditLogs.mockResolvedValue({
      ok: true,
      status: 200,
      data: { logs: [], pagination: { total: 0, page: 1, total_pages: 1 } },
    });
    api.verifyAuditIntegrity.mockResolvedValue({
      ok: true,
      status: 200,
      data: {
        success: true,
        verification: {
          verified: true,
          chain_intact: true,
          total_records: 50,
          mismatches: 0,
          sequence_gaps: 0,
        },
      },
    });

    await act(async () => {
      root.render(<AuditLogsPage token="admin-token" onSessionExpired={() => {}} />);
    });

    const verifyBtn = Array.from(container.querySelectorAll('button')).find((b) =>
      b.textContent.includes('Verify Merkle Chain')
    );
    expect(verifyBtn).toBeDefined();

    await act(async () => {
      verifyBtn.click();
    });

    expect(api.verifyAuditIntegrity).toHaveBeenCalledWith('admin-token');
    expect(container.textContent).toContain('Ledger Integrity');
    expect(container.textContent).toContain('Verified Intact');
  });
});
