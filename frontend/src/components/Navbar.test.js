// =============================================================================
// components/Navbar.test.js — Unit and rendering tests for Navbar component
// =============================================================================
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Navbar from './Navbar';
import * as api from '../services/api';

global.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('../services/api');

describe('Navbar Component Header & Admin Indicators', () => {
  let container = null;
  let root = null;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    jest.clearAllMocks();
    localStorage.clear();

    api.getReceivedShares.mockResolvedValue({ ok: true, data: { shares: [] } });
    api.getAuditLogs.mockResolvedValue({ ok: true, data: { logs: [] } });
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

  test('renders active page title and standard user email without admin badge', async () => {
    const regularUser = { email: 'alice@example.com', is_admin: false, role: 'user' };
    await act(async () => {
      root.render(
        <Navbar
          user={regularUser}
          pageTitle="Privacy & PII Protection"
          onMenuToggle={() => {}}
        />
      );
    });

    expect(container.textContent).toContain('Privacy & PII Protection');
    expect(container.textContent).toContain('alice@example.com');
    expect(container.textContent).not.toContain('ADMIN');
  });

  test('renders ADMIN badge when user has is_admin flag set to true', async () => {
    const adminUser = { email: 'admin@securecloud.com', is_admin: true, role: 'admin' };
    await act(async () => {
      root.render(
        <Navbar
          user={adminUser}
          pageTitle="Security Monitoring & Audit"
          onMenuToggle={() => {}}
        />
      );
    });

    expect(container.textContent).toContain('Security Monitoring & Audit');
    expect(container.textContent).toContain('admin@securecloud.com');
    expect(container.textContent).toContain('ADMIN');
  });

  test('calls onMenuToggle when menu button is clicked', async () => {
    let toggled = false;
    await act(async () => {
      root.render(
        <Navbar
          user={{ email: 'bob@example.com' }}
          pageTitle="Dashboard"
          onMenuToggle={() => {
            toggled = true;
          }}
        />
      );
    });

    const menuButton = container.querySelector('button[aria-label="Toggle sidebar"]');
    expect(menuButton).toBeDefined();
    await act(async () => {
      menuButton.click();
    });
    expect(toggled).toBe(true);
  });

  test('bell button toggles the notifications panel open and closed', async () => {
    const user = { email: 'alice@example.com' };
    await act(async () => {
      root.render(
        <Navbar
          user={user}
          pageTitle="Dashboard"
          onMenuToggle={() => {}}
          token="test-token"
        />
      );
    });

    const bellBtn = container.querySelector('button[aria-label="Notifications"]');
    expect(bellBtn).toBeDefined();
    expect(bellBtn.getAttribute('aria-expanded')).toBe('false');
    expect(container.querySelector('[data-testid="notifications-panel"]')).toBeNull();

    // Click bell to open
    await act(async () => {
      bellBtn.click();
    });
    expect(bellBtn.getAttribute('aria-expanded')).toBe('true');
    expect(container.querySelector('[data-testid="notifications-panel"]')).not.toBeNull();
    expect(container.textContent).toContain('Notifications');

    // Click bell again to close
    await act(async () => {
      bellBtn.click();
    });
    expect(bellBtn.getAttribute('aria-expanded')).toBe('false');
    expect(container.querySelector('[data-testid="notifications-panel"]')).toBeNull();
  });

  test('renders empty state when there are no notifications', async () => {
    api.getReceivedShares.mockResolvedValue({ ok: true, data: { shares: [] } });
    const user = { email: 'alice@example.com' };

    await act(async () => {
      root.render(
        <Navbar
          user={user}
          pageTitle="Dashboard"
          onMenuToggle={() => {}}
          token="test-token"
        />
      );
    });

    const bellBtn = container.querySelector('button[aria-label="Notifications"]');
    await act(async () => {
      bellBtn.click();
    });

    const emptyState = container.querySelector('[data-testid="notifications-empty"]');
    expect(emptyState).not.toBeNull();
    expect(emptyState.textContent).toContain('No notifications');
    expect(emptyState.textContent).toContain("You're all caught up!");
    // Unread indicator should NOT be displayed when there are 0 unread
    expect(container.querySelector('[data-testid="unread-indicator"]')).toBeNull();
  });

  test('fetches received shares, renders notification items, and displays unread indicator', async () => {
    const mockShares = [
      {
        id: 'share_123',
        filename: 'tax_return_2026.pdf',
        owner_email: 'charlie@example.com',
        permission: 'download',
        status: 'active',
        created_at: new Date().toISOString(),
      },
      {
        id: 'share_456',
        filename: 'keys_backup.enc',
        owner_email: 'david@example.com',
        permission: 'view',
        status: 'active',
        created_at: new Date(Date.now() - 3600000).toISOString(),
      },
    ];
    api.getReceivedShares.mockResolvedValue({ ok: true, data: { shares: mockShares } });

    const user = { email: 'alice@example.com' };
    await act(async () => {
      root.render(
        <Navbar
          user={user}
          pageTitle="Dashboard"
          onMenuToggle={() => {}}
          token="test-token"
        />
      );
    });

    // Unread indicator dot should be visible
    expect(container.querySelector('[data-testid="unread-indicator"]')).not.toBeNull();

    // Open notifications panel
    const bellBtn = container.querySelector('button[aria-label="Notifications"]');
    await act(async () => {
      bellBtn.click();
    });

    const items = container.querySelectorAll('[data-testid="notification-item"]');
    expect(items.length).toBe(2);
    expect(container.textContent).toContain('charlie@example.com shared "tax_return_2026.pdf"');
    expect(container.textContent).toContain('david@example.com shared "keys_backup.enc"');
    expect(container.textContent).toContain('2 new');
  });

  test('marks all notifications as read when CheckCheck button is clicked', async () => {
    const mockShares = [
      {
        id: 'share_999',
        filename: 'confidential_report.pdf',
        owner_email: 'boss@example.com',
        permission: 'download',
        status: 'active',
        created_at: new Date().toISOString(),
      },
    ];
    api.getReceivedShares.mockResolvedValue({ ok: true, data: { shares: mockShares } });

    const user = { email: 'alice@example.com' };
    await act(async () => {
      root.render(
        <Navbar
          user={user}
          pageTitle="Dashboard"
          onMenuToggle={() => {}}
          token="test-token"
        />
      );
    });

    expect(container.querySelector('[data-testid="unread-indicator"]')).not.toBeNull();

    // Open panel
    const bellBtn = container.querySelector('button[aria-label="Notifications"]');
    await act(async () => {
      bellBtn.click();
    });

    const markAllBtn = container.querySelector('button[aria-label="Mark all as read"]');
    expect(markAllBtn).not.toBeNull();
    expect(markAllBtn.disabled).toBe(false);

    // Click Mark all as read
    await act(async () => {
      markAllBtn.click();
    });

    // Header badge updates to "All read"
    expect(container.textContent).toContain('All read');
    // Bell unread indicator is removed
    expect(container.querySelector('[data-testid="unread-indicator"]')).toBeNull();
    // LocalStorage persisted
    const saved = JSON.parse(localStorage.getItem('sc_read_notifications_alice@example.com'));
    expect(saved).toContain('share_share_999');
  });

  test('marks individual notification as read and navigates when clicked', async () => {
    let navigatedTo = null;
    const mockShares = [
      {
        id: 'share_single',
        filename: 'nda_signed.docx',
        owner_email: 'legal@example.com',
        permission: 'download',
        status: 'active',
        created_at: new Date().toISOString(),
      },
    ];
    api.getReceivedShares.mockResolvedValue({ ok: true, data: { shares: mockShares } });

    const user = { email: 'alice@example.com' };
    await act(async () => {
      root.render(
        <Navbar
          user={user}
          pageTitle="Dashboard"
          onMenuToggle={() => {}}
          token="test-token"
          onNavigate={(page) => {
            navigatedTo = page;
          }}
        />
      );
    });

    // Open panel
    const bellBtn = container.querySelector('button[aria-label="Notifications"]');
    await act(async () => {
      bellBtn.click();
    });

    const item = container.querySelector('[data-testid="notification-item"]');
    expect(item).not.toBeNull();

    // Click notification item
    await act(async () => {
      item.click();
    });

    expect(navigatedTo).toBe('shared');
    // Panel should close upon navigation
    expect(container.querySelector('[data-testid="notifications-panel"]')).toBeNull();
    // Indicator removed
    expect(container.querySelector('[data-testid="unread-indicator"]')).toBeNull();
  });

  test('closes notification panel when Escape key is pressed', async () => {
    const user = { email: 'alice@example.com' };
    await act(async () => {
      root.render(
        <Navbar
          user={user}
          pageTitle="Dashboard"
          onMenuToggle={() => {}}
          token="test-token"
        />
      );
    });

    const bellBtn = container.querySelector('button[aria-label="Notifications"]');
    await act(async () => {
      bellBtn.click();
    });
    expect(container.querySelector('[data-testid="notifications-panel"]')).not.toBeNull();

    // Press Escape
    await act(async () => {
      const event = new KeyboardEvent('keydown', { key: 'Escape' });
      document.dispatchEvent(event);
    });

    expect(container.querySelector('[data-testid="notifications-panel"]')).toBeNull();
  });

  test('closes notification panel when clicking outside', async () => {
    const user = { email: 'alice@example.com' };
    await act(async () => {
      root.render(
        <Navbar
          user={user}
          pageTitle="Dashboard"
          onMenuToggle={() => {}}
          token="test-token"
        />
      );
    });

    const bellBtn = container.querySelector('button[aria-label="Notifications"]');
    await act(async () => {
      bellBtn.click();
    });
    expect(container.querySelector('[data-testid="notifications-panel"]')).not.toBeNull();

    // Click outside on document.body
    await act(async () => {
      const outsideClick = new MouseEvent('mousedown', { bubbles: true });
      document.body.dispatchEvent(outsideClick);
    });

    expect(container.querySelector('[data-testid="notifications-panel"]')).toBeNull();
  });
});
