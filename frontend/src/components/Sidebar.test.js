// =============================================================================
// components/Sidebar.test.js — Unit and rendering tests for Sidebar component
// =============================================================================
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Sidebar from './Sidebar';

global.IS_REACT_ACT_ENVIRONMENT = true;

describe('Sidebar Component Navigation & Role Isolation', () => {
  let container = null;
  let root = null;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
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

  test('renders base navigation items for standard non-admin user', () => {
    const regularUser = { email: 'user@example.com', is_admin: false, role: 'user' };
    act(() => {
      root.render(
        <Sidebar
          activePage="dashboard"
          setActivePage={() => {}}
          onLogout={() => {}}
          isOpen={true}
          onClose={() => {}}
          user={regularUser}
        />
      );
    });

    const textContent = container.textContent;
    expect(textContent).toContain('CipherVault');
    expect(textContent).toContain('ZERO-KNOWLEDGE VAULT');
    expect(textContent).toContain('Dashboard');
    expect(textContent).toContain('Upload');
    expect(textContent).toContain('My Files');
    expect(textContent).toContain('Shared');
    expect(textContent).toContain('Privacy & PII');

    // Security & Audit must NOT be present for standard users
    expect(textContent).not.toContain('Security & Audit');
  });

  test('renders Security & Audit navigation item for admin user', () => {
    const adminUser = { email: 'admin@securecloud.com', is_admin: true, role: 'admin' };
    act(() => {
      root.render(
        <Sidebar
          activePage="dashboard"
          setActivePage={() => {}}
          onLogout={() => {}}
          isOpen={true}
          onClose={() => {}}
          user={adminUser}
        />
      );
    });

    const textContent = container.textContent;
    expect(textContent).toContain('CipherVault');
    expect(textContent).toContain('ZERO-KNOWLEDGE VAULT');
    expect(textContent).toContain('Dashboard');
    expect(textContent).toContain('Upload');
    expect(textContent).toContain('My Files');
    expect(textContent).toContain('Shared');
    expect(textContent).toContain('Privacy & PII');

    // Security & Audit MUST be present for admin users
    expect(textContent).toContain('Security & Audit');
  });

  test('clicking a navigation item calls setActivePage and onClose', () => {
    const regularUser = { email: 'user@example.com', is_admin: false };
    let selectedPage = null;
    let closed = false;

    act(() => {
      root.render(
        <Sidebar
          activePage="dashboard"
          setActivePage={(page) => {
            selectedPage = page;
          }}
          onLogout={() => {}}
          isOpen={true}
          onClose={() => {
            closed = true;
          }}
          user={regularUser}
        />
      );
    });

    const buttons = container.querySelectorAll('nav button');
    // Button index 1 is Upload
    const uploadBtn = Array.from(buttons).find((b) => b.textContent.includes('Upload'));
    expect(uploadBtn).toBeDefined();

    act(() => {
      uploadBtn.click();
    });

    expect(selectedPage).toBe('upload');
    expect(closed).toBe(true);
  });
});
