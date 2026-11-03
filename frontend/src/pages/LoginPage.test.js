// =============================================================================
// pages/LoginPage.test.js — Unit and integration tests for LoginPage
// =============================================================================
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import LoginPage from './LoginPage';
import * as api from '../services/api';

global.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('../services/api');

describe('LoginPage Authentication Forms & Client Validation', () => {
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

  test('renders Sign In form by default with zero-knowledge branding', () => {
    act(() => {
      root.render(<LoginPage onLogin={() => {}} />);
    });

    expect(container.textContent).toContain('Welcome Back');
    expect(container.textContent).toContain('Sign In');
    expect(container.textContent).toContain('End-to-end encrypted · Zero-knowledge');
  });

  test('toggles to Create Account view when switch link is clicked', () => {
    act(() => {
      root.render(<LoginPage onLogin={() => {}} />);
    });

    const switchBtn = Array.from(container.querySelectorAll('button')).find((b) =>
      b.textContent.includes('Create Account')
    );
    expect(switchBtn).toBeDefined();

    act(() => {
      switchBtn.click();
    });

    expect(container.textContent).toContain('Create Account');
    expect(container.textContent).toContain('Confirm Password');
  });

  test('validates required fields on empty submit without calling API', async () => {
    act(() => {
      root.render(<LoginPage onLogin={() => {}} />);
    });

    const form = container.querySelector('form');
    await act(async () => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });

    expect(api.loginRequest).not.toHaveBeenCalled();
    expect(container.textContent).toContain('Fields cannot be empty');
  });

  test('submits valid credentials and triggers onLogin with token and user object', async () => {
    const mockAuthResponse = {
      ok: true,
      status: 200,
      data: {
        token: 'valid.jwt.token',
        user: { email: 'test@example.com', is_admin: false, role: 'user' },
      },
    };
    api.loginRequest.mockResolvedValue(mockAuthResponse);

    let loggedInData = null;
    act(() => {
      root.render(
        <LoginPage
          onLogin={(data) => {
            loggedInData = data;
          }}
        />
      );
    });

    const emailInput = container.querySelector('input[type="email"]');
    const passwordInput = container.querySelector('input[type="password"]');

    act(() => {
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype,
        'value'
      ).set;
      nativeInputValueSetter.call(emailInput, 'test@example.com');
      emailInput.dispatchEvent(new Event('input', { bubbles: true }));

      nativeInputValueSetter.call(passwordInput, 'ValidPass123!');
      passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
    });

    const form = container.querySelector('form');
    await act(async () => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });

    expect(api.loginRequest).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: 'ValidPass123!',
    });
    expect(loggedInData).toEqual(mockAuthResponse.data);
  });
});
