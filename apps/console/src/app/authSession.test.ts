import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearAuthToken, getAuthToken, storeAuthToken } from './authSession';

describe('authSession storage fallback', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    clearAuthToken();
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    clearAuthToken();
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it('trims and reads an operator token from the current browser session', () => {
    storeAuthToken('  operator-token  ');

    expect(getAuthToken()).toBe('operator-token');
    expect(window.sessionStorage.getItem('agent-supervisor-api-token')).toBe('operator-token');
  });

  it('keeps a validated token in memory when sessionStorage rejects writes', () => {
    vi.spyOn(window.sessionStorage, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage disabled', 'SecurityError');
    });

    expect(() => storeAuthToken('  memory-token  ')).not.toThrow();
    expect(getAuthToken()).toBe('memory-token');
  });

  it('keeps the in-page token available when a later storage read is rejected', () => {
    storeAuthToken('memory-token');
    vi.spyOn(window.sessionStorage, 'getItem').mockImplementation(() => {
      throw new DOMException('Storage disabled', 'SecurityError');
    });

    expect(getAuthToken()).toBe('memory-token');
  });

  it('stops using an in-page token after its persisted session entry is removed', () => {
    storeAuthToken('memory-token');
    window.sessionStorage.removeItem('agent-supervisor-api-token');

    expect(getAuthToken()).toBeNull();
  });

  it('clears the in-page token even when browser storage cleanup fails', () => {
    storeAuthToken('memory-token');
    vi.spyOn(window.sessionStorage, 'removeItem').mockImplementation(() => {
      throw new DOMException('Storage disabled', 'SecurityError');
    });

    expect(() => clearAuthToken()).not.toThrow();
    expect(getAuthToken()).toBeNull();
  });
});
