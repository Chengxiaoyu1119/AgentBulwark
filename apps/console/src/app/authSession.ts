import type { AuthContext } from '../types';
import { request } from './apiRequest';

const AUTH_STORAGE_KEY = 'agent-supervisor-api-token';

// sessionStorage can be unavailable in privacy-restricted or embedded browser
// contexts (for example when the origin is blocked from using DOM storage).
// Keep a short-lived in-page copy so a successfully validated operator session
// can still continue without persisting credentials outside the current tab.
let inMemoryAuthToken: string | null = null;
let memoryOnlyAuthToken = false;

export type PublicConsoleStatus = {
  ok: boolean;
  service: string;
  console_auth: {
    required: boolean;
    transport: 'bearer' | string;
    profile: 'local' | 'production' | string;
  };
};

export function getAuthToken() {
  try {
    const storedToken = window.sessionStorage.getItem(AUTH_STORAGE_KEY);
    if (storedToken) {
      inMemoryAuthToken = storedToken;
      memoryOnlyAuthToken = false;
      return storedToken;
    }
    if (!memoryOnlyAuthToken) inMemoryAuthToken = null;
  } catch {
    // Fall through to the in-page session when browser storage is blocked.
  }
  return inMemoryAuthToken;
}

export function storeAuthToken(token: string) {
  const normalizedToken = token.trim();
  inMemoryAuthToken = normalizedToken || null;
  try {
    window.sessionStorage.setItem(AUTH_STORAGE_KEY, normalizedToken);
    memoryOnlyAuthToken = false;
  } catch {
    memoryOnlyAuthToken = Boolean(normalizedToken);
    // A validated token remains available for this tab even when storage is
    // blocked. It is deliberately not copied to localStorage or a build-time
    // environment variable.
  }
}

export function clearAuthToken() {
  inMemoryAuthToken = null;
  memoryOnlyAuthToken = false;
  try {
    window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Storage may be unavailable in a restricted browser context. The in-page
    // session still returns to the authentication gate.
  }
  try {
    // Remove the legacy localStorage key independently so a failure in one
    // storage backend does not leave credentials behind in the other.
    window.localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Storage may be unavailable in a restricted browser context.
  }
}

export function fetchPublicConsoleStatus() {
  return request<PublicConsoleStatus>('/api/public/status', undefined, {
    retry: 1,
    timeoutMs: 5000,
    skipAuth: true
  });
}

export function validateOperatorToken(token?: string | null) {
  return request<AuthContext>('/api/auth/context', undefined, {
    retry: 0,
    timeoutMs: 5000,
    authToken: token
  });
}
