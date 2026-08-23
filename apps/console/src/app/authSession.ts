import type { AuthContext } from '../types';
import { request } from './apiRequest';

const AUTH_STORAGE_KEY = 'agent-supervisor-api-token';
const configuredApiToken = import.meta.env.VITE_AGENT_SUPERVISOR_API_TOKEN?.trim() ?? '';

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
    return window.sessionStorage.getItem(AUTH_STORAGE_KEY) || configuredApiToken || null;
  } catch {
    return configuredApiToken || null;
  }
}

export function storeAuthToken(token: string) {
  window.sessionStorage.setItem(AUTH_STORAGE_KEY, token.trim());
}

export function clearAuthToken() {
  try {
    window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
    window.localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Storage may be unavailable in a restricted browser context. The in-page
    // session still returns to the authentication gate.
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
