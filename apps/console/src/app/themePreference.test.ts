import { beforeEach, describe, expect, it } from 'vitest';
import { readThemePreference, saveThemePreference } from './themePreference';

describe('themePreference', () => {
  beforeEach(() => {
    window.localStorage.clear();
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: (query: string) => ({
        matches: query.includes('dark'),
        media: query,
        onchange: null,
        addListener: () => undefined,
        removeListener: () => undefined,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false
      })
    });
  });

  it('prefers an explicit operator choice over the system preference', () => {
    saveThemePreference('light');
    expect(readThemePreference()).toBe('light');
  });

  it('uses the system preference when no choice has been saved', () => {
    expect(readThemePreference()).toBe('dark');
  });
});
