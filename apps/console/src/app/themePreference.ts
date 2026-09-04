export type AppTheme = 'light' | 'dark';

const THEME_STORAGE_KEY = 'agent-supervisor-theme';

function isAppTheme(value: string | null): value is AppTheme {
  return value === 'light' || value === 'dark';
}

/**
 * Read the operator's explicit theme choice first, then fall back to the
 * operating-system preference. Storage and matchMedia are both optional so a
 * restricted browser context still gets a deterministic light theme.
 */
export function readThemePreference(): AppTheme {
  if (typeof window === 'undefined') return 'light';
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (isAppTheme(stored)) return stored;
  } catch {
    // A blocked storage context should not prevent the console from loading.
  }

  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

export function saveThemePreference(theme: AppTheme) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // The current page still uses the selected theme when persistence is not available.
  }
}
