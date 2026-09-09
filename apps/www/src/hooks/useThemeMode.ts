import { useEffect, useState } from 'react';

export type ThemeMode = 'light' | 'dark';

const storageKey = 'agent-supervisor-theme';

function getPreferredTheme(): ThemeMode {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function normalizeTheme(value: string | null): ThemeMode | null {
  return value === 'light' || value === 'dark' ? value : null;
}

export function useThemeMode() {
  const [theme, setTheme] = useState<ThemeMode>('light');

  useEffect(() => {
    setTheme(normalizeTheme(window.localStorage.getItem(storageKey)) ?? getPreferredTheme());
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem(storageKey, theme);
  }, [theme]);

  const toggleTheme = () => setTheme((current) => (current === 'dark' ? 'light' : 'dark'));

  return { theme, toggleTheme };
}
