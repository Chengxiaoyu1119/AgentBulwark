import { Github, Moon, Sun } from 'lucide-react';
import type { ThemeMode } from '../../hooks/useThemeMode';

type HeaderProps = {
  theme: ThemeMode;
  consoleUrl: string;
  repoUrl: string;
  onToggleTheme: () => void;
};

export function Header({ theme, consoleUrl, repoUrl, onToggleTheme }: HeaderProps) {
  return (
    <header className="site-header">
      <a className="brand" href="#top" aria-label="智安哨官网首页">
        <img src="/favicon.svg" alt="" />
        <span>智安哨</span>
      </a>

      <div className="header-tools">
        <button
          className="theme-toggle"
          type="button"
          role="switch"
          aria-label="切换深浅色模式"
          aria-checked={theme === 'dark'}
          onClick={onToggleTheme}
        >
          <span className="theme-toggle__track" aria-hidden="true">
            <span className="theme-toggle__thumb">
              <Sun className="theme-toggle__icon theme-toggle__icon--sun" size={12} />
              <Moon className="theme-toggle__icon theme-toggle__icon--moon" size={12} />
            </span>
          </span>
        </button>
        <span className="header-tools__divider" aria-hidden="true" />
        <a className="header-icon-link" href={repoUrl} target="_blank" rel="noreferrer" aria-label="打开 GitHub 仓库">
          <Github size={20} />
        </a>
        <a className="header-action" href={consoleUrl}>
          控制台
        </a>
      </div>
    </header>
  );
}
