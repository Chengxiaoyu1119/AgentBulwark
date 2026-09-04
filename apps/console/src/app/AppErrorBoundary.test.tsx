import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppErrorBoundary } from './AppErrorBoundary';

function BrokenPage(): never {
  throw new Error('provider payload should stay out of the UI');
}

describe('AppErrorBoundary', () => {
  afterEach(() => vi.restoreAllMocks());

  it('keeps an unexpected page failure actionable without exposing the thrown payload', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const suppressUnhandledError = (event: ErrorEvent) => event.preventDefault();
    window.addEventListener('error', suppressUnhandledError);

    try {
      render(
        <AppErrorBoundary>
          <BrokenPage />
        </AppErrorBoundary>
      );

      expect(document.querySelector('main[role="alert"]')).not.toBeNull();
      expect(screen.getByRole('heading', { name: '控制台暂时无法渲染' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: '重新加载控制台' })).toBeInTheDocument();
      expect(screen.queryByText('provider payload should stay out of the UI')).not.toBeInTheDocument();
    } finally {
      window.removeEventListener('error', suppressUnhandledError);
    }
  });
});
