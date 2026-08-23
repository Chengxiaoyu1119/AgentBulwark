import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { openAuthenticatedResource } from '../../app/apiRequest';
import { UiButton } from './Button';

vi.mock('../../app/apiRequest', () => ({
  openAuthenticatedResource: vi.fn()
}));

describe('UiButton', () => {
  beforeEach(() => {
    vi.mocked(openAuthenticatedResource).mockReset();
  });

  it('uses the shared authenticated opener instead of native navigation', async () => {
    vi.mocked(openAuthenticatedResource).mockResolvedValue(undefined);
    render(
      <UiButton authenticatedHref="/api/report" target="_blank">
        打开报告
      </UiButton>
    );

    const button = screen.getByRole('button', { name: '打开报告' });
    await userEvent.click(button);

    expect(openAuthenticatedResource).toHaveBeenCalledWith('/api/report');
    expect(button).not.toHaveAttribute('href');
  });
});
