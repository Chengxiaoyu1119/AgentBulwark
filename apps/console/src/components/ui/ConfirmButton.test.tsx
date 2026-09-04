import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { UiConfirmButton } from './ConfirmButton';

describe('UiConfirmButton', () => {
  it('requires an explicit confirmation before invoking the action', async () => {
    const onConfirm = vi.fn();
    render(
      <UiConfirmButton danger confirmTitle="确认驳回？" confirmDescription="请求会保持阻断。" onConfirm={onConfirm}>
        驳回
      </UiConfirmButton>
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /驳\s*回/ }));
    expect(onConfirm).not.toHaveBeenCalled();
    expect(screen.getByText('确认驳回？')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /确\s*认/ }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
