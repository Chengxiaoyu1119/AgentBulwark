import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RuntimeConnectionBadge } from './RuntimeConnectionBadge';
import { RuntimeConnectionNotice } from './RuntimeConnectionNotice';

describe('runtime connection status', () => {
  it('shows a visible retry attempt and its actionable reason', () => {
    const connection = {
      status: 'reconnecting' as const,
      attempt: 3,
      retryDelayMs: 4_000,
      message: '实时事件服务暂时不可用（HTTP 503）。4 秒后重试。'
    };
    render(
      <>
        <RuntimeConnectionBadge connection={connection} />
        <RuntimeConnectionNotice connection={connection} />
      </>
    );

    expect(screen.getByText('重连中（3）')).toBeInTheDocument();
    expect(screen.getByText('实时更新正在恢复')).toBeInTheDocument();
    expect(screen.getByText(connection.message)).toBeInTheDocument();
  });
});
