import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { UiDataState } from './DataState';

describe('UiDataState', () => {
  it('does not expose stale content while loading', () => {
    render(<UiDataState status="loading" title="正在读取实时请求…" />);
    expect(screen.getByRole('status')).toHaveTextContent('正在读取实时请求…');
  });

  it('renders a retry action for an error state', () => {
    render(
      <UiDataState
        status="error"
        title="实时流量读取失败"
        description="连接超时"
        action={<button type="button">重试读取</button>}
      />
    );
    expect(screen.getByRole('alert')).toHaveTextContent('连接超时');
    expect(screen.getByRole('button', { name: '重试读取' })).toBeInTheDocument();
  });

  it('renders ready content without an extra state wrapper', () => {
    render(
      <UiDataState status="ready">
        <p>实时内容</p>
      </UiDataState>
    );
    expect(screen.getByText('实时内容')).toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});
