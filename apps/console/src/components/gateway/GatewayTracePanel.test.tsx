import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from '../../app/apiRequest';
import { GatewayTracePanel } from './GatewayTracePanel';

vi.mock('../../app/apiRequest', () => ({
  request: vi.fn(),
  subscribeRuntimeEvents: vi.fn(
    (_onEvent, signal: AbortSignal) =>
      new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }))
  )
}));

const trace = {
  request_id: 'gateway-trace-1',
  decision: '允许',
  provider: 'fixture-provider',
  model: 'fixture-model',
  last_seen: '2026-08-23T10:00:00Z'
};

describe('GatewayTracePanel', () => {
  beforeEach(() => {
    vi.mocked(request).mockReset();
    vi.mocked(request).mockResolvedValue({ traces: [trace], summary: {}, count: 1, total_available: 1 });
  });

  it('removes stale traces when the next live read fails', async () => {
    const user = userEvent.setup();
    render(<GatewayTracePanel />);

    expect(await screen.findByRole('button', { name: /gateway-trace-1/ }, { timeout: 10_000 })).toBeInTheDocument();
    vi.mocked(request).mockRejectedValueOnce(new Error('实时流量暂时不可用'));
    await user.click(screen.getByRole('button', { name: '刷新' }));

    expect(await screen.findByText('实时流量暂时不可用')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /gateway-trace-1/ })).not.toBeInTheDocument();
    expect(screen.queryByText('等待第一条请求')).not.toBeInTheDocument();
  });

  it('keeps the trace list visible when only the selected detail read fails', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/gateway/traces?limit=50') {
        return { traces: [trace], summary: {}, count: 1, total_available: 1 };
      }
      throw new Error('请求详情暂时不可用');
    });
    render(<GatewayTracePanel />);

    const row = await screen.findByRole('button', { name: /gateway-trace-1/ }, { timeout: 10_000 });
    await userEvent.click(row);

    expect(await screen.findByText('请求详情读取失败')).toBeInTheDocument();
    expect(screen.getByText('请求详情暂时不可用')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /gateway-trace-1/ })).toBeInTheDocument();
    expect(screen.queryByText('实时流量读取失败')).not.toBeInTheDocument();
  });

  it('uses the server distribution and operational queue for event metrics', async () => {
    vi.mocked(request).mockResolvedValue({
      traces: [{ ...trace, decision: '拒绝' }],
      summary: {
        controlled_count: 41,
        decision_distribution: { 拒绝: 21, 询问: 13, 隔离: 7 }
      },
      count: 1,
      total_available: 41
    });

    render(<GatewayTracePanel mode="events" pendingApprovalCount={4} />);

    expect(await screen.findByText('受控事件')).toHaveTextContent('受控事件');
    expect(screen.getByText('受控事件').parentElement).toHaveTextContent('41');
    expect(screen.getByText('已阻断').parentElement).toHaveTextContent('21');
    expect(screen.getByText('待处理').parentElement).toHaveTextContent('4');
    expect(screen.getByText('已隔离').parentElement).toHaveTextContent('7');
  });

  it('keeps operational columns fixed when a trace contains long identifiers', async () => {
    const longAgent = `agent-${'x'.repeat(160)}`;
    const longSession = `session-${'y'.repeat(160)}`;
    vi.mocked(request).mockResolvedValue({
      traces: [
        {
          ...trace,
          decision: '拒绝',
          agent_id: longAgent,
          session_id: longSession
        }
      ],
      summary: {},
      count: 1,
      total_available: 1
    });

    const { container } = render(<GatewayTracePanel mode="events" />);
    expect(await screen.findByRole('button', { name: /gateway-trace-1/ }, { timeout: 10_000 })).toBeInTheDocument();
    expect(container.querySelector('table')).toHaveStyle({ tableLayout: 'fixed' });
    expect(container.querySelectorAll('.zh-traffic-cell-stack')).toHaveLength(4);
    expect(screen.getByTitle(longAgent)).toHaveClass('ant-typography-ellipsis');
    expect(screen.getByTitle(longSession)).toHaveClass('ant-typography-ellipsis');
    expect(
      screen
        .getAllByRole('columnheader')
        .slice(0, 2)
        .map((header) => header.textContent)
    ).toEqual(['时间 / 请求', '处置']);
  });
});
