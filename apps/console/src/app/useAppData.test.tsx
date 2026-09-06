import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from './apiRequest';
import { fetchHealth, fetchOverview } from './operationalApi';
import { useAppData } from './useAppData';

vi.mock('./operationalApi', () => ({
  fetchHealth: vi.fn(),
  fetchOverview: vi.fn()
}));

function Probe() {
  const { apiAvailable, apiNotice, connection, refreshing, overview, refresh } = useAppData('protection');
  return (
    <div>
      <span data-testid="api-available">{String(apiAvailable)}</span>
      <span data-testid="connection-status">{connection.status}</span>
      <span data-testid="refreshing">{String(refreshing)}</span>
      <span data-testid="overview">{overview ? 'ready' : 'empty'}</span>
      <span data-testid="notice">{apiNotice}</span>
      <button type="button" onClick={() => void refresh()}>
        refresh
      </button>
    </div>
  );
}

const liveOverview = {
  models: [],
  recent_runs: [],
  alerts: [],
  audit_logs: [],
  summary: {
    recent_run_count: 0,
    block_rate: 0,
    avg_latency_ms: 0
  }
};

describe('useAppData', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('keeps the last successful snapshot when a later overview read fails', async () => {
    vi.mocked(fetchHealth).mockResolvedValue(true);
    vi.mocked(fetchOverview).mockResolvedValue(liveOverview);

    render(<Probe />);

    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('online'));
    expect(screen.getByTestId('overview')).toHaveTextContent('ready');
    vi.mocked(fetchOverview).mockRejectedValue(new Error('数据库读取失败'));
    screen.getByRole('button', { name: 'refresh' }).click();

    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('degraded'));
    expect(screen.getByTestId('api-available')).toHaveTextContent('true');
    expect(screen.getByTestId('overview')).toHaveTextContent('ready');
    expect(screen.getByTestId('notice')).toHaveTextContent(
      '后端在线，但实时总览读取失败：数据库读取失败 当前显示的是最后一次成功读取的陈旧快照。'
    );
    expect(screen.getByTestId('refreshing')).toHaveTextContent('false');
  });

  it('marks a health failure as offline and stops the refresh state', async () => {
    vi.mocked(fetchHealth).mockResolvedValue(false);

    render(<Probe />);

    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('offline'));
    expect(screen.getByTestId('api-available')).toHaveTextContent('false');
    expect(screen.getByTestId('overview')).toHaveTextContent('empty');
    expect(screen.getByTestId('notice')).toHaveTextContent('后端连接中断');
    expect(screen.getByTestId('refreshing')).toHaveTextContent('false');
    expect(fetchOverview).not.toHaveBeenCalled();
  });

  it('classifies an authorization failure as an expired session, not an offline backend', async () => {
    vi.mocked(fetchHealth).mockRejectedValue(
      new ApiError('Invalid token', { code: 'http_error', path: '/api/health', status: 401 })
    );

    render(<Probe />);

    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('auth-expired'));
    expect(screen.getByTestId('api-available')).toHaveTextContent('true');
    expect(screen.getByTestId('overview')).toHaveTextContent('empty');
    expect(screen.getByTestId('notice')).toHaveTextContent('当前会话已失效');
  });

  it('classifies a forbidden overview read separately while retaining the snapshot', async () => {
    vi.mocked(fetchHealth).mockResolvedValue(true);
    vi.mocked(fetchOverview)
      .mockResolvedValueOnce(liveOverview)
      .mockRejectedValueOnce(new ApiError('Forbidden', { code: 'http_error', path: '/api/overview', status: 403 }));

    render(<Probe />);
    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('online'));
    screen.getByRole('button', { name: 'refresh' }).click();

    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('forbidden'));
    expect(screen.getByTestId('api-available')).toHaveTextContent('true');
    expect(screen.getByTestId('overview')).toHaveTextContent('ready');
    expect(screen.getByTestId('notice')).toHaveTextContent('没有读取实时运行数据的权限');
  });

  it('redacts and bounds backend diagnostics shown with a stale snapshot', async () => {
    vi.mocked(fetchHealth).mockResolvedValue(true);
    vi.mocked(fetchOverview)
      .mockResolvedValueOnce(liveOverview)
      .mockRejectedValueOnce(
        new ApiError(`query failed token=super-secret ${'x'.repeat(300)}`, {
          code: 'http_error',
          path: '/api/overview',
          status: 500
        })
      );

    render(<Probe />);
    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('online'));
    screen.getByRole('button', { name: 'refresh' }).click();
    await waitFor(() => expect(screen.getByTestId('connection-status')).toHaveTextContent('degraded'));

    const notice = screen.getByTestId('notice').textContent ?? '';
    expect(notice).toContain('token=[已隐藏]');
    expect(notice).not.toContain('super-secret');
    expect(notice.length).toBeLessThan(220);
  });
});
