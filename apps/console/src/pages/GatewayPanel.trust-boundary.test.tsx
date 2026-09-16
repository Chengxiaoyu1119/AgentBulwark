import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from '../app/apiRequest';
import { GatewayPanel } from './GatewayPanel';

vi.mock('../app/apiRequest', () => ({
  request: vi.fn(),
  subscribeRuntimeEvents: vi.fn(
    (_onEvent, signal: AbortSignal) =>
      new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }))
  )
}));

describe('GatewayPanel trust boundary', () => {
  beforeEach(() => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          models: {
            target: [{ provider: 'fixture-provider', model: 'fixture-model', configured: true, mode: 'real-api' }]
          },
          proxy: { enabled: true, tool_receipts_required: true, server_observed_receipts_required: false },
          gateway_evidence: { fingerprint: 'fixture-fingerprint' },
          mcp: { configured: false, enabled: false, guard_enabled: false }
        };
      }
      return { traces: [], summary: {}, total_available: 0 };
    });
  });

  it('不会在服务端回执边界未闭合时显示已配置', async () => {
    render(<GatewayPanel />);
    expect(await screen.findByText('边界待闭合')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '验证防护' })).not.toBeInTheDocument();
  });

  it('本地模式允许调用方回执兼容，不把可选服务端观察标成阻断', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          backend: { security_profile: 'local' },
          models: { target: [{ configured: true, mode: 'real-api' }] },
          proxy: { enabled: true, tool_receipts_required: true, server_observed_receipts_required: false },
          gateway_evidence: { fingerprint: 'local-fingerprint' },
          mcp: { configured: false, enabled: false, guard_enabled: true }
        };
      }
      return { traces: [], summary: {}, total_available: 0 };
    });

    render(<GatewayPanel />);
    expect(await screen.findByText('边界运行中')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'MCP 工具' }));
    expect(await screen.findByText('MCP 未配置（按需）')).toBeInTheDocument();
  });

  it('MCP 未启用时显示待启用状态并保持只读', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          models: { target: [] },
          proxy: { enabled: false },
          mcp: { configured: true, enabled: false, guard_enabled: true }
        };
      }
      return { traces: [], summary: {}, total_available: 0 };
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('tab', { name: 'MCP 工具' }));
    expect(await screen.findByText('MCP 服务未启用')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /initialize|tools\/list|tools\/call/i })).not.toBeInTheDocument();
  });
});
