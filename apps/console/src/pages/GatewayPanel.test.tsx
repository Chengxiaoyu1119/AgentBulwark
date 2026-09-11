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

const runtimeStatus = {
  backend: { security_profile: 'production' },
  models: { target: [{ provider: 'fixture-provider', model: 'fixture-model', configured: true, mode: 'real-api' }] },
  proxy: { enabled: true, tool_receipts_required: true, server_observed_receipts_required: true },
  gateway_evidence: { fingerprint: 'fixture-fingerprint', started_at: '2026-08-16T19:00:00Z' },
  audit_integrity: { hmac_configured: true, receipt_signatures_required: true, key_id: 'fixture-key' },
  mcp: { configured: false, enabled: false, guard_enabled: false }
};

describe('GatewayPanel', () => {
  beforeEach(() => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') return runtimeStatus;
      if (path === '/api/gateway/traces?limit=50') return { traces: [], summary: {}, total_available: 0 };
      return {};
    });
  });

  it('只展示真实运行状态，不渲染手工验证入口', async () => {
    render(<GatewayPanel />);

    expect(await screen.findByText('边界运行中')).toBeInTheDocument();
    expect(screen.getByText('等待第一条请求')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '验证防护' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '发送验证请求' })).not.toBeInTheDocument();
    expect(screen.queryByText('验证一条真实请求')).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: '网关请求 JSON' })).not.toBeInTheDocument();
  });

  it('MCP 页面只展示状态与接入地址，不提供手工协议调用', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          ...runtimeStatus,
          mcp: { configured: true, enabled: true, guard_enabled: true, session_isolation: { enabled: true } }
        };
      }
      return { traces: [], summary: {}, total_available: 0 };
    });

    render(<GatewayPanel />);
    expect(await screen.findByText('边界运行中')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'MCP 工具' }));

    expect(await screen.findByText('MCP 运行状态')).toBeInTheDocument();
    expect(screen.getByText(/由 Agent 请求触发/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '复制 MCP 地址' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /initialize|tools\/list|tools\/call/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('运行状态读取失败时显示明确错误', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') throw new Error('运行状态接口暂时不可用');
      return { traces: [], summary: {}, total_available: 0 };
    });

    render(<GatewayPanel />);
    expect(await screen.findByRole('alert')).toHaveTextContent('运行状态读取失败');
    expect(screen.getByRole('alert')).toHaveTextContent('运行状态接口暂时不可用');
  });
});
