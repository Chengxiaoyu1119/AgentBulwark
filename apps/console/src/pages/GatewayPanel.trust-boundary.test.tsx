import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { GatewayPanel } from './GatewayPanel';
import { request } from '../app/apiRequest';

vi.mock('../app/apiRequest', () => ({
  request: vi.fn(),
  subscribeRuntimeEvents: vi.fn(
    (_onEvent, signal: AbortSignal) =>
      new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }))
  )
}));

describe('GatewayPanel trust boundary', () => {
  beforeEach(() => {
    vi.mocked(request).mockReset();
  });

  it('explains and disables generation for an observer-only credential', async () => {
    vi.mocked(request).mockResolvedValue({
      security_context: {
        role: 'observer',
        agent_id: '',
        identity_bound: false,
        can_generate: false,
        can_execute_managed_tools: false,
        can_view_console: true
      },
      models: { target: [] },
      proxy: { enabled: true, mode: 'transparent' }
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '验证防护' }));

    expect(await screen.findByText('当前凭证为观测角色')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '发送到网关' })).toBeDisabled();
  });

  it('marks local caller-declared receipt compatibility as a downgraded trust boundary', async () => {
    vi.mocked(request).mockResolvedValue({
      backend: { security_profile: 'local' },
      security_context: {
        role: 'analyst',
        agent_id: '',
        identity_bound: false,
        can_generate: true,
        can_execute_managed_tools: false,
        can_view_console: true
      },
      models: { target: [] },
      proxy: {
        enabled: true,
        mode: 'transparent',
        tool_receipts_required: true,
        server_observed_receipts_required: false
      }
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '接入应用' }));
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));

    expect(await screen.findByText('工具回执边界待完善')).toBeInTheDocument();
  });

  it('does not claim OpenAI protection is running before the server-observed tool boundary is ready', async () => {
    vi.mocked(request).mockResolvedValue({
      models: {
        target: [{ provider: 'fixture-provider', model: 'fixture-model', configured: true, mode: 'real-api' }]
      },
      proxy: {
        enabled: true,
        tool_receipts_required: true,
        server_observed_receipts_required: false
      },
      gateway_evidence: { fingerprint: 'fixture-fingerprint' }
    });

    render(<GatewayPanel />);

    expect(await screen.findByText('回执边界待闭合')).toBeInTheDocument();
    expect(screen.queryByText('防护已配置')).not.toBeInTheDocument();
    expect(screen.queryByText('防护运行中')).not.toBeInTheDocument();
  });

  it('does not claim MCP protection is running when its endpoint is disabled', async () => {
    vi.mocked(request).mockResolvedValue({
      models: { target: [] },
      proxy: { enabled: false },
      mcp: { configured: true, enabled: false, guard_enabled: true }
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('tab', { name: 'MCP 工具' }));

    expect(await screen.findByText('MCP 防护待启用')).toBeInTheDocument();
    expect(screen.queryByText('防护已配置')).not.toBeInTheDocument();
    expect(screen.queryByText('防护运行中')).not.toBeInTheDocument();
  });

  it('warns when one response accepted a caller-declared tool result', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          backend: { security_profile: 'local' },
          security_context: { role: 'analyst', can_generate: true, can_execute_managed_tools: false },
          models: {
            target: [{ provider: 'fixture-provider', model: 'fixture-model', configured: true, mode: 'real-api' }]
          },
          proxy: {
            enabled: true,
            mode: 'transparent',
            tool_receipts_required: true,
            server_observed_receipts_required: false
          }
        };
      }
      return {
        choices: [{ message: { role: 'assistant', content: 'ok' } }],
        agent_supervisor: {
          decision: '允许',
          tool_receipt_required: true,
          tool_receipt_server_observed_required: false,
          tool_receipt_evidence: 'caller-declared',
          tool_receipts_verified: 1,
          tool_receipts_server_observed: 0,
          tool_receipts_caller_declared: 1
        }
      };
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '验证防护' }));
    await userEvent.click(screen.getByRole('button', { name: '发送到网关' }));

    expect(await screen.findByText('本次工具结果仅有调用方声明')).toBeInTheDocument();
    expect(screen.getByText(/不代表智垒观察到实际工具执行/)).toBeInTheDocument();
  });
});
