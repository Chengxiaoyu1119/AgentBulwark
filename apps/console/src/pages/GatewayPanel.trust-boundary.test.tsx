import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { GatewayPanel } from './GatewayPanel';
import { request } from '../app/apiRequest';

vi.mock('../app/apiRequest', () => ({
  request: vi.fn(),
  subscribeRuntimeEvents: vi.fn((_onEvent, signal: AbortSignal) =>
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

    expect(await screen.findByText('当前凭证只有观测权限，不能发起模型请求。')).toBeInTheDocument();
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

    expect(await screen.findByText('工具结果信任')).toBeInTheDocument();
    expect(screen.getByText('调用方声明兼容')).toBeInTheDocument();
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
    expect(await screen.findByText('调用方声明兼容')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '发送到网关' }));

    expect(await screen.findByText('本次工具结果仅有调用方声明')).toBeInTheDocument();
    expect(screen.getByText(/不代表智安哨观察到实际工具执行/)).toBeInTheDocument();
  });
});
