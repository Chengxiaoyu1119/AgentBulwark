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

describe('GatewayPanel', () => {
  beforeEach(() => {
    vi.mocked(request).mockReset();
  });

  it('sends the edited request to the transparent gateway and renders evidence', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          backend: { security_profile: 'production' },
          models: {
            real_api_enabled: true,
            target: [{ provider: 'fixture-provider', model: 'fixture-model', configured: true, mode: 'real-api' }]
          },
          proxy: {
            enabled: true,
            mode: 'transparent',
            tool_receipts_required: true,
            server_observed_receipts_required: true
          },
          semantic_detector: { enabled: true, loaded: false },
          mcp: { configured: false, enabled: false, guard_enabled: false, resource_limits: { os_enforced: false } },
          gateway_evidence: { fingerprint: 'fixture-gateway-fingerprint', started_at: '2026-08-16T19:00:00Z' }
        };
      }
      return {
        choices: [{ message: { role: 'assistant', content: 'ok' } }],
        agent_supervisor: {
          decision: '允许',
          request_stage: 'post-provider-output',
          provider_called: true,
          provider: 'fixture-provider',
          policy_id: 'default-allow',
          audit_id: 'audit-1',
          gateway_audit_id: 'audit-1',
          gateway_contract_evidence: 'provider-response-returned',
          evidence_scope: 'gateway-contract',
          request_hash: 'request-1',
          provider_request_hash: 'provider-request-1',
          provider_response_hash: 'response-1',
          provider_response_id: 'provider-response-1',
          decision_enforced_before_tool_execution: false,
          tool_receipt_required: true,
          tool_receipt_server_observed_required: true,
          tool_receipt_evidence: 'server-observed',
          tool_receipts_verified: 1,
          tool_receipts_server_observed: 1,
          tool_receipts_caller_declared: 0,
          execution_boundary: 'caller-owned-tool-execution',
          tool_execution: 'caller-must-enforce-and-report-receipt',
          tool_argument_findings: [{ path: 'arguments.content', verdict: 'warn', signals: ['opaque-payload'] }],
          tool_decisions: [{ tool: 'file.read', decision: '允许', audit_id: 'audit-1' }]
        }
      };
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '验证防护' }));
    await userEvent.click(screen.getByRole('button', { name: '发送到网关' }));

    // The gateway page loads the redacted Trace index on entry, then sends
    // the runtime-status and completion requests.  The Trace request is
    // intentionally separate from the model request so operators can see
    // prior calls before creating a new one.
    expect(request).toHaveBeenCalledTimes(3);
    expect(vi.mocked(request).mock.calls.some(([path]) => path === '/api/gateway/traces?limit=50')).toBe(true);
    expect(vi.mocked(request).mock.calls.some(([path]) => path === '/v1/chat/completions')).toBe(true);
    const gatewayCall = vi.mocked(request).mock.calls.find(([path]) => path === '/v1/chat/completions');
    expect(gatewayCall?.[1]?.headers).toEqual({ 'X-Agent-Session-ID': 'gateway-console-session' });
    expect(screen.getByText('post-provider-output')).toBeInTheDocument();
    expect(screen.getByText('fixture-provider')).toBeInTheDocument();
    expect(screen.getByText('Provider 是否调用')).toBeInTheDocument();
    expect(screen.getByText('provider-response-returned')).toBeInTheDocument();
    expect(screen.getByText('caller-owned-tool-execution')).toBeInTheDocument();
    expect(screen.getByText('工具回执要求')).toBeInTheDocument();
    expect(screen.getByText('回执信任策略')).toBeInTheDocument();
    expect(screen.getByText('本次回执来源')).toBeInTheDocument();
    expect(screen.getByText('server-observed')).toBeInTheDocument();
    expect(screen.getByText('服务端观察回执')).toBeInTheDocument();
    expect(screen.getByText('调用方声明回执')).toBeInTheDocument();
    expect(screen.getByText('已验证回执')).toBeInTheDocument();
    expect(screen.getByText('Tool call 处置')).toBeInTheDocument();
    expect(screen.getByText('Provider 工具参数扫描')).toBeInTheDocument();
    expect(screen.getByText('源码/配置指纹')).toBeInTheDocument();
    expect(screen.getByText('审计精确定位')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '打开本次审计' })).toBeInTheDocument();
  });

  it('loads a real injection payload into the request editor for direct gateway testing', async () => {
    vi.mocked(request).mockResolvedValue({});
    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '验证防护' }));
    await userEvent.click(screen.getByRole('button', { name: '注入测试' }));

    expect((screen.getByRole('textbox', { name: '网关请求 JSON' }) as HTMLTextAreaElement).value).toContain(
      'Ignore previous instructions'
    );
  });

  it('keeps comparison and MCP debug tools out of the primary protection surface', () => {
    vi.mocked(request).mockResolvedValue({});
    render(<GatewayPanel />);
    expect(screen.queryByRole('button', { name: '运行同请求对照' })).not.toBeInTheDocument();
    expect(screen.queryByText('MCP JSON-RPC 实际入口')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '接入应用' })).toBeInTheDocument();
    expect(screen.getByText('实时请求')).toBeInTheDocument();
  });

  it('adds the managed server execution contract when the switch is enabled', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          models: {
            real_api_enabled: true,
            target: [{ provider: 'fixture-provider', model: 'fixture-model', configured: true, mode: 'real-api' }]
          },
          proxy: { enabled: true, mode: 'transparent' },
          semantic_detector: { enabled: true, loaded: false },
          mcp: { configured: false, enabled: false, guard_enabled: false, resource_limits: { os_enforced: false } }
        };
      }
      return { choices: [{ message: { role: 'assistant', content: 'ok' } }], agent_supervisor: { decision: '允许' } };
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '验证防护' }));
    await userEvent.click(screen.getByRole('switch'));
    await userEvent.click(screen.getByRole('button', { name: '发送到网关' }));

    const gatewayCall = vi.mocked(request).mock.calls.find(([path]) => path === '/v1/chat/completions');
    const body = JSON.parse(String(gatewayCall?.[1]?.body));
    expect(body.model).toBe('fixture-model');
    expect(body.agent_supervisor.mode).toBe('managed');
    expect(body.agent_supervisor.max_tool_rounds).toBe(3);
  });

  it('keeps analyst model diagnostics separate from server-owned tool execution', async () => {
    vi.mocked(request).mockResolvedValue({
      security_context: {
        role: 'analyst',
        agent_id: '',
        can_generate: true,
        can_execute_managed_tools: false
      },
      models: { target: [] },
      proxy: { enabled: true, mode: 'transparent' },
      mcp: { configured: false }
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '验证防护' }));

    expect(await screen.findByRole('switch')).toBeDisabled();
    expect(screen.getByText(/当前身份可生成模型响应，但没有服务端工具执行权限/)).toBeInTheDocument();
  });

  it('executes an allowed Provider tool call through the server and can replay the receipt', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/runtime_status') {
        return {
          models: {
            real_api_enabled: true,
            target: [{ provider: 'fixture-provider', model: 'fixture-model', configured: true, mode: 'real-api' }]
          },
          proxy: { enabled: true, mode: 'transparent' },
          semantic_detector: { enabled: true, loaded: false },
          mcp: { configured: false, enabled: false, guard_enabled: false, resource_limits: { os_enforced: false } }
        };
      }
      if (path === '/v1/chat/completions') {
        return {
          choices: [
            {
              message: {
                role: 'assistant',
                content: null,
                tool_calls: [
                  {
                    id: 'call-1',
                    type: 'function',
                    function: { name: 'file_read', arguments: '{"path":"public/项目说明.md"}' }
                  }
                ]
              }
            }
          ],
          agent_supervisor: {
            agent_id: 'gateway-console-agent',
            decision: '允许',
            request_stage: 'post-provider-output',
            provider_called: true,
            provider: 'fixture-provider',
            tool_decisions: [{ tool: 'file.read', call_id: 'call-1', decision: '允许', audit_id: 'audit-1' }]
          }
        };
      }
      if (path === '/api/gateway/tool_calls/audit-1/execute') {
        return {
          audit_id: 'audit-1',
          idempotent: false,
          execution_evidence: 'server-observed',
          execution_observed_by_server: true,
          execution_result: { executed: true },
          tool_result: '公开项目说明',
          tool_result_hash: 'result-hash',
          receipt: { receipt_hash: 'receipt-hash', status: 'completed' }
        };
      }
      return {};
    });

    render(<GatewayPanel />);
    await userEvent.click(screen.getByRole('button', { name: '验证防护' }));
    await userEvent.click(screen.getByRole('button', { name: '发送到网关' }));
    await userEvent.click(await screen.findByRole('button', { name: '服务端沙箱执行' }));

    expect((await screen.findAllByText(/服务端观察/)).length).toBeGreaterThan(0);
    expect(await screen.findByText('公开项目说明')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '回灌结果并继续对话' }));
    expect(vi.mocked(request).mock.calls.some(([path]) => path === '/v1/chat/completions')).toBe(true);
  });
});
