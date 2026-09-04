import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from '../../app/apiRequest';
import { GatewayMcpPanel } from './GatewayMcpPanel';

vi.mock('../../app/apiRequest', () => ({
  request: vi.fn()
}));

const configuredStatus = {
  mcp: { configured: true, enabled: true, guard_enabled: true, resource_limits: { os_enforced: true } }
};

describe('GatewayMcpPanel', () => {
  beforeEach(() => {
    vi.mocked(request).mockReset();
  });

  it('sends a real tools/list JSON-RPC request with the shared session', async () => {
    vi.mocked(request).mockResolvedValue({
      jsonrpc: '2.0',
      id: 'console-tools-list-1',
      result: {
        tools: [{ name: 'file.read' }],
        zhiAnSentinel: {
          quarantinedTools: [],
          filteredTools: [],
          filtered_tool_count: 2,
          quarantined_tool_count: 1,
          scanSummary: { scanned_tool_count: 1, quarantined_tool_count: 0, warning_tool_count: 0 }
        }
      }
    });

    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'tools/list' }));

    const call = vi.mocked(request).mock.calls[0];
    expect(call?.[0]).toBe('/api/mcp');
    expect(call?.[1]?.headers).toEqual({
      'X-Agent-Session-ID': 'mcp-session-1',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2026-07-28',
      'Mcp-Method': 'tools/list'
    });
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
      jsonrpc: '2.0',
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientInfo': { name: 'zhi-an-sentinel-console', version: '0.2.0' },
          'io.modelcontextprotocol/clientCapabilities': { sampling: {}, elicitation: {}, roots: {} }
        }
      }
    });
    expect(await screen.findByText('当前响应可见工具：1 个；已过滤 2 个；模型侧隔离 1 个。')).toBeInTheDocument();
    expect(screen.getByText('网关已扫描：1 个；隔离 0 个；警告 0 个。')).toBeInTheDocument();
    expect(screen.getByText('result')).toBeInTheDocument();
  });

  it('validates tool arguments before crossing the MCP boundary', async () => {
    vi.mocked(request).mockResolvedValue({});
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);
    const argumentsEditor = screen.getByRole('textbox', { name: 'MCP tools/call arguments' });
    fireEvent.change(argumentsEditor, { target: { value: '[]' } });
    await userEvent.click(screen.getByRole('button', { name: 'tools/call' }));

    expect(await screen.findByText('工具 arguments 必须是 JSON 对象。')).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it('sends MCP context discovery and reads operator-only context evidence with the session', async () => {
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/mcp/context/evidence') {
        return {
          session_scope: 'agent+session',
          summary: { visible_context_count: 2, filtered_context_count: 1 },
          visible_context: [{ kind: 'resources', identifier: 'file://public/example' }]
        };
      }
      return {
        jsonrpc: '2.0',
        id: 'context-list-1',
        result: { resources: [{ uri: 'file://public/example' }] }
      };
    });

    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'resources/list' }));

    const contextCall = vi.mocked(request).mock.calls[0];
    expect(JSON.parse(String(contextCall?.[1]?.body))).toMatchObject({
      jsonrpc: '2.0',
      method: 'resources/list',
      params: {}
    });
    expect(contextCall?.[1]?.headers).toEqual({
      'X-Agent-Session-ID': 'mcp-session-1',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2026-07-28',
      'Mcp-Method': 'resources/list'
    });

    await userEvent.click(screen.getByRole('button', { name: '上下文 operator 证据' }));
    const evidenceCall = vi.mocked(request).mock.calls[1];
    expect(evidenceCall?.[0]).toBe('/api/mcp/context/evidence');
    expect(evidenceCall?.[1]?.method).toBe('GET');
    expect(evidenceCall?.[1]?.headers).toEqual({ 'X-Agent-Session-ID': 'mcp-session-1' });
    expect(await screen.findByText(/可见 2 项；已过滤 1 项；会话范围 agent\+session/)).toBeInTheDocument();
  });

  it('forwards the edited resource URI and prompt name instead of dropping their params', async () => {
    vi.mocked(request).mockResolvedValue({ jsonrpc: '2.0', id: 'context-action-1', result: {} });
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);

    const resourceInput = screen.getByRole('textbox', { name: 'MCP resources/read URI' });
    await userEvent.clear(resourceInput);
    await userEvent.type(resourceInput, 'file://public/handbook');
    await userEvent.click(screen.getByRole('button', { name: 'resources/read' }));

    const promptInput = screen.getByRole('textbox', { name: 'MCP prompts/get 名称' });
    await userEvent.clear(promptInput);
    await userEvent.type(promptInput, 'incident-summary');
    await userEvent.click(screen.getByRole('button', { name: 'prompts/get' }));

    const resourceCall = vi.mocked(request).mock.calls.find(([, init]) => {
      const body = JSON.parse(String(init?.body));
      return body.method === 'resources/read';
    });
    const promptCall = vi.mocked(request).mock.calls.find(([, init]) => {
      const body = JSON.parse(String(init?.body));
      return body.method === 'prompts/get';
    });

    expect(JSON.parse(String(resourceCall?.[1]?.body))).toMatchObject({
      method: 'resources/read',
      params: {
        uri: 'file://public/handbook',
        _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' }
      }
    });
    expect(resourceCall?.[1]?.headers).toMatchObject({
      'Mcp-Method': 'resources/read',
      'Mcp-Name': 'file://public/handbook'
    });
    expect(JSON.parse(String(promptCall?.[1]?.body))).toMatchObject({
      method: 'prompts/get',
      params: {
        name: 'incident-summary',
        arguments: {},
        _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' }
      }
    });
    expect(promptCall?.[1]?.headers).toMatchObject({
      'Mcp-Method': 'prompts/get',
      'Mcp-Name': 'incident-summary'
    });
  });

  it('switches to the 2025 compatibility handshake without modern metadata', async () => {
    vi.mocked(request).mockResolvedValue({ jsonrpc: '2.0', id: 'legacy-init-1', result: {} });
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);

    expect(screen.getByRole('button', { name: 'server/discover' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'initialize' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('combobox', { name: 'MCP 协议版本' }));
    await userEvent.click(screen.getByText('2025-06-18 兼容协议'));
    await userEvent.click(screen.getByRole('button', { name: 'initialize' }));

    const call = vi.mocked(request).mock.calls[0];
    expect(call?.[1]?.headers).toEqual({ 'X-Agent-Session-ID': 'mcp-session-1' });
    const body = JSON.parse(String(call?.[1]?.body));
    expect(body).toMatchObject({
      jsonrpc: '2.0',
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'zhi-an-sentinel-console', version: '0.2.0' }
      }
    });
    expect(body.params).not.toHaveProperty('_meta');
    expect(screen.queryByRole('button', { name: 'server/discover' })).not.toBeInTheDocument();
  });

  it('requires an explicit session before sending MCP requests', async () => {
    vi.mocked(request).mockResolvedValue({});
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="" onSessionIdChange={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'resources/list' }));

    expect(await screen.findByText(/MCP 会话 ID 不能为空/)).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it('does not expose fake MCP actions when no upstream is configured', () => {
    render(
      <GatewayMcpPanel
        runtimeStatus={{ mcp: { configured: false, enabled: false } }}
        sessionId="mcp-session-1"
        onSessionIdChange={vi.fn()}
      />
    );

    expect(screen.getByText('MCP 上游待配置')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'tools/call' })).not.toBeInTheDocument();
  });

  it('does not offer MCP requests to an observer-only console session', () => {
    render(
      <GatewayMcpPanel
        runtimeStatus={{
          ...configuredStatus,
          security_context: { role: 'observer', can_use_mcp: false, can_execute_mcp_tools: false }
        }}
        sessionId="mcp-session-1"
        onSessionIdChange={vi.fn()}
      />
    );

    expect(screen.getByText('当前操作员身份为查看角色')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'tools/list' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'tools/call' })).not.toBeInTheDocument();
  });

  it('allows analyst discovery while disabling MCP tool execution', () => {
    render(
      <GatewayMcpPanel
        runtimeStatus={{
          ...configuredStatus,
          security_context: { role: 'analyst', can_use_mcp: true, can_execute_mcp_tools: false }
        }}
        sessionId="mcp-session-1"
        onSessionIdChange={vi.fn()}
      />
    );

    expect(screen.getByRole('button', { name: 'tools/list' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'tools/call' })).toBeDisabled();
    expect(
      screen.getByText('当前身份可以验证 MCP 目录与上下文；绑定 Agent 的 executor 或 admin 凭证可执行 tools/call。')
    ).toBeInTheDocument();
  });
});
