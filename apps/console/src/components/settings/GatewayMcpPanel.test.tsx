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
    expect(call?.[1]?.headers).toEqual({ 'X-Agent-Session-ID': 'mcp-session-1' });
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
      jsonrpc: '2.0',
      method: 'tools/list',
      params: {}
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
    expect(contextCall?.[1]?.headers).toEqual({ 'X-Agent-Session-ID': 'mcp-session-1' });

    await userEvent.click(screen.getByRole('button', { name: '上下文 operator 证据' }));
    const evidenceCall = vi.mocked(request).mock.calls[1];
    expect(evidenceCall?.[0]).toBe('/api/mcp/context/evidence');
    expect(evidenceCall?.[1]?.method).toBe('GET');
    expect(evidenceCall?.[1]?.headers).toEqual({ 'X-Agent-Session-ID': 'mcp-session-1' });
    expect(await screen.findByText(/可见 2 项；已过滤 1 项；会话范围 agent\+session/)).toBeInTheDocument();
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

    expect(screen.getByText('当前没有配置 MCP 上游，真实 tools/list / tools/call 不会被伪造。')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'tools/call' })).not.toBeInTheDocument();
  });
});
