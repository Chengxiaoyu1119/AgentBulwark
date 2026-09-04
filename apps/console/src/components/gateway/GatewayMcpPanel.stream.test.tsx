import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from '../../app/apiRequest';
import { GatewayMcpPanel } from './GatewayMcpPanel';

vi.mock('../../app/apiRequest', () => ({ request: vi.fn() }));

const configuredStatus = {
  mcp: { configured: true, enabled: true, guard_enabled: true, resource_limits: { os_enforced: true } }
};

function sseResponse(events: object[]) {
  const body = events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join('');
  return new Response(body, { headers: { 'Content-Type': 'text/event-stream' } });
}

function openSubscriptionResponse(signal?: AbortSignal) {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          encoder.encode(
            [
              {
                jsonrpc: '2.0',
                method: 'notifications/subscriptions/acknowledged',
                params: { notifications: { toolsListChanged: true } }
              },
              { jsonrpc: '2.0', method: 'notifications/tools/list_changed', params: {} }
            ]
              .map((event) => `data: ${JSON.stringify(event)}\n\n`)
              .join('')
          )
        );
        signal?.addEventListener('abort', () => controller.error(new DOMException('Aborted', 'AbortError')), {
          once: true
        });
      }
    }),
    { headers: { 'Content-Type': 'text/event-stream' } }
  );
}

describe('GatewayMcpPanel request stream', () => {
  beforeEach(() => vi.mocked(request).mockReset());

  it('opts into progress and filtered logs, then renders streamed evidence', async () => {
    vi.mocked(request).mockImplementation(async (_path, _init, options) => {
      const response = sseResponse([
        {
          jsonrpc: '2.0',
          method: 'notifications/progress',
          params: { progressToken: 'stream-1', progress: 1, total: 1 }
        },
        {
          jsonrpc: '2.0',
          method: 'notifications/message',
          params: { level: 'emergency', logger: 'fixture', data: 'emergency' }
        },
        { jsonrpc: '2.0', id: 'stream-1', result: { resultType: 'complete', isError: false } }
      ]);
      return options?.responseParser?.(response) as Promise<Record<string, unknown>>;
    });
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);

    await userEvent.click(screen.getByRole('switch', { name: 'MCP 实时进度' }));
    await userEvent.click(screen.getByRole('combobox', { name: 'MCP 日志级别' }));
    expect(await screen.findByText('notice 及以上')).toBeInTheDocument();
    expect(screen.getByText('alert 及以上')).toBeInTheDocument();
    await userEvent.click(screen.getByText('emergency 及以上'));
    await userEvent.click(screen.getByRole('button', { name: 'tools/call' }));

    expect(await screen.findByText('收到 2 条 MCP 请求级实时事件')).toBeInTheDocument();
    expect(screen.getByText('最新进度：1 / 1；日志：1 条（emergency）。')).toBeInTheDocument();
    const call = vi.mocked(request).mock.calls[0];
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
      method: 'tools/call',
      params: {
        _meta: {
          progressToken: expect.stringMatching(/^console-tools\/call-/),
          'io.modelcontextprotocol/logLevel': 'emergency'
        }
      }
    });
  });

  it('starts, renders, and explicitly stops a long-lived MCP subscription', async () => {
    vi.mocked(request).mockImplementation(async (_path, init, options) => {
      const response = openSubscriptionResponse(init?.signal ?? undefined);
      return options?.responseParser?.(response) as Promise<Record<string, unknown>>;
    });
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: '开始订阅' }));

    expect(await screen.findByText('订阅已连接')).toBeInTheDocument();
    expect(await screen.findByText('MCP 订阅事件 1 条')).toBeInTheDocument();
    const call = vi.mocked(request).mock.calls[0];
    expect(call?.[1]?.headers).toMatchObject({
      'X-Agent-Session-ID': 'mcp-session-1',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2026-07-28',
      'Mcp-Method': 'subscriptions/listen'
    });
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
      method: 'subscriptions/listen',
      params: {
        notifications: {
          toolsListChanged: true,
          promptsListChanged: true,
          resourcesListChanged: true
        }
      }
    });

    await userEvent.click(screen.getByRole('button', { name: '停止订阅' }));
    expect(await screen.findByText('未订阅')).toBeInTheDocument();
  });

  it('rejects an empty subscription filter before opening a connection', async () => {
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);

    await userEvent.click(screen.getByRole('switch', { name: '订阅 MCP 工具目录变化' }));
    await userEvent.click(screen.getByRole('switch', { name: '订阅 MCP Prompt 目录变化' }));
    await userEvent.click(screen.getByRole('switch', { name: '订阅 MCP Resource 目录变化' }));
    await userEvent.click(screen.getByRole('button', { name: '开始订阅' }));

    expect(await screen.findByText('请至少选择一种目录变更或填写一个 Resource URI。')).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });
});
