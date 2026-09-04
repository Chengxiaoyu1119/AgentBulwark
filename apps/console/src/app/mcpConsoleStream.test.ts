import { describe, expect, it, vi } from 'vitest';
import { parseMcpJsonOrSseResponse, parseMcpSubscriptionStream } from './mcpConsoleStream';

function streamResponse(chunks: string[]) {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      chunks.forEach((chunk) => controller.enqueue(encoder.encode(chunk)));
      controller.close();
    }
  });
  return new Response(stream, { headers: { 'Content-Type': 'text/event-stream; charset=utf-8' } });
}

describe('parseMcpJsonOrSseResponse', () => {
  it('keeps ordinary JSON responses on the same request path', async () => {
    const response = new Response(JSON.stringify({ jsonrpc: '2.0', id: 'json-1', result: {} }), {
      headers: { 'Content-Type': 'application/json' }
    });
    await expect(parseMcpJsonOrSseResponse(response, vi.fn())).resolves.toMatchObject({ id: 'json-1' });
  });

  it('parses split CRLF frames, emits notifications, and returns the final response', async () => {
    const progress = { jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1, total: 2 } };
    const log = { jsonrpc: '2.0', method: 'notifications/message', params: { level: 'warning' } };
    const final = { jsonrpc: '2.0', id: 'stream-1', result: { resultType: 'complete' } };
    const serialized = [progress, log, final].map((value) => `data: ${JSON.stringify(value)}\r\n\r\n`).join('');
    const response = streamResponse([serialized.slice(0, 19), serialized.slice(19, 53), serialized.slice(53)]);
    const onEvent = vi.fn();

    await expect(parseMcpJsonOrSseResponse(response, onEvent)).resolves.toEqual(final);
    expect(onEvent.mock.calls.map(([event]) => event)).toEqual([progress, log]);
  });

  it('rejects a stream that closes without a final JSON-RPC response', async () => {
    const response = streamResponse([
      `data: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } })}\n\n`
    ]);
    await expect(parseMcpJsonOrSseResponse(response, vi.fn())).rejects.toThrow('MCP SSE 在最终 JSON-RPC 响应前结束。');
  });

  it('rejects one oversized complete frame instead of only checking the leftover buffer', async () => {
    const response = streamResponse([`data: ${'x'.repeat(1_048_577)}\n\n`]);
    await expect(parseMcpJsonOrSseResponse(response, vi.fn())).rejects.toThrow('MCP SSE 单帧超过浏览器安全上限。');
  });
});

describe('parseMcpSubscriptionStream', () => {
  it('requires acknowledgement first and forwards later subscription notifications', async () => {
    const acknowledged = {
      jsonrpc: '2.0',
      method: 'notifications/subscriptions/acknowledged',
      params: { notifications: { toolsListChanged: true } }
    };
    const changed = { jsonrpc: '2.0', method: 'notifications/tools/list_changed', params: {} };
    const response = streamResponse([`data: ${JSON.stringify(acknowledged)}\n\ndata: ${JSON.stringify(changed)}\n\n`]);
    const onEvent = vi.fn();

    await expect(parseMcpSubscriptionStream(response, onEvent)).resolves.toBeUndefined();
    expect(onEvent.mock.calls.map(([event]) => event)).toEqual([acknowledged, changed]);
  });

  it('rejects a subscription notification before acknowledgement', async () => {
    const response = streamResponse([
      `data: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' })}\n\n`
    ]);
    await expect(parseMcpSubscriptionStream(response, vi.fn())).rejects.toThrow('MCP 订阅流首条消息必须是服务端确认。');
  });
});
