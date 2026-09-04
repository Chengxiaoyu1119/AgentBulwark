import type { JsonObject } from './mcpConsoleContract';

const MAX_SSE_FRAME_BUFFER_CHARS = 1_048_576;

function isJsonObject(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseFrame(frame: string) {
  const data = frame
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trimStart())
    .join('\n');
  if (!data) return null;
  const value: unknown = JSON.parse(data);
  if (!isJsonObject(value)) throw new Error('MCP SSE data 必须是 JSON 对象。');
  return value;
}

async function* readMcpSseObjects(response: Response) {
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('text/event-stream')) throw new Error('MCP 订阅响应必须是 SSE 数据流。');
  if (!response.body) throw new Error('MCP SSE 响应缺少可读数据流。');

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let completed = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      buffer = buffer.replace(/\r\n/g, '\n');
      const frames = buffer.split('\n\n');
      buffer = frames.pop() ?? '';
      if (
        buffer.length > MAX_SSE_FRAME_BUFFER_CHARS ||
        frames.some((frame) => frame.length > MAX_SSE_FRAME_BUFFER_CHARS)
      ) {
        throw new Error('MCP SSE 单帧超过浏览器安全上限。');
      }
      if (done && buffer.trim()) frames.push(buffer);
      for (const frame of frames) {
        const payload = parseFrame(frame);
        if (payload) yield payload;
      }
      if (done) {
        completed = true;
        return;
      }
    }
  } finally {
    if (!completed) {
      try {
        await reader.cancel();
      } catch {
        // The caller's AbortSignal may already own stream cancellation.
      }
    }
    reader.releaseLock();
  }
}

export async function parseMcpJsonOrSseResponse(
  response: Response,
  onEvent: (event: JsonObject) => void
): Promise<JsonObject> {
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('text/event-stream')) {
    const value: unknown = await response.json();
    if (!isJsonObject(value)) throw new Error('MCP JSON 响应必须是对象。');
    return value;
  }
  for await (const payload of readMcpSseObjects(response)) {
    if (typeof payload.method === 'string' && !('id' in payload)) onEvent(payload);
    else return payload;
  }
  throw new Error('MCP SSE 在最终 JSON-RPC 响应前结束。');
}

export async function parseMcpSubscriptionStream(
  response: Response,
  onEvent: (event: JsonObject) => void
): Promise<void> {
  let acknowledged = false;
  for await (const payload of readMcpSseObjects(response)) {
    if (typeof payload.method !== 'string' || 'id' in payload) {
      throw new Error('MCP 订阅流只能包含 JSON-RPC 通知。');
    }
    if (!acknowledged) {
      if (payload.method !== 'notifications/subscriptions/acknowledged') {
        throw new Error('MCP 订阅流首条消息必须是服务端确认。');
      }
      acknowledged = true;
    }
    onEvent(payload);
  }
  if (!acknowledged) throw new Error('MCP 订阅流在服务端确认前结束。');
}
