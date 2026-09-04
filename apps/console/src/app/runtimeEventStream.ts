import {
  ApiError,
  dispatchAuthInvalidation,
  getAuthSessionVersion,
  readableErrorMessage,
  readErrorBody,
  resolveRequestHeaders
} from './apiRequestSupport';

export type RuntimeEvent = {
  id: string;
  type: string;
  created_at: string;
  payload: Record<string, unknown>;
};

export type RuntimeEventSubscriptionLifecycle = { onOpen?: () => void };

const MAX_CONSECUTIVE_INVALID_RUNTIME_EVENTS = 3;
const MAX_RUNTIME_EVENT_FRAME_CHARS = 1_048_576;

function isEventStreamResponse(response: Response) {
  const contentType = response.headers.get('Content-Type') ?? '';
  return contentType.split(';', 1)[0].trim().toLowerCase() === 'text/event-stream';
}

function isRuntimeEvent(value: unknown): value is RuntimeEvent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const event = value as Record<string, unknown>;
  return (
    typeof event.id === 'string' &&
    typeof event.type === 'string' &&
    typeof event.created_at === 'string' &&
    Boolean(event.payload) &&
    typeof event.payload === 'object' &&
    !Array.isArray(event.payload)
  );
}

function parseRuntimeEventFrame(frame: string): RuntimeEvent | null {
  const dataLines = frame
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).replace(/^ /, ''));
  if (!dataLines.length) return null;

  const parsed: unknown = JSON.parse(dataLines.join('\n'));
  if (!isRuntimeEvent(parsed)) throw new TypeError('事件字段不完整。');
  return parsed;
}

function parseAvailableFrames(buffer: string) {
  const normalized = buffer.replace(/\r\n/g, '\n');
  const frames = normalized.split('\n\n');
  return { frames: frames.slice(0, -1), remainder: frames[frames.length - 1] ?? '' };
}

export async function openRuntimeEventStream(
  onEvent: (event: RuntimeEvent) => void,
  signal: AbortSignal,
  lifecycle: RuntimeEventSubscriptionLifecycle = {}
): Promise<void> {
  const path = '/api/events/stream';
  const sessionVersion = getAuthSessionVersion();
  const response = await fetch(path, {
    headers: await resolveRequestHeaders({ Accept: 'text/event-stream' }, undefined, {}, signal),
    signal
  });
  if (!response.ok || !response.body) {
    const body = await readErrorBody(response);
    if (response.status === 401) dispatchAuthInvalidation(path, sessionVersion);
    throw new ApiError(readableErrorMessage(body, response.status), {
      code: 'http_error',
      path,
      status: response.status,
      body
    });
  }
  if (!isEventStreamResponse(response)) {
    await response.body.cancel?.().catch(() => undefined);
    throw new ApiError('实时事件接口未返回 text/event-stream，连接未建立。', {
      code: 'parse_error',
      path,
      status: response.status
    });
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let consecutiveInvalidEvents = 0;
  let completed = false;
  try {
    lifecycle.onOpen?.();
    while (!signal.aborted) {
      const { value, done } = await reader.read();
      buffer += done ? decoder.decode() : decoder.decode(value, { stream: true });
      const parsedFrames = parseAvailableFrames(buffer);
      buffer = parsedFrames.remainder;
      if (
        buffer.length > MAX_RUNTIME_EVENT_FRAME_CHARS ||
        parsedFrames.frames.some((frame) => frame.length > MAX_RUNTIME_EVENT_FRAME_CHARS)
      ) {
        throw new ApiError('实时事件流单帧超过浏览器安全上限，连接已停止。', {
          code: 'parse_error',
          path,
          status: response.status
        });
      }
      for (const frame of parsedFrames.frames) {
        let event: RuntimeEvent | null;
        try {
          event = parseRuntimeEventFrame(frame);
        } catch {
          consecutiveInvalidEvents += 1;
          if (consecutiveInvalidEvents >= MAX_CONSECUTIVE_INVALID_RUNTIME_EVENTS) {
            throw new ApiError('实时事件流连续返回无效事件，连接已停止。', {
              code: 'parse_error',
              path,
              status: response.status
            });
          }
          continue;
        }
        if (!event) continue;
        consecutiveInvalidEvents = 0;
        onEvent(event);
      }
      if (done) {
        completed = true;
        break;
      }
    }
  } finally {
    if (!completed) await reader.cancel?.().catch(() => undefined);
    reader.releaseLock?.();
  }
}
