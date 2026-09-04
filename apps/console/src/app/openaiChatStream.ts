import type { GatewayResponse } from './gatewayPanelPresets';
import { ApiError, dispatchAuthInvalidation, getAuthSessionVersion, resolveRequestHeaders } from './apiRequest';

export type OpenAIStreamProgress = {
  status: 'streaming' | 'completed' | 'interrupted';
  chunkCount: number;
  content: string;
  characterCount: number;
  metadata: Record<string, unknown>;
};

type StreamChoice = {
  index: number;
  message: Record<string, unknown>;
  finish_reason: unknown;
};

const MAX_OPENAI_SSE_FRAME_CHARS = 1_048_576;

function appendText(target: Record<string, unknown>, key: string, value: unknown) {
  if (typeof value !== 'string') return;
  target[key] = String(target[key] ?? '') + value;
}

function mergeToolCalls(message: Record<string, unknown>, value: unknown) {
  if (!Array.isArray(value)) return;
  const calls = Array.isArray(message.tool_calls) ? ([...message.tool_calls] as Record<string, unknown>[]) : [];
  value.forEach((rawCall, fallbackIndex) => {
    if (!rawCall || typeof rawCall !== 'object' || Array.isArray(rawCall)) return;
    const call = rawCall as Record<string, unknown>;
    const index = Number.isInteger(call.index) && Number(call.index) >= 0 ? Number(call.index) : fallbackIndex;
    const current = calls[index] && typeof calls[index] === 'object' ? { ...calls[index] } : {};
    if (typeof call.id === 'string') current.id = String(current.id ?? '') + call.id;
    if (call.type === 'function') current.type = 'function';
    if (call.function && typeof call.function === 'object' && !Array.isArray(call.function)) {
      const rawFunction = call.function as Record<string, unknown>;
      const currentFunction =
        current.function && typeof current.function === 'object' && !Array.isArray(current.function)
          ? { ...(current.function as Record<string, unknown>) }
          : {};
      appendText(currentFunction, 'name', rawFunction.name);
      appendText(currentFunction, 'arguments', rawFunction.arguments);
      current.function = currentFunction;
    }
    calls[index] = current;
  });
  message.tool_calls = calls;
}

function mergeFunctionCall(message: Record<string, unknown>, value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  const current =
    message.function_call && typeof message.function_call === 'object' && !Array.isArray(message.function_call)
      ? { ...(message.function_call as Record<string, unknown>) }
      : {};
  const incoming = value as Record<string, unknown>;
  appendText(current, 'name', incoming.name);
  appendText(current, 'arguments', incoming.arguments);
  message.function_call = current;
}

function streamErrorMessage(value: Record<string, unknown>) {
  const error = value.error;
  if (error && typeof error === 'object' && !Array.isArray(error)) {
    const message = (error as Record<string, unknown>).message;
    if (typeof message === 'string' && message.trim()) return message;
  }
  return '网关流式响应未完成。';
}

export async function streamOpenAIChatCompletion(
  payload: Record<string, unknown>,
  options: {
    sessionId?: string;
    signal: AbortSignal;
    onProgress?: (progress: OpenAIStreamProgress) => void;
  }
): Promise<GatewayResponse> {
  const path = '/v1/chat/completions';
  const sessionVersion = getAuthSessionVersion();
  const body = JSON.stringify({ ...payload, stream: true });
  const requestInit: RequestInit = { method: 'POST', body };
  const baseHeaders = new Headers({ Accept: 'text/event-stream', 'Content-Type': 'application/json' });
  if (options.sessionId?.trim()) baseHeaders.set('X-Agent-Session-ID', options.sessionId.trim());
  const headers = await resolveRequestHeaders(baseHeaders, requestInit, {}, options.signal);

  const response = await fetch(path, {
    ...requestInit,
    headers,
    signal: options.signal
  });
  if (!response.ok || !response.body) {
    const body = await response.text();
    if (response.status === 401) {
      dispatchAuthInvalidation(path, sessionVersion);
    }
    throw new ApiError(body || `HTTP ${response.status}`, {
      code: 'http_error',
      path,
      status: response.status,
      body
    });
  }
  const contentType = response.headers.get('Content-Type') ?? '';
  if (!contentType.toLowerCase().startsWith('text/event-stream')) {
    await response.body.cancel?.().catch(() => undefined);
    throw new ApiError('网关未返回 text/event-stream，流式协议未建立。', {
      code: 'parse_error',
      path,
      status: response.status
    });
  }

  const choices = new Map<number, StreamChoice>();
  let id = '';
  let model = '';
  let created: unknown = 0;
  let usage: unknown;
  let metadata: Record<string, unknown> = {};
  let chunkCount = 0;
  let sawDone = false;
  let buffer = '';

  const snapshot = (status: OpenAIStreamProgress['status']) => {
    const content = [...choices.values()]
      .sort((left, right) => left.index - right.index)
      .map((choice) => String(choice.message.content ?? ''))
      .join('');
    options.onProgress?.({ status, chunkCount, content, characterCount: content.length, metadata });
  };

  const consume = (rawData: string) => {
    if (rawData === '[DONE]') {
      sawDone = true;
      return;
    }
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(rawData) as Record<string, unknown>;
    } catch {
      throw new ApiError('网关返回了无效的SSE JSON事件。', { code: 'parse_error', path });
    }
    if (event.error) {
      const eventMetadata = event.agent_supervisor;
      if (eventMetadata && typeof eventMetadata === 'object' && !Array.isArray(eventMetadata)) {
        metadata = eventMetadata as Record<string, unknown>;
      }
      snapshot('interrupted');
      throw new ApiError(streamErrorMessage(event), { code: 'http_error', path, status: response.status });
    }
    chunkCount += 1;
    if (typeof event.id === 'string') id = event.id;
    if (typeof event.model === 'string') model = event.model;
    if (event.created !== undefined) created = event.created;
    if (event.usage !== undefined) usage = event.usage;
    if (
      event.agent_supervisor &&
      typeof event.agent_supervisor === 'object' &&
      !Array.isArray(event.agent_supervisor)
    ) {
      metadata = event.agent_supervisor as Record<string, unknown>;
    }
    if (Array.isArray(event.choices)) {
      event.choices.forEach((rawChoice, fallbackIndex) => {
        if (!rawChoice || typeof rawChoice !== 'object' || Array.isArray(rawChoice)) return;
        const choice = rawChoice as Record<string, unknown>;
        const index = Number.isInteger(choice.index) ? Number(choice.index) : fallbackIndex;
        const state = choices.get(index) ?? {
          index,
          message: { role: 'assistant', content: '' },
          finish_reason: null
        };
        const delta = choice.delta;
        if (delta && typeof delta === 'object' && !Array.isArray(delta)) {
          const fields = delta as Record<string, unknown>;
          if (fields.role === 'assistant') state.message.role = 'assistant';
          appendText(state.message, 'content', fields.content);
          appendText(state.message, 'refusal', fields.refusal);
          mergeToolCalls(state.message, fields.tool_calls);
          mergeFunctionCall(state.message, fields.function_call);
        }
        if (choice.finish_reason !== undefined && choice.finish_reason !== null) {
          state.finish_reason = choice.finish_reason;
        }
        choices.set(index, state);
      });
    }
    snapshot('streaming');
  };

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  try {
    while (!options.signal.aborted) {
      const { value, done } = await reader.read();
      buffer += (done ? decoder.decode() : decoder.decode(value, { stream: true })).replace(/\r\n/g, '\n');
      const frames = buffer.split('\n\n');
      buffer = frames.pop() ?? '';
      if (
        buffer.length > MAX_OPENAI_SSE_FRAME_CHARS ||
        frames.some((frame) => frame.length > MAX_OPENAI_SSE_FRAME_CHARS)
      ) {
        throw new ApiError('网关 SSE 单帧超过浏览器安全上限。', { code: 'parse_error', path });
      }
      for (const frame of frames) {
        const dataLines = frame
          .split('\n')
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).replace(/^ /, ''));
        if (dataLines.length) consume(dataLines.join('\n'));
      }
      if (sawDone) break;
      if (done) break;
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      // The browser may already have closed the reader because the request
      // signal fired. Either state satisfies the resource-release contract.
    }
    reader.releaseLock();
  }
  if (options.signal.aborted) {
    throw new DOMException('Request aborted', 'AbortError');
  }
  if (!sawDone) {
    throw new ApiError('网关流式响应在 [DONE] 前结束。', { code: 'parse_error', path });
  }
  snapshot('completed');
  return {
    id,
    object: 'chat.completion',
    created,
    model,
    choices: [...choices.values()].sort((left, right) => left.index - right.index),
    usage,
    agent_supervisor: metadata
  };
}
