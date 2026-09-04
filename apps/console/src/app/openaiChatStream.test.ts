import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setAuthTokenProvider } from './apiRequest';
import { getAuthToken } from './authSession';
import { streamOpenAIChatCompletion, type OpenAIStreamProgress } from './openaiChatStream';

function sseResponse(frames: Array<Record<string, unknown> | '[DONE]'>) {
  const body = frames.map((frame) => `data: ${typeof frame === 'string' ? frame : JSON.stringify(frame)}\n\n`).join('');
  return new Response(body, { headers: { 'Content-Type': 'text/event-stream; charset=utf-8' } });
}

describe('streamOpenAIChatCompletion', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    window.sessionStorage.clear();
    window.sessionStorage.setItem('agent-supervisor-api-token', 'operator-token');
    setAuthTokenProvider(getAuthToken);
  });
  afterEach(() => setAuthTokenProvider(null));
  it('assembles text and delayed tool calls while reporting live progress', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      sseResponse([
        {
          id: 'chat-1',
          object: 'chat.completion.chunk',
          created: 1,
          model: 'fixture-model',
          choices: [{ index: 0, delta: { role: 'assistant', content: 'hello ' }, finish_reason: null }]
        },
        {
          id: 'chat-1',
          object: 'chat.completion.chunk',
          created: 1,
          model: 'fixture-model',
          choices: [
            {
              index: 0,
              delta: {
                content: 'world',
                tool_calls: [
                  {
                    index: 0,
                    id: 'call-1',
                    type: 'function',
                    function: { name: 'file_read', arguments: '{"path":"public/readme.md"}' }
                  }
                ]
              },
              finish_reason: null
            }
          ]
        },
        {
          id: 'chat-1',
          object: 'chat.completion.chunk',
          created: 1,
          model: 'fixture-model',
          choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }],
          agent_supervisor: { decision: '允许', stream_buffered: false }
        },
        '[DONE]'
      ])
    );
    vi.stubGlobal('fetch', fetchMock);
    const progress: OpenAIStreamProgress[] = [];

    const result = await streamOpenAIChatCompletion(
      { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
      { sessionId: 'session-1', signal: new AbortController().signal, onProgress: (item) => progress.push(item) }
    );

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/chat/completions',
      expect.objectContaining({ method: 'POST', signal: expect.any(AbortSignal) })
    );
    const request = fetchMock.mock.calls[0][1] as RequestInit;
    const headers = new Headers(request.headers);
    expect(headers.get('Authorization')).toBe('Bearer operator-token');
    expect(headers.get('X-Agent-Session-ID')).toBe('session-1');
    expect(JSON.parse(String(request.body)).stream).toBe(true);
    expect(progress.some((item) => item.status === 'streaming' && item.content === 'hello ')).toBe(true);
    expect(progress[progress.length - 1]).toMatchObject({ status: 'completed', content: 'hello world' });
    const choice = result.choices?.[0] as Record<string, unknown>;
    const message = choice.message as Record<string, unknown>;
    expect(message.content).toBe('hello world');
    expect((message.tool_calls as Array<Record<string, unknown>>)[0]).toMatchObject({ id: 'call-1' });
    expect(result.agent_supervisor).toMatchObject({ decision: '允许', stream_buffered: false });
  });

  it('uses the shared asynchronous auth provider before opening a stream', async () => {
    window.sessionStorage.clear();
    setAuthTokenProvider(async () => 'async-provider-token');
    const fetchMock = vi.fn().mockResolvedValue(sseResponse(['[DONE]']));
    vi.stubGlobal('fetch', fetchMock);

    await streamOpenAIChatCompletion(
      { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
      { signal: new AbortController().signal }
    );

    const request = fetchMock.mock.calls[0][1] as RequestInit;
    expect(new Headers(request.headers).get('Authorization')).toBe('Bearer async-provider-token');
  });

  it('cancels during asynchronous auth resolution without sending the stream request', async () => {
    window.sessionStorage.clear();
    setAuthTokenProvider(() => new Promise<string>(() => undefined));
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const controller = new AbortController();

    const pending = streamOpenAIChatCompletion(
      { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
      { signal: controller.signal }
    );
    controller.abort();

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('raises the bounded gateway error event instead of accepting a partial success', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        sseResponse([
          {
            error: { message: 'Provider流式响应失败或在完成前中断。', code: 'provider_stream_error' },
            agent_supervisor: { stream_interrupted: true, audit_id: 'audit-stream-failure' }
          },
          '[DONE]'
        ])
      )
    );

    await expect(
      streamOpenAIChatCompletion(
        { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
        { signal: new AbortController().signal }
      )
    ).rejects.toThrow('Provider流式响应失败或在完成前中断。');
  });

  it('rejects a stream that closes without the terminal marker', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        sseResponse([
          {
            id: 'chat-1',
            choices: [{ index: 0, delta: { content: 'partial' }, finish_reason: null }]
          }
        ])
      )
    );

    await expect(
      streamOpenAIChatCompletion(
        { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
        { signal: new AbortController().signal }
      )
    ).rejects.toThrow('[DONE]');
  });

  it('cancels a stream whose next SSE frame exceeds the browser memory boundary', async () => {
    const encoder = new TextEncoder();
    const reader = {
      read: vi.fn().mockResolvedValueOnce({ value: encoder.encode(`data: ${'x'.repeat(1_048_577)}`), done: false }),
      cancel: vi.fn().mockResolvedValue(undefined),
      releaseLock: vi.fn()
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/event-stream' }),
        body: { getReader: () => reader }
      } as unknown as Response)
    );

    await expect(
      streamOpenAIChatCompletion(
        { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
        { signal: new AbortController().signal }
      )
    ).rejects.toMatchObject({ code: 'parse_error', path: '/v1/chat/completions' });
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('releases a response body when the gateway returns a non-SSE content type', async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        body: { cancel }
      } as unknown as Response)
    );

    await expect(
      streamOpenAIChatCompletion(
        { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
        { signal: new AbortController().signal }
      )
    ).rejects.toMatchObject({ code: 'parse_error', path: '/v1/chat/completions' });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('stops reading and cancels the reader immediately after the terminal marker', async () => {
    const encoder = new TextEncoder();
    const reader = {
      read: vi.fn().mockResolvedValue({ value: encoder.encode('data: [DONE]\n\n'), done: false }),
      cancel: vi.fn().mockResolvedValue(undefined),
      releaseLock: vi.fn()
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/event-stream' }),
        body: { getReader: () => reader }
      } as unknown as Response)
    );

    await expect(
      streamOpenAIChatCompletion(
        { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
        { signal: new AbortController().signal }
      )
    ).resolves.toMatchObject({ choices: [] });
    expect(reader.read).toHaveBeenCalledOnce();
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('preserves the optional usage-only terminal chunk', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        sseResponse([
          {
            id: 'chat-usage',
            object: 'chat.completion.chunk',
            created: 1,
            model: 'fixture-model',
            choices: [{ index: 0, delta: { role: 'assistant', content: 'done' }, finish_reason: null }]
          },
          {
            id: 'chat-usage',
            object: 'chat.completion.chunk',
            created: 1,
            model: 'fixture-model',
            choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
            agent_supervisor: { decision: '允许' }
          },
          {
            id: 'chat-usage',
            object: 'chat.completion.chunk',
            created: 1,
            model: 'fixture-model',
            choices: [],
            usage: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 }
          },
          '[DONE]'
        ])
      )
    );

    const result = await streamOpenAIChatCompletion(
      {
        model: 'fixture-model',
        messages: [{ role: 'user', content: 'hello' }],
        stream: true,
        stream_options: { include_usage: true }
      },
      { signal: new AbortController().signal }
    );

    expect(result.usage).toEqual({ prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 });
  });

  it('preserves AbortError semantics when cancellation wins before stream consumption', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(sseResponse(['[DONE]'])));
    const controller = new AbortController();
    controller.abort();

    await expect(
      streamOpenAIChatCompletion(
        { model: 'fixture-model', messages: [{ role: 'user', content: 'hello' }], stream: true },
        { signal: controller.signal }
      )
    ).rejects.toMatchObject({ name: 'AbortError' });
  });
});
