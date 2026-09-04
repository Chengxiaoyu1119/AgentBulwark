import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  authInvalidEvent,
  ApiError,
  request,
  safeUiErrorSummary,
  setAuthTokenProvider,
  startAuthSession,
  subscribeRuntimeEvents,
  type RuntimeEvent
} from './apiRequest';

afterEach(() => {
  setAuthTokenProvider(null);
  vi.unstubAllGlobals();
});

describe('request cancellation', () => {
  it('normalizes API and local failures into bounded operator-facing summaries', () => {
    expect(safeUiErrorSummary(new ApiError('expired', { code: 'http_error', path: '/api/test', status: 401 }))).toBe(
      '当前会话已失效，请重新验证身份。'
    );

    const localMessage = safeUiErrorSummary(new Error(`provider token=secret ${'x'.repeat(300)}`));
    expect(localMessage).toContain('token=[已隐藏]');
    expect(localMessage).not.toContain('secret');
    expect(localMessage.length).toBeLessThanOrEqual(120);
    expect(safeUiErrorSummary({ reason: 'unknown' }, '操作失败。')).toBe('操作失败。');
  });

  it('uses a custom response parser after the shared auth and status checks', async () => {
    const response = new Response('stream-payload', { status: 200 });
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(response));
    const responseParser = vi.fn(async (rawResponse: Response) => ({ payload: await rawResponse.text() }));

    await expect(request('/api/stream', undefined, { responseParser })).resolves.toEqual({
      payload: 'stream-payload'
    });
    expect(responseParser).toHaveBeenCalledWith(response);
  });

  it('does not enter fetch when cancellation happens during the token and header stage', async () => {
    const caller = new AbortController();
    const fetchMock = vi.fn<typeof fetch>((_input, init) => {
      return new Promise((_resolve, reject) => {
        const abort = () => reject(new DOMException('Aborted', 'AbortError'));
        if (init?.signal?.aborted) {
          abort();
          return;
        }
        init?.signal?.addEventListener('abort', abort, { once: true });
      }) as Promise<Response>;
    });

    vi.stubGlobal('fetch', fetchMock);
    const pending = request('/api/cancellable', { signal: caller.signal }, { retry: 1, timeoutMs: 5_000 });
    caller.abort();

    await expect(pending).rejects.toMatchObject({ code: 'aborted', path: '/api/cancellable' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not retry when cancellation happens after fetch has started', async () => {
    const caller = new AbortController();
    const fetchMock = vi.fn<typeof fetch>((_input, init) => {
      return new Promise((_resolve, reject) => {
        const abort = () => reject(new DOMException('Aborted', 'AbortError'));
        if (init?.signal?.aborted) return abort();
        init?.signal?.addEventListener('abort', abort, { once: true });
      }) as Promise<Response>;
    });
    vi.stubGlobal('fetch', fetchMock);

    const pending = request('/api/in-flight', { signal: caller.signal }, { retry: 2, timeoutMs: 5_000 });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    caller.abort();

    await expect(pending).rejects.toMatchObject({ code: 'aborted', path: '/api/in-flight' });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[1]?.signal).not.toBe(caller.signal);
  });

  it('includes an asynchronous token provider in the request timeout', async () => {
    setAuthTokenProvider(() => new Promise(() => undefined));
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal('fetch', fetchMock);

    await expect(request('/api/provider-timeout', undefined, { retry: 0, timeoutMs: 5 })).rejects.toMatchObject({
      code: 'timeout',
      path: '/api/provider-timeout'
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not publish a stale 401 after a newer operator session starts', async () => {
    let resolveResponse: ((response: Response) => void) | undefined;
    const responsePending = new Promise<Response>((resolve) => {
      resolveResponse = resolve;
    });
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockReturnValue(responsePending));
    const invalidation = vi.fn();
    window.addEventListener(authInvalidEvent, invalidation);
    startAuthSession();

    try {
      const pending = request('/api/slow', undefined, { retry: 0 });
      await Promise.resolve();
      startAuthSession();
      resolveResponse?.(new Response('expired', { status: 401 }));
      await expect(pending).rejects.toMatchObject({ status: 401 });
      expect(invalidation).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener(authInvalidEvent, invalidation);
    }
  });

  it.each([
    ['/api/public/status', { ok: true }],
    ['/api/auth/context', { role: 'admin', permissions: {} }],
    ['/api/overview', { attack_surfaces: [], summary: {} }]
  ])('rejects malformed successful runtime data from %s', async (path, payload) => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }))
    );

    await expect(request(path, undefined, { retry: 0 })).rejects.toMatchObject({ code: 'parse_error', path });
  });

  it('reports a live connection only after response headers and parses CRLF event frames', async () => {
    const encoder = new TextEncoder();
    const payload: RuntimeEvent = { id: 'event-1', type: 'run', created_at: '', payload: { audit_id: 'audit-1' } };
    const reader = {
      read: vi
        .fn()
        .mockResolvedValueOnce({ value: encoder.encode(`data: ${JSON.stringify(payload)}\r\n\r\n`), done: false })
        .mockResolvedValueOnce({ value: undefined, done: true }),
      releaseLock: vi.fn()
    };
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/event-stream; charset=utf-8' }),
        body: { getReader: () => reader }
      } as unknown as Response)
    );
    const onOpen = vi.fn();
    const onEvent = vi.fn();

    await subscribeRuntimeEvents(onEvent, new AbortController().signal, { onOpen });

    expect(onOpen).toHaveBeenCalledOnce();
    expect(onEvent).toHaveBeenCalledWith(payload);
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('rejects a successful response that does not establish the event-stream protocol', async () => {
    const onOpen = vi.fn();
    const cancel = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/html' }),
        body: { getReader: vi.fn(), cancel }
      } as unknown as Response)
    );

    await expect(subscribeRuntimeEvents(vi.fn(), new AbortController().signal, { onOpen })).rejects.toMatchObject({
      code: 'parse_error',
      path: '/api/events/stream'
    });
    expect(onOpen).not.toHaveBeenCalled();
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('joins multiline data fields before JSON parsing and validates the event shape', async () => {
    const encoder = new TextEncoder();
    const payload: RuntimeEvent = { id: 'event-multiline', type: 'run', created_at: '', payload: { ok: true } };
    const serialized = JSON.stringify(payload);
    const splitAt = Math.max(1, Math.floor(serialized.length / 2));
    const reader = {
      read: vi
        .fn()
        .mockResolvedValueOnce({
          value: encoder.encode(`data: ${serialized.slice(0, splitAt)}\ndata: ${serialized.slice(splitAt)}\n\n`),
          done: false
        })
        .mockResolvedValueOnce({ value: undefined, done: true }),
      releaseLock: vi.fn()
    };
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/event-stream' }),
        body: { getReader: () => reader }
      } as unknown as Response)
    );
    const onEvent = vi.fn();

    await subscribeRuntimeEvents(onEvent, new AbortController().signal);

    expect(onEvent).toHaveBeenCalledWith(payload);
  });

  it('cancels and releases the reader when an event consumer exits with an error', async () => {
    const encoder = new TextEncoder();
    const payload: RuntimeEvent = { id: 'event-callback', type: 'run', created_at: '', payload: {} };
    const reader = {
      read: vi.fn().mockResolvedValueOnce({
        value: encoder.encode(`data: ${JSON.stringify(payload)}\n\n`),
        done: false
      }),
      cancel: vi.fn().mockResolvedValue(undefined),
      releaseLock: vi.fn()
    };
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/event-stream' }),
        body: { getReader: () => reader }
      } as unknown as Response)
    );

    await expect(
      subscribeRuntimeEvents(() => {
        throw new Error('consumer stopped');
      }, new AbortController().signal)
    ).rejects.toThrow('consumer stopped');
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('stops after consecutive malformed runtime events instead of silently showing a live stream', async () => {
    const encoder = new TextEncoder();
    const reader = {
      read: vi.fn().mockResolvedValueOnce({
        value: encoder.encode('data: {bad}\n\ndata: {still-bad}\n\ndata: [1,2,3]\n\n'),
        done: false
      }),
      cancel: vi.fn().mockResolvedValue(undefined),
      releaseLock: vi.fn()
    };
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/event-stream' }),
        body: { getReader: () => reader }
      } as unknown as Response)
    );

    await expect(subscribeRuntimeEvents(vi.fn(), new AbortController().signal)).rejects.toMatchObject({
      code: 'parse_error',
      path: '/api/events/stream'
    });
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('stops an unterminated runtime event before its browser buffer can grow without bound', async () => {
    const encoder = new TextEncoder();
    const reader = {
      read: vi.fn().mockResolvedValueOnce({
        value: encoder.encode(`data: ${'x'.repeat(1_048_577)}`),
        done: false
      }),
      cancel: vi.fn().mockResolvedValue(undefined),
      releaseLock: vi.fn()
    };
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'text/event-stream' }),
        body: { getReader: () => reader }
      } as unknown as Response)
    );

    await expect(subscribeRuntimeEvents(vi.fn(), new AbortController().signal)).rejects.toMatchObject({
      code: 'parse_error',
      path: '/api/events/stream'
    });
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });
});
