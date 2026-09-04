import { describe, expect, it, vi } from 'vitest';
import { ApiError, type RuntimeEvent } from './apiRequest';
import {
  maintainRuntimeEventConnection,
  runtimeEventRetryDelay,
  type RuntimeEventConnection,
  type RuntimeEventSubscriber
} from './runtimeEventConnection';

const event: RuntimeEvent = { id: '1', type: 'run', created_at: '2026-08-23T10:00:00Z', payload: {} };

describe('runtime event connection', () => {
  it('opens, dispatches an event, and reconnects after a short stream closes', async () => {
    const lifetime = new AbortController();
    const states: RuntimeEventConnection[] = [];
    const events: RuntimeEvent[] = [];
    const delays: number[] = [];
    let calls = 0;
    const subscribe: RuntimeEventSubscriber = vi.fn(async (onEvent, signal, lifecycle) => {
      calls += 1;
      lifecycle?.onOpen?.();
      if (calls === 1) {
        onEvent(event);
        return;
      }
      await new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }));
    });

    const running = maintainRuntimeEventConnection({
      signal: lifetime.signal,
      onEvent: (nextEvent) => events.push(nextEvent),
      onConnectionChange: (state) => states.push(state),
      subscribe,
      now: () => 0,
      wait: async (delayMs) => {
        delays.push(delayMs);
      }
    });
    await vi.waitFor(() => expect(subscribe).toHaveBeenCalledTimes(2));
    lifetime.abort();
    await running;

    expect(events).toEqual([event]);
    expect(delays).toEqual([1_000]);
    expect(states.map((state) => state.status)).toContain('connected');
    expect(states).toContainEqual(expect.objectContaining({ status: 'reconnecting', attempt: 1, retryDelayMs: 1_000 }));
  });

  it('stops on an invalid session instead of creating a retry loop', async () => {
    const states: RuntimeEventConnection[] = [];
    const wait = vi.fn();
    await maintainRuntimeEventConnection({
      signal: new AbortController().signal,
      onEvent: vi.fn(),
      onConnectionChange: (state) => states.push(state),
      subscribe: async () => {
        throw new ApiError('Invalid token', { code: 'http_error', path: '/api/events/stream', status: 401 });
      },
      wait
    });

    expect(wait).not.toHaveBeenCalled();
    expect(states[states.length - 1]).toMatchObject({
      status: 'unavailable',
      message: expect.stringContaining('会话已失效')
    });
  });

  it('uses exponential retry delays with a strict upper bound', async () => {
    const lifetime = new AbortController();
    const delays: number[] = [];
    await maintainRuntimeEventConnection({
      signal: lifetime.signal,
      onEvent: vi.fn(),
      onConnectionChange: vi.fn(),
      subscribe: async () => {
        throw new TypeError('network down');
      },
      wait: async (delayMs) => {
        delays.push(delayMs);
        if (delays.length === 6) lifetime.abort();
      }
    });

    expect(delays).toEqual([1_000, 2_000, 4_000, 8_000, 15_000, 15_000]);
    expect(runtimeEventRetryDelay(50)).toBe(15_000);
  });

  it('abandons a connection attempt that never completes its HTTP handshake', async () => {
    const lifetime = new AbortController();
    const states: RuntimeEventConnection[] = [];
    const subscribe: RuntimeEventSubscriber = vi.fn(
      (_onEvent, signal) =>
        new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }))
    );

    await maintainRuntimeEventConnection({
      signal: lifetime.signal,
      onEvent: vi.fn(),
      onConnectionChange: (state) => states.push(state),
      subscribe,
      connectTimeoutMs: 1,
      wait: async () => lifetime.abort()
    });

    expect(subscribe).toHaveBeenCalledOnce();
    expect(states).toContainEqual(
      expect.objectContaining({ status: 'reconnecting', message: expect.stringContaining('握手超时') })
    );
  });
});
