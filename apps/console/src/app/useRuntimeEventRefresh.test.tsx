import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RuntimeEvent } from './apiRequest';
import { useRuntimeEventRefresh } from './useRuntimeEventRefresh';

afterEach(() => vi.useRealTimers());

describe('useRuntimeEventRefresh', () => {
  it('coalesces burst events and aborts the stream when the owner unmounts', async () => {
    vi.useFakeTimers();
    const refresh = vi.fn(() => {
      throw new Error('owner-rendered refresh failure');
    });
    let emit: ((event: RuntimeEvent) => void) | undefined;
    let streamSignal: AbortSignal | undefined;
    const subscribe = vi.fn((onEvent, signal: AbortSignal, lifecycle) => {
      emit = onEvent;
      streamSignal = signal;
      lifecycle?.onOpen?.();
      return new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }));
    });
    const { result, unmount } = renderHook(() =>
      useRuntimeEventRefresh(refresh, { debounceMs: 200, refreshOnConnect: false, subscribe })
    );

    await act(async () => Promise.resolve());
    expect(result.current.status).toBe('connected');
    act(() => {
      const runtimeEvent = { id: '1', type: 'run', created_at: '', payload: {} };
      emit?.(runtimeEvent);
      emit?.(runtimeEvent);
      emit?.(runtimeEvent);
      vi.advanceTimersByTime(199);
    });
    expect(refresh).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(1));
    expect(refresh).toHaveBeenCalledOnce();
    expect(result.current.status).toBe('connected');

    unmount();
    expect(streamSignal?.aborted).toBe(true);
  });
});
