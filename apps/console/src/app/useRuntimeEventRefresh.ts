import { useEffect, useRef, useState } from 'react';
import type { RuntimeEvent } from './apiRequest';
import {
  connectingRuntimeEventConnection,
  idleRuntimeEventConnection,
  maintainRuntimeEventConnection,
  type RuntimeEventConnection,
  type RuntimeEventSubscriber
} from './runtimeEventConnection';

type RuntimeEventRefreshOptions = {
  enabled?: boolean;
  debounceMs?: number;
  refreshOnConnect?: boolean;
  subscribe?: RuntimeEventSubscriber;
};

export function useRuntimeEventRefresh(
  refresh: () => void | Promise<unknown>,
  { enabled = true, debounceMs = 250, refreshOnConnect = true, subscribe }: RuntimeEventRefreshOptions = {}
): RuntimeEventConnection {
  const refreshRef = useRef(refresh);
  const [connection, setConnection] = useState<RuntimeEventConnection>(
    enabled ? connectingRuntimeEventConnection : idleRuntimeEventConnection
  );

  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);

  useEffect(() => {
    if (!enabled) return undefined;

    const lifetime = new AbortController();
    let refreshTimer: number | undefined;
    const scheduleRefresh = () => {
      if (refreshTimer !== undefined) window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(() => {
        refreshTimer = undefined;
        if (!lifetime.signal.aborted) {
          try {
            void Promise.resolve(refreshRef.current()).catch(() => undefined);
          } catch {
            // The owner renders refresh failures next to its data surface. The
            // connection loop must stay alive when a synchronous refresh fails.
          }
        }
      }, debounceMs);
    };
    const onEvent = (_event: RuntimeEvent) => scheduleRefresh();

    void Promise.resolve().then(() =>
      maintainRuntimeEventConnection({
        signal: lifetime.signal,
        onEvent,
        onConnected: refreshOnConnect ? scheduleRefresh : undefined,
        onConnectionChange: (nextConnection) => {
          if (!lifetime.signal.aborted) setConnection(nextConnection);
        },
        subscribe
      })
    );

    return () => {
      lifetime.abort();
      if (refreshTimer !== undefined) window.clearTimeout(refreshTimer);
    };
  }, [debounceMs, enabled, refreshOnConnect, subscribe]);

  return enabled ? connection : idleRuntimeEventConnection;
}
