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
    let refreshInFlight = false;
    let refreshDirty = false;
    const runRefresh = () => {
      refreshTimer = undefined;
      if (lifetime.signal.aborted || refreshInFlight) return;
      refreshInFlight = true;
      refreshDirty = false;
      try {
        void Promise.resolve(refreshRef.current())
          .catch(() => undefined)
          .finally(() => {
            refreshInFlight = false;
            if (refreshDirty && !lifetime.signal.aborted) scheduleRefresh();
          });
      } catch {
        refreshInFlight = false;
        // The owner renders refresh failures next to its data surface. The
        // connection loop must stay alive when a synchronous refresh fails.
      }
    };
    const scheduleRefresh = () => {
      if (lifetime.signal.aborted) return;
      refreshDirty = true;
      if (refreshInFlight || refreshTimer !== undefined) return;
      refreshTimer = window.setTimeout(runRefresh, debounceMs);
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
      refreshTimer = undefined;
    };
  }, [debounceMs, enabled, refreshOnConnect, subscribe]);

  return enabled ? connection : idleRuntimeEventConnection;
}
