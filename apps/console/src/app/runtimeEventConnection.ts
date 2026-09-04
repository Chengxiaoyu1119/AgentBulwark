import { subscribeRuntimeEvents, type RuntimeEvent, type RuntimeEventSubscriptionLifecycle } from './apiRequest';
import { safeUiErrorSummary } from './apiRequestSupport';
import { linkAbortSignal } from './requestAbort';

export type RuntimeEventConnectionStatus = 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'unavailable';

export type RuntimeEventConnection = {
  status: RuntimeEventConnectionStatus;
  attempt: number;
  retryDelayMs: number;
  message: string;
};

export type RuntimeEventSubscriber = (
  onEvent: (event: RuntimeEvent) => void,
  signal: AbortSignal,
  lifecycle?: RuntimeEventSubscriptionLifecycle
) => Promise<void>;

export const idleRuntimeEventConnection: RuntimeEventConnection = {
  status: 'idle',
  attempt: 0,
  retryDelayMs: 0,
  message: '实时事件连接尚未启动。'
};

export const connectingRuntimeEventConnection: RuntimeEventConnection = {
  status: 'connecting',
  attempt: 0,
  retryDelayMs: 0,
  message: '正在连接实时事件流。'
};

type RuntimeEventConnectionOptions = {
  signal: AbortSignal;
  onEvent: (event: RuntimeEvent) => void;
  onConnectionChange: (connection: RuntimeEventConnection) => void;
  onConnected?: () => void;
  subscribe?: RuntimeEventSubscriber;
  wait?: (delayMs: number, signal: AbortSignal) => Promise<void>;
  now?: () => number;
  baseRetryDelayMs?: number;
  maxRetryDelayMs?: number;
  stableConnectionMs?: number;
  connectTimeoutMs?: number;
};

function errorStatus(error: unknown): number | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const status = (error as { status?: unknown }).status;
  return typeof status === 'number' ? status : undefined;
}

function permanentFailureMessage(status: number | undefined): string | null {
  if (status === 401) return '当前会话已失效，实时事件连接已停止。';
  if (status === 403) return '当前身份没有实时事件读取权限。';
  if (status === 404) return '后端未提供实时事件接口，请检查前后端版本。';
  if (status !== undefined && status >= 400 && status < 500 && status !== 408 && status !== 429) {
    return `实时事件请求未通过校验（HTTP ${status}）。`;
  }
  return null;
}

function transientFailureMessage(error: unknown): string {
  const status = errorStatus(error);
  if (status === 429) return '实时事件请求过于频繁，正在降低重连速率。';
  if (status !== undefined && status >= 500) return `实时事件服务暂时不可用（HTTP ${status}）。`;
  if (error instanceof Error && error.message === '实时事件握手超时') return '实时事件握手超时。';
  return safeUiErrorSummary(error, '实时事件连接已断开。');
}

export function runtimeEventRetryDelay(attempt: number, baseRetryDelayMs = 1_000, maxRetryDelayMs = 15_000): number {
  const safeAttempt = Math.max(1, Math.floor(attempt));
  return Math.min(baseRetryDelayMs * 2 ** Math.min(safeAttempt - 1, 20), maxRetryDelayMs);
}

export function waitForRuntimeEventRetry(delayMs: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted || delayMs <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    const finish = () => {
      window.clearTimeout(timer);
      signal.removeEventListener('abort', finish);
      resolve();
    };
    const timer = window.setTimeout(finish, delayMs);
    signal.addEventListener('abort', finish, { once: true });
  });
}

export async function maintainRuntimeEventConnection({
  signal,
  onEvent,
  onConnectionChange,
  onConnected,
  subscribe = subscribeRuntimeEvents,
  wait = waitForRuntimeEventRetry,
  now = Date.now,
  baseRetryDelayMs = 1_000,
  maxRetryDelayMs = 15_000,
  stableConnectionMs = 30_000,
  connectTimeoutMs = 10_000
}: RuntimeEventConnectionOptions): Promise<void> {
  let consecutiveFailures = 0;

  while (!signal.aborted) {
    onConnectionChange(
      consecutiveFailures === 0
        ? connectingRuntimeEventConnection
        : {
            status: 'reconnecting',
            attempt: consecutiveFailures,
            retryDelayMs: 0,
            message: `正在进行第 ${consecutiveFailures + 1} 次实时事件连接。`
          }
    );

    const attemptController = new AbortController();
    const detachLifetimeAbort = linkAbortSignal(signal, attemptController);
    let connectedAt: number | null = null;
    let connectTimedOut = false;
    let connectTimeout = window.setTimeout(
      () => {
        connectTimedOut = true;
        attemptController.abort();
      },
      Math.max(1, connectTimeoutMs)
    );
    try {
      await subscribe(onEvent, attemptController.signal, {
        onOpen: () => {
          if (signal.aborted || attemptController.signal.aborted || connectedAt !== null) return;
          window.clearTimeout(connectTimeout);
          connectTimeout = 0;
          connectedAt = now();
          onConnectionChange({
            status: 'connected',
            attempt: 0,
            retryDelayMs: 0,
            message: '实时事件连接正常。'
          });
          onConnected?.();
        }
      });
      if (connectTimedOut) throw new Error('实时事件握手超时');
      if (signal.aborted) return;
    } catch (error) {
      if (signal.aborted) return;
      window.clearTimeout(connectTimeout);
      connectTimeout = 0;
      detachLifetimeAbort();
      const failure = connectTimedOut ? new Error('实时事件握手超时') : error;
      const permanentMessage = permanentFailureMessage(errorStatus(failure));
      if (permanentMessage) {
        onConnectionChange({ status: 'unavailable', attempt: 0, retryDelayMs: 0, message: permanentMessage });
        return;
      }

      if (connectedAt !== null && now() - connectedAt >= stableConnectionMs) consecutiveFailures = 0;
      consecutiveFailures += 1;
      const retryDelayMs = runtimeEventRetryDelay(consecutiveFailures, baseRetryDelayMs, maxRetryDelayMs);
      onConnectionChange({
        status: 'reconnecting',
        attempt: consecutiveFailures,
        retryDelayMs,
        message: `${transientFailureMessage(failure)} ${Math.ceil(retryDelayMs / 1_000)} 秒后重试。`
      });
      await wait(retryDelayMs, signal);
      continue;
    } finally {
      window.clearTimeout(connectTimeout);
      detachLifetimeAbort();
    }

    if (connectedAt !== null && now() - connectedAt >= stableConnectionMs) consecutiveFailures = 0;
    consecutiveFailures += 1;
    const retryDelayMs = runtimeEventRetryDelay(consecutiveFailures, baseRetryDelayMs, maxRetryDelayMs);
    onConnectionChange({
      status: 'reconnecting',
      attempt: consecutiveFailures,
      retryDelayMs,
      message: `实时事件连接已断开，${Math.ceil(retryDelayMs / 1_000)} 秒后重试。`
    });
    await wait(retryDelayMs, signal);
  }
}
