import { linkAbortSignal } from './requestAbort';
import { validateRuntimeResponse } from './runtimeResponseValidation';
import {
  ApiError,
  dispatchAuthInvalidation,
  getAuthSessionVersion,
  normalizeRequestError,
  readableErrorMessage,
  readErrorBody,
  resolveRequestHeaders,
  type RequestOptions
} from './apiRequestSupport';

export {
  ApiError,
  authInvalidEvent,
  dispatchAuthInvalidation,
  getAuthSessionVersion,
  invalidateAuthSession,
  resolveRequestHeaders,
  safeUiDiagnostic,
  safeUiErrorSummary,
  setAuthTokenProvider,
  startAuthSession,
  type ApiErrorCode,
  type AuthInvalidationDetail,
  type RequestOptions
} from './apiRequestSupport';
export {
  openRuntimeEventStream as subscribeRuntimeEvents,
  type RuntimeEvent,
  type RuntimeEventSubscriptionLifecycle
} from './runtimeEventStream';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_GET_RETRY = 1;

function requestMethod(init?: RequestInit) {
  return (init?.method ?? 'GET').toUpperCase();
}

function shouldRetryRequest(init: RequestInit | undefined, error: ApiError) {
  const method = requestMethod(init);
  if (method !== 'GET' && method !== 'HEAD') return false;
  if (error.code === 'network_error' || error.code === 'timeout') return true;
  return error.status === 408 || error.status === 429 || Boolean(error.status && error.status >= 500);
}

async function parseJsonResponse<T>(response: Response, path: string): Promise<T> {
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new ApiError('Invalid JSON response', { code: 'parse_error', path, status: response.status });
  }
  if (!validateRuntimeResponse(path, value)) {
    throw new ApiError('Invalid runtime response shape', { code: 'parse_error', path, status: response.status });
  }
  return value as T;
}

export async function openAuthenticatedResource(path: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<void> {
  const sessionVersion = getAuthSessionVersion();
  const popup = window.open('', '_blank');
  if (!popup) {
    throw new ApiError('浏览器阻止了报告窗口，请允许当前页面打开新窗口。', { code: 'network_error', path });
  }

  const controller = timeoutMs > 0 ? new AbortController() : undefined;
  const timeoutId = controller ? window.setTimeout(() => controller.abort(), timeoutMs) : undefined;
  try {
    const response = await fetch(path, {
      cache: 'no-store',
      headers: await resolveRequestHeaders(undefined, undefined, {}, controller?.signal),
      signal: controller?.signal
    });
    if (!response.ok) {
      const body = await readErrorBody(response);
      if (response.status === 401) dispatchAuthInvalidation(path, sessionVersion);
      throw new ApiError(readableErrorMessage(body, response.status), {
        code: 'http_error',
        path,
        status: response.status,
        body
      });
    }
    const resourceUrl = URL.createObjectURL(await response.blob());
    popup.location.href = resourceUrl;
    window.setTimeout(() => URL.revokeObjectURL(resourceUrl), 60_000);
  } catch (error) {
    popup.close();
    throw normalizeRequestError(error, path);
  } finally {
    if (timeoutId !== undefined) window.clearTimeout(timeoutId);
  }
}

export async function request<T>(path: string, init?: RequestInit, options: RequestOptions = {}): Promise<T> {
  const sessionVersion = getAuthSessionVersion();
  const attempts = Math.max(1, (options.retry ?? DEFAULT_GET_RETRY) + 1);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let lastError: ApiError | undefined;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const controller = timeoutMs > 0 ? new AbortController() : undefined;
    const timeoutId = controller ? window.setTimeout(() => controller.abort(), timeoutMs) : undefined;
    const { headers, signal, ...requestInit } = init ?? {};
    const detachCallerAbort = controller ? linkAbortSignal(signal, controller) : () => undefined;
    const activeSignal = controller?.signal ?? signal ?? undefined;

    try {
      const response = await fetch(path, {
        ...requestInit,
        cache: requestMethod(init) === 'GET' ? 'no-store' : requestInit.cache,
        headers: await resolveRequestHeaders(headers, init, options, activeSignal),
        signal: activeSignal
      });
      if (!response.ok) {
        const body = await readErrorBody(response);
        if (response.status === 401 && !options.skipAuth) dispatchAuthInvalidation(path, sessionVersion);
        throw new ApiError(readableErrorMessage(body, response.status), {
          code: 'http_error',
          path,
          status: response.status,
          body
        });
      }
      return options.responseParser
        ? ((await options.responseParser(response)) as T)
        : await parseJsonResponse<T>(response, path);
    } catch (error) {
      lastError = normalizeRequestError(error, path, signal?.aborted === true);
      if (!signal?.aborted && attempt < attempts - 1 && shouldRetryRequest(init, lastError)) continue;
      throw lastError;
    } finally {
      detachCallerAbort();
      if (timeoutId !== undefined) window.clearTimeout(timeoutId);
    }
  }

  throw lastError ?? new ApiError('Network request failed', { code: 'network_error', path });
}
