import { isAbortError } from './requestAbort';

export type RequestOptions = {
  timeoutMs?: number;
  retry?: number;
  skipAuth?: boolean;
  authToken?: string | null;
  responseParser?: (response: Response) => Promise<unknown>;
};

export type ApiErrorCode = 'http_error' | 'network_error' | 'timeout' | 'aborted' | 'parse_error';

export const authInvalidEvent = 'agent-supervisor:auth-invalid';

export type AuthInvalidationDetail = {
  path: string;
  sessionVersion: number;
};

type ApiErrorParams = {
  code: ApiErrorCode;
  path: string;
  status?: number;
  body?: string;
};

export class ApiError extends Error {
  code: ApiErrorCode;
  path: string;
  status?: number;
  body?: string;

  constructor(message: string, params: ApiErrorParams) {
    super(message);
    this.name = 'ApiError';
    this.code = params.code;
    this.path = params.path;
    this.status = params.status;
    this.body = params.body;
  }
}

type AuthTokenProvider = () => string | null | undefined | Promise<string | null | undefined>;

let authSessionVersion = 0;
let authTokenProvider: AuthTokenProvider | null = null;

export function startAuthSession() {
  authSessionVersion += 1;
  return authSessionVersion;
}

export function invalidateAuthSession() {
  authSessionVersion += 1;
  return authSessionVersion;
}

export function getAuthSessionVersion() {
  return authSessionVersion;
}

export function dispatchAuthInvalidation(path: string, sessionVersion: number) {
  if (sessionVersion !== getAuthSessionVersion()) return;
  window.dispatchEvent(new CustomEvent<AuthInvalidationDetail>(authInvalidEvent, { detail: { path, sessionVersion } }));
}

export function setAuthTokenProvider(provider: AuthTokenProvider | null) {
  authTokenProvider = provider;
}

function hasJsonBody(init: RequestInit | undefined) {
  return Boolean(init?.body) && !(init?.body instanceof FormData);
}

function abortError() {
  return new DOMException('Aborted', 'AbortError');
}

async function waitForToken(
  candidate: string | null | undefined | Promise<string | null | undefined>,
  signal?: AbortSignal
) {
  if (!signal) return candidate;
  if (signal.aborted) throw abortError();

  return new Promise<string | null | undefined>((resolve, reject) => {
    const abort = () => reject(abortError());
    signal.addEventListener('abort', abort, { once: true });
    void Promise.resolve(candidate).then(
      (token) => {
        signal.removeEventListener('abort', abort);
        resolve(token);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', abort);
        reject(error);
      }
    );
  });
}

export async function resolveRequestHeaders(
  headers: HeadersInit | undefined,
  init: RequestInit | undefined,
  options: RequestOptions,
  signal?: AbortSignal
) {
  const mergedHeaders = new Headers(headers);
  if (hasJsonBody(init) && !mergedHeaders.has('Content-Type')) {
    mergedHeaders.set('Content-Type', 'application/json');
  }
  if (!options.skipAuth && !mergedHeaders.has('Authorization')) {
    const candidate = options.authToken !== undefined ? options.authToken : authTokenProvider?.();
    const token = await waitForToken(candidate, signal);
    if (token) mergedHeaders.set('Authorization', `Bearer ${token}`);
  }
  return mergedHeaders;
}

export async function readErrorBody(response: Response) {
  try {
    return await response.text();
  } catch {
    return '';
  }
}

function boundedText(value: string, maxLength = 500) {
  return Array.from(value, (character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint < 32 || codePoint === 127 ? ' ' : character;
  })
    .join('')
    .trim()
    .slice(0, maxLength);
}

export function safeUiDiagnostic(error: unknown) {
  const raw = error instanceof Error ? error.message : '';
  const redacted = boundedText(raw, 500)
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [已隐藏]')
    .replace(/\b(token|api[-_ ]?key|secret|password)\s*[:=]\s*[^\s,;]+/gi, '$1=[已隐藏]')
    .replace(/([?&](?:token|api_key|key)=)[^&\s]+/gi, '$1[已隐藏]');
  return boundedText(redacted, 120) || '暂无更多诊断信息。';
}

export function readableErrorMessage(body: string, status?: number) {
  const fallback = boundedText(body) || (status ? `HTTP ${status}` : '请求失败');
  if (!body) return fallback;
  try {
    const payload: unknown = JSON.parse(body);
    if (!payload || typeof payload !== 'object') return fallback;
    const record = payload as Record<string, unknown>;
    const detail = record.detail;
    if (typeof detail === 'string' && detail.trim()) return boundedText(detail);
    if (Array.isArray(detail)) {
      const messages = detail
        .slice(0, 5)
        .map((item) => {
          if (!item || typeof item !== 'object') return boundedText(String(item ?? ''), 100);
          const itemRecord = item as Record<string, unknown>;
          const message = typeof itemRecord.msg === 'string' ? boundedText(itemRecord.msg, 100) : '';
          const location = Array.isArray(itemRecord.loc)
            ? itemRecord.loc
                .slice(0, 5)
                .map(String)
                .map((value) => boundedText(value, 40))
                .filter(Boolean)
                .join('.')
            : '';
          return message && location ? `${location}: ${message}` : message;
        })
        .filter(Boolean);
      if (messages.length) return boundedText(messages.join('；'));
    }
    if (detail && typeof detail === 'object') {
      const detailRecord = detail as Record<string, unknown>;
      for (const key of ['message', 'error', 'reason']) {
        const value = detailRecord[key];
        if (typeof value === 'string' && value.trim()) return boundedText(value);
      }
    }
    if (typeof record.message === 'string' && record.message.trim()) return boundedText(record.message);
  } catch {
    // Keep a bounded plain-text diagnostic on the structured error object.
  }
  return fallback;
}

export function normalizeRequestError(error: unknown, path: string, callerAborted = false): ApiError {
  if (error instanceof ApiError) return error;
  if (callerAborted && isAbortError(error)) {
    return new ApiError('Request aborted', { code: 'aborted', path });
  }
  if (isAbortError(error)) {
    return new ApiError('Request timed out', { code: 'timeout', path });
  }
  const message = error instanceof Error ? boundedText(error.message) : 'Network request failed';
  return new ApiError(message || 'Network request failed', { code: 'network_error', path });
}

export function safeUiErrorSummary(error: unknown, fallback = '请求失败，请稍后重试。') {
  if (error instanceof ApiError) {
    if (error.status === 401) return '当前会话已失效，请重新验证身份。';
    if (error.status === 403) return '当前身份没有执行此操作的权限。';
    // A streaming endpoint keeps HTTP 200 after headers are committed and
    // reports a bounded protocol error as an SSE event. Preserve that
    // operator-facing diagnostic instead of mislabeling it as an HTTP denial.
    if (error.code === 'http_error' && error.status === 200) return safeUiDiagnostic(error);
    if (error.code === 'timeout') return '连接后端超时，请稍后重试。';
    if (error.code === 'network_error') return '尚未连接到后端服务，请检查服务状态后重试。';
    if (error.code === 'parse_error') return '后端返回的数据格式不符合预期，请稍后重试。';
    if (error.code === 'aborted') return '请求已取消。';
    return '后端拒绝了本次请求，请稍后重试。';
  }
  // Non-HTTP failures (for example, a local parser or a test double) do not
  // carry a trustworthy status code. Keep their bounded, redacted diagnostic
  // so the operator can act on a concrete validation message without ever
  // rendering the original unbounded Error.message.
  if (error instanceof Error) return safeUiDiagnostic(error);
  return boundedText(fallback, 120) || '请求失败，请稍后重试。';
}
