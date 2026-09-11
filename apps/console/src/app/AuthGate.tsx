import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { LockKeyhole, LogIn, RefreshCw } from 'lucide-react';
import type { AuthContext } from '../types';
import {
  PanelCard,
  UiAlert,
  UiButton,
  UiConfigProvider,
  UiForm,
  UiInput,
  UiSpace,
  UiSpin,
  UiTypography
} from '../components/ui';
import {
  ApiError,
  authInvalidEvent,
  getAuthSessionVersion,
  invalidateAuthSession,
  startAuthSession,
  type AuthInvalidationDetail
} from './apiRequest';
import {
  clearAuthToken,
  fetchPublicConsoleStatus,
  getAuthToken,
  storeAuthToken,
  validateOperatorToken,
  type PublicConsoleStatus
} from './authSession';

export type AuthenticatedConsoleSession = {
  context: AuthContext;
  publicStatus: PublicConsoleStatus;
  signOut: () => void;
};

type AuthGateProps = {
  children: (session: AuthenticatedConsoleSession) => ReactNode;
};

function authErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return '凭证未通过校验，请检查后重新输入。';
    if (error.status === 403) return '凭证有效，但当前角色没有控制台访问权限。';
  }
  // Authentication failures must not echo provider/parser diagnostics into the
  // login surface. Keep the message stable while preserving actionable
  // status-specific guidance above for the known HTTP contract.
  return '身份校验失败，请稍后重试。';
}

export function AuthGate({ children }: AuthGateProps) {
  const [publicStatus, setPublicStatus] = useState<PublicConsoleStatus | null>(null);
  const [context, setContext] = useState<AuthContext | null>(null);
  const [token, setToken] = useState('');
  const [checking, setChecking] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const tokenInputRef = useRef<HTMLInputElement | null>(null);
  const activeSessionVersion = useRef<number | null>(null);
  const bootstrapSequence = useRef(0);
  const submitSequence = useRef(0);

  const activateSession = useCallback((nextContext: AuthContext) => {
    activeSessionVersion.current = startAuthSession();
    setContext(nextContext);
  }, []);

  const clearSessionUi = useCallback((nextError = '', clearStoredToken = true) => {
    if (clearStoredToken) clearAuthToken();
    setContext(null);
    setToken('');
    setError(nextError);
  }, []);

  const clearActiveSession = useCallback(
    (nextError = '', clearStoredToken = true) => {
      activeSessionVersion.current = null;
      invalidateAuthSession();
      clearSessionUi(nextError, clearStoredToken);
    },
    [clearSessionUi]
  );

  const bootstrap = useCallback(async () => {
    const sequence = ++bootstrapSequence.current;
    setChecking(true);
    setError('');
    try {
      const status = await fetchPublicConsoleStatus();
      if (sequence !== bootstrapSequence.current) return;
      setPublicStatus(status);
      const storedToken = getAuthToken();
      if (status.console_auth.required && !storedToken) {
        activeSessionVersion.current = null;
        invalidateAuthSession();
        setContext(null);
        return;
      }
      try {
        const nextContext = await validateOperatorToken(storedToken);
        if (sequence !== bootstrapSequence.current) return;
        if (!nextContext.permissions.can_view) {
          clearActiveSession(
            '当前凭证用于 Agent 运行，不具备控制台查看权限，请使用 observer、analyst 或 admin Token。'
          );
          return;
        }
        activateSession(nextContext);
      } catch (authError) {
        if (sequence !== bootstrapSequence.current) return;
        clearActiveSession(authErrorMessage(authError));
      }
    } catch (statusError) {
      if (sequence !== bootstrapSequence.current) return;
      setPublicStatus(null);
      clearActiveSession(authErrorMessage(statusError), false);
    } finally {
      if (sequence === bootstrapSequence.current) setChecking(false);
    }
  }, [activateSession, clearActiveSession]);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(() => {
      if (!cancelled) return bootstrap();
      return undefined;
    });
    return () => {
      cancelled = true;
    };
  }, [bootstrap]);

  useEffect(() => {
    const handleInvalidSession = (event: Event) => {
      const detail =
        event instanceof CustomEvent ? (event.detail as Partial<AuthInvalidationDetail> | undefined) : undefined;
      if (
        activeSessionVersion.current === null ||
        typeof detail?.sessionVersion !== 'number' ||
        detail.sessionVersion !== activeSessionVersion.current ||
        detail.sessionVersion !== getAuthSessionVersion()
      ) {
        return;
      }
      clearActiveSession('当前会话已失效，请重新验证身份。');
    };
    window.addEventListener(authInvalidEvent, handleInvalidSession);
    return () => window.removeEventListener(authInvalidEvent, handleInvalidSession);
  }, [clearActiveSession]);

  useEffect(() => {
    if (error && publicStatus?.console_auth.required) tokenInputRef.current?.focus();
  }, [error, publicStatus?.console_auth.required]);

  const submit = async () => {
    const normalized = token.trim();
    if (!normalized) {
      setError('请输入运行 Token。');
      return;
    }
    const sequence = ++submitSequence.current;
    setSubmitting(true);
    setError('');
    try {
      const nextContext = await validateOperatorToken(normalized);
      if (sequence !== submitSequence.current) return;
      if (!nextContext.permissions.can_view) {
        clearActiveSession('当前凭证用于 Agent 运行，不具备控制台查看权限，请使用 observer、analyst 或 admin Token。');
        return;
      }
      storeAuthToken(normalized);
      activateSession(nextContext);
      setToken('');
    } catch (authError) {
      if (sequence !== submitSequence.current) return;
      setError(authErrorMessage(authError));
    } finally {
      if (sequence === submitSequence.current) setSubmitting(false);
    }
  };

  const signOut = useCallback(() => {
    invalidateAuthSession();
    clearSessionUi();
  }, [clearSessionUi]);

  const localEntry = publicStatus?.console_auth.required === false;

  if (checking) {
    return (
      <div className="zh-auth-page" aria-live="polite">
        <UiSpin size="large" />
        <UiTypography.Text type="secondary">正在确认控制台与后端状态…</UiTypography.Text>
      </div>
    );
  }

  if (context && publicStatus) {
    return children({ context, publicStatus, signOut });
  }

  return (
    <UiConfigProvider theme={{ hashed: false }}>
      <main className="zh-auth-page">
        <section className="zh-auth-shell" aria-labelledby="console-login-title">
          <div className="zh-auth-brand">
            <img src="/favicon.png" alt="" className="zh-app-logo" />
            <div>
              <UiTypography.Text strong>智垒</UiTypography.Text>
              <UiTypography.Text type="secondary">AI Agent Firewall</UiTypography.Text>
            </div>
          </div>

          <PanelCard variant="borderless" className="zh-auth-card">
            <UiSpace orientation="vertical" size={4} className="zh-auth-heading">
              <UiTypography.Title level={2} id="console-login-title" className="zh-title-flush">
                连接安全控制台
              </UiTypography.Title>
              <UiTypography.Paragraph type="secondary" className="zh-mb-0">
                先验证操作员身份，再加载实时流量、策略和审计数据。Token 只保存在当前浏览器会话。
              </UiTypography.Paragraph>
            </UiSpace>

            {!publicStatus && (
              <UiAlert type="error" showIcon title="后端服务未连接" description="请先运行一键启动脚本，再重试连接。" />
            )}

            {error && <UiAlert type="error" showIcon title={error} />}

            {publicStatus?.console_auth.required && (
              <UiForm layout="vertical" requiredMark={false} onFinish={() => void submit()} className="zh-auth-form">
                <UiForm.Item label="运行 Token" required>
                  <UiInput.Password
                    ref={(input) => {
                      tokenInputRef.current = input?.input ?? null;
                    }}
                    autoFocus
                    autoComplete="current-password"
                    prefix={<LockKeyhole size={16} aria-hidden="true" />}
                    value={token}
                    onChange={(event) => setToken(event.target.value)}
                    placeholder="粘贴操作员 Token"
                    aria-label="运行 Token"
                  />
                </UiForm.Item>
                <UiButton htmlType="submit" type="primary" block loading={submitting}>
                  验证并进入
                </UiButton>
              </UiForm>
            )}

            <UiButton
              icon={localEntry ? <LogIn size={16} /> : <RefreshCw size={16} />}
              onClick={() => void bootstrap()}
              disabled={checking || submitting}
              block
            >
              {localEntry ? '进入系统' : '重新检测后端'}
            </UiButton>
          </PanelCard>
        </section>
      </main>
    </UiConfigProvider>
  );
}
