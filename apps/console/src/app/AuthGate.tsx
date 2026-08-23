import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { ConfigProvider, Form, Space, Spin, Typography } from 'antd';
import { LockKeyhole, RefreshCw, ShieldCheck } from 'lucide-react';
import type { AuthContext } from '../types';
import { PanelCard, UiAlert, UiButton, UiInput } from '../components/ui';
import { ApiError, authInvalidEvent } from './apiRequest';
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
    if (error.code === 'timeout') return '连接后端超时，请确认服务正在运行。';
    if (error.code === 'network_error') return '尚未连接到后端服务，请先启动智安哨。';
  }
  return error instanceof Error ? error.message : '身份校验失败。';
}

export function AuthGate({ children }: AuthGateProps) {
  const [publicStatus, setPublicStatus] = useState<PublicConsoleStatus | null>(null);
  const [context, setContext] = useState<AuthContext | null>(null);
  const [token, setToken] = useState('');
  const [checking, setChecking] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const bootstrap = useCallback(async () => {
    setChecking(true);
    setError('');
    try {
      const status = await fetchPublicConsoleStatus();
      setPublicStatus(status);
      const storedToken = getAuthToken();
      if (status.console_auth.required && !storedToken) {
        setContext(null);
        return;
      }
      try {
        setContext(await validateOperatorToken(storedToken));
      } catch (authError) {
        clearAuthToken();
        setContext(null);
        setError(authErrorMessage(authError));
      }
    } catch (statusError) {
      setPublicStatus(null);
      setContext(null);
      setError(authErrorMessage(statusError));
    } finally {
      setChecking(false);
    }
  }, []);

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
    const handleInvalidSession = () => {
      clearAuthToken();
      setContext(null);
      setError('当前会话已失效，请重新验证身份。');
    };
    window.addEventListener(authInvalidEvent, handleInvalidSession);
    return () => window.removeEventListener(authInvalidEvent, handleInvalidSession);
  }, []);

  const submit = async () => {
    const normalized = token.trim();
    if (!normalized) {
      setError('请输入运行 Token。');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const nextContext = await validateOperatorToken(normalized);
      storeAuthToken(normalized);
      setContext(nextContext);
      setToken('');
    } catch (authError) {
      setError(authErrorMessage(authError));
    } finally {
      setSubmitting(false);
    }
  };

  const signOut = () => {
    clearAuthToken();
    setContext(null);
    setToken('');
    setError('');
  };

  if (checking) {
    return (
      <div className="zh-auth-page" aria-live="polite">
        <Spin size="large" />
        <Typography.Text type="secondary">正在确认控制台与后端状态…</Typography.Text>
      </div>
    );
  }

  if (context && publicStatus) {
    return children({ context, publicStatus, signOut });
  }

  return (
    <ConfigProvider theme={{ hashed: false }}>
      <main className="zh-auth-page">
        <section className="zh-auth-shell" aria-labelledby="console-login-title">
          <div className="zh-auth-brand">
            <img src="/favicon.svg" alt="" className="zh-app-logo" />
            <div>
              <Typography.Text strong>智安哨</Typography.Text>
              <Typography.Text type="secondary">AI Agent Runtime Security</Typography.Text>
            </div>
          </div>

          <PanelCard variant="borderless" className="zh-auth-card">
            <Space orientation="vertical" size={4} className="zh-auth-heading">
              <span className="zh-auth-icon" aria-hidden="true">
                <ShieldCheck size={22} />
              </span>
              <Typography.Title level={2} id="console-login-title" className="zh-title-flush">
                连接安全控制台
              </Typography.Title>
              <Typography.Paragraph type="secondary" className="zh-mb-0">
                先验证操作员身份，再加载实时流量、策略和审计数据。Token 只保存在当前浏览器会话。
              </Typography.Paragraph>
            </Space>

            {!publicStatus && (
              <UiAlert
                type="error"
                showIcon
                title="后端服务未连接"
                description="请先运行一键启动脚本，再重试连接。"
              />
            )}

            {publicStatus && (
              <div className="zh-auth-environment" aria-label="当前后端环境">
                <span>后端在线</span>
                <span>{publicStatus.console_auth.profile === 'production' ? '生产安全档' : '本机安全档'}</span>
                <span>{publicStatus.console_auth.required ? '需要凭证' : '本机免鉴权'}</span>
              </div>
            )}

            {error && <UiAlert type="error" showIcon title={error} />}

            {publicStatus?.console_auth.required && (
              <Form
                layout="vertical"
                requiredMark={false}
                onFinish={() => void submit()}
                className="zh-auth-form"
              >
                <Form.Item label="运行 Token" required>
                  <UiInput.Password
                    autoFocus
                    autoComplete="current-password"
                    prefix={<LockKeyhole size={16} aria-hidden="true" />}
                    value={token}
                    onChange={(event) => setToken(event.target.value)}
                    placeholder="粘贴操作员 Token"
                    aria-label="运行 Token"
                  />
                </Form.Item>
                <UiButton htmlType="submit" type="primary" block loading={submitting}>
                  验证并进入
                </UiButton>
              </Form>
            )}

            <UiButton
              icon={<RefreshCw size={16} />}
              onClick={() => void bootstrap()}
              disabled={checking || submitting}
              block
            >
              重新检测后端
            </UiButton>
          </PanelCard>
        </section>
      </main>
    </ConfigProvider>
  );
}
