import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthGate } from './AuthGate';
import { ApiError, authInvalidEvent, getAuthSessionVersion } from './apiRequest';
import {
  clearAuthToken,
  fetchPublicConsoleStatus,
  getAuthToken,
  storeAuthToken,
  validateOperatorToken
} from './authSession';

vi.mock('./authSession', () => ({
  clearAuthToken: vi.fn(),
  fetchPublicConsoleStatus: vi.fn(),
  getAuthToken: vi.fn(),
  storeAuthToken: vi.fn(),
  validateOperatorToken: vi.fn()
}));

const publicStatus = {
  ok: true,
  service: 'agent-security-supervisor',
  console_auth: { required: true, transport: 'bearer' as const, profile: 'local' as const }
};

const adminContext = {
  role: 'admin',
  agent_id: null,
  permissions: {
    can_edit_policy: true,
    can_review_approval: true,
    can_execute_runtime: true,
    can_generate: true,
    can_execute_managed_tools: true,
    can_view: true
  }
};

const executorContext = {
  role: 'executor',
  agent_id: 'agent-1',
  permissions: {
    can_edit_policy: false,
    can_review_approval: false,
    can_execute_runtime: true,
    can_generate: true,
    can_execute_managed_tools: true,
    can_view: false
  }
};

describe('AuthGate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fetchPublicConsoleStatus).mockResolvedValue(publicStatus);
    vi.mocked(getAuthToken).mockReturnValue(null);
  });

  it('shows a real authentication form instead of loading protected pages anonymously', async () => {
    render(<AuthGate>{() => <div>workspace</div>}</AuthGate>);

    const tokenInput = await screen.findByLabelText('运行 Token');
    expect(tokenInput.closest('form')).not.toBeNull();
    expect(screen.queryByText('workspace')).not.toBeInTheDocument();
    expect(validateOperatorToken).not.toHaveBeenCalled();
  });

  it('uses a direct entry action for a local console without authentication', async () => {
    const user = userEvent.setup();
    vi.mocked(fetchPublicConsoleStatus).mockResolvedValue({
      ...publicStatus,
      console_auth: { required: false, transport: 'bearer', profile: 'local' }
    });
    vi.mocked(validateOperatorToken)
      .mockRejectedValueOnce(new Error('initial check'))
      .mockResolvedValueOnce(adminContext);
    render(<AuthGate>{({ context }) => <div>workspace:{context.role}</div>}</AuthGate>);

    expect(await screen.findByText('身份校验失败，请稍后重试。')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '进入系统' })).toBeInTheDocument();
    expect(screen.queryByText('后端在线')).not.toBeInTheDocument();
    expect(screen.queryByText('本机安全档')).not.toBeInTheDocument();
    expect(screen.queryByText('本机免鉴权')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '进入系统' }));
    await waitFor(() => expect(screen.getByText('workspace:admin')).toBeInTheDocument());
  });

  it('validates and stores the operator token before mounting the workspace', async () => {
    const user = userEvent.setup();
    vi.mocked(validateOperatorToken).mockResolvedValue(adminContext);
    render(<AuthGate>{({ context }) => <div>workspace:{context.role}</div>}</AuthGate>);

    await user.type(await screen.findByLabelText('运行 Token'), 'local-admin-token');
    await user.click(screen.getByRole('button', { name: '验证并进入' }));

    await waitFor(() => expect(screen.getByText('workspace:admin')).toBeInTheDocument());
    expect(validateOperatorToken).toHaveBeenCalledWith('local-admin-token');
    expect(storeAuthToken).toHaveBeenCalledWith('local-admin-token');
  });

  it('returns focus to the token input after authentication fails', async () => {
    const user = userEvent.setup();
    vi.mocked(validateOperatorToken).mockRejectedValue(
      new ApiError('Invalid token', { code: 'http_error', path: '/api/auth/context', status: 401 })
    );
    render(<AuthGate>{() => <div>workspace</div>}</AuthGate>);

    const tokenInput = await screen.findByLabelText('运行 Token');
    await user.type(tokenInput, 'invalid-token');
    await user.click(screen.getByRole('button', { name: '验证并进入' }));

    expect(await screen.findByText('凭证未通过校验，请检查后重新输入。')).toBeInTheDocument();
    expect(tokenInput).toHaveFocus();
  });

  it('clears a stale stored token and keeps the error next to the login action', async () => {
    vi.mocked(getAuthToken).mockReturnValue('stale-token');
    vi.mocked(validateOperatorToken).mockRejectedValue(new Error('stale'));
    render(<AuthGate>{() => <div>workspace</div>}</AuthGate>);

    expect(await screen.findByText('身份校验失败，请稍后重试。')).toBeInTheDocument();
    expect(clearAuthToken).toHaveBeenCalled();
    expect(screen.queryByText('workspace')).not.toBeInTheDocument();
  });

  it('keeps Agent execution credentials out of the operator console', async () => {
    const user = userEvent.setup();
    vi.mocked(validateOperatorToken).mockResolvedValue(executorContext);
    render(<AuthGate>{() => <div>workspace</div>}</AuthGate>);

    await user.type(await screen.findByLabelText('运行 Token'), 'agent-token');
    await user.click(screen.getByRole('button', { name: '验证并进入' }));

    expect(await screen.findByText(/当前凭证用于 Agent 运行/)).toBeInTheDocument();
    expect(screen.queryByText('workspace')).not.toBeInTheDocument();
    expect(storeAuthToken).not.toHaveBeenCalled();
    expect(clearAuthToken).toHaveBeenCalled();
  });

  it('ignores an old request 401 after the operator has replaced the session', async () => {
    const user = userEvent.setup();
    vi.mocked(validateOperatorToken).mockResolvedValue(adminContext);
    render(
      <AuthGate>
        {({ context, signOut }) => (
          <div>
            <span>workspace:{context.role}</span>
            <button type="button" onClick={signOut}>
              test sign out
            </button>
          </div>
        )}
      </AuthGate>
    );

    await user.type(await screen.findByLabelText('运行 Token'), 'first-token');
    await user.click(screen.getByRole('button', { name: '验证并进入' }));
    await screen.findByText('workspace:admin');
    const firstSessionVersion = getAuthSessionVersion();

    await user.click(screen.getByRole('button', { name: 'test sign out' }));
    await user.type(await screen.findByLabelText('运行 Token'), 'second-token');
    await user.click(screen.getByRole('button', { name: '验证并进入' }));
    await screen.findByText('workspace:admin');
    const secondSessionVersion = getAuthSessionVersion();
    expect(secondSessionVersion).toBeGreaterThan(firstSessionVersion);

    vi.mocked(clearAuthToken).mockClear();
    act(() => {
      window.dispatchEvent(
        new CustomEvent(authInvalidEvent, {
          detail: { path: '/api/slow-request', sessionVersion: firstSessionVersion }
        })
      );
    });
    expect(screen.getByText('workspace:admin')).toBeInTheDocument();
    expect(clearAuthToken).not.toHaveBeenCalled();

    act(() => {
      window.dispatchEvent(
        new CustomEvent(authInvalidEvent, {
          detail: { path: '/api/current-request', sessionVersion: secondSessionVersion }
        })
      );
    });
    expect(await screen.findByLabelText('运行 Token')).toBeInTheDocument();
  });
});
