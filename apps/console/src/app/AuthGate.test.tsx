import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthGate } from './AuthGate';
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

  it('clears a stale stored token and keeps the error next to the login action', async () => {
    vi.mocked(getAuthToken).mockReturnValue('stale-token');
    vi.mocked(validateOperatorToken).mockRejectedValue(new Error('stale'));
    render(<AuthGate>{() => <div>workspace</div>}</AuthGate>);

    expect(await screen.findByText('stale')).toBeInTheDocument();
    expect(clearAuthToken).toHaveBeenCalled();
    expect(screen.queryByText('workspace')).not.toBeInTheDocument();
  });
});
