import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PolicySettings } from '@/types';
import { AgentToolAllowlistEditor } from './AgentToolAllowlistEditor';

const settings: PolicySettings = {
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: ['internal.example'],
  sensitive_path_markers: ['secret'],
  sensitive_api_markers: ['admin'],
  agent_tool_allowlists: { 'report-agent': ['file.read'] }
};

describe('AgentToolAllowlistEditor', () => {
  it('adds a least-privilege Agent rule', async () => {
    const onPatch = vi.fn();
    render(<AgentToolAllowlistEditor policySettings={settings} canEdit onPatch={onPatch} />);

    expect(screen.getByLabelText('允许调用的工具')).toHaveAttribute('id', 'agent-tools-report-agent');
    await userEvent.click(screen.getByRole('button', { name: '新增 Agent' }));

    expect(onPatch).toHaveBeenCalledWith({
      agent_tool_allowlists: {
        'report-agent': ['file.read'],
        'agent-2': ['file.read']
      }
    });
  });

  it('removes an Agent rule', async () => {
    const onPatch = vi.fn();
    render(<AgentToolAllowlistEditor policySettings={settings} canEdit onPatch={onPatch} />);

    await userEvent.click(screen.getByRole('button', { name: /删\s*除/ }));
    await userEvent.click(screen.getByRole('button', { name: /确\s*认/ }));

    expect(onPatch).toHaveBeenCalledWith({ agent_tool_allowlists: {} });
  });

  it('does not overwrite another Agent rule when an ID is empty or duplicated', async () => {
    const onPatch = vi.fn();
    const user = userEvent.setup();
    const duplicateSettings: PolicySettings = {
      ...settings,
      agent_tool_allowlists: {
        'report-agent': ['file.read'],
        'backup-agent': ['file.write']
      }
    };
    render(<AgentToolAllowlistEditor policySettings={duplicateSettings} canEdit onPatch={onPatch} />);

    const input = screen.getByRole('textbox', { name: 'Agent ID：report-agent' });
    await user.clear(input);
    await user.tab();
    expect(input).toHaveValue('report-agent');
    expect(screen.getByRole('alert')).toHaveTextContent('Agent ID 不能为空');
    expect(onPatch).not.toHaveBeenCalled();

    await user.clear(input);
    await user.type(input, 'backup-agent');
    await user.tab();
    expect(input).toHaveValue('report-agent');
    expect(screen.getByRole('alert')).toHaveTextContent('backup-agent 已存在');
    expect(onPatch).not.toHaveBeenCalled();

    await user.clear(input);
    await user.type(input, 'renamed-agent');
    await user.tab();
    expect(input).toHaveValue('renamed-agent');
    expect(onPatch).toHaveBeenLastCalledWith({
      agent_tool_allowlists: {
        'backup-agent': ['file.write'],
        'renamed-agent': ['file.read']
      }
    });
  });
});
