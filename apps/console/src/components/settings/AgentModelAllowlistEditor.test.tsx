import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PolicySettings } from '@/types';
import { AgentModelAllowlistEditor } from './AgentModelAllowlistEditor';

const settings: PolicySettings = {
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: ['internal.example'],
  sensitive_path_markers: ['secret'],
  sensitive_api_markers: ['admin'],
  agent_tool_allowlists: { 'report-agent': ['api.call'] },
  agent_model_allowlists: { 'report-agent': ['approved-model'] }
};

describe('AgentModelAllowlistEditor', () => {
  it('adds an Agent model boundary with an empty default list', async () => {
    const onPatch = vi.fn();
    render(<AgentModelAllowlistEditor policySettings={settings} canEdit onPatch={onPatch} />);

    expect(screen.getByLabelText('允许模型 ID')).toHaveAttribute('id', 'agent-models-report-agent');
    await userEvent.click(screen.getByRole('button', { name: '新增 Agent' }));

    expect(onPatch).toHaveBeenCalledWith({
      agent_model_allowlists: {
        'report-agent': ['approved-model'],
        'agent-2': []
      }
    });
  });

  it('keeps an existing model boundary when a rename is empty or already registered', async () => {
    const onPatch = vi.fn();
    const user = userEvent.setup();
    const duplicateSettings: PolicySettings = {
      ...settings,
      agent_model_allowlists: {
        'report-agent': ['approved-model'],
        'backup-agent': ['backup-model']
      }
    };
    render(<AgentModelAllowlistEditor policySettings={duplicateSettings} canEdit onPatch={onPatch} />);

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
      agent_model_allowlists: {
        'backup-agent': ['backup-model'],
        'renamed-agent': ['approved-model']
      }
    });
  });
});
