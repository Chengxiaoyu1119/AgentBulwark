import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PolicySettings } from '@/types';
import { AgentBoundarySettingsPanel } from './AgentBoundarySettingsPanel';

const settings: PolicySettings = {
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: [],
  sensitive_path_markers: [],
  sensitive_api_markers: [],
  agent_tool_allowlists: {}
};

describe('settings field label associations', () => {
  it('associates boundary labels with their tag selectors', () => {
    render(
      <AgentBoundarySettingsPanel policySettings={settings} canEdit saving={false} onPatch={vi.fn()} onSave={vi.fn()} />
    );

    expect(screen.getByLabelText('内部邮箱域')).toHaveAttribute('id', 'policy-internal-email-domains');
    expect(screen.getByLabelText('敏感路径标记')).toHaveAttribute('id', 'policy-sensitive-path-markers');
    expect(screen.getByLabelText('高敏 API 标记')).toHaveAttribute('id', 'policy-sensitive-api-markers');
  });

  it('creates fail-closed policy boundaries for a registered Agent', async () => {
    const onPatch = vi.fn();
    render(
      <AgentBoundarySettingsPanel
        policySettings={settings}
        canEdit
        saving={false}
        onPatch={onPatch}
        onSave={vi.fn()}
        registeredAgentIds={['support-agent']}
        selectedAgentId="support-agent"
      />
    );

    await screen.findByText('正在配置 Agent support-agent。');
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: '建立空权限边界' }));

    expect(onPatch).toHaveBeenCalledWith({
      agent_tool_allowlists: { 'support-agent': [] },
      agent_api_allowlists: { 'support-agent': [] },
      agent_model_allowlists: { 'support-agent': [] },
      agent_context_allowlists: { 'support-agent': { resources: [], resource_templates: [], prompts: [] } }
    });
  });
});
