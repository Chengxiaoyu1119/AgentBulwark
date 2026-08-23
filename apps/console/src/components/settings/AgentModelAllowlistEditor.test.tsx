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

    await userEvent.click(screen.getByRole('button', { name: '新增 Agent' }));

    expect(onPatch).toHaveBeenCalledWith({
      agent_model_allowlists: {
        'report-agent': ['approved-model'],
        'agent-2': []
      }
    });
  });
});
