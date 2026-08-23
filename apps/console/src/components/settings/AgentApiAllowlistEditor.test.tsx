import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PolicySettings } from '@/types';
import { AgentApiAllowlistEditor } from './AgentApiAllowlistEditor';

const settings: PolicySettings = {
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: ['internal.example'],
  sensitive_path_markers: ['secret'],
  sensitive_api_markers: ['admin'],
  agent_tool_allowlists: { 'report-agent': ['api.call'] },
  agent_api_allowlists: { 'report-agent': ['https://api.example.com'] }
};

describe('AgentApiAllowlistEditor', () => {
  it('adds an Agent host boundary with an empty default list', async () => {
    const onPatch = vi.fn();
    render(<AgentApiAllowlistEditor policySettings={settings} canEdit onPatch={onPatch} />);

    await userEvent.click(screen.getByRole('button', { name: '新增 Agent' }));

    expect(onPatch).toHaveBeenCalledWith({
      agent_api_allowlists: {
        'report-agent': ['https://api.example.com'],
        'agent-2': []
      }
    });
  });
});
