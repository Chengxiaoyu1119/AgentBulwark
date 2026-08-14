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

    expect(onPatch).toHaveBeenCalledWith({ agent_tool_allowlists: {} });
  });
});
