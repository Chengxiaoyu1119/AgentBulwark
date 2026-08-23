import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { AgentContextAllowlistEditor } from './AgentContextAllowlistEditor';

describe('AgentContextAllowlistEditor', () => {
  it('offers existing Agent identities before context scopes are entered', async () => {
    const onPatch = vi.fn();
    render(
      <AgentContextAllowlistEditor
        canEdit
        onPatch={onPatch}
        policySettings={{
          anomaly_review_threshold: 55,
          anomaly_reject_threshold: 85,
          approval_sla_minutes: 30,
          high_risk_auto_escalation: true,
          agent_tool_allowlists: { 'fixture-agent': ['file.read'] },
          agent_model_allowlists: { 'fixture-agent': ['fixture-model'] },
          agent_context_allowlists: {},
          internal_email_domains: [],
          sensitive_path_markers: [],
          sensitive_api_markers: []
        }}
      />
    );

    expect(await screen.findByText(/已有 1 个 Agent 登记了其他权限/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '为已登记 Agent 建立空范围' }));

    expect(onPatch).toHaveBeenCalledWith({
      agent_context_allowlists: {
        'fixture-agent': { resources: [], resource_templates: [], prompts: [] }
      }
    });
  });
});
