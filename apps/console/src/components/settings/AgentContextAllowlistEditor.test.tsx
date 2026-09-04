import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { AgentContextAllowlistEditor } from './AgentContextAllowlistEditor';

describe('AgentContextAllowlistEditor', () => {
  it('associates every context scope label with its Agent-specific control', () => {
    render(
      <AgentContextAllowlistEditor
        canEdit
        onPatch={vi.fn()}
        policySettings={{
          anomaly_review_threshold: 55,
          anomaly_reject_threshold: 85,
          approval_sla_minutes: 30,
          high_risk_auto_escalation: true,
          agent_tool_allowlists: {},
          agent_context_allowlists: {
            'fixture-agent': { resources: [], resource_templates: [], prompts: [] }
          },
          internal_email_domains: [],
          sensitive_path_markers: [],
          sensitive_api_markers: []
        }}
      />
    );

    expect(screen.getByLabelText('Resource URI')).toHaveAttribute('id', 'agent-context-resources-fixture-agent');
    expect(screen.getByLabelText('Resource Template')).toHaveAttribute(
      'id',
      'agent-context-resource-templates-fixture-agent'
    );
    expect(screen.getByLabelText('Prompt 名称')).toHaveAttribute('id', 'agent-context-prompts-fixture-agent');
  });

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

  it('preserves both context scopes when an Agent rename is empty or conflicts', async () => {
    const onPatch = vi.fn();
    const user = userEvent.setup();
    render(
      <AgentContextAllowlistEditor
        canEdit
        onPatch={onPatch}
        policySettings={{
          anomaly_review_threshold: 55,
          anomaly_reject_threshold: 85,
          approval_sla_minutes: 30,
          high_risk_auto_escalation: true,
          agent_tool_allowlists: {},
          agent_context_allowlists: {
            'fixture-agent': { resources: ['file://public/*'], resource_templates: [], prompts: [] },
            'backup-agent': { resources: ['file://backup/*'], resource_templates: [], prompts: [] }
          },
          internal_email_domains: [],
          sensitive_path_markers: [],
          sensitive_api_markers: []
        }}
      />
    );

    const input = screen.getByRole('textbox', { name: 'Agent ID：fixture-agent' });
    await user.clear(input);
    await user.tab();
    expect(input).toHaveValue('fixture-agent');
    expect(screen.getByRole('alert')).toHaveTextContent('Agent ID 不能为空');
    expect(onPatch).not.toHaveBeenCalled();

    await user.clear(input);
    await user.type(input, 'backup-agent');
    await user.tab();
    expect(input).toHaveValue('fixture-agent');
    expect(screen.getByRole('alert')).toHaveTextContent('backup-agent 已存在');
    expect(onPatch).not.toHaveBeenCalled();

    await user.clear(input);
    await user.type(input, 'renamed-agent');
    await user.tab();
    expect(input).toHaveValue('renamed-agent');
    expect(onPatch).toHaveBeenLastCalledWith({
      agent_context_allowlists: {
        'backup-agent': { resources: ['file://backup/*'], resource_templates: [], prompts: [] },
        'renamed-agent': { resources: ['file://public/*'], resource_templates: [], prompts: [] }
      }
    });
  });
});
