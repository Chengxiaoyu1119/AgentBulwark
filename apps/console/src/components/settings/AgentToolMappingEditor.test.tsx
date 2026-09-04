import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { AgentToolMappingConfig, PolicySettings } from '@/types';
import { AgentToolMappingEditor } from './AgentToolMappingEditor';

const browserMapping: AgentToolMappingConfig = {
  capability: 'api.call',
  argument_mapping: { url: 'endpoint' },
  required_arguments: ['url'],
  risk_hint: 'custom_network_tool',
  description: '浏览器访问'
};

const databaseMapping: AgentToolMappingConfig = {
  capability: 'code.run',
  argument_mapping: { query: 'code' },
  required_arguments: ['query'],
  risk_hint: 'custom_database_tool',
  description: '数据库查询'
};

const settings: PolicySettings = {
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: [],
  sensitive_path_markers: [],
  sensitive_api_markers: [],
  agent_tool_allowlists: { 'fixture-agent': ['browser.open', 'database.query'] },
  agent_tool_mappings: {
    'fixture-agent': {
      'browser.open': browserMapping,
      'database.query': databaseMapping
    }
  }
};

describe('AgentToolMappingEditor', () => {
  it('associates mapping labels with each concrete editor control', () => {
    render(<AgentToolMappingEditor policySettings={settings} canEdit onPatch={vi.fn()} />);

    expect(screen.getAllByLabelText('标准安全能力')[0]).toHaveAttribute(
      'id',
      'agent-tool-mapping-fixture-agent-browser.open-capability'
    );
    expect(screen.getAllByLabelText('参数映射（原始:标准）')[0]).toHaveAttribute(
      'id',
      'agent-tool-mapping-fixture-agent-browser.open-argument-mapping'
    );
    expect(screen.getAllByLabelText('必填原始参数')[0]).toHaveAttribute(
      'id',
      'agent-tool-mapping-fixture-agent-browser.open-required-arguments'
    );
    expect(screen.getAllByLabelText('固定风险提示')[0]).toHaveAttribute(
      'id',
      'agent-tool-mapping-fixture-agent-browser.open-risk-hint'
    );
    expect(screen.getAllByLabelText('用途说明')[0]).toHaveAttribute(
      'id',
      'agent-tool-mapping-fixture-agent-browser.open-description'
    );
  });

  it('rejects empty names and an existing Agent/tool target without overwriting either mapping', async () => {
    const onPatch = vi.fn();
    const user = userEvent.setup();
    render(<AgentToolMappingEditor policySettings={settings} canEdit onPatch={onPatch} />);

    const agentInput = screen.getByRole('textbox', { name: 'Agent ID：fixture-agent / browser.open' });
    await user.clear(agentInput);
    await user.tab();
    expect(agentInput).toHaveValue('fixture-agent');
    expect(screen.getByRole('alert')).toHaveTextContent('Agent ID 不能为空');
    expect(onPatch).not.toHaveBeenCalled();

    const toolInput = screen.getByRole('textbox', { name: '原始工具名：fixture-agent / browser.open' });
    await user.clear(toolInput);
    await user.tab();
    expect(toolInput).toHaveValue('browser.open');
    expect(screen.getByRole('alert')).toHaveTextContent('原始工具名不能为空');
    expect(onPatch).not.toHaveBeenCalled();

    await user.clear(toolInput);
    await user.type(toolInput, 'database.query');
    await user.tab();
    expect(toolInput).toHaveValue('browser.open');
    expect(screen.getByRole('alert')).toHaveTextContent('fixture-agent / database.query 已存在');
    expect(onPatch).not.toHaveBeenCalled();

    await user.clear(toolInput);
    await user.type(toolInput, 'browser.navigate');
    await user.tab();
    expect(toolInput).toHaveValue('browser.navigate');
    expect(onPatch).toHaveBeenLastCalledWith({
      agent_tool_mappings: {
        'fixture-agent': {
          'database.query': databaseMapping,
          'browser.navigate': browserMapping
        }
      },
      agent_tool_allowlists: { 'fixture-agent': ['database.query', 'browser.navigate'] }
    });
  });
});
