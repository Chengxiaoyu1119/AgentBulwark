import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { SettingsPanel } from './SettingsPanel';
import type { Overview } from '../types';

const policySettings = vi.hoisted(() => ({
  anomaly_review_threshold: 55,
  anomaly_reject_threshold: 85,
  approval_sla_minutes: 30,
  high_risk_auto_escalation: true,
  internal_email_domains: [],
  sensitive_path_markers: [],
  sensitive_api_markers: [],
  agent_tool_allowlists: {}
}));

vi.mock('../app/governanceApi', () => ({
  fetchAgentIntegrationBundle: vi.fn().mockResolvedValue({
    version: '1.0',
    examples: [],
    event_contract: { required_fields: ['agent_id'], recommended_fields: [], safe_default: 'deny' }
  }),
  fetchAgents: vi.fn().mockResolvedValue([
    {
      agent_id: 'support-agent',
      display_name: 'Support Agent',
      token_prefix: 'tok_supp',
      status: 'active',
      created_at: '2026-09-10T00:00:00Z',
      updated_at: '2026-09-10T00:00:00Z',
      policy_binding: { tools: false, models: false, context: false, api: false, ready: false }
    }
  ]),
  fetchAuthContext: vi.fn().mockResolvedValue({ role: 'admin', permissions: { can_edit_policy: true } }),
  fetchPolicyConfig: vi.fn().mockResolvedValue({ settings: policySettings, versions: [] }),
  publishPolicySettings: vi.fn(),
  rollbackPolicyVersion: vi.fn(),
  validatePolicySettings: vi.fn(),
  createAgent: vi.fn(),
  rotateAgentToken: vi.fn(),
  revokeAgent: vi.fn()
}));

vi.mock('../app/operationalApi', () => ({
  fetchModelConfig: vi.fn().mockResolvedValue({ real_api_enabled: false, allowed_providers: [], profiles: {} }),
  fetchModelStatuses: vi.fn().mockResolvedValue([]),
  probeModelProvider: vi.fn(),
  updateModelConfig: vi.fn()
}));

const overview = {
  models: [],
  recent_runs: [],
  alerts: [],
  audit_logs: [],
  summary: { surface_count: 0, scenario_count: 0, recent_run_count: 0, block_rate: 0, avg_latency_ms: 0 }
} as Overview;

describe('Agent policy onboarding', () => {
  it('routes a registered Agent into a fail-closed policy setup flow', async () => {
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: 'Agent 接入' }));
    expect(await screen.findByText('Support Agent')).toBeInTheDocument();
    expect(screen.getByText('任务 0')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '配置策略' }));
    expect(await screen.findByText('正在配置 Agent support-agent。')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '建立空权限边界' }));
    expect(await screen.findByText('Agent support-agent 已建立四类权限边界。')).toBeInTheDocument();
  });
});
