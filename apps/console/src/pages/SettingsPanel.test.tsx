import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SettingsPanel } from './SettingsPanel';
import type { Overview } from '../types';

const apiMocks = vi.hoisted(() => ({
  fetchAgentIntegrationBundle: vi.fn().mockResolvedValue({
    version: '1.0',
    examples: [],
    event_contract: { required_fields: ['agent_id'], recommended_fields: [], safe_default: 'deny' }
  })
}));

vi.mock('../api', () => ({
  fetchAttackCaseDataset: vi.fn().mockResolvedValue(null),
  fetchAgentIntegrationBundle: apiMocks.fetchAgentIntegrationBundle,
  fetchAuthContext: vi.fn().mockResolvedValue({ role: 'admin', permissions: { can_edit_policy: true } }),
  fetchPolicyConfig: vi.fn().mockResolvedValue({
    settings: {
      anomaly_review_threshold: 55,
      anomaly_reject_threshold: 85,
      approval_sla_minutes: 30,
      high_risk_auto_escalation: true,
      internal_email_domains: [],
      sensitive_path_markers: [],
      sensitive_api_markers: [],
      agent_tool_allowlists: {}
    }
  }),
  fetchCompetitionReadiness: vi.fn().mockResolvedValue(null),
  fetchDemoDrill: vi.fn().mockResolvedValue(null),
  fetchModelConfig: vi.fn().mockResolvedValue({
    real_api_enabled: true,
    real_api_enabled_source: 'runtime',
    allowed_providers: [
      { id: 'deepseek', label: 'DeepSeek' },
      { id: 'zhipu', label: '智谱' },
      { id: 'openai-compatible', label: 'OpenAI 兼容接口' }
    ],
    profiles: {
      target: { provider_priority: ['deepseek', 'zhipu'], model_overrides: {} },
      optimizer: { provider_priority: ['zhipu', 'deepseek'], model_overrides: {} },
      global: { provider_priority: ['deepseek', 'zhipu'], model_overrides: {} }
    }
  }),
  runDemoDrill: vi.fn(),
  runExternalAgentDemo: vi.fn(),
  updateModelConfig: vi.fn(),
  updatePolicySettings: vi.fn(),
  writeCompetitionReadiness: vi.fn(),
  writeOpenClawPluginPackage: vi.fn(),
  writeOpenClawPluginValidation: vi.fn(),
  evaluateSupervisorEvent: vi.fn(),
  evaluateSupervisorBatch: vi.fn()
}));

const overview = {
  attack_surfaces: [
    {
      id: 'prompt-injection',
      name: '提示词注入',
      risk: 'high',
      status: '已覆盖',
      summary: '覆盖核心攻击面',
      samples: 3,
      scripts: 2,
      defense: '输入检测与工具拦截'
    }
  ],
  scenarios: [],
  models: [
    {
      provider: '本地安全评测模型',
      configured: false,
      model: 'agent-supervisor-sim-guard',
      mode: 'fallback'
    }
  ],
  recent_runs: [],
  alerts: [],
  audit_logs: [],
  summary: {
    surface_count: 1,
    scenario_count: 2,
    recent_run_count: 0,
    block_rate: 0,
    attack_success_rate: 0,
    avg_latency_ms: 0
  }
} as Overview;

describe('SettingsPanel', () => {
  beforeEach(() => {
    apiMocks.fetchAgentIntegrationBundle.mockClear();
  });

  it('renders the settings shell and primary tabs', async () => {
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    expect(await screen.findByRole('heading', { name: '设置' })).toBeInTheDocument();
    expect(screen.getByText('应用入口')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '应用接入' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '模型连接' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '工具与数据权限' })).toBeInTheDocument();
    expect(screen.queryByText('验证工具（非生产路径）')).not.toBeInTheDocument();
    expect(apiMocks.fetchAgentIntegrationBundle).toHaveBeenCalledTimes(1);
  });

  it('does not expose demo drills or framework-specific generators', async () => {
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);
    expect(await screen.findByText('接入契约')).toBeInTheDocument();
    expect(screen.queryByText('OpenClaw')).not.toBeInTheDocument();
    expect(screen.queryByText('闭环复现实验')).not.toBeInTheDocument();
  });
});
