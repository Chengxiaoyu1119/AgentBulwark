import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SettingsPanel } from './SettingsPanel';
import type { Overview } from '../types';

const apiMocks = vi.hoisted(() => ({
  fetchOpenClawIntegrationBundle: vi.fn().mockResolvedValue(null)
}));

vi.mock('../api', () => ({
  fetchAttackCaseDataset: vi.fn().mockResolvedValue(null),
  fetchOpenClawIntegrationBundle: apiMocks.fetchOpenClawIntegrationBundle,
  fetchAgentIntegrationBundle: vi.fn().mockResolvedValue(null),
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
    apiMocks.fetchOpenClawIntegrationBundle.mockClear();
  });

  it('renders the settings shell and primary tabs', async () => {
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    expect(await screen.findByText('Agent接入与系统设置')).toBeInTheDocument();
    expect(screen.getByText('Agent运行时安全接入')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Agent 运行时接入' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '模型连接' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '验证工具（非生产路径）' })).toBeInTheDocument();
    expect(screen.queryByText('运行治理与记忆状态')).not.toBeInTheDocument();
    expect(apiMocks.fetchOpenClawIntegrationBundle).not.toHaveBeenCalled();
  });

  it('loads the optional OpenClaw adapter only after the user expands it', async () => {
    const user = userEvent.setup();
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    await user.click(await screen.findByText('可选框架适配器'));

    expect(apiMocks.fetchOpenClawIntegrationBundle).toHaveBeenCalledTimes(1);
  });
});
