import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SettingsPanel } from './SettingsPanel';
import type { Overview } from '../types';

const apiMocks = vi.hoisted(() => ({
  fetchAgentIntegrationBundle: vi.fn().mockResolvedValue({
    version: '1.0',
    examples: [],
    event_contract: { required_fields: ['agent_id'], recommended_fields: [], safe_default: 'deny' }
  }),
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
  fetchModelStatuses: vi.fn().mockImplementation((profile: string) =>
    Promise.resolve([
      {
        profile,
        provider: 'deepseek',
        configured: false,
        model: 'deepseek-chat',
        mode: 'unconfigured'
      }
    ])
  ),
  probeModelProvider: vi.fn(),
  updateModelConfig: vi.fn()
}));

vi.mock('../app/governanceApi', () => ({
  fetchAgentIntegrationBundle: apiMocks.fetchAgentIntegrationBundle,
  fetchAuthContext: apiMocks.fetchAuthContext,
  fetchPolicyConfig: apiMocks.fetchPolicyConfig,
  updatePolicySettings: vi.fn()
}));

vi.mock('../app/operationalApi', () => ({
  fetchModelConfig: apiMocks.fetchModelConfig,
  fetchModelStatuses: apiMocks.fetchModelStatuses,
  probeModelProvider: apiMocks.probeModelProvider,
  updateModelConfig: apiMocks.updateModelConfig
}));

const overview = {
  models: [
    {
      provider: 'DeepSeek',
      configured: false,
      model: 'deepseek-chat',
      mode: 'unconfigured'
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
    avg_latency_ms: 0
  }
} as Overview;

describe('SettingsPanel', () => {
  beforeEach(() => {
    apiMocks.fetchAgentIntegrationBundle.mockClear();
    apiMocks.fetchAuthContext.mockReset();
    apiMocks.fetchAuthContext.mockResolvedValue({ role: 'admin', permissions: { can_edit_policy: true } });
    apiMocks.fetchModelConfig.mockClear();
    apiMocks.fetchModelStatuses.mockReset();
    apiMocks.fetchModelStatuses.mockImplementation((profile: string) =>
      Promise.resolve([
        {
          profile,
          provider: 'deepseek',
          configured: false,
          model: 'deepseek-chat',
          mode: 'unconfigured'
        }
      ])
    );
    apiMocks.probeModelProvider.mockReset();
    apiMocks.updateModelConfig.mockReset();
    apiMocks.updateModelConfig.mockImplementation(async (payload) => ({
      ...(await apiMocks.fetchModelConfig()),
      ...payload
    }));
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

  it('does not expose non-operational generators', async () => {
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);
    expect(await screen.findByText('接入契约')).toBeInTheDocument();
    expect(screen.queryByText('验证工具（非生产路径）')).not.toBeInTheDocument();
  });

  it('keeps independent settings surfaces available when one read fails', async () => {
    apiMocks.fetchAgentIntegrationBundle.mockRejectedValueOnce(new Error('接入契约服务暂时不可用'));
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    expect(await screen.findByText('接入契约读取失败')).toBeInTheDocument();
    expect(screen.getByText('部分设置读取失败')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('tab', { name: '模型连接' }));
    expect(await screen.findByText('模型连接配置状态')).toBeInTheDocument();
  });

  it('disables model writes for read-only operators instead of sending a guaranteed 403', async () => {
    const user = userEvent.setup();
    apiMocks.fetchAuthContext.mockResolvedValueOnce({ role: 'observer', permissions: { can_edit_policy: false } });
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    await user.click(await screen.findByRole('tab', { name: '模型连接' }));
    expect(await screen.findByText('当前角色只有查看权限')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '保存模型连接' })).toBeDisabled();
  });

  it('describes discovered credentials as configured rather than network-verified', async () => {
    const configuredOverview: Overview = {
      ...overview,
      models: [
        {
          provider: 'deepseek',
          configured: true,
          model: 'deepseek-chat',
          mode: 'real-api',
          endpoint: 'https://provider.example/v1'
        }
      ]
    };
    render(<SettingsPanel overview={configuredOverview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    await userEvent.setup().click(await screen.findByRole('tab', { name: '模型连接' }));

    expect((await screen.findAllByText('凭证已配置')).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText('真实可用')).not.toBeInTheDocument();
    expect(screen.queryByText('已接入真实 API')).not.toBeInTheDocument();
  });

  it('renders credential state from each profile instead of reusing global overview status', async () => {
    apiMocks.fetchModelStatuses.mockImplementation((profile: string) =>
      Promise.resolve([
        {
          profile,
          provider: profile === 'target' ? 'deepseek' : 'zhipu',
          configured: profile === 'target',
          model: profile === 'target' ? 'target-model' : 'optimizer-model',
          mode: profile === 'target' ? 'real-api' : 'unconfigured'
        }
      ])
    );
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    await userEvent.setup().click(await screen.findByRole('tab', { name: '模型连接' }));
    const statusCards = Array.from(document.querySelectorAll<HTMLElement>('.zh-settings-profile-status'));
    const targetStatus = statusCards.find((card) => card.textContent?.includes('主模型'));
    const optimizerStatus = statusCards.find((card) => card.textContent?.includes('副模型'));
    expect(targetStatus).toHaveTextContent('凭证已配置');
    expect(optimizerStatus).toHaveTextContent('凭证未配置');
    expect(apiMocks.fetchModelStatuses).toHaveBeenCalledWith('target');
    expect(apiMocks.fetchModelStatuses).toHaveBeenCalledWith('optimizer');
    expect(apiMocks.fetchModelStatuses).toHaveBeenCalledWith('global');
  });

  it('keeps permissions unknown when the authorization context read fails', async () => {
    apiMocks.fetchAuthContext.mockRejectedValueOnce(new Error('权限上下文暂时不可用'));
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    await userEvent.setup().click(await screen.findByRole('tab', { name: '模型连接' }));

    expect(await screen.findByText(/权限上下文暂时不可用/)).toBeInTheDocument();
    expect(screen.queryByText('当前角色只有查看权限')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '保存模型连接' })).toBeDisabled();
  });

  it('reports a saved model configuration separately from a failed overview refresh', async () => {
    const refresh = vi.fn().mockRejectedValue(new Error('总览服务暂时不可用'));
    render(<SettingsPanel overview={overview} refresh={refresh} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('tab', { name: '模型连接' }));
    await user.click(screen.getByRole('button', { name: '保存模型连接' }));

    expect(await screen.findByText('模型连接已保存。')).toBeInTheDocument();
    expect(screen.getByText(/模型连接已保存，但总览刷新失败/)).toBeInTheDocument();
    expect(screen.queryByText('模型连接保存失败。')).not.toBeInTheDocument();
  });

  it('runs an explicit Provider probe and renders its result separately from configuration', async () => {
    apiMocks.fetchAuthContext.mockResolvedValueOnce({
      role: 'analyst',
      permissions: { can_edit_policy: false, can_review_approval: true }
    });
    apiMocks.probeModelProvider.mockResolvedValueOnce({
      schema_version: 'agent-supervisor.provider-probe.v1',
      profile: 'target',
      provider_id: 'deepseek',
      provider: 'DeepSeek',
      status: 'healthy',
      configured: true,
      model: 'deepseek-chat',
      latency_ms: 42.5,
      endpoint_scope: 'external-provider'
    });
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('tab', { name: '模型连接' }));
    await user.click(screen.getAllByRole('button', { name: '检测连接' })[0]);

    expect(await screen.findByText('DeepSeek 连接探针通过')).toBeInTheDocument();
    expect(screen.getByText(/延迟：42.5 ms/)).toBeInTheDocument();
    expect(apiMocks.probeModelProvider).toHaveBeenCalledWith({ profile: 'target', provider_id: 'deepseek' });
  });

  it('locks model fields while a save response is pending', async () => {
    let resolveSave: ((value: Awaited<ReturnType<typeof apiMocks.fetchModelConfig>>) => void) | undefined;
    apiMocks.updateModelConfig.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveSave = resolve;
        })
    );
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('tab', { name: '模型连接' }));
    await user.click(screen.getByRole('button', { name: '保存模型连接' }));

    expect(screen.getByRole('switch')).toBeDisabled();
    expect(screen.getAllByRole('combobox').every((input) => input.hasAttribute('disabled'))).toBe(true);

    resolveSave?.(await apiMocks.fetchModelConfig());
    expect(await screen.findByText('模型连接已保存。')).toBeInTheDocument();
  });

  it('retries only failed settings reads without discarding successful sections', async () => {
    apiMocks.fetchAgentIntegrationBundle.mockRejectedValueOnce(new Error('接入契约服务暂时不可用'));
    render(<SettingsPanel overview={overview} refresh={vi.fn().mockResolvedValue(undefined)} />);

    expect(await screen.findByText('接入契约读取失败')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: '重试失败项' }));

    expect(await screen.findByText('1.0')).toBeInTheDocument();
    expect(screen.queryByText('接入契约读取失败')).not.toBeInTheDocument();
    expect(apiMocks.fetchModelConfig).toHaveBeenCalledTimes(1);
  });
});
