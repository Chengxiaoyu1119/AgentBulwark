import { useEffect, useMemo, useState } from 'react';
import { Flex, Space, Typography } from 'antd';
import { Bot, KeyRound, Network, ShieldCheck } from 'lucide-react';
import {
  fetchAgentIntegrationBundle,
  fetchAuthContext,
  fetchModelConfig,
  fetchPolicyConfig,
  updateModelConfig,
  updatePolicySettings
} from '../api';
import { AgentBoundarySettingsPanel } from '../components/settings/AgentBoundarySettingsPanel';
import {
  CopyButton,
  LabelTag,
  PanelCard,
  UiAlert,
  UiButton,
  UiInput,
  UiSelect,
  UiSwitch,
  UiTabs
} from '../components/ui';
import type { AgentIntegrationBundle, AuthContext, ModelRuntimeConfig, Overview, PolicySettings } from '../types';

export function SettingsPanel({ overview, refresh }: { overview: Overview; refresh: () => Promise<unknown> }) {
  const [integration, setIntegration] = useState<AgentIntegrationBundle | null>(null);
  const [modelConfig, setModelConfig] = useState<ModelRuntimeConfig | null>(null);
  const [auth, setAuth] = useState<AuthContext | null>(null);
  const [policySettings, setPolicySettings] = useState<PolicySettings | null>(null);
  const [savingModel, setSavingModel] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  useEffect(() => {
    let cancelled = false;
    void Promise.all([fetchAgentIntegrationBundle(), fetchModelConfig(), fetchAuthContext(), fetchPolicyConfig()])
      .then(([nextIntegration, nextModelConfig, nextAuth, nextPolicy]) => {
        if (cancelled) return;
        setIntegration(nextIntegration);
        setModelConfig(nextModelConfig);
        setAuth(nextAuth);
        setPolicySettings(nextPolicy.settings);
      })
      .catch((loadError: unknown) => {
        if (!cancelled) setError(loadError instanceof Error ? loadError.message : '设置读取失败。');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function saveModelConfig() {
    if (!modelConfig) return;
    setSavingModel(true);
    setError('');
    setNotice('');
    try {
      setModelConfig(
        await updateModelConfig({ real_api_enabled: modelConfig.real_api_enabled, profiles: modelConfig.profiles })
      );
      await refresh();
      setNotice('模型连接已保存。');
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : '模型连接保存失败。');
    } finally {
      setSavingModel(false);
    }
  }

  async function savePolicySettings() {
    if (!policySettings) return;
    setSavingPolicy(true);
    setError('');
    setNotice('');
    try {
      setPolicySettings(
        await updatePolicySettings({
          ...policySettings,
          operator: 'security-admin',
          comment: '通过设置页更新 Agent 工具、模型、API 与上下文最小权限'
        })
      );
      setNotice('工具与数据权限已保存，并生成新的策略版本。');
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : '权限保存失败。');
    } finally {
      setSavingPolicy(false);
    }
  }

  return (
    <div className="zh-product-page">
      <header className="zh-product-heading">
        <div>
          <Typography.Title level={1}>设置</Typography.Title>
          <Typography.Text type="secondary">只保留接入、模型和权限三类生产配置。</Typography.Text>
        </div>
      </header>

      {error ? <UiAlert type="error" showIcon title={error} /> : null}
      {notice ? <UiAlert type="success" showIcon title={notice} /> : null}

      <UiTabs
        className="zh-product-tabs"
        defaultActiveKey="connection"
        items={[
          {
            key: 'connection',
            label: '应用接入',
            children: <ConnectionSettings integration={integration} />
          },
          {
            key: 'provider',
            label: '模型连接',
            children: (
              <ProviderSettings
                overview={overview}
                config={modelConfig}
                saving={savingModel}
                onChange={setModelConfig}
                onSave={() => void saveModelConfig()}
              />
            )
          },
          {
            key: 'permissions',
            label: '工具与数据权限',
            children: (
              <AgentBoundarySettingsPanel
                policySettings={policySettings}
                canEdit={Boolean(auth?.permissions.can_edit_policy)}
                saving={savingPolicy}
                onPatch={(patch) => setPolicySettings((current) => (current ? { ...current, ...patch } : current))}
                onSave={() => void savePolicySettings()}
              />
            )
          }
        ]}
      />
    </div>
  );
}

function ConnectionSettings({ integration }: { integration: AgentIntegrationBundle | null }) {
  const baseUrl = `${window.location.origin}/v1`;
  const mcpUrl = `${window.location.origin}/api/mcp`;
  return (
    <div className="zh-settings-column">
      <PanelCard title="应用入口" subtitle="业务应用只需要修改模型地址，并使用独立的 Agent Token。">
        <div className="zh-endpoint-list">
          <EndpointRow icon={<Network size={18} />} label="OpenAI 兼容地址" value={baseUrl} />
          <EndpointRow icon={<Bot size={18} />} label="MCP 地址" value={mcpUrl} />
        </div>
      </PanelCard>

      <PanelCard title="身份边界" subtitle="控制台与业务 Agent 使用不同凭证，避免共享权限。">
        <div className="zh-identity-boundary">
          <KeyRound size={20} aria-hidden="true" />
          <div>
            <Typography.Text strong>一个 Agent，一个 Token</Typography.Text>
            <Typography.Paragraph type="secondary" className="zh-mb-0">
              当前操作员 Token 只保存在浏览器会话中；业务 Token 由后端绑定 Agent 身份、模型和工具权限。
            </Typography.Paragraph>
          </div>
        </div>
      </PanelCard>

      <PanelCard title="接入契约" subtitle="接口返回实时生成，读取失败时不会展示示例数据。">
        {integration ? (
          <Space orientation="vertical" size={14} className="zh-full-width">
            <Flex align="center" gap={8} wrap="wrap">
              <LabelTag color="green">{integration.version}</LabelTag>
              <Typography.Text>{integration.examples.length} 种接入方式可用</Typography.Text>
            </Flex>
            <Typography.Text type="secondary">
              必填字段：{integration.event_contract.required_fields.join('、')}
            </Typography.Text>
            <UiButton authenticatedHref="/api/integrations/agents/bundle">下载接入契约</UiButton>
          </Space>
        ) : (
          <UiAlert type="info" showIcon title="正在读取接入契约。" />
        )}
      </PanelCard>
    </div>
  );
}

function EndpointRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="zh-endpoint-row">
      <span aria-hidden="true">{icon}</span>
      <div>
        <Typography.Text type="secondary">{label}</Typography.Text>
        <Typography.Text code>{value}</Typography.Text>
      </div>
      <CopyButton text={value}>复制</CopyButton>
    </div>
  );
}

function ProviderSettings({
  overview,
  config,
  saving,
  onChange,
  onSave
}: {
  overview: Overview;
  config: ModelRuntimeConfig | null;
  saving: boolean;
  onChange: (config: ModelRuntimeConfig) => void;
  onSave: () => void;
}) {
  const providers = config?.allowed_providers ?? [];
  const providerIds = providers.map((provider) => provider.id);
  const target = config?.profiles.target ?? { provider_priority: providerIds, model_overrides: {} };
  const primaryProvider = target.provider_priority?.[0] ?? providerIds[0] ?? '';
  const configuredProviders = useMemo(
    () => overview.models.filter((model) => model.configured && model.mode === 'real-api'),
    [overview.models]
  );
  const modelName = target.model_overrides?.[primaryProvider] ?? '';

  function patchTarget(providerId: string, nextModelName = modelName) {
    if (!config) return;
    const currentTarget = config.profiles.target ?? { provider_priority: [], model_overrides: {} };
    onChange({
      ...config,
      profiles: {
        ...config.profiles,
        target: {
          ...currentTarget,
          provider_priority: [
            providerId,
            ...(currentTarget.provider_priority ?? []).filter((item) => item !== providerId),
            ...providerIds.filter((item) => item !== providerId && !currentTarget.provider_priority?.includes(item))
          ],
          model_overrides: { ...currentTarget.model_overrides, [providerId]: nextModelName }
        }
      }
    });
  }

  return (
    <PanelCard title="目标模型" subtitle="页面保存 Provider 顺序和模型名；API 密钥始终留在后端环境中。">
      {!config ? (
        <UiAlert type="info" showIcon title="正在读取模型连接。" />
      ) : (
        <Space orientation="vertical" size={22} className="zh-full-width">
          <div className="zh-provider-status">
            <div>
              <Typography.Text type="secondary">真实 Provider</Typography.Text>
              <Typography.Title level={3}>{configuredProviders.length} 个已连接</Typography.Title>
            </div>
            <LabelTag color={configuredProviders.length ? 'green' : 'warning'}>
              {configuredProviders.length ? '可用' : '待配置'}
            </LabelTag>
          </div>
          <div className="zh-form-grid">
            <label>
              <Typography.Text type="secondary">优先 Provider</Typography.Text>
              <UiSelect
                value={primaryProvider}
                options={providers.map((provider) => ({ value: provider.id, label: provider.label }))}
                onChange={(value) => patchTarget(String(value), '')}
                className="zh-full-width"
              />
            </label>
            <label>
              <Typography.Text type="secondary">模型名</Typography.Text>
              <UiInput value={modelName} onChange={(event) => patchTarget(primaryProvider, event.target.value)} />
            </label>
          </div>
          <Flex justify="space-between" align="center" gap={12} wrap="wrap">
            <Flex align="center" gap={10}>
              <UiSwitch
                checked={config.real_api_enabled}
                onChange={(checked) => onChange({ ...config, real_api_enabled: checked })}
              />
              <Typography.Text>启用真实 Provider</Typography.Text>
            </Flex>
            <UiButton type="primary" icon={<ShieldCheck size={16} />} loading={saving} onClick={onSave}>
              保存模型连接
            </UiButton>
          </Flex>
        </Space>
      )}
    </PanelCard>
  );
}
