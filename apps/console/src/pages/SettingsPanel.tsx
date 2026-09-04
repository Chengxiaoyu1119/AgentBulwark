import { useEffect, useState } from 'react';
import { UiFlex, UiSpace, UiTypography } from '../components/ui';
import { Bot, KeyRound, Network } from 'lucide-react';
import {
  fetchAgentIntegrationBundle,
  fetchAuthContext,
  fetchPolicyConfig,
  updatePolicySettings
} from '../app/governanceApi';
import { safeUiErrorSummary } from '../app/apiRequestSupport';
import { fetchModelConfig, updateModelConfig } from '../app/operationalApi';
import { AgentBoundarySettingsPanel } from '../components/settings/AgentBoundarySettingsPanel';
import { ProviderSettings } from '../components/settings/ProviderSettings';
import { useProviderProbe, useProviderStatuses } from '../components/settings/useProviderProbe';
import { CopyButton, LabelTag, PageHeader, PanelCard, UiAlert, UiButton, UiTabs } from '../components/ui';
import type { AgentIntegrationBundle, AuthContext, ModelRuntimeConfig, Overview, PolicySettings } from '../types';

type SettingsLoadErrors = Partial<Record<'integration' | 'model' | 'auth' | 'policy', string>>;
type SettingKey = keyof SettingsLoadErrors;

export function SettingsPanel({ overview, refresh }: { overview: Overview; refresh: () => Promise<unknown> }) {
  const [integration, setIntegration] = useState<AgentIntegrationBundle | null>(null);
  const [modelConfig, setModelConfig] = useState<ModelRuntimeConfig | null>(null);
  const [auth, setAuth] = useState<AuthContext | null>(null);
  const [policySettings, setPolicySettings] = useState<PolicySettings | null>(null);
  const [savingModel, setSavingModel] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loadErrors, setLoadErrors] = useState<SettingsLoadErrors>({});
  const [loadingSettings, setLoadingSettings] = useState(true);

  useEffect(() => {
    let cancelled = false;
    void Promise.allSettled([
      fetchAgentIntegrationBundle(),
      fetchModelConfig(),
      fetchAuthContext(),
      fetchPolicyConfig()
    ]).then(([integrationResult, modelResult, authResult, policyResult]) => {
      if (cancelled) return;
      const results = [integrationResult, modelResult, authResult, policyResult] as const;
      const keys = ['integration', 'model', 'auth', 'policy'] as const;
      const nextErrors: SettingsLoadErrors = {};
      results.forEach((result, index) => {
        if (result.status === 'rejected') {
          const reason = result.reason;
          nextErrors[keys[index]] = safeUiErrorSummary(reason, '设置读取失败。');
        }
      });
      if (integrationResult.status === 'fulfilled') setIntegration(integrationResult.value);
      if (modelResult.status === 'fulfilled') setModelConfig(modelResult.value);
      if (authResult.status === 'fulfilled') setAuth(authResult.value);
      if (policyResult.status === 'fulfilled') setPolicySettings(policyResult.value.settings);
      setLoadErrors(nextErrors);
      setLoadingSettings(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const loadErrorEntries = Object.entries(loadErrors);
  const settingsLoadNotice = loadErrorEntries.length
    ? loadErrorEntries.map(([key, message]) => `${settingsLoadLabel(key)}：${message}`).join('；')
    : '';
  const canEditModel = Boolean(auth?.permissions.can_edit_policy && modelConfig);
  const canEditPolicy = Boolean(auth?.permissions.can_edit_policy && policySettings);
  const canProbeProvider = Boolean(auth?.permissions.can_review_approval);
  const { probingProviderKey, probeResult, probeProvider } = useProviderProbe(canProbeProvider, setError);
  const { profileStatuses, profileStatusError, profileStatusLoading } = useProviderStatuses(Boolean(auth));

  async function retryFailedSettings() {
    const keys = Object.keys(loadErrors) as SettingKey[];
    if (!keys.length) return;
    setLoadingSettings(true);
    const results = await Promise.allSettled(keys.map((key) => reloadSetting(key)));
    const nextErrors = { ...loadErrors };
    results.forEach((result, index) => {
      const key = keys[index];
      if (result.status === 'fulfilled') {
        delete nextErrors[key];
      } else {
        nextErrors[key] = safeUiErrorSummary(result.reason, '设置读取失败。');
      }
    });
    setLoadErrors(nextErrors);
    setLoadingSettings(false);
  }

  async function reloadSetting(key: SettingKey) {
    if (key === 'integration') setIntegration(await fetchAgentIntegrationBundle());
    if (key === 'model') setModelConfig(await fetchModelConfig());
    if (key === 'auth') setAuth(await fetchAuthContext());
    if (key === 'policy') setPolicySettings((await fetchPolicyConfig()).settings);
  }

  async function saveModelConfig() {
    if (!modelConfig) return;
    if (!auth?.permissions.can_edit_policy) {
      setError('当前角色只有查看权限，模型连接由管理员维护。');
      return;
    }
    setSavingModel(true);
    setError('');
    setNotice('');
    try {
      const savedConfig = await updateModelConfig({
        real_api_enabled: modelConfig.real_api_enabled,
        profiles: modelConfig.profiles
      });
      setModelConfig(savedConfig);
      setNotice('模型连接已保存。');
      try {
        await refresh();
      } catch (refreshError) {
        setError(`模型连接已保存，但总览刷新失败：${safeUiErrorSummary(refreshError)}`);
      }
    } catch (saveError) {
      setError(safeUiErrorSummary(saveError, '模型连接保存失败。'));
    } finally {
      setSavingModel(false);
    }
  }

  async function savePolicySettings() {
    if (!policySettings) return;
    if (!auth?.permissions.can_edit_policy) {
      setError('当前角色只有查看权限，权限设置由管理员维护。');
      return;
    }
    setSavingPolicy(true);
    setError('');
    setNotice('');
    try {
      setPolicySettings(
        await updatePolicySettings({
          ...policySettings,
          comment: '通过设置页更新 Agent 工具、模型、API 与上下文最小权限'
        })
      );
      setNotice('工具与数据权限已保存，并生成新的策略版本。');
    } catch (saveError) {
      setError(safeUiErrorSummary(saveError, '权限保存失败。'));
    } finally {
      setSavingPolicy(false);
    }
  }

  return (
    <div className="zh-product-page">
      <PageHeader title="设置" description="只保留接入、模型和权限三类生产配置。" />

      {settingsLoadNotice ? (
        <UiAlert
          type="warning"
          showIcon
          title="部分设置读取失败"
          description={`${settingsLoadNotice} 已成功读取的设置仍可继续查看。`}
          action={
            <UiButton size="small" loading={loadingSettings} onClick={() => void retryFailedSettings()}>
              重试失败项
            </UiButton>
          }
        />
      ) : null}
      {error ? <UiAlert type="error" showIcon title={error} /> : null}
      {notice ? <UiAlert type="success" showIcon title={notice} /> : null}

      <UiTabs
        className="zh-product-tabs"
        defaultActiveKey="connection"
        items={[
          {
            key: 'connection',
            label: '应用接入',
            children: (
              <ConnectionSettings integration={integration} loading={loadingSettings} error={loadErrors.integration} />
            )
          },
          {
            key: 'provider',
            label: '模型连接',
            children: (
              <ProviderSettings
                overview={overview}
                config={modelConfig}
                canEdit={canEditModel && !savingModel}
                permissionKnown={Boolean(auth)}
                saving={savingModel}
                onChange={setModelConfig}
                onSave={() => void saveModelConfig()}
                loading={loadingSettings}
                loadError={loadErrors.model}
                canProbe={canProbeProvider}
                probingProviderKey={probingProviderKey}
                probeResult={probeResult}
                onProbeProvider={probeProvider}
                profileStatuses={profileStatuses}
                profileStatusError={profileStatusError}
                profileStatusLoading={profileStatusLoading}
              />
            )
          },
          {
            key: 'permissions',
            label: '工具与数据权限',
            children: (
              <AgentBoundarySettingsPanel
                policySettings={policySettings}
                canEdit={canEditPolicy && !savingPolicy}
                saving={savingPolicy}
                onPatch={(patch) => setPolicySettings((current) => (current ? { ...current, ...patch } : current))}
                onSave={() => void savePolicySettings()}
                loading={loadingSettings}
                loadError={loadErrors.policy}
              />
            )
          }
        ]}
      />
    </div>
  );
}

function ConnectionSettings({
  integration,
  loading,
  error
}: {
  integration: AgentIntegrationBundle | null;
  loading: boolean;
  error?: string;
}) {
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
            <UiTypography.Text strong>一个 Agent，一个 Token</UiTypography.Text>
            <UiTypography.Paragraph type="secondary" className="zh-mb-0">
              当前操作员 Token 只保存在浏览器会话中；业务 Token 由后端绑定 Agent 身份、模型和工具权限。
            </UiTypography.Paragraph>
          </div>
        </div>
      </PanelCard>

      <PanelCard title="接入契约" subtitle="内容来自运行时接口，可直接用于配置业务 Agent。">
        {integration ? (
          <UiSpace orientation="vertical" size={14} className="zh-full-width">
            <UiFlex align="center" gap={8} wrap="wrap">
              <LabelTag color="green">{integration.version}</LabelTag>
              <UiTypography.Text>{integration.examples.length} 种接入方式可用</UiTypography.Text>
            </UiFlex>
            <UiTypography.Text type="secondary">
              必填字段：{integration.event_contract.required_fields.join('、')}
            </UiTypography.Text>
            <UiButton authenticatedHref="/api/integrations/agents/bundle">下载接入契约</UiButton>
          </UiSpace>
        ) : error ? (
          <UiAlert type="error" showIcon title="接入契约读取失败" description={error} />
        ) : loading ? (
          <UiAlert type="info" showIcon title="正在读取接入契约。" />
        ) : (
          <UiAlert type="warning" showIcon title="接入契约暂时没有返回内容。" />
        )}
      </PanelCard>
    </div>
  );
}

function settingsLoadLabel(key: string) {
  return { integration: '接入契约', model: '模型连接', auth: '权限上下文', policy: '业务安全边界' }[key] ?? '设置';
}

function EndpointRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="zh-endpoint-row">
      <span aria-hidden="true">{icon}</span>
      <div>
        <UiTypography.Text type="secondary">{label}</UiTypography.Text>
        <UiTypography.Text code>{value}</UiTypography.Text>
      </div>
      <CopyButton text={value}>复制</CopyButton>
    </div>
  );
}
