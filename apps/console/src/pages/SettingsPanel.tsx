import { useEffect, useState } from 'react';
import {
  fetchAgentIntegrationBundle,
  fetchAuthContext,
  fetchPolicyConfig,
  publishPolicySettings,
  rollbackPolicyVersion,
  validatePolicySettings
} from '../app/governanceApi';
import { safeUiErrorSummary } from '../app/apiRequestSupport';
import { fetchModelConfig, updateModelConfig } from '../app/operationalApi';
import { AgentBoundarySettingsPanel } from '../components/settings/AgentBoundarySettingsPanel';
import { ConnectionSettings } from '../components/settings/ConnectionSettings';
import { AgentRegistryPanel } from '../components/settings/AgentRegistryPanel';
import { ProviderSettings } from '../components/settings/ProviderSettings';
import { useProviderProbe, useProviderStatuses } from '../components/settings/useProviderProbe';
import { PageHeader, UiAlert, UiButton, UiTabs } from '../components/ui';
import type {
  AgentIntegrationBundle,
  AuthContext,
  AgentRegistration,
  ModelRuntimeConfig,
  Overview,
  PolicySettings,
  PolicyVersion
} from '../types';

type SettingsLoadErrors = Partial<Record<'integration' | 'model' | 'auth' | 'policy', string>>;
type SettingKey = keyof SettingsLoadErrors;

export function SettingsPanel({ overview, refresh }: { overview: Overview; refresh: () => Promise<unknown> }) {
  const [integration, setIntegration] = useState<AgentIntegrationBundle | null>(null);
  const [modelConfig, setModelConfig] = useState<ModelRuntimeConfig | null>(null);
  const [auth, setAuth] = useState<AuthContext | null>(null);
  const [policySettings, setPolicySettings] = useState<PolicySettings | null>(null);
  const [policyVersions, setPolicyVersions] = useState<PolicyVersion[]>([]);
  const [savingModel, setSavingModel] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loadErrors, setLoadErrors] = useState<SettingsLoadErrors>({});
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [activeSettingsTab, setActiveSettingsTab] = useState('connection');
  const [registeredAgents, setRegisteredAgents] = useState<AgentRegistration[]>([]);
  const [policyAgentId, setPolicyAgentId] = useState<string | null>(null);

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
      if (policyResult.status === 'fulfilled') {
        setPolicySettings(policyResult.value.settings);
        setPolicyVersions(policyResult.value.versions);
      }
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
    if (key === 'policy') {
      const config = await fetchPolicyConfig();
      setPolicySettings(config.settings);
      setPolicyVersions(config.versions);
    }
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
      const validation = await validatePolicySettings(policySettings);
      const published = await publishPolicySettings(
        policySettings,
        '通过设置页发布 Agent 工具、模型、API 与上下文最小权限'
      );
      if (published.config) setPolicySettings(published.config);
      const latest = await fetchPolicyConfig();
      setPolicyVersions(latest.versions);
      const impact = validation.impact_preview?.affected_agents.length ?? 0;
      setNotice(`策略已校验并发布，影响 ${impact} 个 Agent。`);
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
        activeKey={activeSettingsTab}
        onChange={setActiveSettingsTab}
        items={[
          {
            key: 'connection',
            label: '应用接入',
            children: (
              <ConnectionSettings integration={integration} loading={loadingSettings} error={loadErrors.integration} />
            )
          },
          {
            key: 'agents',
            label: 'Agent 接入',
            children: (
              <AgentRegistryPanel
                canEdit={Boolean(auth?.permissions.can_edit_policy)}
                onAgentsChange={setRegisteredAgents}
                onConfigurePolicy={(agentId) => {
                  setPolicyAgentId(agentId);
                  setActiveSettingsTab('permissions');
                }}
              />
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
                versions={policyVersions}
                registeredAgentIds={registeredAgents
                  .filter((agent) => agent.status === 'active')
                  .map((agent) => agent.agent_id)}
                selectedAgentId={policyAgentId}
                onRollback={async (version) => {
                  await rollbackPolicyVersion(version);
                  const latest = await fetchPolicyConfig();
                  setPolicySettings(latest.settings);
                  setPolicyVersions(latest.versions);
                  setNotice(`已生成策略回滚版本（来源 ${version}）。`);
                }}
              />
            )
          }
        ]}
      />
    </div>
  );
}

function settingsLoadLabel(key: string) {
  return { integration: '接入契约', model: '模型连接', auth: '权限上下文', policy: '业务安全边界' }[key] ?? '设置';
}
