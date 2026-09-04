import { UiCol, UiFlex, UiRow, UiSpace, UiTypography } from '../ui';
import { LabelTag, PanelCard, UiAlert, UiButton, UiFieldLabel, UiInput, UiSelect, UiSwitch } from '../ui';
import type { ModelProviderProbeResult, ModelRuntimeConfig, ModelStatusByProfile, Overview } from '@/types';
import { buildProfileRuntimeRows, fallbackModelProviders } from './modelConfigHelpers';
import {
  ProviderProbeAlert,
  ProviderProbeButton,
  ProviderProfileStatus,
  ProviderStatusNotice
} from './ProviderProbeFeedback';

export type SettingsBasicsTabProps = {
  overview: Overview;
  modelConfig: ModelRuntimeConfig | null;
  savingModelConfig: boolean;
  onModelConfigChange: (config: ModelRuntimeConfig) => void;
  onSaveModelConfig: () => void | Promise<void>;
  canEdit?: boolean;
  permissionKnown?: boolean;
  loadingModelConfig?: boolean;
  modelConfigError?: string;
  canProbe?: boolean;
  probingProviderKey?: string;
  probeResult?: ModelProviderProbeResult | null;
  onProbeProvider?: (profile: string, providerId: string) => void | Promise<void>;
  profileStatuses?: ModelStatusByProfile;
  profileStatusError?: string;
  profileStatusLoading?: boolean;
};

export function SettingsBasicsTab({
  overview,
  modelConfig,
  savingModelConfig,
  onModelConfigChange,
  onSaveModelConfig,
  canEdit = true,
  permissionKnown = true,
  loadingModelConfig = false,
  modelConfigError,
  canProbe = true,
  probingProviderKey = '',
  probeResult = null,
  onProbeProvider,
  profileStatuses = {},
  profileStatusError,
  profileStatusLoading = false
}: SettingsBasicsTabProps) {
  const providers = modelConfig?.allowed_providers?.length ? modelConfig.allowed_providers : fallbackModelProviders;
  const providerOptions = providers.map((provider) => ({ label: provider.label, value: provider.id }));
  const providerIds = providers.map((provider) => provider.id);
  const configuredModelCount = overview.models.filter((model) => model.configured && model.mode === 'real-api').length;
  const profileRuntimeRows = buildProfileRuntimeRows(modelConfig, overview, providers, profileStatuses);

  function updateModelConfig(updater: (config: ModelRuntimeConfig) => ModelRuntimeConfig) {
    if (!modelConfig) return;
    onModelConfigChange(updater(modelConfig));
  }

  function updateRealApiEnabled(realApiEnabled: boolean) {
    updateModelConfig((config) => ({ ...config, real_api_enabled: realApiEnabled }));
  }

  function updatePrimaryProvider(profileId: string, providerId: string) {
    updateModelConfig((config) => {
      const profile = config.profiles[profileId] ?? { provider_priority: [], model_overrides: {} };
      const existing = profile.provider_priority ?? [];
      const providerPriority = [
        providerId,
        ...existing.filter((item) => item !== providerId),
        ...providerIds.filter((item) => item !== providerId && !existing.includes(item))
      ];
      return {
        ...config,
        profiles: {
          ...config.profiles,
          [profileId]: {
            ...profile,
            provider_priority: providerPriority
          }
        }
      };
    });
  }

  function updateModelOverride(profileId: string, providerId: string, modelName: string) {
    updateModelConfig((config) => {
      const profile = config.profiles[profileId] ?? { provider_priority: [], model_overrides: {} };
      return {
        ...config,
        profiles: {
          ...config.profiles,
          [profileId]: {
            ...profile,
            model_overrides: {
              ...profile.model_overrides,
              [providerId]: modelName
            }
          }
        }
      };
    });
  }

  return (
    <UiSpace orientation="vertical" size="large" className="zh-tab-stack">
      <PanelCard
        title="模型连接配置状态"
        subtitle="这里只展示配置发现状态，不代表网络探针或密钥校验已通过；密钥仍由本地或服务器 .env 保存。"
        type="inner"
      >
        {!modelConfig ? (
          modelConfigError ? (
            <UiAlert type="error" showIcon title="模型运行配置读取失败" description={modelConfigError} />
          ) : loadingModelConfig ? (
            <UiAlert type="info" showIcon title="正在读取模型运行配置。" />
          ) : (
            <UiAlert type="warning" showIcon title="模型运行配置暂时没有返回内容。" />
          )
        ) : (
          <>
            {!canEdit && permissionKnown ? (
              <UiAlert
                type="info"
                showIcon
                title="当前角色只有查看权限"
                description="模型连接由管理员统一维护；当前页面不会提交必然失败的保存请求。"
                className="zh-mb-16"
              />
            ) : null}
            <ProviderStatusNotice error={profileStatusError} loading={profileStatusLoading} />
            <UiRow gutter={[16, 16]} className="zh-settings-status-grid">
              <UiCol xs={24} sm={8}>
                <div className="zh-settings-status-card">
                  <UiFieldLabel>调用模式</UiFieldLabel>
                  <UiTypography.Text strong>
                    {modelConfig?.real_api_enabled ? '真实 API 已启用' : '真实 API 未启用'}
                  </UiTypography.Text>
                </div>
              </UiCol>
              <UiCol xs={24} sm={8}>
                <div className="zh-settings-status-card">
                  <UiFieldLabel>已配置模型</UiFieldLabel>
                  <UiTypography.Text strong>
                    {configuredModelCount}/{overview.models.length}
                  </UiTypography.Text>
                </div>
              </UiCol>
              <UiCol xs={24} sm={8}>
                <div className="zh-settings-status-card">
                  <UiFieldLabel>配置来源</UiFieldLabel>
                  <UiTypography.Text strong>{modelConfig?.real_api_enabled_source ?? '读取中'}</UiTypography.Text>
                </div>
              </UiCol>
            </UiRow>
            {probeResult ? <ProviderProbeAlert result={probeResult} /> : null}
            <UiRow gutter={[16, 16]}>
              {profileRuntimeRows.map((profile) => (
                <UiCol xs={24} md={8} key={profile.id}>
                  <ProviderProfileStatus
                    title={profile.title}
                    providerLabel={profile.selectedProvider.label}
                    model={profile.profileConfig.model_overrides?.[profile.primaryProvider] || profile.defaultModel}
                    configured={profile.configured}
                  />
                </UiCol>
              ))}
            </UiRow>
          </>
        )}
      </PanelCard>

      <PanelCard title="模型连接明细" type="inner">
        <UiRow gutter={[16, 16]}>
          {overview.models.map((model) => (
            <UiCol xs={24} sm={12} md={8} lg={6} key={model.provider}>
              <PanelCard type="inner" size="small" hoverable className="zh-full-height zh-settings-provider-card">
                <UiTypography.Text strong className="zh-text-block">
                  {model.provider}
                </UiTypography.Text>
                <UiTypography.Text type="secondary" className="zh-text-sm zh-text-block zh-mb-4">
                  {model.model}
                </UiTypography.Text>
                <UiTypography.Text className="zh-settings-provider-endpoint">
                  {model.endpoint ?? model.mode}
                </UiTypography.Text>
                <LabelTag
                  variant="filled"
                  color={model.configured && model.mode === 'real-api' ? 'success' : 'warning'}
                >
                  {model.configured && model.mode === 'real-api' ? '凭证已配置' : '凭证未配置'}
                </LabelTag>
              </PanelCard>
            </UiCol>
          ))}
        </UiRow>
      </PanelCard>

      <PanelCard title="大语言模型运行配置" type="inner">
        {modelConfig ? (
          <UiSpace orientation="vertical" size="large" className="zh-settings-stack">
            <div className="zh-settings-model-toolbar">
              <div className="zh-flex-min">
                <UiTypography.Text strong className="zh-text-block">
                  真实 API 调用
                </UiTypography.Text>
                <UiTypography.Text type="secondary" className="zh-text-sm zh-text-block zh-mt-4">
                  密钥仍读取服务器 .env，页面只保存模型用途、优先级和模型名。
                </UiTypography.Text>
              </div>
              <UiFlex align="center" gap={12} wrap="wrap">
                <UiSwitch checked={modelConfig.real_api_enabled} onChange={updateRealApiEnabled} disabled={!canEdit} />
                <UiButton
                  type="primary"
                  loading={savingModelConfig}
                  onClick={() => void onSaveModelConfig()}
                  disabled={!canEdit}
                >
                  保存模型连接
                </UiButton>
              </UiFlex>
            </div>

            <UiRow gutter={[16, 16]}>
              {profileRuntimeRows.map((profile) => (
                <UiCol xs={24} md={8} key={profile.id}>
                  <PanelCard type="inner" size="small" className="zh-full-height zh-settings-model-card">
                    <UiSpace orientation="vertical" size="middle" className="zh-settings-stack">
                      <div>
                        <UiTypography.Text strong className="zh-text-block">
                          {profile.title}
                        </UiTypography.Text>
                        <UiTypography.Text type="secondary" className="zh-text-sm zh-text-block zh-mt-4">
                          {profile.description}
                        </UiTypography.Text>
                      </div>
                      <div className="zh-settings-model-field">
                        <UiTypography.Text type="secondary" className="zh-settings-info-label">
                          优先调用
                        </UiTypography.Text>
                        <UiSelect
                          className="zh-settings-model-select"
                          value={profile.primaryProvider}
                          options={providerOptions}
                          onChange={(value) => updatePrimaryProvider(profile.id, value)}
                          disabled={!canEdit}
                        />
                      </div>
                      <div className="zh-settings-model-field">
                        <UiTypography.Text type="secondary" className="zh-settings-info-label">
                          模型名称
                        </UiTypography.Text>
                        <UiInput
                          className="zh-settings-model-input"
                          value={profile.profileConfig.model_overrides?.[profile.primaryProvider] ?? ''}
                          placeholder={
                            profile.defaultModel
                              ? `默认：${profile.defaultModel}`
                              : `默认：${profile.selectedProvider.label}`
                          }
                          onChange={(event) =>
                            updateModelOverride(profile.id, profile.primaryProvider, event.target.value)
                          }
                          disabled={!canEdit}
                        />
                      </div>
                      <ProviderProbeButton
                        profile={profile.id}
                        providerId={profile.primaryProvider}
                        orderLabels={profile.orderLabels}
                        canProbe={canProbe}
                        loading={probingProviderKey === `${profile.id}:${profile.primaryProvider}`}
                        onProbe={onProbeProvider}
                      />
                    </UiSpace>
                  </PanelCard>
                </UiCol>
              ))}
            </UiRow>
          </UiSpace>
        ) : modelConfigError ? (
          <UiAlert type="error" showIcon title="模型运行配置读取失败" description={modelConfigError} />
        ) : loadingModelConfig ? (
          <UiAlert type="info" showIcon title="正在读取模型运行配置。" />
        ) : (
          <UiAlert type="warning" showIcon title="模型运行配置暂时没有返回内容。" />
        )}
      </PanelCard>
    </UiSpace>
  );
}
