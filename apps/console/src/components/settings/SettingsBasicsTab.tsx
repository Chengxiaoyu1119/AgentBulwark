import { Col, Flex, Row, Space, Typography } from 'antd';
import { LabelTag, PanelCard, UiButton, UiInput, UiSelect, UiSwitch } from '../ui';
import type { ModelRuntimeConfig, Overview } from '@/types';
import { fallbackModelProviders, modelProfileMeta, normalizeProviderId } from './modelConfigHelpers';

type SettingsBasicsTabProps = {
  overview: Overview;
  modelConfig: ModelRuntimeConfig | null;
  savingModelConfig: boolean;
  onModelConfigChange: (config: ModelRuntimeConfig) => void;
  onSaveModelConfig: () => Promise<void>;
};

export function SettingsBasicsTab({
  overview,
  modelConfig,
  savingModelConfig,
  onModelConfigChange,
  onSaveModelConfig
}: SettingsBasicsTabProps) {
  const providers = modelConfig?.allowed_providers?.length ? modelConfig.allowed_providers : fallbackModelProviders;
  const providerOptions = providers.map((provider) => ({ label: provider.label, value: provider.id }));
  const providerIds = providers.map((provider) => provider.id);
  const modelStatusByProvider = new Map(
    overview.models
      .map((model) => [normalizeProviderId(model.provider), model] as const)
      .filter(([providerId]) => providerIds.includes(providerId))
  );
  const configuredModelCount = overview.models.filter((model) => model.configured && model.mode === 'real-api').length;
  const profileRuntimeRows = modelProfileMeta.map((profile) => {
    const profileConfig = modelConfig?.profiles[profile.id] ?? {
      provider_priority: providerIds,
      model_overrides: {}
    };
    const primaryProvider = profileConfig.provider_priority?.[0] ?? providerIds[0];
    const selectedProvider = providers.find((provider) => provider.id === primaryProvider) ?? providers[0];
    const runtimeModel = modelStatusByProvider.get(primaryProvider);
    const configured = Boolean(
      modelConfig?.real_api_enabled && runtimeModel?.configured && runtimeModel?.mode === 'real-api'
    );
    const defaultModel = runtimeModel?.model ?? '';
    const orderLabels = (profileConfig.provider_priority?.length ? profileConfig.provider_priority : providerIds)
      .map((providerId) => providers.find((provider) => provider.id === providerId)?.label ?? providerId)
      .join(' -> ');
    return {
      ...profile,
      profileConfig,
      primaryProvider,
      selectedProvider,
      runtimeModel,
      configured,
      defaultModel,
      orderLabels
    };
  });

  function updateModelConfig(updater: (config: ModelRuntimeConfig) => ModelRuntimeConfig) {
    if (!modelConfig) {
      return;
    }
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
    <Space orientation="vertical" size="large" className="zh-tab-stack">
      <PanelCard
        title="真实模型链路状态"
        subtitle="这里只展示运行状态，不展示 API 密钥；密钥仍由本地或服务器 .env 保存。"
        type="inner"
      >
        <Row gutter={[16, 16]} className="zh-settings-status-grid">
          <Col xs={24} sm={8}>
            <div className="zh-settings-status-card">
              <Typography.Text type="secondary" className="zh-meta-block">
                调用模式
              </Typography.Text>
              <Typography.Text strong>
                {modelConfig?.real_api_enabled ? '真实 API 优先' : '本地兜底模式'}
              </Typography.Text>
            </div>
          </Col>
          <Col xs={24} sm={8}>
            <div className="zh-settings-status-card">
              <Typography.Text type="secondary" className="zh-meta-block">
                已配置模型
              </Typography.Text>
              <Typography.Text strong>
                {configuredModelCount}/{overview.models.length}
              </Typography.Text>
            </div>
          </Col>
          <Col xs={24} sm={8}>
            <div className="zh-settings-status-card">
              <Typography.Text type="secondary" className="zh-meta-block">
                配置来源
              </Typography.Text>
              <Typography.Text strong>{modelConfig?.real_api_enabled_source ?? '读取中'}</Typography.Text>
            </div>
          </Col>
        </Row>
        <Row gutter={[16, 16]}>
          {profileRuntimeRows.map((profile) => (
            <Col xs={24} md={8} key={profile.id}>
              <div className="zh-settings-profile-status">
                <div>
                  <Typography.Text strong className="zh-text-block">
                    {profile.title}
                  </Typography.Text>
                  <Typography.Text type="secondary" className="zh-meta-block">
                    {profile.selectedProvider.label} /{' '}
                    {profile.profileConfig.model_overrides?.[profile.primaryProvider] ||
                      profile.defaultModel ||
                      '默认模型'}
                  </Typography.Text>
                </div>
                <LabelTag
                  variant="filled"
                  color={profile.configured ? 'success' : 'warning'}
                  className="zh-settings-tag-flush"
                >
                  {profile.configured ? '真实可用' : '兜底/待配置'}
                </LabelTag>
              </div>
            </Col>
          ))}
        </Row>
      </PanelCard>

      <PanelCard title="模型连接明细" type="inner">
        <Row gutter={[16, 16]}>
          {overview.models.map((model) => (
            <Col xs={24} sm={12} md={8} lg={6} key={model.provider}>
              <PanelCard type="inner" size="small" hoverable className="zh-full-height zh-settings-provider-card">
                <Typography.Text strong className="zh-text-block">
                  {model.provider}
                </Typography.Text>
                <Typography.Text type="secondary" className="zh-text-sm zh-text-block zh-mb-4">
                  {model.model}
                </Typography.Text>
                <Typography.Text className="zh-settings-provider-endpoint">
                  {model.endpoint ?? model.mode}
                </Typography.Text>
                <LabelTag
                  variant="filled"
                  color={model.configured && model.mode === 'real-api' ? 'success' : 'warning'}
                >
                  {model.configured && model.mode === 'real-api' ? '已接入真实 API' : '本地兜底/待配置'}
                </LabelTag>
              </PanelCard>
            </Col>
          ))}
        </Row>
      </PanelCard>

      <PanelCard title="大语言模型运行配置" type="inner">
        {modelConfig ? (
          <Space orientation="vertical" size="large" className="zh-settings-stack">
            <div className="zh-settings-model-toolbar">
              <div className="zh-flex-min">
                <Typography.Text strong className="zh-text-block">
                  真实 API 调用
                </Typography.Text>
                <Typography.Text type="secondary" className="zh-text-sm zh-text-block zh-mt-4">
                  密钥仍读取服务器 .env，页面只保存模型用途、优先级和模型名。
                </Typography.Text>
              </div>
              <Flex align="center" gap={12} wrap="wrap">
                <UiSwitch checked={modelConfig.real_api_enabled} onChange={updateRealApiEnabled} />
                <UiButton type="primary" loading={savingModelConfig} onClick={onSaveModelConfig}>
                  保存配置
                </UiButton>
              </Flex>
            </div>

            <Row gutter={[16, 16]}>
              {profileRuntimeRows.map((profile) => (
                <Col xs={24} md={8} key={profile.id}>
                  <PanelCard type="inner" size="small" className="zh-full-height zh-settings-model-card">
                    <Space orientation="vertical" size="middle" className="zh-settings-stack">
                      <div>
                        <Typography.Text strong className="zh-text-block">
                          {profile.title}
                        </Typography.Text>
                        <Typography.Text type="secondary" className="zh-text-sm zh-text-block zh-mt-4">
                          {profile.description}
                        </Typography.Text>
                      </div>
                      <div className="zh-settings-model-field">
                        <Typography.Text type="secondary" className="zh-settings-info-label">
                          优先调用
                        </Typography.Text>
                        <UiSelect
                          className="zh-settings-model-select"
                          value={profile.primaryProvider}
                          options={providerOptions}
                          onChange={(value) => updatePrimaryProvider(profile.id, value)}
                        />
                      </div>
                      <div className="zh-settings-model-field">
                        <Typography.Text type="secondary" className="zh-settings-info-label">
                          模型名称
                        </Typography.Text>
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
                        />
                      </div>
                      <Typography.Text type="secondary" className="zh-code-sm">
                        调用顺序：{profile.orderLabels}
                      </Typography.Text>
                    </Space>
                  </PanelCard>
                </Col>
              ))}
            </Row>
          </Space>
        ) : (
          <Typography.Text type="secondary">正在读取模型运行配置...</Typography.Text>
        )}
      </PanelCard>
    </Space>
  );
}
