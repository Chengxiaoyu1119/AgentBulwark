import type {
  ModelProfileId,
  ModelProviderOption,
  ModelRuntimeConfig,
  ModelStatus,
  ModelStatusByProfile,
  Overview
} from '@/types';

export const fallbackModelProviders: ModelProviderOption[] = [
  { id: 'deepseek', label: 'DeepSeek' },
  { id: 'zhipu', label: '智谱' },
  { id: 'openai-compatible', label: 'OpenAI 兼容接口' }
];

export const modelProfileMeta: Array<{ id: ModelProfileId; title: string; description: string }> = [
  { id: 'target', title: '主模型', description: 'Agent 任务规划与安全攻防验证默认使用的模型链路。' },
  { id: 'optimizer', title: '副模型', description: '提示词优化、语言变体生成默认走智谱优先链路。' },
  { id: 'global', title: '全局默认模型', description: '普通模型调用、工具调用盲测与兜底评估统一使用。' }
];

export function normalizeProviderId(provider: string): string {
  if (/deepseek/i.test(provider)) {
    return 'deepseek';
  }
  if (/智谱|zhipu/i.test(provider)) {
    return 'zhipu';
  }
  if (/openai|兼容接口/i.test(provider)) {
    return 'openai-compatible';
  }
  return '';
}

export function buildProfileRuntimeRows(
  modelConfig: ModelRuntimeConfig | null,
  overview: Overview,
  providers: ModelProviderOption[],
  profileStatuses: ModelStatusByProfile
) {
  const providerIds = providers.map((provider) => provider.id);
  return modelProfileMeta.map((profile) => {
    const profileConfig = modelConfig?.profiles[profile.id] ?? { provider_priority: providerIds, model_overrides: {} };
    const primaryProvider = profileConfig.provider_priority?.[0] ?? providerIds[0];
    const selectedProvider = providers.find((provider) => provider.id === primaryProvider) ?? providers[0];
    const statuses: ModelStatus[] = profileStatuses[profile.id] ?? (profile.id === 'global' ? overview.models : []);
    const statusByProvider = new Map<string, ModelStatus>(
      statuses
        .map((model) => [normalizeProviderId(model.provider), model] as const)
        .filter(([providerId]) => providerIds.includes(providerId))
    );
    const runtimeModel = statusByProvider.get(primaryProvider);
    const configured = runtimeModel
      ? Boolean(runtimeModel.configured && runtimeModel.mode === 'real-api')
      : profileStatuses[profile.id]
        ? false
        : null;
    const orderLabels = (profileConfig.provider_priority?.length ? profileConfig.provider_priority : providerIds)
      .map((providerId) => providers.find((provider) => provider.id === providerId)?.label ?? providerId)
      .join(' -> ');
    return {
      ...profile,
      profileConfig,
      primaryProvider,
      selectedProvider,
      configured,
      defaultModel: runtimeModel?.model ?? '',
      orderLabels
    };
  });
}
