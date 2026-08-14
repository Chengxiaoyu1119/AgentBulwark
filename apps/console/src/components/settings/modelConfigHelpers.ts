export const fallbackModelProviders = [
  { id: 'deepseek', label: 'DeepSeek' },
  { id: 'zhipu', label: '智谱' },
  { id: 'openai-compatible', label: 'OpenAI 兼容接口' }
];

export const modelProfileMeta = [
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
