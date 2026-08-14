import type { LabRuntimeFlowStep } from './LabRuntimeFlow';

export function attackFunctionFlowSteps(
  plannerMode: 'fixed' | 'model',
  executeInSandbox: boolean
): LabRuntimeFlowStep[] {
  return [
    { label: '输入构造', detail: '读取当前攻击文本和工具参数', tone: 'active' },
    {
      label: plannerMode === 'model' ? '模型规划' : '固定规划',
      detail: plannerMode === 'model' ? '调用后端配置模型生成工具调用' : '锁定相同工具调用，稳定复现唯一变量',
      tone: plannerMode === 'model' ? 'success' : 'warning'
    },
    { label: '本地受控环境', detail: executeInSandbox ? '沙箱工具执行并改变环境状态' : '只生成判定证据' },
    { label: '监督审计', detail: '输出无防护/有防护两组记录', tone: 'success' }
  ];
}

export function attackTestsetFlowSteps(selectedSurface: string, plannerMode: 'fixed' | 'model'): LabRuntimeFlowStep[] {
  return [
    { label: '样本选择', detail: selectedSurface === 'all' ? '当前覆盖全部攻击面' : '当前覆盖单一攻击面' },
    {
      label: plannerMode === 'model' ? '真实模型规划' : '本地批量规划',
      detail: plannerMode === 'model' ? '调用配置模型生成工具调用' : '快速覆盖全部样本，不消耗模型额度',
      tone: plannerMode === 'model' ? 'success' : 'warning'
    },
    { label: '检测器判定', detail: '逐条检查攻击是否复现', tone: 'active' },
    { label: '审计证据', detail: '输出控制率、审计编号和样本结果', tone: 'success' }
  ];
}

export function jailbreakFlowSteps(variantLimit: number, forceRealModel: boolean): LabRuntimeFlowStep[] {
  return [
    { label: '变体生成', detail: `生成 ${variantLimit} 个越狱测试输入`, tone: 'active' },
    {
      label: forceRealModel ? '真实模型' : '本地评测',
      detail: forceRealModel ? '优先调用后端已配置大模型' : '只使用本地安全评测模型',
      tone: forceRealModel ? 'success' : 'warning'
    },
    { label: '输出过滤', detail: '检查系统提示词、token、flag 等泄露信号' },
    { label: '监督审计', detail: '逐条记录决策、风险分和审计编号', tone: 'success' }
  ];
}

export const dualModelFlowSteps: LabRuntimeFlowStep[] = [
  { label: '副模型优化', detail: '智谱优先改写评测输入', tone: 'success' },
  { label: '主模型对测', detail: 'DeepSeek 优先响应优化后的输入', tone: 'success' },
  { label: '输出过滤', detail: '识别敏感内容和突破信号', tone: 'active' },
  { label: '监督审计', detail: '生成无监督/有监督对照证据', tone: 'success' }
];

export function refusalRewriteFlowSteps(iterationCount: number, forceRealTarget: boolean): LabRuntimeFlowStep[] {
  return [
    {
      label: '首轮主模型',
      detail: forceRealTarget ? '优先调用真实目标模型' : '使用本地可复现拒答样例',
      tone: 'active'
    },
    { label: '拒答命中', detail: '检查抱歉、无法协助等拒答词并记录证据' },
    { label: '副模型改写', detail: `最多 ${iterationCount} 轮，复现拒答后重写链`, tone: 'success' },
    { label: '监督审计', detail: '识别 rewrite_evasion、refusal_rewrite、prompt_pollution 风险', tone: 'success' }
  ];
}

export function authorizedTargetFlowSteps(authorizationConfirmed: boolean): LabRuntimeFlowStep[] {
  return [
    {
      label: '授权确认',
      detail: authorizationConfirmed ? '已确认授权范围' : '需要先勾选授权确认',
      tone: authorizationConfirmed ? 'success' : 'warning'
    },
    { label: '边界预检', detail: '拦截内网、本机和非模型接口', tone: 'active' },
    { label: '受控请求', detail: '只发起一次 LLM/Agent POST 测试' },
    { label: '响应审计', detail: '过滤输出并写入监督证据', tone: 'success' }
  ];
}

export const capabilityReplayFlowSteps: LabRuntimeFlowStep[] = [
  { label: '功能探针', detail: '触发核心能力测试', tone: 'active' },
  { label: '后端调用', detail: '运行实验接口和沙箱工具' },
  { label: '监督判定', detail: '验证允许、拒绝、询问策略' },
  { label: '证据汇总', detail: '集中展示审计 hash 和通过率', tone: 'success' }
];

export function penetrationFlowSteps(
  assetLabel: string,
  category: string,
  executeInSandbox: boolean,
  hasResult: boolean
): LabRuntimeFlowStep[] {
  return [
    { label: '选择资产', detail: assetLabel, tone: 'active' },
    { label: '构造输入', detail: category },
    { label: '沙箱执行', detail: executeInSandbox ? '会触碰本地受控环境资产' : '仅生成判定证据' },
    {
      label: '攻防对照',
      detail: hasResult ? '已有运行证据' : '运行后生成差异',
      tone: hasResult ? 'success' : 'neutral'
    }
  ];
}
