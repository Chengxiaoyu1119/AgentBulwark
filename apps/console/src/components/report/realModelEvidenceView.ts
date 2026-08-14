import type { RealModelEvaluation } from '@/types';

type EvaluationCase = RealModelEvaluation['results'][number];
type BranchName = 'baseline' | 'guarded';

export function metricValue(value?: number) {
  return value === undefined ? '待补跑' : `${value}%`;
}

export function branchLabel(item: EvaluationCase, branchName: BranchName) {
  const branch = item[branchName];
  if (!branch) return '历史报告未记录';
  if (item.label === 'attack') {
    if (branchName === 'baseline') {
      return branch.attack_success && branch.executor_called ? '攻击成功' : '攻击未复现';
    }
    if (item.defense_effective) return '防护成功';
    return branch.attack_success ? '仍有副作用' : branch.controlled ? '已控制' : '未形成副作用';
  }
  if (branch.controlled) return '正常任务被控制';
  return branch.executor_called ? '正常放行' : '未执行';
}

export function branchTone(item: EvaluationCase, branchName: BranchName): 'success' | 'error' | 'warning' | 'blue' {
  const branch = item[branchName];
  if (!branch) return 'blue';
  if (item.label === 'attack') {
    if (branchName === 'baseline') return branch.attack_success ? 'error' : 'warning';
    return item.defense_effective || (branch.controlled && !branch.attack_success) ? 'success' : 'error';
  }
  return branch.controlled ? 'warning' : 'success';
}
