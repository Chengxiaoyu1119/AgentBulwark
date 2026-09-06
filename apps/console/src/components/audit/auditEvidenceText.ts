import type { ApprovalReview, AuditLog } from '@/types';
import { riskLabel } from '@/utils';

export function buildApprovalEvidenceText(review: ApprovalReview) {
  return [
    `复核单：${review.id}`,
    `状态：${review.status}`,
    `最终结论：${review.final_decision}`,
    `工具：${review.tool}`,
    `标准能力：${review.standard_capability || review.tool}`,
    `策略：${review.policy_id}`,
    `风险：${riskLabel[review.risk_level]} / ${review.risk_score ?? '-'}分`,
    `异常分：${review.anomaly_score ?? '-'}`,
    `原审计 hash：${review.audit_hash || '-'}`,
    `复核 hash：${review.review_hash || '-'}`,
    `操作人：${review.operator || '-'}`,
    `Agent：${review.agent_id || '-'}`,
    `执行状态：${review.execution_status || '-'}`,
    `领取 Agent：${review.execution_claim_agent_id || '-'}`,
    `领取时间：${review.execution_claimed_at || '-'}`,
    `完成时间：${review.execution_completed_at || '-'}`,
    `结果 Hash：${review.execution_result_hash || '-'}`,
    `备注：${review.comment || '-'}`,
    `原因：${review.reason}`,
    `建议：${review.recommendation}`,
    `参数：${JSON.stringify(review.arguments, null, 2)}`
  ].join('\n');
}

export function buildAuditEvidenceText(log: AuditLog) {
  return [
    `工具：${log.tool}`,
    `标准能力：${log.standard_capability ?? log.tool}`,
    `决策：${log.decision}`,
    `风险：${riskLabel[log.risk_level]}`,
    `风险分：${log.risk_score ?? '-'}`,
    `异常分：${log.anomaly_score ?? '-'}`,
    `风险因子：${log.risk_factors?.join(' / ') || '-'}`,
    `异常信号：${log.anomaly_signals?.join(' / ') || '-'}`,
    `审计哈希：${log.audit_hash ?? '-'}`,
    `工具调用 Hash：${log.tool_call_hash ?? '-'}`,
    `上一条哈希：${log.previous_hash ?? '-'}`,
    `策略：${log.policy_id}`,
    `原因：${log.reason}`,
    `建议：${log.recommendation}`,
    `参数：${JSON.stringify(log.arguments, null, 2)}`,
    `标准参数：${JSON.stringify(log.standard_arguments ?? log.arguments, null, 2)}`,
    `执行状态：${log.execution_status ?? 'awaiting_receipt'}`,
    `执行目标：${log.execution_target ?? 'unknown'}`,
    `结果 Hash：${log.execution_receipt?.result_hash ?? '-'}`,
    `回执 Hash：${log.execution_receipt?.receipt_hash ?? '-'}`,
    `回执签名：${log.execution_receipt?.receipt_signature ?? '-'}`,
    `输出：${log.tool_output?.output ?? '-'}`
  ].join('\n');
}

export function buildFilteredAuditEvidenceText(logs: AuditLog[]) {
  if (!logs.length) return '当前筛选条件下没有审计记录。';

  return logs
    .map((log, index) =>
      [
        `#${index + 1} ${log.tool}`,
        `标准能力：${log.standard_capability ?? log.tool}`,
        `决策：${log.decision}`,
        `风险：${riskLabel[log.risk_level]} / ${log.risk_score ?? '-'}分`,
        `异常分：${log.anomaly_score ?? '-'}`,
        `风险因子：${log.risk_factors?.join(' / ') || '-'}`,
        `异常信号：${log.anomaly_signals?.join(' / ') || '-'}`,
        `审计哈希：${log.audit_hash ?? '-'}`,
        `工具调用 Hash：${log.tool_call_hash ?? '-'}`,
        `策略：${log.policy_id}`,
        `原因：${log.reason}`,
        `建议：${log.recommendation}`,
        `执行：${log.tool_output?.executed ? '是' : '否'} / 目标：${log.execution_target ?? 'unknown'} / 状态：${log.execution_status ?? 'awaiting_receipt'}`,
        `回执：${log.execution_receipt?.receipt_hash ?? '未收到'}`
      ].join('\n')
    )
    .join('\n\n');
}
