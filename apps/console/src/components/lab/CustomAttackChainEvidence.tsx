import { Descriptions, Space, Typography } from 'antd';
import type { CustomAttackChainResult } from '../../types';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import { DecisionPill, PanelCard, UiButton } from '../ui';

export function CustomAttackChainEvidence({
  result,
  onOpenAgentChain
}: {
  result: CustomAttackChainResult;
  onOpenAgentChain?: () => void;
}) {
  return (
    <PanelCard
      title="当前 Payload 的多 Agent 链证据"
      subtitle={`来源标识 ${result.source_comparison_id || '-'} · 已验证溯源`}
      type="inner"
    >
      <Space orientation="vertical" size={12} className="zh-full-width">
        <Descriptions column={{ xs: 1, md: 2 }} size="small" bordered>
          <Descriptions.Item label="实际 Payload">{result.request.payload}</Descriptions.Item>
          <Descriptions.Item label="实际工具">{result.tool_call.tool}</Descriptions.Item>
          <Descriptions.Item label="监督决策">
            <DecisionPill decision={result.summary.decision} />
          </Descriptions.Item>
          <Descriptions.Item label="攻击结果">
            {result.summary.final_outcome === 'controlled' || result.summary.controlled
              ? '风险已控制'
              : result.summary.final_outcome === 'attack_success' || result.summary.attack_success
                ? '攻击判据成立'
                : result.summary.final_outcome === 'side_effect_only' || result.environment?.changed
                  ? '副作用已观察，未命中攻击判据'
                  : '未产生工具副作用'}
          </Descriptions.Item>
          <Descriptions.Item label="执行回执">{receiptSummary(result)}</Descriptions.Item>
          <Descriptions.Item label="审计编号">{result.audit.audit_id}</Descriptions.Item>
          <Descriptions.Item label="监督阶段">
            {result.summary.stage_count} 个阶段 / {result.summary.all_stages_audited ? '全部有审计' : '审计不完整'}
          </Descriptions.Item>
          <Descriptions.Item label="链路一致性">
            {result.chain_integrity?.same_payload &&
            result.chain_integrity?.same_tool_call &&
            result.chain_integrity?.shared_conversation_id
              ? 'Payload、工具调用、会话均一致'
              : result.chain_integrity
                ? '链路证据不一致'
                : '等待链路一致性证据'}
          </Descriptions.Item>
          <Descriptions.Item label="阶段依赖">
            {result.chain_integrity?.artifact_chain_valid &&
            result.chain_integrity?.artifact_hashes_valid &&
            result.chain_integrity?.executor_consumed_planner_artifact &&
            result.chain_integrity?.supervisor_consumed_execution_artifact &&
            result.chain_integrity?.evaluator_consumed_prior_artifacts
              ? '计划、执行、监督、汇总产物已逐级校验'
              : '阶段产物依赖校验未通过'}
          </Descriptions.Item>
          <Descriptions.Item label="链路根 Hash">
            {shortHash(result.chain_integrity?.chain_root_hash)}
          </Descriptions.Item>
        </Descriptions>
        <div className="zh-attack-lab__explain-list">
          {(result.stages ?? []).map((stage) => (
            <div key={stage.stage_id} className="zh-attack-lab__explain-item">
              <Typography.Text strong>{stage.stage_name}</Typography.Text>
              <Typography.Text>
                {stage.evaluation.decision} · {stage.execution_attempted ? '工具执行阶段' : '仅监督留痕'} · 审计{' '}
                {stage.audit.audit_id} · 回执 {stage.receipt.status}
                {stage.stage_context?.source ? ` · 上游 ${String(stage.stage_context.source)}` : ''}
              </Typography.Text>
              <Typography.Text type="secondary">
                {artifactLabel(stage.artifact?.artifact_type)} · 输入{' '}
                {stage.artifact?.input_artifact_hashes?.map(shortHash).join('、') || '原始请求'} · 产物{' '}
                {shortHash(stage.artifact?.artifact_hash)}
              </Typography.Text>
            </div>
          ))}
        </div>
        <Space wrap>
          <AuditDeepLinkButton auditId={result.audit.audit_id}>查看本次链路审计</AuditDeepLinkButton>
          {onOpenAgentChain ? <UiButton onClick={onOpenAgentChain}>查看预置多阶段攻击链</UiButton> : null}
        </Space>
      </Space>
    </PanelCard>
  );
}

function artifactLabel(type?: string) {
  return (
    {
      'execution-plan': '生成执行计划',
      'execution-evidence': '按计划执行并固化回执',
      'supervisor-verdict': '核验执行与环境证据',
      'evaluation-summary': '汇总全链路结论'
    }[type ?? ''] ?? '阶段产物'
  );
}

function shortHash(value?: string) {
  return value ? `${value.slice(0, 12)}…` : '-';
}

function receiptSummary(result: CustomAttackChainResult) {
  const receipt = result.receipt;
  return `${receipt.status} / ${receipt.execution_target} / ${receipt.receipt_hash?.slice(0, 16) ?? '-'}…`;
}
