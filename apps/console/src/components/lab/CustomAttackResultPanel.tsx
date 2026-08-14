import { useState } from 'react';
import { Network } from 'lucide-react';
import { Col, Descriptions, Row, Space, Typography } from 'antd';
import { runCustomAttackChain } from '../../api';
import type { CustomAttackChainResult, CustomAttackCompareResult, ExecutionReceipt } from '../../types';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import { DecisionPill, EvidenceCodeBlock, MetricCard, PanelCard, UiButton } from '../ui';
import { CustomAttackChainEvidence } from './CustomAttackChainEvidence';
import { ExternalReceiptWorkspace } from './ExternalReceiptWorkspace';

export function CustomAttackResultPanel({
  result,
  onResultChange,
  onOpenAgentChain,
  onNotice,
  refresh
}: {
  result: CustomAttackCompareResult;
  onResultChange: (result: CustomAttackCompareResult) => void;
  onOpenAgentChain?: () => void;
  onNotice: (message: string) => void;
  refresh?: () => Promise<unknown>;
}) {
  const [chainRunning, setChainRunning] = useState(false);
  const [chainResult, setChainResult] = useState<CustomAttackChainResult | null>(null);
  const without = result.environment_comparison.without_guard;
  const guarded = result.environment_comparison.with_guard;
  const receiptStatus = result.summary.receipts_complete
    ? '双分支回执已落库'
    : result.summary.receipt_required
      ? '等待外部 Agent 回执'
      : '本次未生成回执';
  const comparisonVerified =
    result.request.execution_mode === 'sandbox' &&
    result.summary.same_initial_state &&
    result.summary.exposed_without_guard &&
    result.summary.controlled_with_guard;
  const externalReceiptsVerified =
    result.request.execution_mode === 'external_receipt' &&
    result.summary.same_initial_state &&
    Boolean(
      result.receipts.without_guard?.execution_confirmed &&
      result.receipts.without_guard.agent_followed_decision &&
      result.receipts.with_guard?.control_verified &&
      result.receipts.with_guard.agent_followed_decision
    );
  async function continueAgentChain() {
    setChainRunning(true);
    onNotice('');
    try {
      const next = await runCustomAttackChain(result);
      setChainResult(next);
      await refresh?.();
      onNotice('同一 Payload 与工具调用已进入多 Agent 链并完成监督执行。');
    } catch (error) {
      onNotice(`多 Agent 链运行失败：${error instanceof Error ? error.message : '未知错误'}`);
    } finally {
      setChainRunning(false);
    }
  }
  return (
    <div className="zh-custom-attack-result">
      <PanelCard
        title="本次自定义调用的执行证据"
        subtitle={`对照编号 ${result.comparison_id}`}
        extra={<AuditDeepLinkButton auditId={result.audit.with_guard.audit_id} />}
      >
        <Space orientation="vertical" size={16} className="zh-full-width">
          <Row gutter={[12, 12]}>
            <Col xs={12} md={6}>
              <MetricCard
                label="关闭防护"
                value={
                  result.request.execution_mode === 'external_receipt'
                    ? externalBranchOutcome(result.receipts.without_guard)
                    : result.summary.exposed_without_guard
                      ? '攻击成功'
                      : '未产生副作用'
                }
                tone={
                  result.request.execution_mode === 'external_receipt'
                    ? result.receipts.without_guard?.status === 'completed'
                      ? 'red'
                      : 'amber'
                    : result.summary.exposed_without_guard
                      ? 'red'
                      : 'green'
                }
              />
            </Col>
            <Col xs={12} md={6}>
              <MetricCard
                label="智安哨"
                value={
                  result.request.execution_mode === 'external_receipt'
                    ? externalGuardOutcome(result.receipts.with_guard)
                    : result.summary.controlled_with_guard
                      ? '防护成功'
                      : '仍有风险'
                }
                tone={
                  result.request.execution_mode === 'external_receipt'
                    ? result.receipts.with_guard?.control_verified
                      ? 'green'
                      : 'amber'
                    : result.summary.controlled_with_guard
                      ? 'green'
                      : 'red'
                }
              />
            </Col>
            <Col xs={12} md={6}>
              <MetricCard
                label={result.request.execution_mode === 'external_receipt' ? '回执闭环' : '因果对照'}
                value={comparisonVerified || externalReceiptsVerified ? '已验证' : '证据不足'}
                tone={comparisonVerified || externalReceiptsVerified ? 'green' : 'amber'}
              />
            </Col>
            <Col xs={12} md={6}>
              <MetricCard
                label="执行回执"
                value={receiptStatus}
                tone={result.summary.receipt_required ? 'amber' : 'green'}
              />
            </Col>
          </Row>
          <div className="zh-custom-attack-proof-grid">
            <BranchResult
              title="关闭智安哨"
              branch={without}
              evaluation={result.without_guard}
              auditId={result.audit.without_guard.audit_id}
            />
            <BranchResult
              title="启用智安哨"
              branch={guarded}
              evaluation={result.with_guard}
              auditId={result.audit.with_guard.audit_id}
            />
          </div>
          <Descriptions column={{ xs: 1, md: 2 }} size="small" bordered>
            <Descriptions.Item label="用户 Payload">{result.request.payload}</Descriptions.Item>
            <Descriptions.Item label="Agent / 角色">
              {result.request.agent_id} / {result.request.agent_role}
            </Descriptions.Item>
            <Descriptions.Item label="上下文来源">{result.request.context_sources.join(', ')}</Descriptions.Item>
            <Descriptions.Item label="实际工具">{result.tool_call.tool}</Descriptions.Item>
            <Descriptions.Item label="实际参数">
              <EvidenceCodeBlock size="small">{JSON.stringify(result.tool_call.arguments, null, 2)}</EvidenceCodeBlock>
            </Descriptions.Item>
            <Descriptions.Item label="命中策略">{result.summary.policy_id || '-'}</Descriptions.Item>
            <Descriptions.Item label="初始环境">
              {result.summary.same_initial_state ? '两分支完全一致' : '不一致'}
            </Descriptions.Item>
            <Descriptions.Item label="唯一变量">
              {result.environment_comparison.integrity.only_variable}
            </Descriptions.Item>
            <Descriptions.Item label="工具调用 Hash">{result.summary.tool_call_hash}</Descriptions.Item>
            <Descriptions.Item label="防护执行状态">
              {result.summary.execution_status || receiptStatus}
            </Descriptions.Item>
            <Descriptions.Item label="审计链">{result.audit.with_guard.audit_hash || '-'}</Descriptions.Item>
            <Descriptions.Item label="无防护回执">{receiptSummary(result.receipts.without_guard)}</Descriptions.Item>
            <Descriptions.Item label="有防护回执">{receiptSummary(result.receipts.with_guard)}</Descriptions.Item>
          </Descriptions>
          {result.request.execution_mode === 'external_receipt' ? (
            <ExternalReceiptWorkspace
              result={result}
              onResultChange={onResultChange}
              onNotice={onNotice}
              refresh={refresh}
            />
          ) : null}
          <UiButton icon={<Network size={16} />} loading={chainRunning} onClick={continueAgentChain}>
            用当前 Payload 运行多 Agent 链
          </UiButton>
          {chainResult ? <CustomAttackChainEvidence result={chainResult} onOpenAgentChain={onOpenAgentChain} /> : null}
        </Space>
      </PanelCard>
    </div>
  );
}

function BranchResult({
  title,
  branch,
  evaluation,
  auditId
}: {
  title: string;
  branch: CustomAttackCompareResult['environment_comparison']['without_guard'];
  evaluation: CustomAttackCompareResult['without_guard'];
  auditId: string;
}) {
  const output = evaluation.audit_log.tool_output;
  const isolatedDecision = evaluation.decision === '隔离';
  const attackResult = branch.attack_success
    ? '攻击判据成立'
    : branch.effect_observed
      ? '工具副作用已落地，但未命中攻击判据'
    : isolatedDecision && branch.executor_called
      ? '已隔离执行，风险未落地'
      : evaluation.decision === '允许'
        ? '未观察到工具副作用'
        : '已阻断';
  return (
    <div className="zh-custom-attack-branch">
      <div className="zh-custom-attack-branch__header">
        <Typography.Text strong>{title}</Typography.Text>
        <DecisionPill decision={evaluation.decision} />
      </div>
      <div className="zh-custom-attack-branch__facts">
        <span>执行器：{branch.executor_called ? '已调用' : '未调用'}</span>
        <span>执行结果：{attackResult}</span>
        <span>
          环境：
          {branch.changed ? (isolatedDecision ? '隔离副本已改变' : '业务副本已改变') : '保持不变'}
        </span>
      </div>
      {branch.changes.length ? (
        branch.changes.map((change) => (
          <div className="zh-custom-attack-change" key={`${title}-${change.key}`}>
            <span>{change.label}</span>
            <strong>
              {change.before} → {change.after}
            </strong>
            {change.details?.length ? <small>{change.details.join('、')}</small> : null}
          </div>
        ))
      ) : (
        <Typography.Text type="secondary">未检测到文件、外发队列、记忆或业务状态变化。</Typography.Text>
      )}
      <Typography.Paragraph type="secondary" className="zh-attack-lab__hint">
        {branch.effect_reason}
      </Typography.Paragraph>
      <div>
        <Typography.Text strong>工具实际输出</Typography.Text>
        <EvidenceCodeBlock size="small" maxHeight="small">
          {JSON.stringify(
            {
              executed: output.executed,
              executor: output.executor ?? (output.executed ? 'built-in-tool-executor' : 'not-started'),
              execution_target: output.execution_target ?? (output.executed ? 'sandbox' : 'none'),
              exit_code: output.exit_code,
              timed_out: output.timed_out ?? false,
              output: output.output
            },
            null,
            2
          )}
        </EvidenceCodeBlock>
      </div>
      <AuditDeepLinkButton auditId={auditId} size="small">
        精确查看此分支审计
      </AuditDeepLinkButton>
    </div>
  );
}

function receiptSummary(receipt: CustomAttackCompareResult['receipts']['without_guard']) {
  if (!receipt) return '待外部 Agent 提交';
  return `${receipt.status} / ${receipt.execution_target} / ${receipt.receipt_hash?.slice(0, 16) ?? '-'}…`;
}

function externalBranchOutcome(receipt: ExecutionReceipt | null) {
  if (!receipt) return '等待外部回执';
  if (receipt.status === 'completed') return '已确认执行';
  if (receipt.status === 'failed') return '执行失败';
  return '确认未执行';
}

function externalGuardOutcome(receipt: ExecutionReceipt | null) {
  if (!receipt) return '等待外部回执';
  return receipt.control_verified ? '防护已验证' : receipt.status === 'failed' ? '执行失败' : '回执已确认';
}
