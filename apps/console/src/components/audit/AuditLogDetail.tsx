import { UiDescriptions, UiFlex, UiSpace, UiTypography } from '../ui';
import { Copy, ShieldCheck } from 'lucide-react';
import type { AuditLog, EvidenceVerification } from '@/types';
import { riskLabel } from '@/utils';
import { EvidenceCodeBlock, LabelTag, PanelCard, UiAlert, UiBadge, UiButton } from '../ui';

interface AuditLogDetailProps {
  log?: AuditLog;
  copied: boolean;
  onCopy: () => void;
  evidenceVerification?: EvidenceVerification | null;
  evidenceVerificationBusy?: boolean;
  evidenceVerificationError?: string;
  onVerifyEvidence?: () => void | Promise<void>;
}

export function AuditLogDetail({
  log,
  copied,
  onCopy,
  evidenceVerification,
  evidenceVerificationBusy = false,
  evidenceVerificationError = '',
  onVerifyEvidence
}: AuditLogDetailProps) {
  if (!log) {
    return <div className="zh-empty-panel zh-empty-panel--large">选择一条记录查看详情。</div>;
  }

  const receipt = log.execution_receipt;
  const executionStatus =
    log.execution_status ??
    (receipt ? receipt.status : log.execution_receipt_expected ? 'awaiting_receipt' : 'not_applicable');
  const executionTarget =
    log.execution_target ?? (receipt ? receipt.execution_target : log.execution_receipt_expected ? 'unknown' : 'none');
  const statusLabel =
    executionStatus === 'completed'
      ? '已完成'
      : executionStatus === 'failed'
        ? '执行失败'
        : executionStatus === 'unknown'
          ? '状态不确定·需核查'
          : executionStatus === 'pending'
            ? '执行中·待确认'
            : executionStatus === 'not_executed'
              ? '未执行'
              : executionStatus === 'not_applicable'
                ? '无需外部回执'
                : '等待外部回执';
  const verification = evidenceVerification?.verification;
  const verificationFailures = verification
    ? [
        !verification.audit_hash_valid ? '审计 Hash' : '',
        verification.audit_signature_required && !verification.audit_signature_valid ? '审计签名' : '',
        !verification.receipt_valid ? '执行回执' : '',
        verification.trace_required && !verification.trace_valid ? '请求链 Trace' : ''
      ].filter(Boolean)
    : [];
  const verifiedChecks = verification
    ? [
        '审计 Hash',
        verification.audit_signature_required ? '审计签名' : '',
        verification.receipt_present ? '执行回执绑定' : '',
        verification.trace_required ? '请求链 Trace' : ''
      ].filter(Boolean)
    : [];

  return (
    <PanelCard
      type="inner"
      title={
        <UiSpace>
          <UiTypography.Text>{log.tool}</UiTypography.Text>
          <LabelTag variant="filled">{log.decision}</LabelTag>
        </UiSpace>
      }
      extra={<UiTypography.Text type="secondary">{log.timestamp.slice(0, 19).replace('T', ' ')}</UiTypography.Text>}
    >
      <UiDescriptions column={2} size="small" bordered className="zh-mb-16">
        <UiDescriptions.Item label="风险等级">
          <LabelTag variant="filled" color={['critical', 'high'].includes(log.risk_level) ? 'error' : 'default'}>
            {riskLabel[log.risk_level]}
          </LabelTag>
        </UiDescriptions.Item>
        <UiDescriptions.Item label="风险分">{log.risk_score ?? '-'}</UiDescriptions.Item>
        <UiDescriptions.Item label="异常分">{log.anomaly_score ?? '-'}</UiDescriptions.Item>
        <UiDescriptions.Item label="策略编号">{log.policy_id}</UiDescriptions.Item>
        <UiDescriptions.Item label="原始工具">{log.tool}</UiDescriptions.Item>
        <UiDescriptions.Item label="标准能力">{log.standard_capability ?? log.tool}</UiDescriptions.Item>
        <UiDescriptions.Item label="监督决策">
          <LabelTag variant="filled" color={log.decision === '允许' ? 'success' : 'warning'}>
            {log.decision}
          </LabelTag>
        </UiDescriptions.Item>
        <UiDescriptions.Item label="外部执行状态">
          <UiBadge
            status={
              executionStatus === 'completed'
                ? 'success'
                : executionStatus === 'failed' || executionStatus === 'unknown'
                  ? 'error'
                  : 'processing'
            }
            text={statusLabel}
          />
        </UiDescriptions.Item>
        <UiDescriptions.Item label="实际执行目标">
          <UiBadge
            status={executionTarget === 'real' || executionTarget === 'external' ? 'warning' : 'default'}
            text={
              executionTarget === 'real' || executionTarget === 'external'
                ? '外部执行器'
                : executionTarget === 'none'
                  ? '无'
                  : executionTarget === 'local-runtime'
                    ? '本地受控运行时'
                    : '未确认'
            }
          />
        </UiDescriptions.Item>
        <UiDescriptions.Item label="工具本次执行">
          <UiBadge
            status={log.tool_output?.executed ? 'success' : 'default'}
            text={log.tool_output?.executed ? '是' : '否'}
          />
        </UiDescriptions.Item>
        <UiDescriptions.Item label="执行耗时">
          {receipt?.duration_ms != null ? `${receipt.duration_ms} ms` : '未收到回执'}
        </UiDescriptions.Item>
        <UiDescriptions.Item label="结果 Hash">{receipt?.result_hash || '未收到回执'}</UiDescriptions.Item>
        <UiDescriptions.Item label="回执 Hash">{receipt?.receipt_hash || '未收到回执'}</UiDescriptions.Item>
        <UiDescriptions.Item label="回执签名">
          {receipt?.receipt_signature ? `${receipt.receipt_signature.slice(0, 24)}…` : '未配置或未收到'}
        </UiDescriptions.Item>
      </UiDescriptions>

      {!receipt && executionStatus === 'awaiting_receipt' ? (
        <UiTypography.Paragraph type="warning">
          监督器判定已经完成，但外部 Agent
          尚未回传执行回执；“允许”不等于工具已经成功，“拒绝/询问”也暂时不能证明调用方遵守。
        </UiTypography.Paragraph>
      ) : null}

      {executionStatus === 'unknown' ? (
        <UiAlert
          type="error"
          showIcon
          title="工具副作用状态不确定，禁止自动重试"
          description="请使用当前审计 ID 在执行状态核查清单中确认目标系统实际状态，再决定补偿、关闭或人工重放。"
          className="zh-mb-16"
        />
      ) : null}

      <UiTypography.Title level={5}>命中原因</UiTypography.Title>
      <UiTypography.Paragraph>{log.reason}</UiTypography.Paragraph>

      <UiTypography.Title level={5}>推荐处置</UiTypography.Title>
      <UiTypography.Paragraph>{log.recommendation}</UiTypography.Paragraph>

      {log.risk_factors && log.risk_factors.length > 0 ? (
        <>
          <UiTypography.Title level={5}>风险因子</UiTypography.Title>
          <UiSpace wrap className="zh-mb-16">
            {log.risk_factors.map((factor) => (
              <LabelTag variant="filled" key={factor}>
                {factor}
              </LabelTag>
            ))}
          </UiSpace>
        </>
      ) : null}

      <UiTypography.Title level={5}>工具参数</UiTypography.Title>
      <EvidenceCodeBlock size="small">{JSON.stringify(log.arguments, null, 2)}</EvidenceCodeBlock>

      {log.standard_capability && log.standard_capability !== log.tool ? (
        <>
          <UiTypography.Title level={5}>标准化参数</UiTypography.Title>
          <EvidenceCodeBlock size="small">{JSON.stringify(log.standard_arguments ?? {}, null, 2)}</EvidenceCodeBlock>
        </>
      ) : null}

      <UiTypography.Title level={5}>工具调用绑定 Hash</UiTypography.Title>
      <EvidenceCodeBlock size="small">{log.tool_call_hash ?? '旧记录未提供 tool_call_hash'}</EvidenceCodeBlock>

      <UiTypography.Title level={5}>工具输出</UiTypography.Title>
      <EvidenceCodeBlock size="small" maxHeight="small">
        {log.tool_output?.output || '无工具输出'}
      </EvidenceCodeBlock>

      {receipt?.error ? (
        <>
          <UiTypography.Title level={5}>执行错误摘要</UiTypography.Title>
          <UiTypography.Paragraph type="danger">{receipt.error}</UiTypography.Paragraph>
        </>
      ) : null}

      {evidenceVerificationError ? (
        <UiAlert
          type="warning"
          showIcon
          title="证据核验失败"
          description={evidenceVerificationError}
          className="zh-mb-16"
        />
      ) : null}

      {evidenceVerification?.evidence_status === 'verified' && verification?.valid ? (
        <UiAlert
          type="success"
          showIcon
          title="证据已验证"
          description={`${verifiedChecks.join('、')}核验通过。${
            verification.receipt_present ? '' : '当前记录没有执行回执。'
          }`}
          className="zh-mb-16"
        />
      ) : null}

      {evidenceVerification && (!verification?.valid || evidenceVerification.evidence_status !== 'verified') ? (
        <UiAlert
          type="error"
          showIcon
          title="证据无效"
          description={
            verificationFailures.length > 0
              ? `未通过：${verificationFailures.join('、')}。请检查原始请求链后再处置。`
              : '证据链未通过完整性核验，请检查原始请求链后再处置。'
          }
          className="zh-mb-16"
        />
      ) : null}

      <UiFlex justify="flex-end" className="zh-detail-actions">
        <UiButton
          icon={<ShieldCheck size={16} />}
          loading={evidenceVerificationBusy}
          disabled={!onVerifyEvidence}
          onClick={() => void onVerifyEvidence?.()}
        >
          {evidenceVerification ? '重新核验证据' : '核验证据'}
        </UiButton>
        <UiButton icon={<Copy size={16} />} onClick={onCopy}>
          {copied ? '已复制' : '复制证据'}
        </UiButton>
      </UiFlex>
    </PanelCard>
  );
}
