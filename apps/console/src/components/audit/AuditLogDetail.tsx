import { Descriptions, Flex, Space, Typography } from 'antd';
import { Copy } from 'lucide-react';
import type { AuditLog } from '@/types';
import { riskLabel } from '@/utils';
import { EvidenceCodeBlock, LabelTag, PanelCard, UiBadge, UiButton } from '../ui';

interface AuditLogDetailProps {
  log?: AuditLog;
  copied: boolean;
  onCopy: () => void;
}

export function AuditLogDetail({ log, copied, onCopy }: AuditLogDetailProps) {
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
        : executionStatus === 'not_executed'
          ? '未执行'
          : executionStatus === 'server_sandbox_completed'
            ? '服务端沙箱已完成'
            : executionStatus === 'not_applicable'
              ? '无需外部回执'
              : '等待外部回执';

  return (
    <PanelCard
      type="inner"
      title={
        <Space>
          <Typography.Text>{log.tool}</Typography.Text>
          <LabelTag variant="filled">{log.decision}</LabelTag>
        </Space>
      }
      extra={<Typography.Text type="secondary">{log.timestamp.slice(0, 19).replace('T', ' ')}</Typography.Text>}
    >
      <Descriptions column={2} size="small" bordered className="zh-mb-16">
        <Descriptions.Item label="风险等级">
          <LabelTag variant="filled" color={['critical', 'high'].includes(log.risk_level) ? 'error' : 'default'}>
            {riskLabel[log.risk_level]}
          </LabelTag>
        </Descriptions.Item>
        <Descriptions.Item label="风险分">{log.risk_score ?? '-'}</Descriptions.Item>
        <Descriptions.Item label="异常分">{log.anomaly_score ?? '-'}</Descriptions.Item>
        <Descriptions.Item label="策略编号">{log.policy_id}</Descriptions.Item>
        <Descriptions.Item label="原始工具">{log.tool}</Descriptions.Item>
        <Descriptions.Item label="标准能力">{log.standard_capability ?? log.tool}</Descriptions.Item>
        <Descriptions.Item label="监督决策">
          <LabelTag variant="filled" color={log.decision === '允许' ? 'success' : 'warning'}>
            {log.decision}
          </LabelTag>
        </Descriptions.Item>
        <Descriptions.Item label="外部执行状态">
          <UiBadge
            status={executionStatus === 'completed' ? 'success' : executionStatus === 'failed' ? 'error' : 'processing'}
            text={statusLabel}
          />
        </Descriptions.Item>
        <Descriptions.Item label="实际执行目标">
          <UiBadge
            status={executionTarget === 'real' ? 'warning' : executionTarget === 'sandbox' ? 'processing' : 'default'}
            text={
              executionTarget === 'real'
                ? '真实执行器'
                : executionTarget === 'sandbox'
                  ? '沙箱'
                  : executionTarget === 'none'
                    ? '无'
                    : '未确认'
            }
          />
        </Descriptions.Item>
        <Descriptions.Item label="工具本次执行">
          <UiBadge
            status={log.tool_output.executed ? 'success' : 'default'}
            text={log.tool_output.executed ? '是' : '否'}
          />
        </Descriptions.Item>
        <Descriptions.Item label="执行耗时">
          {receipt?.duration_ms != null ? `${receipt.duration_ms} ms` : '未收到回执'}
        </Descriptions.Item>
        <Descriptions.Item label="结果 Hash">{receipt?.result_hash || '未收到回执'}</Descriptions.Item>
        <Descriptions.Item label="回执 Hash">{receipt?.receipt_hash || '未收到回执'}</Descriptions.Item>
        <Descriptions.Item label="回执签名">
          {receipt?.receipt_signature ? `${receipt.receipt_signature.slice(0, 24)}…` : '未配置或未收到'}
        </Descriptions.Item>
      </Descriptions>

      {!receipt && executionStatus === 'awaiting_receipt' ? (
        <Typography.Paragraph type="warning">
          监督器判定已经完成，但外部 Agent
          尚未回传执行回执；“允许”不等于工具已经成功，“拒绝/询问”也暂时不能证明调用方遵守。
        </Typography.Paragraph>
      ) : null}

      <Typography.Title level={5}>命中原因</Typography.Title>
      <Typography.Paragraph>{log.reason}</Typography.Paragraph>

      <Typography.Title level={5}>推荐处置</Typography.Title>
      <Typography.Paragraph>{log.recommendation}</Typography.Paragraph>

      {log.risk_factors && log.risk_factors.length > 0 ? (
        <>
          <Typography.Title level={5}>风险因子</Typography.Title>
          <Space wrap className="zh-mb-16">
            {log.risk_factors.map((factor) => (
              <LabelTag variant="filled" key={factor}>
                {factor}
              </LabelTag>
            ))}
          </Space>
        </>
      ) : null}

      <Typography.Title level={5}>工具参数</Typography.Title>
      <EvidenceCodeBlock size="small">{JSON.stringify(log.arguments, null, 2)}</EvidenceCodeBlock>

      {log.standard_capability && log.standard_capability !== log.tool ? (
        <>
          <Typography.Title level={5}>标准化参数</Typography.Title>
          <EvidenceCodeBlock size="small">{JSON.stringify(log.standard_arguments ?? {}, null, 2)}</EvidenceCodeBlock>
        </>
      ) : null}

      <Typography.Title level={5}>工具调用绑定 Hash</Typography.Title>
      <EvidenceCodeBlock size="small">{log.tool_call_hash ?? '旧记录未提供 tool_call_hash'}</EvidenceCodeBlock>

      <Typography.Title level={5}>工具输出</Typography.Title>
      <EvidenceCodeBlock size="small" maxHeight="small">
        {log.tool_output.output}
      </EvidenceCodeBlock>

      {receipt?.error ? (
        <>
          <Typography.Title level={5}>执行错误摘要</Typography.Title>
          <Typography.Paragraph type="danger">{receipt.error}</Typography.Paragraph>
        </>
      ) : null}

      <Flex justify="flex-end" className="zh-detail-actions">
        <UiButton icon={<Copy size={16} />} onClick={onCopy}>
          {copied ? '已复制' : '复制证据'}
        </UiButton>
      </Flex>
    </PanelCard>
  );
}
