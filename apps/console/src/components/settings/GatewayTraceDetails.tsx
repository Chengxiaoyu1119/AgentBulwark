import { Drawer, Flex, Space, Typography } from 'antd';
import { Activity, CircleCheck, ShieldX, Wrench } from 'lucide-react';
import { LabelTag, MetaGrid, UiButton } from '../ui';
import {
  CONTROLLED_DECISIONS,
  formatTraceTime,
  gatewayRequestId,
  shortTraceHash,
  traceDecisionColor,
  traceLabel,
  type GatewayTrace
} from './gatewayTraceModel';

export function GatewayTraceDetails({
  trace,
  onClose,
  onOpenApproval
}: {
  trace: GatewayTrace | null;
  onClose: () => void;
  onOpenApproval?: (auditId: string) => void;
}) {
  const reviewAuditId =
    trace?.stages?.find((stage) => traceLabel(stage.decision) === '询问' && Boolean(stage.audit_id))?.audit_id ?? '';

  return (
    <Drawer title="请求安全详情" size="large" open={Boolean(trace)} onClose={onClose} destroyOnHidden>
      {trace ? (
        <div className="zh-traffic-detail">
          <Flex justify="space-between" align="center" gap={12} wrap="wrap">
            <div>
              <Typography.Text type="secondary">请求 ID</Typography.Text>
              <Typography.Title level={4} className="zh-title-flush zh-code-sm">
                {gatewayRequestId(trace)}
              </Typography.Title>
            </div>
            <LabelTag color={traceDecisionColor(traceLabel(trace.decision))}>{traceLabel(trace.decision)}</LabelTag>
          </Flex>

          {reviewAuditId && onOpenApproval ? (
            <UiButton
              type="primary"
              onClick={() => {
                onClose();
                onOpenApproval(reviewAuditId);
              }}
            >
              处理人工复核
            </UiButton>
          ) : null}

          <MetaGrid
            columns={2}
            items={[
              { key: 'time', label: '最后时间', value: formatTraceTime(trace.last_seen) },
              { key: 'agent', label: 'Agent', value: traceLabel(trace.agent_id, '未绑定') },
              { key: 'session', label: '会话', value: traceLabel(trace.session_id) },
              { key: 'provider', label: 'Provider', value: traceLabel(trace.provider, '未调用') },
              { key: 'model', label: '模型', value: traceLabel(trace.model) },
              { key: 'policy', label: '主要策略', value: traceLabel(trace.primary_policy_id) },
              { key: 'risk', label: '最高风险', value: trace.risk_score ?? 0 },
              { key: 'receipt', label: '执行回执', value: trace.receipt_count ?? 0 },
              { key: 'request-hash', label: '请求 Hash', value: shortTraceHash(trace.request_hash) },
              { key: 'response-hash', label: '响应 Hash', value: shortTraceHash(trace.provider_response_hash) }
            ]}
          />

          <div>
            <Typography.Title level={5}>输入 → 模型 → 工具 → 执行</Typography.Title>
            <ol className="zh-traffic-timeline">
              {(trace.stages ?? []).map((stage, index) => (
                <li key={`${stage.audit_id || stage.stage}-${index}`}>
                  <span className="zh-traffic-timeline__icon" aria-hidden="true">
                    {stage.execution_receipt_present ? (
                      <CircleCheck size={16} />
                    ) : stage.provider_call_id ? (
                      <Wrench size={16} />
                    ) : CONTROLLED_DECISIONS.has(traceLabel(stage.decision)) ? (
                      <ShieldX size={16} />
                    ) : (
                      <Activity size={16} />
                    )}
                  </span>
                  <div>
                    <Flex justify="space-between" gap={8} wrap="wrap">
                      <div>
                        <Typography.Text strong>{stageLabel(stage.stage, index)}</Typography.Text>
                        <Typography.Text type="secondary" className="zh-meta-block">
                          {stageDescription(stage.stage, stage.provider_called)}
                        </Typography.Text>
                      </div>
                      <Typography.Text type="secondary">{formatTraceTime(stage.timestamp)}</Typography.Text>
                    </Flex>
                    <Space wrap size={[6, 4]}>
                      <LabelTag color={traceDecisionColor(traceLabel(stage.decision))}>
                        {traceLabel(stage.decision)}
                      </LabelTag>
                      {stage.policy_id ? <LabelTag>{stage.policy_id}</LabelTag> : null}
                      {stage.tool ? <LabelTag>{stage.tool}</LabelTag> : null}
                      {stage.execution_status ? <LabelTag>{stage.execution_status}</LabelTag> : null}
                    </Space>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

function stageLabel(stage: unknown, index: number) {
  const labels: Record<string, string> = {
    'pre-provider': '输入检查',
    'provider-response': '模型响应',
    'provider-failure': '模型调用失败',
    'tool-call': '工具调用',
    execution: '执行回执'
  };
  return labels[String(stage ?? '')] ?? `处置阶段 ${index + 1}`;
}

function stageDescription(stage: unknown, providerCalled: boolean | null | undefined) {
  if (stage === 'pre-provider') return '在内容到达模型前完成来源、策略与风险检查';
  if (stage === 'provider-response') return '记录真实 Provider 返回并检查输出';
  if (stage === 'provider-failure') return 'Provider 已尝试调用，但没有形成有效响应';
  if (stage === 'tool-call') return '对模型提出的工具、参数与权限再次决策';
  if (stage === 'execution') return '绑定服务端观察到的执行事实与回执';
  return providerCalled === false ? '在 Provider 调用前结束' : '记录网关处置证据';
}
