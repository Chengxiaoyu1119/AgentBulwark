import { Drawer, Flex, Space, Typography } from 'antd';
import { Activity, CircleCheck, ShieldX, Wrench } from 'lucide-react';
import { LabelTag, MetaGrid } from '../ui';
import {
  CONTROLLED_DECISIONS,
  formatTraceTime,
  gatewayRequestId,
  shortTraceHash,
  traceDecisionColor,
  traceLabel,
  type GatewayTrace
} from './gatewayTraceModel';

export function GatewayTraceDetails({ trace, onClose }: { trace: GatewayTrace | null; onClose: () => void }) {
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
            <Typography.Title level={5}>处置时间线</Typography.Title>
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
                      <Typography.Text strong>{traceLabel(stage.stage, `阶段 ${index + 1}`)}</Typography.Text>
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
