import { UiTypography, type UiTableColumnsType } from '../ui';
import { LabelTag, UiTable } from '../ui';
import {
  formatTraceTime,
  gatewayRequestId,
  traceDecisionColor,
  traceLabel,
  type GatewayTrace
} from './gatewayTraceModel';

export function GatewayTraceTable({
  traces,
  onOpen
}: {
  traces: GatewayTrace[];
  onOpen: (trace: GatewayTrace) => void;
}) {
  const columns: UiTableColumnsType<GatewayTrace> = [
    {
      title: '时间 / 请求',
      key: 'request',
      width: 230,
      render: (_, trace) => (
        <button type="button" className="zh-traffic-request-link" onClick={() => onOpen(trace)}>
          <span>{formatTraceTime(trace.last_seen)}</span>
          <strong>{gatewayRequestId(trace) || 'unknown-request'}</strong>
        </button>
      )
    },
    {
      title: '处置',
      dataIndex: 'decision',
      width: 92,
      render: (value) => <LabelTag color={traceDecisionColor(traceLabel(value))}>{traceLabel(value)}</LabelTag>
    },
    {
      title: 'Agent / 会话',
      key: 'agent',
      width: 180,
      render: (_, trace) => {
        const agent = traceLabel(trace.agent_id, '未绑定 Agent');
        const session = traceLabel(trace.session_id, '无会话');
        return (
          <div className="zh-traffic-cell-stack">
            <UiTypography.Text ellipsis title={agent}>
              {agent}
            </UiTypography.Text>
            <UiTypography.Text type="secondary" ellipsis title={session}>
              {session}
            </UiTypography.Text>
          </div>
        );
      }
    },
    {
      title: 'Provider / 模型',
      key: 'provider',
      width: 180,
      render: (_, trace) => {
        const provider = traceLabel(trace.provider, trace.provider_called === false ? 'Provider 前阻断' : '未知');
        const model = traceLabel(trace.model);
        return (
          <div className="zh-traffic-cell-stack">
            <UiTypography.Text ellipsis title={provider}>
              {provider}
            </UiTypography.Text>
            <UiTypography.Text type="secondary" ellipsis title={model}>
              {model}
            </UiTypography.Text>
          </div>
        );
      }
    },
    {
      title: '风险 / 策略',
      key: 'risk',
      width: 160,
      render: (_, trace) => {
        const policy = traceLabel(trace.primary_policy_id, '未命中策略');
        return (
          <div className="zh-traffic-cell-stack">
            <UiTypography.Text strong className="zh-tabular-nums">
              {trace.risk_score ?? 0}
            </UiTypography.Text>
            <UiTypography.Text type="secondary" ellipsis title={policy}>
              {policy}
            </UiTypography.Text>
          </div>
        );
      }
    },
    {
      title: '执行证据',
      key: 'evidence',
      width: 150,
      render: (_, trace) => (
        <div className="zh-traffic-cell-stack">
          <UiTypography.Text>{trace.tool_call_stage_count ?? 0} 个 Tool Call</UiTypography.Text>
          <UiTypography.Text type="secondary">{trace.receipt_count ?? 0} 个回执</UiTypography.Text>
        </div>
      )
    }
  ];

  return (
    <UiTable<GatewayTrace>
      rowKey={(trace) => gatewayRequestId(trace)}
      columns={columns}
      dataSource={traces}
      size="small"
      tableLayout="fixed"
      pagination={{ pageSize: 10, showSizeChanger: false }}
      scroll={{ x: 990 }}
    />
  );
}
