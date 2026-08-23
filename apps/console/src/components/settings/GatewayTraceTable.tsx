import { Space, Typography, type TableColumnsType } from 'antd';
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
  const columns: TableColumnsType<GatewayTrace> = [
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
      title: 'Agent / 会话',
      key: 'agent',
      width: 180,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text>{traceLabel(trace.agent_id, '未绑定 Agent')}</Typography.Text>
          <Typography.Text type="secondary" ellipsis>
            {traceLabel(trace.session_id, '无会话')}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: 'Provider / 模型',
      key: 'provider',
      width: 180,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text>
            {traceLabel(trace.provider, trace.provider_called === false ? 'Provider 前阻断' : '未知')}
          </Typography.Text>
          <Typography.Text type="secondary" ellipsis>
            {traceLabel(trace.model)}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '处置',
      dataIndex: 'decision',
      width: 92,
      render: (value) => <LabelTag color={traceDecisionColor(traceLabel(value))}>{traceLabel(value)}</LabelTag>
    },
    {
      title: '风险 / 策略',
      key: 'risk',
      width: 160,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text strong className="zh-tabular-nums">
            {trace.risk_score ?? 0}
          </Typography.Text>
          <Typography.Text type="secondary" ellipsis>
            {traceLabel(trace.primary_policy_id, '未命中策略')}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '执行证据',
      key: 'evidence',
      width: 150,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text>{trace.tool_call_stage_count ?? 0} 个 Tool Call</Typography.Text>
          <Typography.Text type="secondary">{trace.receipt_count ?? 0} 个回执</Typography.Text>
        </Space>
      )
    }
  ];

  return (
    <UiTable<GatewayTrace>
      rowKey={(trace) => gatewayRequestId(trace)}
      columns={columns}
      dataSource={traces}
      size="small"
      pagination={{ pageSize: 10, showSizeChanger: false }}
      scroll={{ x: 990 }}
    />
  );
}
