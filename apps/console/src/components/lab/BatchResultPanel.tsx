import { Col, Row, Space, Typography } from 'antd';
import type { BatchCompareResult, CompareResult } from '@/types';
import { DecisionPill, LabelTag, MetricCard as Metric, PanelCard, UiTable } from '../ui';

export function BatchResultPanel({ batch }: { batch: BatchCompareResult }) {
  const columns = [
    {
      title: '脚本',
      dataIndex: 'scenario_id',
      key: 'scenario_id',
      render: (text: string) => <Typography.Text strong>{text}</Typography.Text>
    },
    {
      title: '无防护',
      key: 'without_guard',
      render: (_value: unknown, record: CompareResult) => (
        <LabelTag color={record.without_guard.attack_success ? 'error' : 'default'}>
          {record.without_guard.attack_success ? '暴露' : '未暴露'}
        </LabelTag>
      )
    },
    {
      title: '有防护',
      key: 'with_guard',
      render: (_value: unknown, record: CompareResult) => (
        <LabelTag color={record.with_guard.attack_success ? 'error' : 'success'}>
          {record.with_guard.attack_success ? '仍成功' : '已控制'}
        </LabelTag>
      )
    },
    {
      title: '监督决策',
      key: 'decision',
      render: (_value: unknown, record: CompareResult) => {
        const dec = record.with_guard.audit_logs[0]?.decision ?? '未记录';
        return <DecisionPill decision={dec} />;
      }
    },
    {
      title: '延迟',
      key: 'latency',
      render: (_value: unknown, record: CompareResult) => (
        <Typography.Text>{record.with_guard.metrics.detection_latency_ms}ms</Typography.Text>
      )
    }
  ];

  return (
    <PanelCard
      type="inner"
      title={
        <Space orientation="vertical" size={0}>
          <Typography.Text strong>批量对比结果</Typography.Text>
          <Typography.Text type="secondary" className="zh-text-meta">
            {batch.summary.total} 个脚本 · 控制率 {batch.summary.control_rate}%
          </Typography.Text>
        </Space>
      }
      className="zh-mt-24"
    >
      <Row gutter={[16, 16]} className="zh-mb-24" align="stretch">
        <Col xs={12} md={6}>
          <Metric label="无防护暴露" value={`${batch.summary.exposed_without_guard}`} tone="red" />
        </Col>
        <Col xs={12} md={6}>
          <Metric label="有防护控制" value={`${batch.summary.controlled_with_guard}`} tone="green" />
        </Col>
        <Col xs={12} md={6}>
          <Metric label="攻击下降" value={`${batch.summary.attack_success_reduced}`} tone="cyan" />
        </Col>
        <Col xs={12} md={6}>
          <Metric label="平均延迟" value={`${batch.summary.avg_latency_ms}ms`} tone="amber" />
        </Col>
      </Row>
      <UiTable
        dataSource={batch.comparisons}
        columns={columns}
        rowKey="scenario_id"
        pagination={false}
        size="small"
        bordered
      />
      <Typography.Paragraph type="secondary" className="zh-note-text">
        * 批量运行会写入实验日志；需要复核或交付时，再到“证据导出（按需）”生成固定证据。
      </Typography.Paragraph>
    </PanelCard>
  );
}
