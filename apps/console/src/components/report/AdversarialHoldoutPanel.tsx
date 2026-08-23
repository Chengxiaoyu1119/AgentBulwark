import { Col, Row, Typography } from 'antd';
import type { AdversarialHoldout } from '@/types';
import { LabelTag, MetricCard as Metric, PanelCard, SectionTitle, UiTable } from '../ui';

export function AdversarialHoldoutPanel({ report }: { report: AdversarialHoldout }) {
  const summary = report.summary;
  return (
    <PanelCard
      title={
        <SectionTitle title="独立对抗留出集" meta={`${summary.sample_count} 条人工固定标签 / ${report.label_source}`} />
      }
      variant="borderless"
    >
      <Row gutter={[16, 16]} className="zh-mb-24">
        <Col xs={24} sm={12} lg={6}>
          <Metric label="攻击召回率" value={`${summary.attack_recall_rate}%`} tone="green" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="正常误报率" value={`${summary.benign_false_positive_rate}%`} tone="cyan" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="固定标签匹配率" value={`${summary.expected_match_rate}%`} tone="amber" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="漏检 / 误报" value={`${summary.false_negative} / ${summary.false_positive}`} tone="red" />
        </Col>
      </Row>
      <UiTable
        dataSource={report.records}
        rowKey="id"
        size="small"
        pagination={{ pageSize: 8 }}
        columns={[
          { title: '样本', dataIndex: 'id', render: (value) => <Typography.Text code>{value}</Typography.Text> },
          {
            title: '标签',
            dataIndex: 'label',
            render: (value) => (
              <LabelTag variant="filled" color={value === 'attack' ? 'error' : 'success'}>
                {value === 'attack' ? '攻击' : '正常'}
              </LabelTag>
            )
          },
          { title: '决策', dataIndex: 'decision' },
          { title: '策略', dataIndex: 'policy_id', render: (value) => <Typography.Text code>{value}</Typography.Text> },
          {
            title: '标签匹配',
            dataIndex: 'expected_match',
            render: (value) => (value ? '匹配' : '不匹配')
          }
        ]}
      />
    </PanelCard>
  );
}
