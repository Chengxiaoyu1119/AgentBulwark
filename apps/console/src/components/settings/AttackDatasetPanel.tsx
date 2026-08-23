import { useMemo, useState } from 'react';
import { Col, Row, Space, Typography } from 'antd';
import type { AttackCaseDataset, Overview } from '@/types';
import { LabelTag, MetricCard as Metric, PanelCard, UiButton, UiSelect } from '../ui';

interface AttackDatasetPanelProps {
  overview: Overview;
  attackDataset: AttackCaseDataset | null;
}

export function AttackDatasetPanel({ overview, attackDataset }: AttackDatasetPanelProps) {
  const [selectedSurfaceId, setSelectedSurfaceId] = useState(overview.attack_surfaces[0]?.id ?? '');
  const surfaceOptions = useMemo(
    () => overview.attack_surfaces.map((surface) => ({ label: surface.name, value: surface.id })),
    [overview.attack_surfaces]
  );
  const exportUrl = selectedSurfaceId
    ? `/api/datasets/attack_cases?surface_id=${encodeURIComponent(selectedSurfaceId)}`
    : '/api/datasets/attack_cases';

  return (
    <PanelCard title="攻击样本数据集" type="inner">
      <Row gutter={[16, 16]} className="zh-mb-24">
        <Col xs={12} sm={8} md={4}>
          <Metric label="攻击面" value={`${attackDataset?.summary.surface_count ?? overview.summary.surface_count}`} />
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Metric label="脚本" value={`${attackDataset?.summary.scenario_count ?? overview.summary.scenario_count}`} />
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Metric
            label="对抗样本"
            value={`${attackDataset?.summary.adversarial_sample_count ?? overview.summary.scenario_count}`}
          />
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Metric
            label="越狱用例"
            value={`${attackDataset?.summary.jailbreak_case_count ?? overview.summary.scenario_count}`}
          />
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Metric label="复现入口" value={`${attackDataset?.summary.replay_recipe_count ?? '-'}`} />
        </Col>
        <Col xs={12} sm={8} md={4}>
          <Metric label="工具调用" value={`${attackDataset?.summary.tool_call_count ?? '-'}`} />
        </Col>
      </Row>
      <Space className="zh-mb-24" wrap>
        <UiButton authenticatedHref="/api/datasets/attack_cases" type="link" className="zh-settings-link-flush">
          查看 JSON
        </UiButton>
        <UiButton authenticatedHref="/api/datasets/attack_cases.md" type="link">
          查看 Markdown
        </UiButton>
        <LabelTag variant="filled" className="zh-settings-code-tag">
          npm run cli -- samples --format json
        </LabelTag>
      </Space>
      <div>
        <Typography.Text strong className="zh-settings-field-title">
          按攻击面筛选
        </Typography.Text>
        <Typography.Text type="secondary" className="zh-meta-block zh-mb-8">
          这里读取后端生成的数据集接口，筛选后可直接打开对应攻击面的样本、越狱用例和工具调用复现入口。
        </Typography.Text>
        <Space.Compact block className="zh-settings-filter-row">
          <UiSelect
            value={selectedSurfaceId}
            onChange={setSelectedSurfaceId}
            options={surfaceOptions}
            className="zh-settings-dataset-surface-select"
            disabled={surfaceOptions.length === 0}
          />
          <UiButton authenticatedHref={exportUrl} disabled={surfaceOptions.length === 0}>
            打开筛选数据
          </UiButton>
        </Space.Compact>
      </div>
    </PanelCard>
  );
}
