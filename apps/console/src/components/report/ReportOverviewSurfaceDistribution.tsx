import { Col, Flex, Row, Space, Typography } from 'antd';
import { ArrowRight, ExternalLink } from 'lucide-react';
import type { PageKey } from '@/app/navigation';
import type { ReportData } from '@/types';
import { riskLabel } from '@/utils';
import { LabelTag, PanelCard, SectionTitle, UiButton, UiProgress } from '../ui';

type ReportOverviewSurfaceDistributionProps = {
  report: ReportData;
  onOpenPage?: (page: PageKey) => void;
};

export function ReportOverviewSurfaceDistribution({ report, onOpenPage }: ReportOverviewSurfaceDistributionProps) {
  const maxCount = Math.max(1, ...report.surface_coverage.map((item) => item.scenario_count));
  const readyCount = report.surface_coverage.filter((item) => item.demo_ready).length;
  const highRiskCount = report.surface_coverage.filter((item) => ['critical', 'high'].includes(item.risk)).length;
  const sampleCount = report.surface_coverage.reduce((sum, item) => sum + item.samples, 0);

  return (
    <PanelCard
      title={<SectionTitle title="攻击面脚本分布" meta={`${readyCount}/7 类可复现`} />}
      variant="borderless"
      className="zh-full-height"
    >
      <div className="zh-report-surface-summary">
        <div>
          <Typography.Text strong>攻击面运行入口</Typography.Text>
          <Typography.Text type="secondary" className="zh-text-block zh-mt-4">
            选择攻击面后可运行脚本、生成审计日志，并同步更新报告证据。
          </Typography.Text>
        </div>
        <Space wrap className="zh-report-surface-actions">
          <UiButton
            size="small"
            icon={<ArrowRight size={14} />}
            onClick={() => {
              onOpenPage?.('dashboard');
            }}
          >
            进入攻击面工作台
          </UiButton>
          <UiButton
            size="small"
            authenticatedHref="/api/attack_surfaces/evidence_packs.md"
            icon={<ExternalLink size={14} />}
          >
            打开证据索引
          </UiButton>
        </Space>
      </div>

      <Row gutter={[12, 12]} className="zh-report-surface-kpis">
        <Col xs={8}>
          <div className="zh-report-mini-kpi">
            <Typography.Text type="secondary">样本</Typography.Text>
            <Typography.Text strong>{sampleCount}</Typography.Text>
          </div>
        </Col>
        <Col xs={8}>
          <div className="zh-report-mini-kpi">
            <Typography.Text type="secondary">高风险</Typography.Text>
            <Typography.Text strong>{highRiskCount}</Typography.Text>
          </div>
        </Col>
        <Col xs={8}>
          <div className="zh-report-mini-kpi">
            <Typography.Text type="secondary">脚本</Typography.Text>
            <Typography.Text strong>{report.summary.scenario_count}</Typography.Text>
          </div>
        </Col>
      </Row>

      <div className="zh-report-surface-list">
        {report.surface_coverage.map((surface) => (
          <div key={surface.id} className="zh-report-surface-row">
            <Flex justify="space-between" align="center" gap={12}>
              <Space size={8} wrap>
                <Typography.Text strong>{surface.name}</Typography.Text>
                <LabelTag variant="filled" color={surface.demo_ready ? 'success' : 'warning'}>
                  {surface.demo_ready ? '可复现' : '待补证据'}
                </LabelTag>
                <LabelTag variant="filled" color={surface.risk === 'critical' ? 'error' : 'default'}>
                  {riskLabel[surface.risk]}
                </LabelTag>
              </Space>
              <Typography.Text strong>{surface.scenario_count}</Typography.Text>
            </Flex>
            <UiProgress
              percent={Math.max(2, Math.round((surface.scenario_count / maxCount) * 100))}
              showInfo={false}
              strokeColor={surface.demo_ready ? 'var(--ant-color-primary)' : 'var(--ant-color-warning)'}
              size="small"
            />
          </div>
        ))}
      </div>
    </PanelCard>
  );
}
