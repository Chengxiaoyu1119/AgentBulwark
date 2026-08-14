import { Col, Row, Space, Typography } from 'antd';
import { EvidenceCodeBlock, MetricCard as Metric, PanelCard, SectionTitle, UiBadge } from '../ui';
import type { ReportData } from '@/types';
import { ReportBriefingExportGallery } from './ReportBriefingExportGallery';
import { ReportDeliveryPackageGrid } from './ReportDeliveryPackageGrid';

type ReportDeliveryTabProps = {
  competitionPackage: ReportData['competition_package'];
  packageFiles: NonNullable<ReportData['competition_package']>['files'];
  markdown: string;
  copiedFile: string;
  copyPackageFile: (filename: string, content: string) => void | Promise<void>;
  downloadPackageFile: (filename: string, content: string, contentType: string) => void;
};

export function ReportDeliveryTab({
  competitionPackage,
  packageFiles,
  markdown,
  copiedFile,
  copyPackageFile,
  downloadPackageFile
}: ReportDeliveryTabProps) {
  return (
    <Space orientation="vertical" size="large" className="zh-tab-stack">
      <ReportBriefingExportGallery />
      {!competitionPackage && (
        <PanelCard title="成果交付材料包" variant="borderless">
          <Typography.Text type="secondary">
            交付材料快照尚未生成；管理员可调用 POST /api/deliverables/refresh 生成，报告概览与攻防评测不受影响。
          </Typography.Text>
        </PanelCard>
      )}
      {competitionPackage && (
        <PanelCard
          title={
            <SectionTitle
              title="成果交付材料包"
              meta={`${competitionPackage.summary.file_count} 份材料 / ${competitionPackage.summary.alert_count} 条告警证据`}
            />
          }
          variant="borderless"
        >
          <Row gutter={[16, 16]} className="zh-mb-24">
            <Col xs={24} sm={12} lg={6}>
              <Metric
                label="可复现攻击面"
                value={`${competitionPackage.summary.demo_ready_surface_count}/7`}
                tone="green"
              />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Metric label="材料文件" value={`${competitionPackage.summary.file_count}`} tone="cyan" />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Metric label="实验记录" value={`${competitionPackage.summary.run_count}`} tone="amber" />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Metric label="控制率" value={`${competitionPackage.summary.control_rate}%`} tone="red" />
            </Col>
          </Row>

          <ReportDeliveryPackageGrid
            packageFiles={packageFiles}
            copiedFile={copiedFile}
            copyPackageFile={copyPackageFile}
            downloadPackageFile={downloadPackageFile}
          />
        </PanelCard>
      )}
      {competitionPackage && (
        <PanelCard
          title={<SectionTitle title="功能目标逐条检查" meta={`${competitionPackage.checklist.length} 条验收项`} />}
          variant="borderless"
        >
          <div className="zh-column-stack">
            {competitionPackage.checklist.map((item, idx) => (
              <div key={idx} className="zh-checklist-item">
                <div className="zh-pt-2">
                  <UiBadge status={item.status === '满足' ? 'success' : 'processing'} text={item.status} />
                </div>
                <div className="zh-flex-spacer">
                  <div>
                    <Typography.Text strong>{item.requirement}</Typography.Text>
                  </div>
                  <div className="zh-mt-4">
                    <Typography.Text type="secondary">{item.evidence}</Typography.Text>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </PanelCard>
      )}
      {competitionPackage && (
        <PanelCard
          title={<SectionTitle title="OpenClaw / 通用智能体适配接口" meta="工具调用事件 -> 监督决策" />}
          variant="borderless"
        >
          <EvidenceCodeBlock>{JSON.stringify(competitionPackage.adapter_schema, null, 2)}</EvidenceCodeBlock>
        </PanelCard>
      )}
      <PanelCard title="Markdown 导出内容" variant="borderless">
        <EvidenceCodeBlock maxHeight="large">{markdown}</EvidenceCodeBlock>
      </PanelCard>
    </Space>
  );
}
