import { Col, Row, Space, Typography } from 'antd';
import { Play, ScrollText, TerminalSquare } from 'lucide-react';
import type { DemoDrillResult } from '@/types';
import { DecisionPill, LabelTag, MetricCard as Metric, PanelCard, UiAlert, UiButton, UiFieldLabel } from '../ui';

interface DemoDrillPanelProps {
  demoDrill: DemoDrillResult | null;
  runningDemoDrill: boolean;
  handleRunDemoDrill: () => void | Promise<void>;
}

export function DemoDrillPanel({ demoDrill, runningDemoDrill, handleRunDemoDrill }: DemoDrillPanelProps) {
  return (
    <PanelCard
      title="闭环复现实验"
      extra={
        <UiButton type="primary" icon={<Play size={16} />} onClick={handleRunDemoDrill} loading={runningDemoDrill}>
          运行闭环复现
        </UiButton>
      }
      type="inner"
    >
      <Typography.Paragraph type="secondary">
        按顺序执行正常放行、外发复核、批量导出审批和记忆隔离，自动生成 audit_hash、review_hash 与本地证据文件。
      </Typography.Paragraph>
      <Space className="zh-settings-action-row" wrap>
        <UiButton authenticatedHref="/api/demo_drill">查看最近 JSON</UiButton>
        <UiButton authenticatedHref="/api/demo_drill.md">查看最近 Markdown</UiButton>
        <LabelTag variant="filled" className="zh-settings-code-tag">
          POST /api/demo_drill/run
        </LabelTag>
      </Space>
      {demoDrill && demoDrill.summary.stage_count > 0 ? (
        <>
          <Row gutter={[16, 16]} className="zh-mb-24">
            <Col xs={12} sm={8} md={4}>
              <Metric label="复现步骤" value={`${demoDrill.summary.stage_count}`} />
            </Col>
            <Col xs={12} sm={8} md={4}>
              <Metric label="监督控制" value={`${demoDrill.summary.controlled_count}`} tone="green" />
            </Col>
            <Col xs={12} sm={8} md={4}>
              <Metric label="人工批准" value={`${demoDrill.summary.approved_count}`} tone="cyan" />
            </Col>
            <Col xs={12} sm={8} md={4}>
              <Metric label="人工驳回" value={`${demoDrill.summary.rejected_count}`} tone="red" />
            </Col>
            <Col xs={12} sm={8} md={4}>
              <Metric label="审计 hash" value={`${demoDrill.summary.audit_hash_count}`} />
            </Col>
            <Col xs={12} sm={8} md={4}>
              <Metric label="复核 hash" value={`${demoDrill.summary.review_hash_count}`} />
            </Col>
          </Row>
          <div className="zh-column-stack">
            {demoDrill.stages.map((stage) => (
              <div key={stage.index} className="zh-settings-record">
                <Row className="zh-settings-row-full" align="middle" gutter={[16, 16]}>
                  <Col xs={4} md={2}>
                    <Typography.Text strong className="zh-settings-record-index">
                      {String(stage.index).padStart(2, '0')}
                    </Typography.Text>
                  </Col>
                  <Col xs={20} md={8}>
                    <Typography.Text strong className="zh-settings-record-title">
                      {stage.title}
                    </Typography.Text>
                    <Typography.Text
                      type="secondary"
                      className="zh-settings-record-title zh-settings-endpoint-description"
                    >
                      {stage.objective}
                    </Typography.Text>
                    <Typography.Text type="secondary" className="zh-settings-meta-sm">
                      {stage.reason}
                    </Typography.Text>
                  </Col>
                  <Col xs={24} md={6}>
                    <Space orientation="vertical" size={2}>
                      <LabelTag variant="filled" className="zh-settings-tag-flush">
                        {stage.tool}
                      </LabelTag>
                      <Typography.Text type="secondary" className="zh-settings-meta-sm">
                        策略: {stage.policy_id}
                      </Typography.Text>
                    </Space>
                  </Col>
                  <Col xs={12} md={4}>
                    <Space orientation="vertical" size={2}>
                      <DecisionPill decision={stage.decision} />
                      <UiFieldLabel>复核: {stage.approval_action_label}</UiFieldLabel>
                    </Space>
                  </Col>
                  <Col xs={12} md={4}>
                    <Space orientation="vertical" size={2}>
                      <UiFieldLabel>audit: {stage.audit_hash?.slice(0, 14) ?? '-'}</UiFieldLabel>
                      <UiFieldLabel>review: {stage.review_hash?.slice(0, 14) ?? '-'}</UiFieldLabel>
                    </Space>
                  </Col>
                </Row>
              </div>
            ))}
          </div>
          <Space className="zh-settings-path-list" wrap>
            <UiButton size="small" authenticatedHref="/api/demo_drill.md">
              打开证据报告
            </UiButton>
            <UiButton size="small" authenticatedHref="/api/demo_drill">
              打开证据 JSON
            </UiButton>
            <LabelTag variant="filled" icon={<ScrollText size={14} />} className="zh-settings-path-tag">
              {demoDrill.markdown_path}
            </LabelTag>
            <LabelTag variant="filled" icon={<TerminalSquare size={14} />} className="zh-settings-path-tag">
              {demoDrill.json_path}
            </LabelTag>
          </Space>
        </>
      ) : (
        <UiAlert
          title="还没有运行闭环复现实验。点击按钮后会生成 4 步运行记录、审计证据和本地报告。"
          type="info"
          showIcon
        />
      )}
    </PanelCard>
  );
}
