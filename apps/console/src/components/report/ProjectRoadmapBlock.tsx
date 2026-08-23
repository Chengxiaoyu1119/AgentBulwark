import { useMemo, useState } from 'react';
import { ExternalLink, ListChecks } from 'lucide-react';
import { Col, Row, Space, Typography } from 'antd';
import { LabelTag, MetricCard as Metric, PanelCard, UiButton, UiProgress } from '../ui';
import type { PageKey } from '@/app/navigation';
import type { ProjectRoadmap } from '@/types';

function roadmapAction(id: string): { label: string; page: PageKey } {
  if (id === 'real-agent-gateway-e2e' || id === 'one-command-run') {
    return { label: '进入设置验收', page: 'settings' };
  }
  if (id === 'multi-model-eval') {
    return { label: '进入模型实验台', page: 'lab' };
  }
  return { label: '查看报告证据', page: 'report' };
}

export function ProjectRoadmapBlock({
  roadmap,
  onOpenPage
}: {
  roadmap: ProjectRoadmap;
  onOpenPage?: (page: PageKey) => void;
}) {
  const [showAllDimensions, setShowAllDimensions] = useState(false);
  const [showAllBacklog, setShowAllBacklog] = useState(false);
  const pendingDimensions = roadmap.dimensions.filter((item) => item.status !== '已完成');
  const pendingBacklog = roadmap.feature_backlog.filter((item) => item.status !== '已完成');
  const backlogIsPending = pendingBacklog.length > 0;
  const dimensionLimit = 5;
  const backlogLimit = 5;
  const visibleDimensions = showAllDimensions ? roadmap.dimensions : roadmap.dimensions.slice(0, dimensionLimit);
  const backlogSource = backlogIsPending ? pendingBacklog : roadmap.feature_backlog;
  const visibleBacklog = showAllBacklog ? backlogSource : backlogSource.slice(0, backlogLimit);
  const completionHint = useMemo(() => {
    if (!pendingDimensions.length && !pendingBacklog.length)
      return '当前报告判断为已闭环，建议复核前重新补跑一次证据。';
    return `仍有 ${pendingDimensions.length} 个成熟度维度或 ${pendingBacklog.length} 个功能闭环需要复核。`;
  }, [pendingBacklog.length, pendingDimensions.length]);

  return (
    <PanelCard variant="borderless" className="zh-mb-24">
      <div className="zh-section-surface">
        <Row align="middle" gutter={[20, 12]}>
          <Col xs={24} md={18}>
            <Typography.Text type="secondary" className="zh-meta-block">
              项目方向判断
            </Typography.Text>
            <Typography.Title level={3} className="zh-title-flush zh-mb-8 zh-roadmap-verdict-title">
              {roadmap.direction.verdict}
            </Typography.Title>
            <Typography.Paragraph type="secondary" className="zh-title-flush">
              {roadmap.direction.reason}
            </Typography.Paragraph>
            <Space size={8} wrap className="zh-mt-16">
              <LabelTag color="success">90+ 已完成</LabelTag>
              <LabelTag color="warning">65-89 需完善</LabelTag>
              <LabelTag color="error">低于 65 高优先级缺口</LabelTag>
            </Space>
          </Col>
          <Col xs={24} md={6} className="zh-text-right zh-roadmap-score-col">
            <Typography.Title level={1} className="zh-title-flush zh-color-primary">
              {roadmap.summary.overall_score}%
            </Typography.Title>
            <Typography.Text type="secondary" className="zh-text-meta">
              综合成熟度
            </Typography.Text>
          </Col>
        </Row>
      </div>

      <Row gutter={[16, 16]} className="zh-mb-32">
        <Col xs={24} sm={12} lg={6}>
          <Metric
            label="已完成维度"
            value={`${roadmap.summary.completed_count}/${roadmap.summary.dimension_count}`}
            tone="green"
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="高优先级缺口" value={`${roadmap.summary.high_priority_gap_count}`} tone="red" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="P0 待办" value={`${roadmap.summary.p0_backlog_count}`} tone="amber" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="方向匹配" value={`${roadmap.direction.competition_fit}%`} tone="cyan" />
        </Col>
      </Row>

      <div className="zh-roadmap-evidence-toolbar zh-mb-24">
        <div>
          <Typography.Text strong>路线图证据入口</Typography.Text>
          <Typography.Text type="secondary" className="zh-text-block zh-mt-4">
            {completionHint}
          </Typography.Text>
        </div>
        <Space wrap className="zh-roadmap-evidence-actions">
          <UiButton authenticatedHref="/api/project_roadmap.md" icon={<ExternalLink size={15} />}>
            打开 Markdown
          </UiButton>
          <UiButton authenticatedHref="/api/project_roadmap" icon={<ExternalLink size={15} />}>
            打开 JSON
          </UiButton>
        </Space>
      </div>

      <Row gutter={[24, 24]}>
        <Col xs={24} lg={12}>
          <div className="zh-roadmap-section-head">
            <div>
              <Typography.Title level={5} className="zh-title-flush">
                成熟度维度 ({roadmap.dimensions.length} 项)
              </Typography.Title>
              <Typography.Text type="secondary" className="zh-text-meta">
                当前显示 {visibleDimensions.length}/{roadmap.dimensions.length} 项
              </Typography.Text>
            </div>
            {roadmap.dimensions.length > dimensionLimit && (
              <UiButton size="small" onClick={() => setShowAllDimensions((value) => !value)}>
                {showAllDimensions ? '收起' : '查看全部'}
              </UiButton>
            )}
          </div>
          <Space orientation="vertical" className="zh-full-width">
            {visibleDimensions.map((item) => (
              <PanelCard key={item.name} size="small" type="inner" className="zh-roadmap-dimension-card">
                <div className="zh-split-row zh-mb-8">
                  <Typography.Text strong>{item.name}</Typography.Text>
                  <LabelTag
                    color={item.status === '已完成' ? 'success' : item.status === '高优先级缺口' ? 'error' : 'warning'}
                  >
                    {item.status}
                  </LabelTag>
                </div>
                <UiProgress
                  percent={Math.min(100, Math.max(0, item.score))}
                  size="small"
                  strokeColor={
                    item.status === '已完成'
                      ? 'var(--ant-color-success)'
                      : item.status === '高优先级缺口'
                        ? 'var(--ant-color-error)'
                        : 'var(--ant-color-warning)'
                  }
                />
                <Typography.Text type="secondary" className="zh-text-body zh-mt-8 zh-text-block zh-line-clamp-2">
                  {item.evidence}
                </Typography.Text>
                {item.next_actions.length ? (
                  <div className="zh-roadmap-next-actions">
                    <ListChecks size={14} />
                    <Typography.Text type="secondary" className="zh-text-meta zh-line-clamp-2">
                      下一步：{item.next_actions.join('；')}
                    </Typography.Text>
                  </div>
                ) : null}
              </PanelCard>
            ))}
          </Space>
        </Col>
        <Col xs={24} lg={12}>
          <div className="zh-roadmap-section-head">
            <div>
              <Typography.Title level={5} className="zh-title-flush">
                {backlogIsPending ? '待补功能优先级' : '核心功能闭环'} (
                {backlogIsPending ? pendingBacklog.length : roadmap.feature_backlog.length} 项)
              </Typography.Title>
              <Typography.Text type="secondary" className="zh-text-meta">
                当前显示 {visibleBacklog.length}/{backlogSource.length} 项
              </Typography.Text>
            </div>
            {backlogSource.length > backlogLimit && (
              <UiButton size="small" onClick={() => setShowAllBacklog((value) => !value)}>
                {showAllBacklog ? '收起' : '查看全部'}
              </UiButton>
            )}
          </div>
          <Space orientation="vertical" className="zh-full-width">
            {visibleBacklog.map((item) => (
              <PanelCard
                key={item.id}
                size="small"
                type="inner"
                className={
                  !backlogIsPending
                    ? 'zh-roadmap-card--done zh-roadmap-backlog-card'
                    : item.priority === 'P0'
                      ? 'zh-roadmap-card--p0 zh-roadmap-backlog-card'
                      : item.priority === 'P1'
                        ? 'zh-roadmap-card--p1 zh-roadmap-backlog-card'
                        : 'zh-roadmap-card--p2 zh-roadmap-backlog-card'
                }
              >
                <div className="zh-split-row zh-mb-4">
                  <Typography.Text strong>{item.title}</Typography.Text>
                  <Space size={6}>
                    <LabelTag color={item.status === '已完成' ? 'success' : 'default'}>{item.status}</LabelTag>
                    {backlogIsPending && (
                      <LabelTag
                        color={item.priority === 'P0' ? 'error' : item.priority === 'P1' ? 'warning' : 'default'}
                      >
                        {item.priority}
                      </LabelTag>
                    )}
                  </Space>
                </div>
                <Typography.Paragraph type="secondary" className="zh-text-body zh-my-8 zh-line-clamp-2">
                  {item.why}
                </Typography.Paragraph>
                <Typography.Text type="secondary" className="zh-text-meta zh-line-clamp-2">
                  {backlogIsPending ? '验收标准' : '已闭环能力'}: {item.acceptance}
                </Typography.Text>
                {onOpenPage ? (
                  <div className="zh-roadmap-card-actions">
                    <UiButton
                      size="small"
                      type="link"
                      onClick={() => {
                        onOpenPage(roadmapAction(item.id).page);
                      }}
                    >
                      {roadmapAction(item.id).label}
                    </UiButton>
                  </div>
                ) : null}
              </PanelCard>
            ))}
          </Space>
        </Col>
      </Row>

      {(roadmap.next_sprint.length || roadmap.risk_register.length) && (
        <Row gutter={[16, 16]} className="zh-mt-24">
          <Col xs={24} lg={12}>
            <PanelCard title="下一轮优先动作" type="inner" className="zh-full-height">
              <Space orientation="vertical" className="zh-full-width">
                {roadmap.next_sprint.length ? (
                  roadmap.next_sprint.map((item) => (
                    <div key={item.id} className="zh-roadmap-compact-item">
                      <LabelTag color={item.priority === 'P0' ? 'error' : 'warning'}>{item.priority}</LabelTag>
                      <div>
                        <Typography.Text strong>{item.title}</Typography.Text>
                        <Typography.Text type="secondary" className="zh-text-block zh-mt-4">
                          {item.acceptance}
                        </Typography.Text>
                      </div>
                    </div>
                  ))
                ) : (
                  <Typography.Text type="secondary">当前没有 P0 待办，保持证据可复跑即可。</Typography.Text>
                )}
              </Space>
            </PanelCard>
          </Col>
          <Col xs={24} lg={12}>
            <PanelCard title="风险登记" type="inner" className="zh-full-height">
              <Space orientation="vertical" className="zh-full-width">
                {roadmap.risk_register.map((item) => (
                  <div key={item.risk} className="zh-roadmap-risk-item">
                    <Typography.Text strong>{item.risk}</Typography.Text>
                    <Typography.Text type="secondary" className="zh-text-block">
                      影响：{item.impact}
                    </Typography.Text>
                    <Typography.Text type="secondary" className="zh-text-block">
                      缓解：{item.mitigation}
                    </Typography.Text>
                  </div>
                ))}
              </Space>
            </PanelCard>
          </Col>
        </Row>
      )}
    </PanelCard>
  );
}
