import { Col, Divider, Flex, Row, Space, Statistic, Typography } from 'antd';
import { Activity, ArrowRight, Bot, CircleCheck, CircleX, Play, ShieldCheck, TerminalSquare } from 'lucide-react';
import { ActionRow, MetricCard as Metric, PanelCard, UiButton } from '../ui';
import type { AlertItem, Overview } from '@/types';
import { DashboardAgentNode } from './DashboardAgentNode';
import type { PageKey } from '@/app/navigation';

type DashboardPipelineNode = {
  label: string;
  value: string;
};

type DashboardOverviewTabProps = {
  overview: Overview;
  apiAvailable: boolean | null;
  maxRiskScore: number;
  latestAlert?: AlertItem;
  gatewayAuditCount: number;
  gatewayControlRate: number | null;
  gatewayPendingReceiptCount: number;
  pipelineNodes: DashboardPipelineNode[];
  onOpenPage: (page: PageKey) => void;
};

export function DashboardOverviewTab({
  overview,
  apiAvailable,
  maxRiskScore,
  latestAlert,
  gatewayAuditCount,
  gatewayControlRate,
  gatewayPendingReceiptCount,
  pipelineNodes,
  onOpenPage
}: DashboardOverviewTabProps) {
  const configuredModelCount = overview.models.filter((model) => model.configured && model.mode === 'real-api').length;

  return (
    <div className="zh-page-stack zh-mt-8">
      <Row gutter={[24, 24]}>
        <Col span={24}>
          <PanelCard variant="borderless" bodyPadding={32}>
            <Flex justify="space-between" align="center" wrap="wrap" gap={24}>
              <div className="zh-dashboard-hero-copy">
                <Typography.Text type="secondary">AI Agent 运行时安全网关</Typography.Text>
                <Typography.Title level={1} className="zh-title-compact">
                  看见每次工具调用，在产生副作用前做出控制
                </Typography.Title>
                <Typography.Paragraph type="secondary" className="zh-text-lead">
                  把工具调用送入执行前闸门，返回允许、拒绝、审批或隔离决策；执行后再用回执确认动作是否真正发生。
                </Typography.Paragraph>
                <ActionRow>
                  <UiButton
                    type="primary"
                    size="large"
                    icon={<ShieldCheck size={16} />}
                    onClick={() => onOpenPage('gateway')}
                  >
                    打开 LLM API / MCP 网关
                  </UiButton>
                  <UiButton size="large" icon={<TerminalSquare size={16} />} onClick={() => onOpenPage('audit')}>
                    处理事件与复核
                  </UiButton>
                </ActionRow>
              </div>
              <div className="zh-dashboard-metric-row">
                <PanelCard variant="borderless" className="zh-dashboard-metric-panel zh-dashboard-metric-panel--risk">
                  <Typography.Text type="secondary">最高风险分</Typography.Text>
                  <Typography.Title level={2} className="zh-title-flush zh-color-error">
                    {maxRiskScore}
                  </Typography.Title>
                  <Typography.Text type="secondary" className="zh-text-meta">
                    {latestAlert ? latestAlert.title : '当前没有高风险事件'}
                  </Typography.Text>
                </PanelCard>
                <PanelCard
                  variant="borderless"
                  className="zh-dashboard-metric-panel zh-dashboard-metric-panel--control"
                >
                  <Typography.Text type="secondary">网关受控比例</Typography.Text>
                  <Typography.Title level={2} className="zh-title-flush zh-color-success">
                    {gatewayControlRate === null ? '—' : `${gatewayControlRate}%`}
                  </Typography.Title>
                  <Typography.Text type="secondary" className="zh-text-meta">
                    {gatewayAuditCount ? `${gatewayAuditCount} 条网关阶段证据` : '暂无真实网关阶段证据'}
                  </Typography.Text>
                </PanelCard>
              </div>
            </Flex>
          </PanelCard>
        </Col>
      </Row>

      <PanelCard variant="borderless">
        <Row gutter={[16, 16]} align="middle" justify="start">
          {pipelineNodes.map((node, index) => (
            <Col xs={12} sm={8} md={4} key={node.label}>
              <Statistic
                title={
                  <span>
                    <span className="zh-color-primary zh-mr-8">{String(index + 1).padStart(2, '0')}</span>
                    {node.label}
                  </span>
                }
                value={node.value}
              />
            </Col>
          ))}
        </Row>
      </PanelCard>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={6}>
          <Metric
            label="服务状态"
            value={apiAvailable ? '在线' : apiAvailable === false ? '离线' : '检查中'}
            tone={apiAvailable ? 'green' : 'red'}
          />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Metric
            label="待处理事件"
            value={`${overview.alerts.length}`}
            tone={overview.alerts.length ? 'red' : 'green'}
          />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Metric
            label="待确认网关回执"
            value={`${gatewayPendingReceiptCount}`}
            tone={gatewayPendingReceiptCount ? 'amber' : 'green'}
          />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Metric
            label="真实模型连接"
            value={`${configuredModelCount}/${overview.models.length}`}
            tone={configuredModelCount ? 'cyan' : 'amber'}
          />
        </Col>
      </Row>

      <Row gutter={[24, 24]}>
        <Col xs={24} md={14}>
          <PanelCard
            title={
              <Space>
                <ShieldCheck size={18} color="var(--ant-color-primary)" />
                <Typography.Text strong>一次调用如何被控制</Typography.Text>
              </Space>
            }
            variant="borderless"
            className="zh-full-height"
            extra={
              <UiButton type="link" onClick={() => onOpenPage('gateway')}>
                查看网关
              </UiButton>
            }
          >
            <div className="zh-soft-block">
              <Typography.Text type="secondary" className="zh-text-meta zh-mb-12 zh-text-block">
                业务 Agent 发起工具调用
              </Typography.Text>
              <div className="zh-dashboard-agent-flow">
                <DashboardAgentNode icon={<Bot size={20} />} title="业务 Agent" desc="提交 OpenAI 请求" />
                <ArrowRight size={16} color="var(--ant-color-text-tertiary)" />
                <DashboardAgentNode icon={<ShieldCheck size={20} />} title="智安哨网关" desc="输入/输出检查" active />
                <ArrowRight size={16} color="var(--ant-color-text-tertiary)" />
                <DashboardAgentNode icon={<Activity size={20} />} title="Provider" desc="真实模型响应" />
                <ArrowRight size={16} color="var(--ant-color-text-tertiary)" />
                <DashboardAgentNode icon={<TerminalSquare size={20} />} title="工具闸门" desc="执行、暂停或隔离" />
              </div>
              <Divider dashed className="zh-attack-divider" titlePlacement="left" plain>
                <Typography.Text type="danger" className="zh-text-meta">
                  强制执行边界
                </Typography.Text>
              </Divider>
              <Typography.Text type="secondary" className="zh-text-meta zh-mb-12 zh-text-block">
                决策之后必须有执行结果回执
              </Typography.Text>
              <div className="zh-dashboard-pipeline-row">
                <DashboardAgentNode icon={<CircleCheck size={20} />} title="允许" desc="最小权限执行" />
                <ArrowRight size={16} color="var(--ant-color-text-tertiary)" />
                <DashboardAgentNode
                  icon={<CircleX size={20} />}
                  title="拒绝 / 审批 / 隔离"
                  desc="阻断副作用或暂停复核"
                  activeTone="success"
                />
                <ArrowRight size={16} color="var(--ant-color-text-tertiary)" />
                <DashboardAgentNode icon={<Activity size={20} />} title="执行回执" desc="核验真实结果" />
              </div>
            </div>
          </PanelCard>
        </Col>
        <Col xs={24} md={10}>
          <PanelCard
            title={
              <Space orientation="vertical" size={0}>
                <Typography.Text strong>最近需要关注的事件</Typography.Text>
                <Typography.Text type="secondary" className="zh-text-meta">
                  {overview.alerts.length} 条风险事件
                </Typography.Text>
              </Space>
            }
            variant="borderless"
            className="zh-full-height"
            bodyPadding={0}
          >
            <div className="zh-column-stack">
              {overview.alerts.slice(0, 5).map((alert) => (
                <div key={alert.id} onClick={() => onOpenPage('audit')} className="zh-dashboard-scenario-item">
                  <div>
                    <div>
                      <Typography.Text strong>{alert.title}</Typography.Text>
                    </div>
                    <div className="zh-mt-4">
                      <Typography.Text type="secondary" className="zh-text-meta">
                        {alert.decision} · 风险分 {alert.risk_score ?? '-'} · {alert.policy_id ?? '未标注策略'}
                      </Typography.Text>
                    </div>
                  </div>
                  <div>
                    <Play size={16} color="var(--ant-color-primary)" />
                  </div>
                </div>
              ))}
              {!overview.alerts.length ? (
                <div className="zh-p-24 zh-text-center">
                  <Typography.Text type="secondary">当前没有待关注事件。</Typography.Text>
                </div>
              ) : null}
            </div>
          </PanelCard>
        </Col>
      </Row>

      <PanelCard variant="borderless" bodyPadding={20}>
        <Flex justify="space-between" align="center" wrap="wrap" gap={16}>
          <div>
            <Typography.Text strong>网关运营与安全边界</Typography.Text>
            <Typography.Text type="secondary" className="zh-meta-block">
              真实 Provider 前后检查 · tool call 执行前控制 · 回执与审计证据
            </Typography.Text>
          </div>
          <ActionRow>
            <UiButton onClick={() => onOpenPage('gateway')}>打开网关</UiButton>
            <UiButton onClick={() => onOpenPage('policy')}>配置策略</UiButton>
            <UiButton onClick={() => onOpenPage('settings')}>接入 Agent</UiButton>
          </ActionRow>
        </Flex>
      </PanelCard>
    </div>
  );
}
