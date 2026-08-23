import { Col, Divider, Row, Space, Typography } from 'antd';
import { ClipboardList, ExternalLink, Play } from 'lucide-react';
import type { AttackSurface, Scenario, SurfaceEvidencePack } from '@/types';
import { riskLabel } from '@/utils';
import { LabelTag, MetricCard as Metric, PanelCard, UiButton } from '../ui';
import { SurfaceAttributeGroup } from './SurfaceAttributeGroup';
import { SurfaceDefenseBriefCard } from './SurfaceDefenseBriefCard';
import { SurfaceEvidencePackPanel } from './SurfaceEvidencePackPanel';
import { SurfaceAttackPlaybookPanel } from './SurfaceAttackPlaybookPanel';
import { SurfaceScenarioList } from './SurfaceScenarioList';
import { getSurfaceRiskColor } from './surfaceWorkbenchUtils';

export { SurfaceCard } from './SurfaceCard';

export function SurfaceWorkbench({
  surface,
  scenarios,
  surfacePack,
  surfacePackLoading,
  surfacePackError,
  running,
  onOpenScenario,
  onBatchCompare
}: {
  surface: AttackSurface;
  scenarios: Scenario[];
  surfacePack: SurfaceEvidencePack | null;
  surfacePackLoading: boolean;
  surfacePackError: string;
  running: boolean;
  onOpenScenario: (id: string) => void;
  onBatchCompare: (ids: string[], label: string) => void;
}) {
  const firstScenarioId = scenarios[0]?.id;
  const color = getSurfaceRiskColor(surface.risk);
  const evidencePackUrl = `/api/attack_surfaces/${encodeURIComponent(surface.id)}/evidence_pack`;
  const evidencePackMarkdownUrl = `${evidencePackUrl}.md`;

  return (
    <PanelCard className={`zh-surface-workbench zh-surface-workbench--${color}`} bodyPadding={24}>
      <Row gutter={32}>
        <Col xs={24} lg={16}>
          <div className="zh-surface-workbench__head">
            <div>
              <Typography.Title level={3} className="zh-surface-workbench__title">
                {surface.name}
              </Typography.Title>
              <Space size="small" align="center" wrap>
                <LabelTag color={color}>{riskLabel[surface.risk]}风险</LabelTag>
                <Typography.Text type="secondary" className="zh-code-sm">
                  {surface.id}
                </Typography.Text>
                <Typography.Text type="secondary" className="zh-text-sm">
                  {surface.status}
                </Typography.Text>
              </Space>
            </div>
            <Space>
              <UiButton
                type="primary"
                icon={<ClipboardList size={16} />}
                onClick={() => firstScenarioId && onOpenScenario(firstScenarioId)}
                disabled={!firstScenarioId}
              >
                运行首个脚本
              </UiButton>
              <UiButton
                icon={<Play size={16} />}
                onClick={() =>
                  onBatchCompare(
                    scenarios.map((scenario) => scenario.id),
                    surface.name
                  )
                }
                disabled={running || !scenarios.length}
              >
                {running ? '验证中...' : '批量验证'}
              </UiButton>
            </Space>
          </div>

          <Typography.Paragraph type="secondary" className="zh-surface-workbench__summary">
            {surface.summary}
          </Typography.Paragraph>

          <div className="zh-surface-run-strip">
            <div className="zh-surface-run-strip__copy">
              <Typography.Text strong>真实复现闭环</Typography.Text>
              <Typography.Text type="secondary" className="zh-text-block zh-mt-4">
                运行脚本会触发本地受控环境工具调用、监督判定、审计 hash 和证据包刷新，页面可直接打开 JSON/Markdown
                核对。
              </Typography.Text>
            </div>
            <div className="zh-surface-run-strip__steps">
              {['攻击输入', '工具调用', '监督判定', '审计证据'].map((item) => (
                <span key={item}>{item}</span>
              ))}
            </div>
            <Space wrap className="zh-surface-run-strip__actions">
              <UiButton
                type="primary"
                icon={<Play size={16} />}
                onClick={() =>
                  onBatchCompare(
                    scenarios.map((scenario) => scenario.id),
                    surface.name
                  )
                }
                disabled={running || !scenarios.length}
              >
                {running ? '验证中...' : '运行本攻击面'}
              </UiButton>
              <UiButton authenticatedHref={evidencePackUrl} icon={<ExternalLink size={15} />}>
                JSON 证据
              </UiButton>
              <UiButton authenticatedHref={evidencePackMarkdownUrl} icon={<ExternalLink size={15} />}>
                Markdown 证据
              </UiButton>
            </Space>
          </div>

          {surfacePack && (
            <Row gutter={[12, 12]} className="zh-surface-run-metrics">
              <Col xs={12} md={6}>
                <Metric label="运行记录" value={`${surfacePack.summary.run_count}`} tone="cyan" />
              </Col>
              <Col xs={12} md={6}>
                <Metric label="控制率" value={`${surfacePack.summary.control_rate}%`} tone="green" />
              </Col>
              <Col xs={12} md={6}>
                <Metric label="完整度" value={`${surfacePack.summary.readiness_score}%`} tone="amber" />
              </Col>
              <Col xs={12} md={6}>
                <Metric label="缺口" value={`${surfacePack.summary.gap_count}`} tone="red" />
              </Col>
            </Row>
          )}

          <Row gutter={[16, 16]} className="zh-mb-24">
            <Col xs={12} sm={6}>
              <Metric label="样本" value={`${surface.samples}`} tone="cyan" />
            </Col>
            <Col xs={12} sm={6}>
              <Metric label="脚本条目" value={`${surface.scripts}`} tone="amber" />
            </Col>
            <Col xs={12} sm={6}>
              <Metric label="可运行" value={`${scenarios.length}`} tone="green" />
            </Col>
            <Col xs={12} sm={6}>
              <Metric
                label="风险"
                value={riskLabel[surface.risk]}
                tone={surface.risk === 'critical' ? 'red' : surface.risk === 'high' ? 'amber' : 'cyan'}
              />
            </Col>
          </Row>

          <Row gutter={[16, 16]} className="zh-surface-workbench__attributes">
            <Col xs={24} md={12}>
              <SurfaceAttributeGroup title="攻击入口" items={surface.entry_points} />
            </Col>
            <Col xs={24} md={12}>
              <SurfaceAttributeGroup title="保护资产" items={surface.protected_assets} />
            </Col>
            <Col xs={24} md={12}>
              <SurfaceAttributeGroup title="攻击目标" items={surface.attacker_goals} />
            </Col>
            <Col xs={24} md={12}>
              <SurfaceAttributeGroup title="检测信号" items={surface.detection_signals} />
            </Col>
            <Col xs={24} md={12}>
              <SurfaceAttributeGroup title="评测重点" items={surface.evaluation_focus} />
            </Col>
            <Col xs={24} md={12}>
              <SurfaceAttributeGroup
                title="防御加固"
                items={surface.mitigations?.length ? surface.mitigations : [surface.defense]}
              />
            </Col>
          </Row>

          <SurfaceAttackPlaybookPanel
            surface={surface}
            scenarios={scenarios}
            pack={surfacePack}
            running={running}
            onOpenScenario={onOpenScenario}
            onBatchCompare={onBatchCompare}
          />

          <SurfaceDefenseBriefCard
            surface={surface}
            scenarios={scenarios}
            pack={surfacePack}
            loading={surfacePackLoading}
          />
          <Divider />
          <SurfaceEvidencePackPanel
            surface={surface}
            pack={surfacePack}
            loading={surfacePackLoading}
            error={surfacePackError}
          />
        </Col>

        <Col xs={24} lg={8}>
          <SurfaceScenarioList scenarios={scenarios} onOpenScenario={onOpenScenario} />
        </Col>
      </Row>
    </PanelCard>
  );
}
