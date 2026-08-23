import { Col, Row, Space, Typography } from 'antd';
import { ScrollText } from 'lucide-react';
import type { AttackSurface, Scenario, SurfaceEvidencePack } from '@/types';
import { LabelTag, PanelCard, UiButton } from '../ui';
import { coverageLabel } from './surfaceWorkbenchUtils';

export function SurfaceDefenseBriefCard({
  surface,
  scenarios,
  pack,
  loading
}: {
  surface: AttackSurface;
  scenarios: Scenario[];
  pack: SurfaceEvidencePack | null;
  loading: boolean;
}) {
  const markdownHref = `/api/attack_surfaces/${encodeURIComponent(surface.id)}/evidence_pack.md`;
  const briefingSheetHref = `/api/attack_surfaces/${encodeURIComponent(surface.id)}/briefing_sheet.html`;
  const summary = pack?.summary;
  const mainScenario = pack?.scenarios[0];
  const fallbackScenario = scenarios[0];
  const displayValue = (value: number | string) => (loading && !pack ? '...' : value);
  const threatNodes = (
    pack?.threat_chain?.length
      ? pack.threat_chain
      : [
          { stage: '攻击入口', text: surface.entry_points?.[0] ?? '待补充' },
          { stage: '目标资产', text: surface.protected_assets?.[0] ?? '待补充' },
          { stage: '监督策略', text: surface.defense }
        ]
  ).slice(0, 4);
  const coverageEntries = Object.entries(
    pack?.coverage_checks ?? {
      has_surface_profile: Boolean(surface.entry_points?.length && surface.protected_assets?.length),
      has_adversarial_samples: surface.samples > 0,
      has_jailbreak_cases: surface.samples > 0,
      has_agent_scripts: surface.scripts > 0,
      has_policy_expectations: false,
      has_runtime_evidence: false
    }
  );
  const policyItems = pack?.policy_distribution.slice(0, 4) ?? [];
  const toolItems = pack?.tool_coverage.slice(0, 4) ?? [];
  const latestGuarded = mainScenario?.latest_guarded_result;
  const decisionTone =
    latestGuarded?.status === '已控制' ? 'success' : latestGuarded?.status === '攻击成功' ? 'error' : 'processing';

  return (
    <PanelCard type="inner" className="zh-mb-24" bodyPadding={24}>
      <div className="zh-surface-brief__head">
        <div>
          <Typography.Text type="secondary" className="zh-surface-matrix-label">
            评测单页
          </Typography.Text>
          <Typography.Title level={4} className="zh-zero-margin">
            {surface.name}
          </Typography.Title>
        </div>
        <div className="zh-surface-brief__score">
          <Typography.Title level={2} className="zh-surface-brief__score-value">
            {displayValue(`${summary?.readiness_score ?? 0}%`)}
          </Typography.Title>
          <Typography.Text type="secondary" className="zh-text-sm">
            证据完整度
          </Typography.Text>
        </div>
      </div>

      <Row gutter={[16, 16]} className="zh-surface-brief__stats">
        <Col xs={12} sm={6}>
          <Typography.Text type="secondary" className="zh-meta-block">
            可运行
          </Typography.Text>
          <Typography.Text strong>{displayValue(summary?.scenario_count ?? scenarios.length)}</Typography.Text>
        </Col>
        <Col xs={12} sm={6}>
          <Typography.Text type="secondary" className="zh-meta-block">
            样本/条目
          </Typography.Text>
          <Typography.Text strong>
            {displayValue(
              `${summary?.sample_count ?? surface.samples}/${summary?.agent_script_count ?? surface.scripts}`
            )}
          </Typography.Text>
        </Col>
        <Col xs={12} sm={6}>
          <Typography.Text type="secondary" className="zh-meta-block">
            控制率
          </Typography.Text>
          <Typography.Text strong>{displayValue(`${summary?.control_rate ?? 0}%`)}</Typography.Text>
        </Col>
        <Col xs={12} sm={6}>
          <Typography.Text type="secondary" className="zh-meta-block">
            缺口
          </Typography.Text>
          <Typography.Text strong>{displayValue(summary?.gap_count ?? 0)}</Typography.Text>
        </Col>
      </Row>

      <Row gutter={[24, 24]}>
        <Col xs={24} lg={8}>
          <Typography.Text strong className="zh-surface-section-title">
            攻击链路
          </Typography.Text>
          <Space orientation="vertical" className="zh-surface-threat-list">
            {threatNodes.map((node, index) => (
              <div key={`${node.stage}-${index}`} className="zh-surface-threat-row">
                <div className="zh-surface-threat-index">{index + 1}</div>
                <div>
                  <Typography.Text type="secondary" className="zh-meta-block">
                    {node.stage}
                  </Typography.Text>
                  <Typography.Text strong className="zh-text-md">
                    {node.text}
                  </Typography.Text>
                </div>
              </div>
            ))}
          </Space>
        </Col>

        <Col xs={24} lg={8}>
          <Typography.Text strong className="zh-surface-section-title">
            监督命中
          </Typography.Text>
          <div className="zh-surface-subsection">
            <Space>
              <LabelTag color={decisionTone}>{latestGuarded?.status ?? '待验证'}</LabelTag>
              <Typography.Text type="secondary" className="zh-text-sm">
                {mainScenario?.id ?? fallbackScenario?.id ?? '暂无脚本'}
              </Typography.Text>
            </Space>
          </div>
          <Typography.Text type="secondary" className="zh-surface-matrix-label">
            命中策略
          </Typography.Text>
          <Space size={[0, 8]} wrap className="zh-surface-subsection">
            {policyItems.length ? (
              policyItems.map((item) => (
                <LabelTag key={item.policy_id} color="processing">
                  {item.policy_id}
                </LabelTag>
              ))
            ) : (
              <Typography.Text type="secondary" className="zh-text-sm">
                加载中
              </Typography.Text>
            )}
          </Space>
          <Typography.Text type="secondary" className="zh-surface-matrix-label">
            覆盖工具
          </Typography.Text>
          <Space size={[0, 8]} wrap>
            {toolItems.length ? (
              toolItems.map((item) => <LabelTag key={item.tool}>{item.tool}</LabelTag>)
            ) : (
              <Typography.Text type="secondary" className="zh-text-sm">
                加载中
              </Typography.Text>
            )}
          </Space>
        </Col>

        <Col xs={24} lg={8}>
          <Typography.Text strong className="zh-surface-section-title">
            验收闭环{' '}
            <Typography.Text type="secondary">
              ({coverageEntries.filter(([, checked]) => checked).length}/{coverageEntries.length})
            </Typography.Text>
          </Typography.Text>
          <Space orientation="vertical" size={4} className="zh-surface-coverage-list">
            {coverageEntries.map(([key, checked]) => (
              <div key={key} className="zh-surface-coverage-row">
                <div className={`zh-surface-coverage-dot${checked ? ' zh-surface-coverage-dot--checked' : ''}`} />
                <Typography.Text
                  type={checked ? undefined : 'secondary'}
                  className={`zh-surface-coverage-text${checked ? ' zh-surface-coverage-text--checked' : ''}`}
                >
                  {coverageLabel[key] ?? key}
                </Typography.Text>
              </div>
            ))}
          </Space>
          <Space orientation="vertical" className="zh-full-width">
            <UiButton block authenticatedHref={briefingSheetHref} icon={<ScrollText size={14} />}>
              打开独立单页
            </UiButton>
            <UiButton block type="dashed" authenticatedHref={markdownHref} icon={<ScrollText size={14} />}>
              Markdown
            </UiButton>
          </Space>
        </Col>
      </Row>
    </PanelCard>
  );
}
