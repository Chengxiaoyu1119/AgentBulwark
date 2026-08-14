import { Play } from 'lucide-react';
import { Col, Row, Space, Typography } from 'antd';
import type { AttackEffectivenessCase } from '@/types';
import { riskLabel } from '@/utils';
import { LabelTag, PanelCard, UiBadge, UiButton } from '../ui';
import { EvidenceRunCell } from './EvidenceRunCell';

interface DefenseEvidenceCardProps {
  item: AttackEffectivenessCase;
  onOpenScenario: (id: string) => void;
}

export function DefenseEvidenceCard({ item, onOpenScenario }: DefenseEvidenceCardProps) {
  const observed = item.observed_decisions[0];
  const withoutHash = item.without_guard?.audit_hashes?.[0] ?? '';
  const withHash = item.with_guard?.audit_hashes?.[0] ?? '';
  const attackAssertions = item.without_guard?.attack_assertions ?? [];

  return (
    <PanelCard key={item.scenario_id} type="inner" bodyPadding={16}>
      <Row gutter={[24, 24]} align="top">
        <Col xs={24} md={8}>
          <Space orientation="vertical" className="zh-defense-evidence-case-stack">
            <div>
              <Typography.Text strong className="zh-defense-evidence-case-id">
                {item.scenario_id}
              </Typography.Text>
              <LabelTag color={['critical', 'high'].includes(item.severity) ? 'error' : 'warning'}>
                {item.surface_name} · {riskLabel[item.severity]}
              </LabelTag>
            </div>
            <Typography.Paragraph className="zh-zero-margin">{item.title}</Typography.Paragraph>
            <UiButton
              size="small"
              type="primary"
              ghost
              icon={<Play size={14} />}
              onClick={() => onOpenScenario(item.scenario_id)}
            >
              实验室复现
            </UiButton>
          </Space>
        </Col>
        <Col xs={24} md={16}>
          <Row gutter={[16, 16]} align="middle">
            <Col xs={24} lg={11}>
              <EvidenceRunCell
                title="无防护复现"
                state={item.attack_reproduced_without_guard ? '攻击暴露' : '未复现'}
                tone={item.attack_reproduced_without_guard ? 'danger' : 'muted'}
                decision={item.without_guard?.decisions?.[0] ?? '未记录'}
                policy={item.without_guard?.policies?.[0] ?? '未记录'}
                risk={item.without_guard?.risk_scores?.[0]}
                anomaly={item.without_guard?.anomaly_scores?.[0]}
                hash={withoutHash}
                hashValid={item.unguarded_hash_status?.valid}
              />
            </Col>
            <Col xs={24} lg={2} className="zh-defense-evidence-arrow-col">
              <Typography.Text type="secondary" className="zh-defense-evidence-arrow">
                →
              </Typography.Text>
            </Col>
            <Col xs={24} lg={11}>
              <EvidenceRunCell
                title="有防护验证"
                state={item.defense_effective_with_guard ? '风险已控制' : '仍需补强'}
                tone={item.defense_effective_with_guard ? 'safe' : 'danger'}
                decision={item.with_guard?.decisions?.[0] ?? observed?.decision ?? '未记录'}
                policy={item.with_guard?.policies?.[0] ?? observed?.policy_id ?? '未记录'}
                risk={item.with_guard?.risk_scores?.[0] ?? observed?.risk_score}
                anomaly={item.with_guard?.anomaly_scores?.[0] ?? observed?.anomaly_score}
                hash={withHash}
                hashValid={item.guarded_hash_status?.valid}
              />
            </Col>
          </Row>
        </Col>
      </Row>
      <div className="zh-defense-evidence-summary">
        <Row gutter={[16, 16]}>
          <Col xs={12} md={6}>
            <Typography.Text type="secondary" className="zh-meta-block">
              预期策略
            </Typography.Text>
            <Typography.Text strong>
              {item.expected_decisions.map((decision) => decision.policy_id).join(' / ') || '未记录'}
            </Typography.Text>
          </Col>
          <Col xs={12} md={6}>
            <Typography.Text type="secondary" className="zh-meta-block">
              实际策略
            </Typography.Text>
            <Typography.Text strong>
              {item.observed_decisions.map((decision) => decision.policy_id ?? '未记录').join(' / ') || '未记录'}
            </Typography.Text>
          </Col>
          <Col xs={12} md={6}>
            <Typography.Text type="secondary" className="zh-meta-block">
              匹配
            </Typography.Text>
            <UiBadge
              status={item.expected_decision_match ? 'success' : 'warning'}
              text={item.expected_decision_match ? '一致' : '待复核'}
            />
          </Col>
          <Col xs={12} md={6}>
            <Typography.Text type="secondary" className="zh-meta-block">
              证据
            </Typography.Text>
            <UiBadge
              status={item.evidence_complete ? 'success' : 'error'}
              text={item.evidence_complete ? '完整' : '有缺口'}
            />
          </Col>
        </Row>
      </div>
      {item.observed_decisions.length > 1 && (
        <div className="zh-defense-evidence-steps">
          <Typography.Text strong className="zh-defense-evidence-step-title">
            执行步骤
          </Typography.Text>
          <Space orientation="vertical" className="zh-full-width">
            {item.observed_decisions.map((decision, index) => (
              <div key={`${item.scenario_id}-${index}`} className="zh-defense-evidence-step-row">
                <LabelTag color="default">{index + 1}</LabelTag>
                <Typography.Text code>{decision.tool ?? '未知工具'}</Typography.Text>
                <Typography.Text type="secondary" className="zh-defense-evidence-step-text">
                  {decision.decision ?? '未记录'} / {decision.policy_id ?? '未记录'} · 风险 {decision.risk_score ?? '-'}{' '}
                  · 异常 {decision.anomaly_score ?? '-'}
                </Typography.Text>
              </div>
            ))}
          </Space>
        </div>
      )}
      {attackAssertions.length > 0 && (
        <div className="zh-defense-evidence-steps">
          <Typography.Text strong className="zh-defense-evidence-step-title">
            无防护副作用证据
          </Typography.Text>
          <Space orientation="vertical" className="zh-full-width">
            {attackAssertions.map((assertion, index) => (
              <div key={`${item.scenario_id}-effect-${index}`} className="zh-defense-evidence-step-row">
                <LabelTag color={assertion.observed ? 'error' : 'default'}>{assertion.tool}</LabelTag>
                <Typography.Text type="secondary" className="zh-defense-evidence-step-text">
                  {assertion.reason} · {assertion.fixture_source || 'sandbox-runtime'}
                </Typography.Text>
              </div>
            ))}
          </Space>
        </div>
      )}
      <div className="zh-defense-evidence-gap">
        <Typography.Text
          type={item.evidence_gaps.length ? 'danger' : 'success'}
          className="zh-defense-evidence-gap-text"
        >
          {item.evidence_gaps.length ? item.evidence_gaps.join('；') : '无证据缺口，可用于复核。'}
        </Typography.Text>
      </div>
    </PanelCard>
  );
}
