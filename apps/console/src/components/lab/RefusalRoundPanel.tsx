import { Col, Descriptions, Row, Space, Typography } from 'antd';
import { ShieldCheck } from 'lucide-react';
import type { RefusalRewriteEvasionRound } from '../../types';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import { DecisionPill, EvidenceCodeBlock, LabelTag, MetricCard, PanelCard, UiAlert } from '../ui';

function findingText(findings: Array<Record<string, string>>) {
  if (!findings.length) return '未命中过滤器';
  return findings.map((item) => `${item.type ?? 'finding'}:${item.count ?? '1'}`).join('；');
}

function modeTag(mode: string) {
  if (mode === 'real-api') return <LabelTag color="processing">真实接口</LabelTag>;
  if (mode === 'skipped') return <LabelTag>未触发</LabelTag>;
  return <LabelTag color="default">{mode || 'fallback'}</LabelTag>;
}

export function RefusalRoundPanel({ round }: { round: RefusalRewriteEvasionRound }) {
  return (
    <PanelCard
      title={`第 ${round.round_index} 轮拒答改写链`}
      subtitle={round.summary.decision_change}
      extra={<AuditDeepLinkButton auditId={round.supervisor.rewritten_with_guard.audit_id} size="small" />}
      type="inner"
    >
      <Space orientation="vertical" size={16} className="zh-full-width">
        <Row gutter={[12, 12]}>
          <Col xs={12} md={6}>
            <MetricCard
              label="首轮拒答"
              value={round.summary.initial_refused ? '命中' : '未命中'}
              tone={round.summary.initial_refused ? 'amber' : 'green'}
            />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard
              label="副模型改写"
              value={round.summary.rewrite_attempted ? '已触发' : '跳过'}
              tone={round.summary.rewrite_attempted ? 'cyan' : 'default'}
            />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard
              label="疑似突破"
              value={round.summary.attack_success ? '是' : '否'}
              tone={round.summary.attack_success ? 'red' : 'green'}
            />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard label="风险分" value={round.summary.risk_score} tone="amber" />
          </Col>
        </Row>
        <Descriptions column={{ xs: 1, md: 2 }} size="small">
          <Descriptions.Item label="拒答命中">
            {round.refusal.hits.length ? round.refusal.hits.join('，') : '未命中'}
          </Descriptions.Item>
          <Descriptions.Item label="首轮目标模型">{modeTag(round.initial_target.mode)}</Descriptions.Item>
          <Descriptions.Item label="副模型链路">{modeTag(round.optimizer.mode)}</Descriptions.Item>
          <Descriptions.Item label="改写后目标模型">{modeTag(round.rewritten_target.mode)}</Descriptions.Item>
          <Descriptions.Item label="输出过滤">{findingText(round.output_filter.rewritten.findings)}</Descriptions.Item>
          <Descriptions.Item label="命中策略">{round.summary.policy_id}</Descriptions.Item>
          <Descriptions.Item label="无监督">
            <DecisionPill decision={round.supervisor.rewritten_without_guard.decision} />
          </Descriptions.Item>
          <Descriptions.Item label="开启监督器">
            <DecisionPill decision={round.supervisor.rewritten_with_guard.decision} />
          </Descriptions.Item>
        </Descriptions>
        <UiAlert type={round.refusal.detected ? 'warning' : 'info'} showIcon message={round.refusal.reason} />
        <Row gutter={[16, 16]}>
          <Col xs={24} lg={12}>
            <Typography.Text strong>首轮主模型输出</Typography.Text>
            <EvidenceCodeBlock maxHeight="small">{round.initial_target.filtered_output || '无输出'}</EvidenceCodeBlock>
          </Col>
          <Col xs={24} lg={12}>
            <Typography.Text strong>副模型改写后的用户消息</Typography.Text>
            <EvidenceCodeBlock maxHeight="small">
              {round.optimizer.optimized_prompt || round.optimizer.skip_reason || '未触发改写'}
            </EvidenceCodeBlock>
          </Col>
          <Col xs={24}>
            <Typography.Text strong>第二次主模型输出</Typography.Text>
            <EvidenceCodeBlock maxHeight="small">
              {round.rewritten_target.filtered_output || '未触发第二次主模型调用'}
            </EvidenceCodeBlock>
          </Col>
        </Row>
        <Typography.Paragraph type="secondary" className="zh-mb-0">
          <ShieldCheck size={14} className="zh-inline-icon" />
          {round.supervisor.rewritten_with_guard.reason}
        </Typography.Paragraph>
      </Space>
    </PanelCard>
  );
}
