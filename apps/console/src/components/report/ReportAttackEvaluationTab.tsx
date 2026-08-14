import { Col, Row, Space, Typography } from 'antd';
import { DecisionPill, LabelTag, MetricCard as Metric, PanelCard, SectionTitle, UiBadge, UiTable } from '../ui';
import type { ReportData } from '@/types';
import { riskLabel } from '@/utils';
import { ReportAttackEvidenceActions } from './ReportAttackEvidenceActions';
import { AdversarialHoldoutPanel } from './AdversarialHoldoutPanel';
import { ReportDefenseEvidenceBoard } from './ReportDefenseEvidenceBoard';

type ReportAttackEvaluationTabProps = {
  report: ReportData;
  onOpenScenario: (id: string) => void;
  onRefreshReport?: () => Promise<void> | void;
  onRefreshRuntime?: () => Promise<unknown> | void;
};

export function ReportAttackEvaluationTab({
  report,
  onOpenScenario,
  onRefreshReport,
  onRefreshRuntime
}: ReportAttackEvaluationTabProps) {
  return (
    <Space orientation="vertical" size="large" className="zh-tab-stack">
      <ReportAttackEvidenceActions onRefreshReport={onRefreshReport} onRefreshRuntime={onRefreshRuntime} />
      {report.adversarial_holdout && <AdversarialHoldoutPanel report={report.adversarial_holdout} />}
      {report.attack_effectiveness && (
        <PanelCard
          title={
            <SectionTitle
              title="攻防有效性评测"
              meta={`${report.attack_effectiveness.summary.attack_reproduced_count}/${report.attack_effectiveness.summary.scenario_count} 个脚本已复现攻击`}
            />
          }
          variant="borderless"
        >
          <Row gutter={[16, 16]} className="zh-mb-24">
            <Col xs={24} sm={12} lg={6}>
              <Metric
                label="无防护复现率"
                value={`${report.attack_effectiveness.summary.attack_reproduced_rate}%`}
                tone="red"
              />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Metric
                label="有防护控制率"
                value={`${report.attack_effectiveness.summary.defense_effective_rate}%`}
                tone="green"
              />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Metric
                label="策略匹配率"
                value={`${report.attack_effectiveness.summary.expected_match_rate}%`}
                tone="cyan"
              />
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Metric
                label="证据完整率"
                value={`${report.attack_effectiveness.summary.evidence_complete_rate}%`}
                tone="amber"
              />
            </Col>
          </Row>
          <ReportDefenseEvidenceBoard cases={report.attack_effectiveness.cases} onOpenScenario={onOpenScenario} />
          <UiTable
            dataSource={report.attack_effectiveness.cases}
            rowKey="scenario_id"
            size="small"
            pagination={{ pageSize: 10 }}
            className="zh-mt-24"
            columns={[
              {
                title: '脚本',
                dataIndex: 'scenario_id',
                render: (t) => <Typography.Text strong>{t}</Typography.Text>
              },
              { title: '攻击面', dataIndex: 'surface_name' },
              {
                title: '无防护',
                key: 'attack_reproduced_without_guard',
                render: (_, r) => (
                  <LabelTag variant="filled" color={r.attack_reproduced_without_guard ? 'error' : 'default'}>
                    {r.attack_reproduced_without_guard ? '已复现' : '未复现'}
                  </LabelTag>
                )
              },
              {
                title: '有防护',
                key: 'defense_effective_with_guard',
                render: (_, r) => (
                  <LabelTag variant="filled" color={r.defense_effective_with_guard ? 'success' : 'error'}>
                    {r.defense_effective_with_guard ? '已控制' : '缺证据'}
                  </LabelTag>
                )
              },
              {
                title: '策略',
                key: 'expected_decision_match',
                render: (_, r) => (
                  <UiBadge
                    status={r.expected_decision_match ? 'success' : 'warning'}
                    text={r.expected_decision_match ? '匹配' : '不完整'}
                  />
                )
              },
              {
                title: '证据',
                key: 'evidence_complete',
                render: (_, r) => (
                  <Typography.Text>
                    {r.evidence_complete ? '完整' : '待补'}{' '}
                    {r.guarded_hash_status?.valid && r.unguarded_hash_status?.valid ? ' / hash有效' : ' / hash待补'}
                  </Typography.Text>
                )
              },
              {
                title: '缺口',
                key: 'evidence_gaps',
                render: (_, r) => (
                  <Typography.Text type="secondary">{r.evidence_gaps.join('；') || '无'}</Typography.Text>
                )
              }
            ]}
          />
        </PanelCard>
      )}
      <PanelCard
        title={
          <SectionTitle
            title="攻击面实验结论"
            meta={`${report.surface_conclusions.summary.conclusion_count} 类结论 / ${report.surface_conclusions.summary.with_run_evidence_count} 类已有运行证据`}
          />
        }
        variant="borderless"
      >
        <div className="zh-column-stack">
          {report.surface_conclusions.conclusions.map((item, idx) => (
            <div key={idx} className="zh-divided-list__item">
              <div className="zh-mb-8">
                <Space>
                  <Typography.Text strong>{item.surface_name}</Typography.Text>
                  <LabelTag variant="filled" color={item.risk === 'critical' ? 'error' : 'warning'}>
                    {riskLabel[item.risk]}
                  </LabelTag>
                  <Typography.Text type="secondary">{item.experiment_status}</Typography.Text>
                </Space>
              </div>
              <Space orientation="vertical" size={4} className="zh-full-width">
                <Typography.Text>{item.key_findings[0]}</Typography.Text>
                <Space>
                  <Typography.Text code>
                    {Object.keys(item.expected_policies).join(' / ') || 'default-allow'}
                  </Typography.Text>
                  <Typography.Text strong type="success">
                    {item.control_rate}%
                  </Typography.Text>
                </Space>
              </Space>
            </div>
          ))}
        </div>
      </PanelCard>
      <PanelCard
        title={
          <SectionTitle
            title="模型输出过滤前后对比"
            meta={`${report.output_filter_evidence.summary.case_count} 个输出风险样本 / 阻断率 ${report.output_filter_evidence.summary.block_rate}%`}
          />
        }
        variant="borderless"
      >
        <UiTable
          dataSource={report.output_filter_evidence.cases}
          rowKey="scenario_id"
          size="small"
          pagination={{ pageSize: 5 }}
          columns={[
            {
              title: '脚本',
              dataIndex: 'scenario_id',
              render: (t) => <Typography.Text strong>{t}</Typography.Text>
            },
            { title: '类型', dataIndex: 'filter_type' },
            {
              title: '关闭防护',
              key: 'without_guard',
              render: (_, r) => <Typography.Text type="danger">{r.without_guard.decision}</Typography.Text>
            },
            {
              title: '开启防护',
              key: 'with_guard',
              render: (_, r) => <Typography.Text type="success">{r.with_guard.decision}</Typography.Text>
            },
            {
              title: '命中策略',
              key: 'policy',
              render: (_, r) => <Typography.Text code>{r.with_guard.policy_id}</Typography.Text>
            },
            {
              title: '结论',
              key: 'reason',
              render: (_, r) => (
                <Typography.Text type="secondary" ellipsis>
                  {r.with_guard.reason}
                </Typography.Text>
              )
            }
          ]}
        />
      </PanelCard>
      <PanelCard
        title={
          <SectionTitle
            title="攻击面覆盖矩阵"
            meta={`${report.surface_coverage.filter((item) => item.demo_ready).length} 类可复现`}
          />
        }
        variant="borderless"
      >
        <UiTable
          dataSource={report.surface_coverage}
          rowKey="id"
          size="small"
          pagination={false}
          columns={[
            {
              title: '攻击面',
              dataIndex: 'name',
              render: (t) => <Typography.Text strong>{t}</Typography.Text>
            },
            {
              title: '风险',
              dataIndex: 'risk',
              render: (t) => (
                <LabelTag variant="filled" color={t === 'critical' ? 'error' : 'warning'}>
                  {riskLabel[t]}
                </LabelTag>
              )
            },
            { title: '样本', dataIndex: 'samples' },
            { title: '脚本', dataIndex: 'scripts' },
            { title: '状态', dataIndex: 'status' },
            {
              title: '防御策略',
              dataIndex: 'defense',
              render: (t) => <Typography.Text type="secondary">{t}</Typography.Text>
            }
          ]}
        />
      </PanelCard>
      <PanelCard
        title={<SectionTitle title="攻击脚本证据矩阵" meta={`${report.scenario_matrix.length} 个脚本`} />}
        variant="borderless"
      >
        <UiTable
          dataSource={report.scenario_matrix}
          rowKey="id"
          size="small"
          pagination={{ pageSize: 10 }}
          columns={[
            {
              title: '脚本',
              dataIndex: 'id',
              render: (t) => <Typography.Text strong>{t}</Typography.Text>
            },
            { title: '攻击面', dataIndex: 'surface' },
            {
              title: '目标',
              dataIndex: 'target',
              render: (t) => <Typography.Text code>{t}</Typography.Text>
            },
            {
              title: '样本',
              dataIndex: 'has_adversarial_prompt',
              render: (t) => <Typography.Text type={t ? 'success' : 'secondary'}>{t ? '有' : '缺失'}</Typography.Text>
            },
            {
              title: '越狱',
              dataIndex: 'has_jailbreak_case',
              render: (t) => <Typography.Text type={t ? 'success' : 'secondary'}>{t ? '有' : '缺失'}</Typography.Text>
            },
            {
              title: '步骤',
              key: 'steps',
              render: (_, r) => (
                <Typography.Text>
                  {r.script_steps} 步 / {r.tool_calls} 调用
                </Typography.Text>
              )
            },
            { title: '决策', dataIndex: 'last_decision', render: (t) => <DecisionPill decision={t} /> }
          ]}
        />
      </PanelCard>
    </Space>
  );
}
