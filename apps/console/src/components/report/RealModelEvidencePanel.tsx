import { Col, Row, Space, Typography } from 'antd';
import type { RealModelEvaluation } from '@/types';
import { LabelTag, MetricCard, PanelCard, SectionTitle, UiAlert, UiButton, UiTable } from '../ui';
import { branchLabel, branchTone, metricValue } from './realModelEvidenceView';

type RealModelEvidencePanelProps = {
  evaluation?: RealModelEvaluation | null;
};

export function RealModelEvidencePanel({ evaluation }: RealModelEvidencePanelProps) {
  if (!evaluation) {
    return (
      <PanelCard title={<SectionTitle title="真实模型运行证据" meta="尚未生成" />} variant="borderless">
        <UiAlert
          type="info"
          showIcon
          title="尚未生成真实模型工具调用盲测报告。"
          description="点击上方“运行真实模型盲测”后，页面会在这里展示模型来源、工具调用、监督决策和延迟；报告生成总过程不会把本地兜底结果标记为真实 API。"
        />
      </PanelCard>
    );
  }

  const evaluationData = evaluation;
  const { summary } = evaluationData;
  const integrityValid =
    summary.report_integrity_valid === true && evaluationData.integrity_verification?.valid !== false;
  const strictEvidenceReady = summary.strict_real_api_ready === true && integrityValid;
  const hasRealApi = summary.real_api_case_count > 0;
  const sourceLabel = strictEvidenceReady
    ? '全量真实 API 严格证据通过'
    : hasRealApi
      ? '含真实 API，但严格证据未通过'
      : '报告仅含本地兜底';
  const sourceColor = strictEvidenceReady ? 'success' : 'warning';
  const realApiCoverage =
    summary.real_api_coverage_rate ?? Math.round((summary.real_api_case_count / Math.max(1, summary.case_count)) * 100);
  const evidenceGaps = Array.from(new Set(evaluationData.results.flatMap((item) => item.evidence_gaps ?? [])));

  function downloadEvidence(filename: string, content: string, contentType: string) {
    const url = URL.createObjectURL(new Blob([content], { type: `${contentType};charset=utf-8` }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }

  function downloadJson() {
    downloadEvidence('真实模型工具调用盲测报告.json', JSON.stringify(evaluationData, null, 2), 'application/json');
  }

  function downloadMarkdown() {
    const lines = [
      '# 真实模型工具调用盲测报告',
      '',
      `生成时间：${evaluationData.generated_at}`,
      `样本：${summary.case_count}；模型工具调用：${summary.model_tool_call_success_count}；真实 API：${summary.real_api_case_count}`,
      `严格证据判定：${strictEvidenceReady ? '通过' : '未通过'}；真实 API 覆盖率：${realApiCoverage}%；回执完整率：${summary.receipt_complete_rate === undefined ? '待补跑' : `${summary.receipt_complete_rate}%`}`,
      `预期决策匹配率：${summary.expected_control_match_rate ?? '待补跑'}%；因果一致性：${summary.causal_integrity_rate ?? '待补跑'}%；报告 Hash：${evaluationData.report_hash ?? '历史报告未记录'}`,
      '',
      '| 样本 | 标签 | 模型来源 | 工具 | 无防护 | 有防护 | 决策 | 回执 | 监督延迟 |',
      '|---|---|---|---|---|---|---|---|---:|',
      ...evaluationData.results.map(
        (item) =>
          `| ${item.id} | ${item.label} | ${item.provider} / ${item.mode} | ${item.tool_call?.tool ?? '-'} | ${branchLabel(item, 'baseline')} | ${branchLabel(item, 'guarded')} | ${item.decision} | ${item.receipt_complete ? '完整' : '缺失'} | ${item.supervisor_latency_ms ?? '-'}ms |`
      )
    ];
    downloadEvidence('真实模型工具调用盲测报告.md', lines.join('\n'), 'text/markdown');
  }

  return (
    <PanelCard
      title={<SectionTitle title="真实模型运行证据" meta={`${summary.case_count} 个样本 / ${sourceLabel}`} />}
      variant="borderless"
    >
      <Space orientation="vertical" className="zh-full-width" size="middle">
        <Space wrap>
          <LabelTag variant="filled" color={sourceColor}>
            {sourceLabel}
          </LabelTag>
          <Typography.Text type="secondary">生成于 {evaluationData.generated_at}</Typography.Text>
          {summary.provider_modes.map((mode) => (
            <LabelTag key={mode} variant="filled" color="blue">
              {mode}
            </LabelTag>
          ))}
          {summary.model_tool_call_count !== undefined ? (
            <LabelTag variant="filled" color="processing">
              模型实际调用 {summary.model_tool_call_count} 次 / 多步样本 {summary.multi_step_case_count ?? 0}
            </LabelTag>
          ) : null}
          {evaluationData.report_hash ? (
            <LabelTag variant="filled" color={integrityValid ? 'success' : 'warning'}>
              报告 Hash {evaluationData.report_hash.slice(0, 12)}…
            </LabelTag>
          ) : null}
        </Space>
        <UiAlert
          type={strictEvidenceReady ? 'success' : 'warning'}
          showIcon
          title={
            strictEvidenceReady
              ? '这份报告可证明：真实模型生成调用，无防护产生副作用，有防护控制副作用，两个分支都有执行回执。'
              : '当前报告只可作为部分运行记录，暂不计入严格真实模型效果结论。'
          }
          description={
            strictEvidenceReady
              ? `${evaluationData.method?.causal_rule ?? ''} 报告完整性 Hash 已校验。`
              : evidenceGaps.length
                ? `主要缺口：${evidenceGaps.slice(0, 4).join('；')}`
                : '重新运行盲测后，将补齐独立沙箱因果对照、执行回执和严格来源判定。'
          }
        />
        <Row gutter={[12, 12]}>
          <Col xs={12} md={8} xl={4}>
            <MetricCard
              label="真实 API 覆盖"
              value={`${realApiCoverage}%`}
              tone={strictEvidenceReady ? 'green' : 'amber'}
            />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard label="无防护攻击复现" value={metricValue(summary.attack_reproduced_rate)} tone="red" />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard label="有防护有效控制" value={metricValue(summary.defense_effective_rate)} tone="green" />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard label="执行回执完整" value={metricValue(summary.receipt_complete_rate)} tone="cyan" />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard
              label="正常误报"
              value={`${summary.benign_false_positive_rate}%`}
              tone={summary.benign_false_positive_rate ? 'amber' : 'green'}
            />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard
              label="任务工具对齐"
              value={metricValue(summary.task_alignment_rate)}
              tone={summary.task_alignment_rate === 100 ? 'green' : 'amber'}
            />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard label="监督 P95" value={`${summary.p95_supervisor_latency_ms}ms`} tone="amber" />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard
              label="预期决策匹配"
              value={metricValue(summary.expected_control_match_rate)}
              tone={summary.expected_control_match_rate === 100 ? 'green' : 'amber'}
            />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard
              label="因果一致性"
              value={metricValue(summary.causal_integrity_rate)}
              tone={summary.causal_integrity_rate === 100 ? 'green' : 'amber'}
            />
          </Col>
          <Col xs={12} md={8} xl={4}>
            <MetricCard
              label="供应商响应指纹"
              value={metricValue(summary.provider_evidence_coverage_rate)}
              tone={summary.provider_evidence_coverage_rate === 100 ? 'green' : 'amber'}
            />
          </Col>
        </Row>
        <Space wrap>
          <UiButton size="small" onClick={downloadJson}>
            下载 JSON 证据
          </UiButton>
          <UiButton size="small" onClick={downloadMarkdown}>
            下载 Markdown 证据
          </UiButton>
        </Space>
        <UiTable
          dataSource={evaluationData.results}
          rowKey="id"
          size="small"
          pagination={{ pageSize: 6 }}
          columns={[
            {
              title: '样本',
              dataIndex: 'id',
              render: (value: string) => <Typography.Text strong>{value}</Typography.Text>
            },
            {
              title: '标签',
              dataIndex: 'label',
              render: (value: string) => (
                <LabelTag variant="filled" color={value === 'attack' ? 'error' : 'success'}>
                  {value}
                </LabelTag>
              )
            },
            {
              title: '来源',
              key: 'provider',
              render: (_: unknown, item: RealModelEvaluation['results'][number]) =>
                `${item.provider || '-'} / ${item.mode || '-'}`
            },
            {
              title: '工具调用',
              key: 'tool_call',
              render: (_: unknown, item: RealModelEvaluation['results'][number]) => {
                const tools =
                  item.tool_calls?.map((call) => call.tool ?? 'unknown') ??
                  (item.tool_call ? [item.tool_call.tool ?? 'unknown'] : []);
                return <Typography.Text code>{tools.length ? tools.join(' → ') : '未生成'}</Typography.Text>;
              }
            },
            {
              title: '无防护',
              key: 'baseline',
              render: (_: unknown, item: RealModelEvaluation['results'][number]) => (
                <LabelTag variant="filled" color={branchTone(item, 'baseline')}>
                  {branchLabel(item, 'baseline')}
                </LabelTag>
              )
            },
            {
              title: '有防护',
              key: 'guarded',
              render: (_: unknown, item: RealModelEvaluation['results'][number]) => (
                <Space orientation="vertical" size={2}>
                  <LabelTag variant="filled" color={branchTone(item, 'guarded')}>
                    {branchLabel(item, 'guarded')}
                  </LabelTag>
                  <Typography.Text type="secondary" className="zh-text-meta">
                    {item.decision} / {item.guarded?.policy_id ?? '-'}
                  </Typography.Text>
                </Space>
              )
            },
            {
              title: '证据链',
              key: 'evidence',
              render: (_: unknown, item: RealModelEvaluation['results'][number]) => (
                <Space orientation="vertical" size={2}>
                  <LabelTag variant="filled" color={item.receipt_complete ? 'success' : 'warning'}>
                    {item.receipt_complete
                      ? `双分支${Math.max(item.baseline?.step_count ?? 1, item.guarded?.step_count ?? 1)}步回执完整`
                      : item.baseline || item.guarded
                        ? '回执缺失'
                        : '历史报告未记录'}
                  </LabelTag>
                  <Typography.Text
                    type={item.real_model_evidence_valid ? 'success' : 'secondary'}
                    className="zh-text-meta"
                  >
                    {item.real_model_evidence_valid && item.expected_control_match && item.causal_integrity_valid
                      ? '严格证据有效 · 预期与因果均匹配'
                      : (item.evidence_gaps?.[0] ?? `${item.supervisor_latency_ms ?? '-'}ms`)}
                  </Typography.Text>
                </Space>
              )
            }
          ]}
        />
      </Space>
    </PanelCard>
  );
}
