import { useState } from 'react';
import { Col, Flex, Row, Space, Typography } from 'antd';
import { RefreshCw } from 'lucide-react';
import { runAttackEffectivenessEvidence, writeProjectRoadmapEvidence } from '@/api';
import { LabelTag, MetricCard as Metric, PanelCard, SectionTitle, UiAlert, UiButton, UiProgress } from '../ui';
import type { ReportData } from '@/types';
import type { PageKey } from '@/app/navigation';
import { AnomalyCalibrationBlock } from './AnomalyCalibrationBlock';
import { ProjectRoadmapBlock } from './ProjectRoadmapBlock';
import { ReportMaturityActions } from './ReportMaturityActions';
import { ReportOverviewSurfaceDistribution } from './ReportOverviewSurfaceDistribution';
import { RealModelEvidencePanel } from './RealModelEvidencePanel';

type ReportOverviewTabProps = {
  report: ReportData;
  onRefreshReport?: () => Promise<void> | void;
  onRefreshRuntime?: () => Promise<unknown> | void;
  onOpenPage?: (page: PageKey) => void;
};

const policyLabelMap: Record<string, string> = {
  'external-mail': '外部收件复核',
  'sensitive-api': '敏感接口拒绝',
  'jailbreak-filter': '越狱过滤',
  'model-output-filter': '输出过滤',
  'bulk-action-review': '批量操作复核',
  'tool-return-trust': '工具返回隔离',
  'environment-trust': '环境信任降级',
  'memory-write': '记忆写入隔离',
  'memory-read-sensitive': '敏感记忆读取控制',
  'path-boundary': '路径边界控制',
  'guard-disabled': '未启用防护'
};

function policyLabel(policyId?: string) {
  if (!policyId) {
    return '未记录策略';
  }
  return policyLabelMap[policyId] ?? policyId;
}

export function ReportOverviewTab({ report, onRefreshReport, onRefreshRuntime, onOpenPage }: ReportOverviewTabProps) {
  const [isRerunningCoreEvidence, setIsRerunningCoreEvidence] = useState(false);
  const [coreEvidenceNotice, setCoreEvidenceNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  );
  const coreMetrics = [
    {
      label: '防护控制率',
      value: report.summary.control_rate,
      color: 'var(--ant-color-success)',
      description: '22 个固定攻击脚本在有防护分支中成功阻断副作用的比例。'
    },
    {
      label: '攻击成功率',
      value: report.summary.attack_success_rate,
      color: 'var(--ant-color-error)',
      description: '无防护对照中的暴露比例，用来证明攻击样本确实能复现，不代表防护失败。'
    },
    {
      label: '正常业务任务误报率',
      value: report.summary.false_positive_rate,
      color: 'var(--ant-color-warning)',
      description: '正常业务工具调用被误拦的比例，越低说明系统越不影响正常使用。'
    },
    {
      label: '期望决策匹配率',
      value: report.summary.expected_match_rate,
      color: 'var(--ant-color-info)',
      description: '监督器最终动作与样本预期动作一致的比例，用来衡量策略稳定性。'
    },
    {
      label: '输出过滤阻断率',
      value: report.summary.output_filter_block_rate,
      color: 'var(--ant-color-success)',
      description: '模型输出触发泄露、滥用或越权内容过滤的比例。'
    },
    {
      label: '策略启用率',
      value: Math.round((report.summary.enabled_policy_count / Math.max(1, report.summary.policy_count)) * 100),
      color: 'var(--ant-color-info)',
      description: '当前策略库中已经参与运行判定的策略比例。'
    }
  ];

  async function handleRerunCoreEvidence() {
    setIsRerunningCoreEvidence(true);
    setCoreEvidenceNotice(null);
    try {
      const result = await runAttackEffectivenessEvidence();
      await writeProjectRoadmapEvidence();
      await Promise.all([Promise.resolve(onRefreshReport?.()), Promise.resolve(onRefreshRuntime?.())]);
      setCoreEvidenceNotice({
        type: 'success',
        message: `攻防证据已补跑：${result.run_result.summary.total} 个脚本，控制率 ${result.run_result.summary.control_rate}%。`
      });
    } catch (error) {
      setCoreEvidenceNotice({
        type: 'error',
        message: `攻防证据补跑失败：${error instanceof Error ? error.message : '未知错误'}`
      });
    } finally {
      setIsRerunningCoreEvidence(false);
    }
  }

  return (
    <Space orientation="vertical" size="large" className="zh-tab-stack">
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={8} lg={4}>
          <Metric label="攻击面覆盖" value={`${report.summary.surface_count}/7`} tone="cyan" />
        </Col>
        <Col xs={24} sm={12} md={8} lg={4}>
          <Metric label="攻击脚本" value={`${report.summary.scenario_count}`} tone="amber" />
        </Col>
        <Col xs={24} sm={12} md={8} lg={4}>
          <Metric label="固定脚本防护率" value={`${report.summary.control_rate}%`} tone="green" />
        </Col>
        <Col xs={24} sm={12} md={8} lg={4}>
          <Metric
            label="正常误报率"
            value={`${report.summary.false_positive_rate}%`}
            tone={report.summary.false_positive_rate ? 'amber' : 'green'}
          />
        </Col>
        <Col xs={24} sm={12} md={8} lg={4}>
          <Metric
            label="异常召回率"
            value={`${report.summary.anomaly_attack_recall_rate ?? report.anomaly_calibration?.summary.attack_recall_rate ?? 0}%`}
            tone="cyan"
          />
        </Col>
        <Col xs={24} sm={12} md={8} lg={4}>
          <Metric label="实时事件均延迟" value={`${report.summary.avg_latency_ms}ms`} tone="red" />
        </Col>
      </Row>
      <ReportMaturityActions onRefreshReport={onRefreshReport} onRefreshRuntime={onRefreshRuntime} />
      <RealModelEvidencePanel evaluation={report.real_model_evaluation} />
      {report.project_roadmap && <ProjectRoadmapBlock roadmap={report.project_roadmap} onOpenPage={onOpenPage} />}
      {report.anomaly_calibration && (
        <AnomalyCalibrationBlock
          calibration={report.anomaly_calibration}
          onRefreshReport={onRefreshReport}
          onRefreshRuntime={onRefreshRuntime}
        />
      )}
      <Row gutter={[24, 24]}>
        <Col xs={24} lg={13}>
          <PanelCard
            title={<SectionTitle title="核心评测曲线" meta={`固定脚本证据 + ${report.summary.run_count} 条实时运行`} />}
            variant="borderless"
            className="zh-full-height"
          >
            <Space orientation="vertical" className="zh-full-width zh-report-curve-stack">
              <div className="zh-report-card-toolbar">
                <Typography.Text type="secondary">
                  攻防指标取每个固定脚本最新对照；平均延迟取近期实时运行，两个口径互不混用。
                </Typography.Text>
                <UiButton
                  size="small"
                  icon={<RefreshCw size={15} />}
                  loading={isRerunningCoreEvidence}
                  onClick={() => {
                    void handleRerunCoreEvidence();
                  }}
                >
                  补跑攻防证据
                </UiButton>
              </div>
              {coreEvidenceNotice && (
                <UiAlert type={coreEvidenceNotice.type} message={coreEvidenceNotice.message} showIcon />
              )}
              {coreMetrics.map((item) => (
                <div key={item.label} className="zh-report-metric-row">
                  <Flex justify="space-between" align="center" gap={12}>
                    <Typography.Text strong>{item.label}</Typography.Text>
                    <Typography.Text strong>{item.value}%</Typography.Text>
                  </Flex>
                  <UiProgress
                    percent={Math.min(100, Math.max(0, item.value))}
                    showInfo={false}
                    strokeColor={item.color}
                    size="small"
                  />
                  <Typography.Text type="secondary" className="zh-text-meta">
                    {item.description}
                  </Typography.Text>
                </div>
              ))}
            </Space>
          </PanelCard>
        </Col>
        <Col xs={24} lg={11}>
          <ReportOverviewSurfaceDistribution report={report} onOpenPage={onOpenPage} />
        </Col>
      </Row>
      <Row gutter={[24, 24]}>
        <Col xs={24} lg={12}>
          <PanelCard
            title={<SectionTitle title="成果能力对齐" meta={`${report.deliverables.length} 项`} />}
            variant="borderless"
            className="zh-full-height"
          >
            <div className="zh-column-stack">
              {report.deliverables.map((item, idx) => (
                <div key={idx} className="zh-report-list-item zh-report-list-item--deliverable">
                  <div className="zh-report-list-main">
                    <div className="zh-pt-4">
                      <span className="zh-report-dot" />
                    </div>
                    <div>
                      <div>
                        <Typography.Text strong>{item.name}</Typography.Text>
                      </div>
                      <div className="zh-mt-4">
                        <Typography.Text type="secondary">{item.evidence}</Typography.Text>
                      </div>
                    </div>
                  </div>
                  <LabelTag color="blue" className="zh-report-status-tag">
                    {item.status}
                  </LabelTag>
                </div>
              ))}
              {!report.deliverables.length && <div className="zh-empty-panel">暂无数据</div>}
            </div>
          </PanelCard>
        </Col>
        <Col xs={24} lg={12}>
          <PanelCard
            title={<SectionTitle title="策略命中统计" meta={`${report.policy_hits.length || 0} 类策略`} />}
            variant="borderless"
            className="zh-full-height"
          >
            <div className="zh-column-stack">
              {report.policy_hits.map((item, idx) => (
                <div key={idx} className="zh-report-list-item">
                  <Typography.Text>{policyLabel(item.policy_id)}</Typography.Text>
                  <Typography.Text strong>{item.count}</Typography.Text>
                </div>
              ))}
              {!report.policy_hits.length && (
                <div className="zh-empty-panel">暂无策略命中记录，先运行一次攻击脚本。</div>
              )}
            </div>
          </PanelCard>
        </Col>
      </Row>
    </Space>
  );
}
