import { useState, type ReactNode } from 'react';
import { Space, Typography } from 'antd';
import { Activity, BrainCircuit, FileDown, Play, PlugZap, RefreshCw, ShieldCheck } from 'lucide-react';
import {
  runDemoDrill,
  runGapRerunEvidence,
  runAttackEffectivenessEvidence,
  writeCompetitionReadiness,
  writeAnomalyCalibrationEvidence,
  writeBriefingSheetExports,
  writeOpenClawPluginPackage,
  writeOpenClawPluginValidation,
  writeProjectRoadmapEvidence,
  writeRealModelEvaluationEvidence
} from '@/api';
import { PanelCard, UiAlert, UiButton } from '../ui';

type ReportMaturityActionsProps = {
  onRefreshReport?: () => Promise<void> | void;
  onRefreshRuntime?: () => Promise<unknown> | void;
};

type ActionId = 'attack' | 'gap-rerun' | 'demo-readiness' | 'calibration' | 'openclaw' | 'brief-export' | 'real-model';

type Notice = {
  type: 'success' | 'error' | 'info';
  message: string;
  description?: ReactNode;
};

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

async function refreshReportData(
  onRefreshReport?: () => Promise<void> | void,
  onRefreshRuntime?: () => Promise<unknown> | void
) {
  await Promise.all([Promise.resolve(onRefreshReport?.()), Promise.resolve(onRefreshRuntime?.())]);
}

export function ReportMaturityActions({ onRefreshReport, onRefreshRuntime }: ReportMaturityActionsProps) {
  const [runningAction, setRunningAction] = useState<ActionId | ''>('');
  const [notice, setNotice] = useState<Notice | null>(null);

  async function runAction(action: ActionId, handler: () => Promise<Notice | string>) {
    setRunningAction(action);
    setNotice(null);
    try {
      const result = await handler();
      await refreshReportData(onRefreshReport, onRefreshRuntime);
      setNotice(typeof result === 'string' ? { type: 'success', message: result } : result);
    } catch (error) {
      setNotice({ type: 'error', message: `补证失败：${errorMessage(error, '未知错误')}` });
    } finally {
      setRunningAction('');
    }
  }

  return (
    <PanelCard variant="borderless" className="zh-report-action-panel">
      <div className="zh-report-action-row">
        <div className="zh-report-action-copy">
          <Typography.Text strong>成熟度补证操作</Typography.Text>
          <Typography.Text type="secondary">
            针对当前报告里的缺口直接运行后端评测，刷新本地证据文件和成熟度结果。
          </Typography.Text>
        </div>
        <Space wrap className="zh-report-action-buttons">
          <UiButton
            icon={<ShieldCheck size={16} />}
            loading={runningAction === 'attack'}
            disabled={Boolean(runningAction)}
            onClick={() => {
              void runAction('attack', async () => {
                const result = await runAttackEffectivenessEvidence();
                await writeProjectRoadmapEvidence();
                return `已补跑 ${result.run_result.summary.total} 个攻防脚本，对照控制率 ${result.run_result.summary.control_rate}%。`;
              });
            }}
          >
            补齐攻防证据
          </UiButton>
          <UiButton
            variant="primary"
            icon={<RefreshCw size={16} />}
            loading={runningAction === 'gap-rerun'}
            disabled={Boolean(runningAction)}
            onClick={() => {
              void runAction('gap-rerun', async () => {
                const result = await runGapRerunEvidence();
                const targetCount = result.target_scenario_ids.length;
                return `缺口补跑完成：补跑 ${targetCount} 个脚本，证据缺口 ${result.before.evidence_gap_count} -> ${result.after.evidence_gap_count}，成熟度 ${result.after.roadmap_score}%。`;
              });
            }}
          >
            一键补跑缺口
          </UiButton>
          <UiButton
            icon={<Play size={16} />}
            loading={runningAction === 'demo-readiness'}
            disabled={Boolean(runningAction)}
            onClick={() => {
              void runAction('demo-readiness', async () => {
                const demo = await runDemoDrill();
                const readiness = await writeCompetitionReadiness();
                return `闭环复现已生成 ${demo.summary.stage_count} 步记录；体检得分 ${readiness.readiness_score}%，通过 ${readiness.summary.passed_count}/${readiness.summary.check_count}，需补强 ${readiness.summary.warning_count}，阻塞 ${readiness.summary.blocker_count}。`;
              });
            }}
          >
            运行闭环体检
          </UiButton>
          <UiButton
            icon={<Activity size={16} />}
            loading={runningAction === 'calibration'}
            disabled={Boolean(runningAction)}
            onClick={() => {
              void runAction('calibration', async () => {
                const result = await writeAnomalyCalibrationEvidence();
                await writeProjectRoadmapEvidence();
                const threshold = result.summary?.recommended_threshold ?? '-';
                return `异常阈值校准报告已生成，推荐阈值 ${threshold}，成熟度路线图已刷新。`;
              });
            }}
          >
            生成校准报告
          </UiButton>
          <UiButton
            icon={<PlugZap size={16} />}
            loading={runningAction === 'openclaw'}
            disabled={Boolean(runningAction)}
            onClick={() => {
              void runAction('openclaw', async () => {
                await writeOpenClawPluginPackage();
                const validation = await writeOpenClawPluginValidation();
                await writeProjectRoadmapEvidence();
                return `OpenClaw 插件包已生成，验收状态：${validation.validation.overall_status}。如服务器安装了 OpenClaw CLI，会同步执行 runtime inspect。`;
              });
            }}
          >
            OpenClaw 插件验收
          </UiButton>
          <UiButton
            icon={<FileDown size={16} />}
            loading={runningAction === 'brief-export'}
            disabled={Boolean(runningAction)}
            onClick={() => {
              void runAction('brief-export', async () => {
                const result = await writeBriefingSheetExports('both');
                await writeProjectRoadmapEvidence();
                if (!result.ok) {
                  throw new Error(result.reason || '攻击面评测单页导出失败');
                }
                const firstFile = result.export.files?.[0];
                return {
                  type: 'success',
                  message: `攻击面评测单页导出完成：PNG ${result.summary.png_count} 个，PDF ${result.summary.pdf_count} 个。`,
                  description: (
                    <Space wrap className="zh-report-action-notice-links">
                      <UiButton size="small" authenticatedHref="/api/attack_surfaces/briefing_sheets/export.md">
                        打开导出报告
                      </UiButton>
                      {firstFile && (
                        <>
                          <UiButton
                            size="small"
                            authenticatedHref={`/api/attack_surfaces/briefing_sheets/export/files/${encodeURIComponent(firstFile.surface_id)}.png`}
                          >
                            预览首张 PNG
                          </UiButton>
                          <UiButton
                            size="small"
                            authenticatedHref={`/api/attack_surfaces/briefing_sheets/export/files/${encodeURIComponent(firstFile.surface_id)}.pdf`}
                          >
                            打开首份 PDF
                          </UiButton>
                        </>
                      )}
                    </Space>
                  )
                };
              });
            }}
          >
            导出评测单页
          </UiButton>
          <UiButton
            variant="primary"
            icon={<BrainCircuit size={16} />}
            loading={runningAction === 'real-model'}
            disabled={Boolean(runningAction)}
            onClick={() => {
              void runAction('real-model', async () => {
                const result = await writeRealModelEvaluationEvidence(true);
                await writeProjectRoadmapEvidence();
                const cases = result.summary?.case_count ?? 0;
                const realCases = result.summary?.real_api_case_count ?? 0;
                const strictReady = result.summary?.strict_real_api_ready === true;
                return {
                  type: strictReady ? 'success' : 'info',
                  message: `真实模型因果盲测已生成：${cases} 个样本，其中真实 API 样本 ${realCases} 个，严格证据${strictReady ? '通过' : '未通过'}。`,
                  description: `无防护攻击复现率 ${result.summary?.attack_reproduced_rate ?? 0}%，有防护有效控制率 ${result.summary?.defense_effective_rate ?? 0}%，双分支回执完整率 ${result.summary?.receipt_complete_rate ?? 0}%，任务工具对齐率 ${result.summary?.task_alignment_rate ?? 0}%。`
                };
              });
            }}
          >
            运行真实模型盲测
          </UiButton>
        </Space>
      </div>
      {notice && (
        <UiAlert
          className="zh-mt-16"
          type={notice.type}
          message={notice.message}
          description={notice.description}
          showIcon
        />
      )}
    </PanelCard>
  );
}
