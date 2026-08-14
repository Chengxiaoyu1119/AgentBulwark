import type { Overview } from '../types';
import { DashboardOverviewTab } from '../components/dashboard';
import type { PageKey } from '../app/navigation';

export function Dashboard({
  overview,
  apiAvailable,
  running,
  onSelectScenario,
  onOpenPage,
  onBatchCompare: _onBatchCompare
}: {
  overview: Overview;
  apiAvailable: boolean | null;
  running: boolean;
  onSelectScenario: (id: string) => void;
  onOpenPage: (page: PageKey) => void;
  onBatchCompare: (ids: string[], label: string) => void;
}) {
  void _onBatchCompare;
  const totalSamples = overview.attack_surfaces.reduce((sum, surface) => sum + surface.samples, 0);
  const totalScripts = overview.summary.scenario_count;
  const highRiskSurfaceCount = overview.attack_surfaces.filter((surface) =>
    ['critical', 'high'].includes(surface.risk)
  ).length;
  const completeSurfaceCount = overview.attack_surfaces.filter(
    (surface) =>
      surface.entry_points?.length &&
      surface.protected_assets?.length &&
      surface.detection_signals?.length &&
      surface.evaluation_focus?.length
  ).length;
  const controlledLogs = overview.audit_logs.filter((log) => ['拒绝', '询问', '隔离'].includes(log.decision)).length;
  const maxRiskScore = Math.max(
    0,
    ...overview.audit_logs.map((log) => log.risk_score ?? 0),
    ...overview.alerts.map((alert) => alert.risk_score ?? 0)
  );
  const latestAlert = overview.alerts[0];
  const priorityScenario =
    overview.scenarios.find((scenario) => scenario.severity === 'critical') ?? overview.scenarios[0];
  const pipelineNodes = [
    { label: '近期工具调用', value: `${overview.audit_logs.length}` },
    { label: '风险控制动作', value: `${controlledLogs}` },
    { label: '待处理告警', value: `${overview.alerts.length}` },
    { label: '已覆盖风险面', value: `${completeSurfaceCount}` },
    { label: '已接入模型', value: `${overview.models.filter((model) => model.configured).length}` }
  ];

  return (
    <div className="zh-page-stack">
      <DashboardOverviewTab
        overview={overview}
        apiAvailable={apiAvailable}
        running={running}
        priorityScenario={priorityScenario}
        maxRiskScore={maxRiskScore}
        latestAlert={latestAlert}
        completeSurfaceCount={completeSurfaceCount}
        totalSamples={totalSamples}
        totalScripts={totalScripts}
        highRiskSurfaceCount={highRiskSurfaceCount}
        pipelineNodes={pipelineNodes}
        onSelectScenario={onSelectScenario}
        onOpenPage={onOpenPage}
      />
    </div>
  );
}
