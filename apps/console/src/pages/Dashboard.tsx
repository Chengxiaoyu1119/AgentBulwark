import type { Overview } from '../types';
import { DashboardOverviewTab } from '../components/dashboard';
import type { PageKey } from '../app/navigation';

function isGatewayAudit(log: Overview['audit_logs'][number]) {
  const stage = log.stage_context ?? {};
  return Boolean(
    stage.request_id ||
    stage.provider_request_hash ||
    stage.gateway_contract_evidence ||
    stage.source_app === 'openai-compatible-proxy' ||
    stage.source_app === 'mcp-gateway'
  );
}

export function Dashboard({
  overview,
  apiAvailable,
  onOpenPage
}: {
  overview: Overview;
  apiAvailable: boolean | null;
  onOpenPage: (page: PageKey) => void;
}) {
  // The overview also contains historical supervisor/fixture events.  Mixing
  // those with live gateway stages makes the headline look like a production
  // success rate even when no real Provider has been reached.  Keep the main
  // surface scoped to events that carry an explicit gateway stage marker.
  const gatewayAuditLogs = overview.audit_logs.filter(isGatewayAudit);
  const controlledLogs = gatewayAuditLogs.filter((log) => ['拒绝', '询问', '隔离'].includes(log.decision)).length;
  const preProviderBlocks = gatewayAuditLogs.filter(
    (log) => log.stage_context?.provider_called === false && ['拒绝', '询问', '隔离'].includes(log.decision)
  ).length;
  const serverReceipts = gatewayAuditLogs.filter((log) => Boolean(log.execution_receipt)).length;
  const pendingGatewayReceipts = gatewayAuditLogs.filter(
    (log) => log.execution_receipt_expected && !log.execution_receipt
  ).length;
  const gatewayControlRate = gatewayAuditLogs.length
    ? Math.round((controlledLogs / gatewayAuditLogs.length) * 100)
    : null;
  const maxRiskScore = Math.max(
    0,
    ...overview.audit_logs.map((log) => log.risk_score ?? 0),
    ...overview.alerts.map((alert) => alert.risk_score ?? 0)
  );
  const latestAlert = overview.alerts[0];
  const pipelineNodes = [
    { label: '网关审计请求', value: `${gatewayAuditLogs.length}` },
    { label: 'Provider 前阻断', value: `${preProviderBlocks}` },
    { label: '工具调用控制', value: `${controlledLogs}` },
    { label: '服务端执行回执', value: `${serverReceipts}` },
    {
      label: '真实模型连接',
      value: `${overview.models.filter((model) => model.configured && model.mode === 'real-api').length}`
    }
  ];

  return (
    <div className="zh-page-stack">
      <DashboardOverviewTab
        overview={overview}
        apiAvailable={apiAvailable}
        maxRiskScore={maxRiskScore}
        latestAlert={latestAlert}
        gatewayAuditCount={gatewayAuditLogs.length}
        gatewayControlRate={gatewayControlRate}
        gatewayPendingReceiptCount={pendingGatewayReceipts}
        pipelineNodes={pipelineNodes}
        onOpenPage={onOpenPage}
      />
    </div>
  );
}
