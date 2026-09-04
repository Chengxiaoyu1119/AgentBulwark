import { useCallback, useEffect, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { fetchAuditLogs, fetchExecutionInventory } from '../app/operationalApi';
import { safeUiErrorSummary } from '../app/apiRequestSupport';
import { useRuntimeEventRefresh } from '../app/useRuntimeEventRefresh';
import { ApprovalReviewQueue } from '../components/audit/ApprovalReviewQueue';
import { AuditSummaryCards } from '../components/audit/AuditSummaryCards';
import { ExecutionAuditWorkspace } from '../components/audit/ExecutionAuditWorkspace';
import { ExecutionReconciliationPanel } from '../components/audit/ExecutionReconciliationPanel';
import { useAuditLogViewModel } from '../components/audit/useAuditLogViewModel';
import { GatewayTracePanel } from '../components/gateway/GatewayTracePanel';
import {
  PageHeader,
  RuntimeConnectionBadge,
  RuntimeConnectionNotice,
  UiAlert,
  UiButton,
  UiStack,
  UiTabs
} from '../components/ui';
import type { AuthContext, AuditLog, ExecutionInventory } from '../types';

type EventTab = 'events' | 'reviews' | 'audit';

export function SecurityEventsPanel({ authContext }: { authContext: AuthContext }) {
  const [activeTab, setActiveTab] = useState<EventTab>('events');
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [executionInventory, setExecutionInventory] = useState<ExecutionInventory | null>(null);
  const [executionInventoryError, setExecutionInventoryError] = useState('');
  const [focusedApprovalAuditId, setFocusedApprovalAuditId] = useState('');
  const auditRequestSequence = useRef(0);

  const loadAuditLogs = useCallback(async () => {
    const sequence = ++auditRequestSequence.current;
    setLoading(true);
    setError('');
    setExecutionInventoryError('');
    const canInspectExecutionInventory = authContext.permissions.can_review_approval;
    const [auditResult, inventoryResult] = await Promise.allSettled([
      fetchAuditLogs(200),
      canInspectExecutionInventory ? fetchExecutionInventory(200) : Promise.resolve(null)
    ]);
    if (sequence !== auditRequestSequence.current) return;

    if (auditResult.status === 'fulfilled') {
      setLogs(auditResult.value);
    } else {
      // Once the live read fails, discard the previous snapshot. Keeping it on
      // screen would make stale audit evidence look current beside the error.
      setLogs([]);
      setError(safeUiErrorSummary(auditResult.reason, '执行审计读取失败。'));
    }

    if (inventoryResult.status === 'fulfilled') {
      setExecutionInventory(inventoryResult.value);
    } else {
      setExecutionInventory(null);
      setExecutionInventoryError(safeUiErrorSummary(inventoryResult.reason, '执行核查清单读取失败。'));
    }
    setLoading(false);
  }, [authContext.permissions.can_review_approval]);

  const liveConnection = useRuntimeEventRefresh(loadAuditLogs);

  const view = useAuditLogViewModel({ logs, refresh: loadAuditLogs });
  const operationalPendingCount = view.latestReviews.filter(
    (review) => review.status === '待复核' && review.scope === 'operational'
  ).length;
  const unknownExecutionCount = executionInventory?.summary.gateway_unknown ?? 0;

  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) void loadAuditLogs();
    });
    return () => {
      cancelled = true;
    };
  }, [loadAuditLogs]);

  function openApproval(auditId: string) {
    setFocusedApprovalAuditId(auditId);
    setActiveTab('reviews');
    void view.loadApprovalReviews();
  }

  return (
    <div className="zh-product-page">
      <PageHeader
        title="安全事件"
        description="处置风险请求、人工复核和工具执行回执。"
        actions={
          <UiStack direction="horizontal" align="center" gap="sm" wrap>
            <RuntimeConnectionBadge connection={liveConnection} />
            <UiButton icon={<RefreshCw size={16} />} loading={loading} onClick={() => void loadAuditLogs()}>
              刷新事件
            </UiButton>
          </UiStack>
        }
      />

      <RuntimeConnectionNotice connection={liveConnection} />
      {error ? <UiAlert type="warning" showIcon title={error} /> : null}

      <UiTabs
        className="zh-product-tabs"
        activeKey={activeTab}
        onChange={(key) => setActiveTab(key as EventTab)}
        items={[
          {
            key: 'events',
            label: '风险事件',
            children: (
              <GatewayTracePanel
                mode="events"
                pendingApprovalCount={view.approvalError ? '—' : view.approvalQueue.summary.pending_count}
                onOpenApproval={openApproval}
              />
            )
          },
          {
            key: 'reviews',
            label: `待人工复核（${operationalPendingCount}）`,
            children: (
              <UiStack gap="lg">
                <AuditSummaryCards
                  total={logs.length}
                  controlledCount={view.controlledCount}
                  highRiskCount={view.highRiskCount}
                  executedCount={view.executedCount}
                  receiptCount={view.receiptCount}
                  unconfirmedCount={view.unconfirmedCount}
                />
                <ApprovalReviewQueue
                  queue={view.approvalQueue}
                  reviews={view.latestReviews}
                  loading={view.approvalLoading}
                  error={view.approvalError}
                  busyId={view.approvalBusyId}
                  copiedApprovalId={view.copiedApprovalId}
                  onRefresh={view.loadApprovalReviews}
                  onDecision={view.handleApprovalDecision}
                  onCopy={view.copyApprovalEvidence}
                  focusAuditId={focusedApprovalAuditId}
                  onClearFocus={() => setFocusedApprovalAuditId('')}
                />
              </UiStack>
            )
          },
          {
            key: 'audit',
            label: `执行审计（${logs.length}${unknownExecutionCount ? ` · 待核查 ${unknownExecutionCount}` : ''}）`,
            children: (
              <UiStack gap="lg">
                {authContext.permissions.can_review_approval ? (
                  <ExecutionReconciliationPanel inventory={executionInventory} error={executionInventoryError} />
                ) : null}
                <ExecutionAuditWorkspace view={view} />
              </UiStack>
            )
          }
        ]}
      />
    </div>
  );
}
