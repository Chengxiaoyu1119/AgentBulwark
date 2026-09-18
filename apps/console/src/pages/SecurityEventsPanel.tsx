import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
import type { RuntimeEventConnection } from '../app/runtimeEventConnection';
import { PageHeader, RuntimeConnectionNotice, UiAlert, UiButton, UiStack, UiSelect, UiTabs } from '../components/ui';
import type { AuthContext, AuditLog, ExecutionInventory } from '../types';

type EventTab = 'events' | 'reviews' | 'audit';
type EventWindowKey = '1h' | '6h' | '24h' | '7d' | 'all';

const EVENT_WINDOW_SECONDS: Record<Exclude<EventWindowKey, 'all'>, number> = {
  '1h': 60 * 60,
  '6h': 6 * 60 * 60,
  '24h': 24 * 60 * 60,
  '7d': 7 * 24 * 60 * 60
};

export function SecurityEventsPanel({
  authContext,
  liveConnection: externalLiveConnection,
  refreshSignal = ''
}: {
  authContext: AuthContext;
  liveConnection?: RuntimeEventConnection;
  refreshSignal?: string;
}) {
  const [activeTab, setActiveTab] = useState<EventTab>('events');
  const [eventWindow, setEventWindow] = useState<EventWindowKey>('1h');
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

  const ownLiveConnection = useRuntimeEventRefresh(loadAuditLogs, { enabled: !externalLiveConnection });
  const liveConnection = externalLiveConnection ?? ownLiveConnection;
  // The SSE revision intentionally invalidates this rolling window's end timestamp.
  const eventTimeWindow = useMemo(() => {
    if (eventWindow === 'all') return undefined;
    const end = new Date();
    const start = new Date(end.getTime() - EVENT_WINDOW_SECONDS[eventWindow] * 1000);
    return { start_at: start.toISOString(), end_at: end.toISOString() };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refreshSignal rolls the window forward.
  }, [eventWindow, refreshSignal]);

  const view = useAuditLogViewModel({ logs, refresh: loadAuditLogs });
  const operationalPendingCount = view.latestReviews.filter((review) => review.status === '待复核').length;
  const unknownExecutionCount = executionInventory?.summary.gateway_unknown ?? 0;

  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) void loadAuditLogs();
    });
    return () => {
      cancelled = true;
    };
  }, [loadAuditLogs, refreshSignal]);

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
            {activeTab === 'events' ? (
              <UiSelect
                aria-label="事件时间范围"
                size="small"
                value={eventWindow}
                onChange={(value) => setEventWindow(value as EventWindowKey)}
                options={[
                  { value: '1h', label: '近 1 小时' },
                  { value: '6h', label: '近 6 小时' },
                  { value: '24h', label: '近 24 小时' },
                  { value: '7d', label: '近 7 天' },
                  { value: 'all', label: '全部历史' }
                ]}
              />
            ) : null}
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
                refreshSignal={refreshSignal}
                timeWindow={eventTimeWindow}
                liveConnection={liveConnection}
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
            label: unknownExecutionCount ? `执行审计（待核查 ${unknownExecutionCount}）` : '执行审计',
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
