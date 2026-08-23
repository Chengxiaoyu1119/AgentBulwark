import { useCallback, useEffect, useRef, useState } from 'react';
import { Typography } from 'antd';
import { RefreshCw } from 'lucide-react';
import { fetchAuditLogs, subscribeRuntimeEvents } from '../api';
import { ApprovalReviewQueue } from '../components/audit/ApprovalReviewQueue';
import { AuditSummaryCards } from '../components/audit/AuditSummaryCards';
import { ExecutionAuditWorkspace } from '../components/audit/ExecutionAuditWorkspace';
import { useAuditLogViewModel } from '../components/audit/useAuditLogViewModel';
import { GatewayTracePanel } from '../components/settings/GatewayTracePanel';
import { UiAlert, UiButton, UiTabs } from '../components/ui';
import type { AuditLog } from '../types';

type EventTab = 'events' | 'reviews' | 'audit';

export function SecurityEventsPanel() {
  const [activeTab, setActiveTab] = useState<EventTab>('events');
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [focusedApprovalAuditId, setFocusedApprovalAuditId] = useState('');
  const refreshTimerRef = useRef<number | undefined>(undefined);

  const loadAuditLogs = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setLogs(await fetchAuditLogs(200));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : '执行审计读取失败。');
    } finally {
      setLoading(false);
    }
  }, []);

  const view = useAuditLogViewModel({ logs, refresh: loadAuditLogs });
  const operationalPendingCount = view.latestReviews.filter(
    (review) => review.status === '待复核' && review.scope === 'operational'
  ).length;

  useEffect(() => {
    const timer = window.setTimeout(() => void loadAuditLogs(), 0);
    return () => window.clearTimeout(timer);
  }, [loadAuditLogs]);

  useEffect(() => {
    let stopped = false;
    let controller: AbortController | undefined;

    const connect = async () => {
      while (!stopped) {
        controller = new AbortController();
        try {
          await subscribeRuntimeEvents(() => {
            if (refreshTimerRef.current !== undefined) window.clearTimeout(refreshTimerRef.current);
            refreshTimerRef.current = window.setTimeout(() => void loadAuditLogs(), 250);
          }, controller.signal);
        } catch {
          // Explicit refresh remains available while the event stream reconnects.
        }
        if (!stopped) await new Promise((resolve) => window.setTimeout(resolve, 1500));
      }
    };

    void connect();
    return () => {
      stopped = true;
      controller?.abort();
      if (refreshTimerRef.current !== undefined) window.clearTimeout(refreshTimerRef.current);
    };
  }, [loadAuditLogs]);

  function openApproval(auditId: string) {
    setFocusedApprovalAuditId(auditId);
    setActiveTab('reviews');
    void view.loadApprovalReviews();
  }

  return (
    <div className="zh-product-page">
      <header className="zh-product-heading">
        <div>
          <Typography.Title level={1}>安全事件</Typography.Title>
          <Typography.Text type="secondary">处置风险请求、人工复核和工具执行回执。</Typography.Text>
        </div>
        <UiButton icon={<RefreshCw size={16} />} loading={loading} onClick={() => void loadAuditLogs()}>
          刷新事件
        </UiButton>
      </header>

      {error ? <UiAlert type="warning" showIcon title={error} /> : null}

      <UiTabs
        className="zh-product-tabs"
        activeKey={activeTab}
        onChange={(key) => setActiveTab(key as EventTab)}
        items={[
          {
            key: 'events',
            label: '风险事件',
            children: <GatewayTracePanel mode="events" onOpenApproval={openApproval} />
          },
          {
            key: 'reviews',
            label: `待人工复核（${operationalPendingCount}）`,
            children: (
              <div className="zh-page-stack">
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
              </div>
            )
          },
          {
            key: 'audit',
            label: `执行审计（${logs.length}）`,
            children: <ExecutionAuditWorkspace view={view} />
          }
        ]}
      />
    </div>
  );
}
