import { useEffect, useState } from 'react';
import { Flex, Typography } from 'antd';
import { ApprovalReviewQueue } from '../components/audit/ApprovalReviewQueue';
import { AlertsPanel } from './AlertsPanel';
import { AuditSummaryCards } from '../components/audit/AuditSummaryCards';
import { ExecutionAuditWorkspace } from '../components/audit/ExecutionAuditWorkspace';
import { useAuditLogViewModel } from '../components/audit/useAuditLogViewModel';
import { PanelCard, UiButton, UiTabs } from '../components/ui';
import { auditDeepLinkEvent, getAuditIdFromHash } from '../components/audit/auditDeepLink';
import type { AlertItem, AuditLog } from '../types';

export function AuditLogPanel({
  logs,
  alerts = [],
  refresh,
  refreshAlerts
}: {
  logs: AuditLog[];
  alerts?: AlertItem[];
  refresh: () => void | Promise<void>;
  refreshAlerts?: () => void | Promise<void>;
}) {
  const view = useAuditLogViewModel({ logs, refresh });
  const [activeTab, setActiveTab] = useState(() => (getAuditIdFromHash() ? 'audit' : 'review'));
  useEffect(() => {
    const openAuditTab = () => {
      if (getAuditIdFromHash()) setActiveTab('audit');
    };
    window.addEventListener('hashchange', openAuditTab);
    window.addEventListener(auditDeepLinkEvent, openAuditTab);
    return () => {
      window.removeEventListener('hashchange', openAuditTab);
      window.removeEventListener(auditDeepLinkEvent, openAuditTab);
    };
  }, []);
  const operationalPendingCount = view.latestReviews.filter(
    (review) => review.status === '待复核' && review.scope === 'operational'
  ).length;
  const reviewWorkspace = (
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
      />
    </div>
  );
  const auditWorkspace = <ExecutionAuditWorkspace view={view} />;

  return (
    <div className="zh-page-stack">
      <PanelCard variant="borderless">
        <Flex justify="space-between" align="center">
          <Typography.Title level={3} className="zh-title-flush">
            安全事件、人工复核与执行审计
          </Typography.Title>
          <UiButton
            onClick={async () => {
              await Promise.all([refresh(), refreshAlerts?.()]);
            }}
          >
            刷新事件
          </UiButton>
        </Flex>
      </PanelCard>
      <UiTabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'review', label: `业务待办（${operationalPendingCount}）`, children: reviewWorkspace },
          {
            key: 'alerts',
            label: `风险事件（${alerts.length}）`,
            children: <AlertsPanel alerts={alerts} refresh={() => void refreshAlerts?.()} embedded />
          },
          { key: 'audit', label: `调用审计（${logs.length}）`, children: auditWorkspace }
        ]}
      />
    </div>
  );
}
