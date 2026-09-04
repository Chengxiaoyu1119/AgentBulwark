import { UiCol, UiRow, UiTypography } from '../ui';
import { AuditFilterBar } from './AuditFilterBar';
import { AuditLogDetail } from './AuditLogDetail';
import { AuditLogList } from './AuditLogList';
import type { AuditLogViewModel } from './useAuditLogViewModel';
import { PanelCard } from '../ui';

export function ExecutionAuditWorkspace({ view }: { view: AuditLogViewModel }) {
  return (
    <PanelCard variant="borderless">
      {view.activeAuditLinkId ? (
        <div className="zh-audit-locator">
          <UiTypography.Text type="secondary">正在定位</UiTypography.Text>
          <UiTypography.Text code>{view.activeAuditLinkId}</UiTypography.Text>
        </div>
      ) : null}

      <AuditFilterBar
        query={view.query}
        decisionFilter={view.decisionFilter}
        riskFilter={view.riskFilter}
        riskScoreFilter={view.riskScoreFilter}
        toolFilter={view.toolFilter}
        executionFilter={view.executionFilter}
        tools={view.tools}
        copiedFiltered={view.copiedFiltered}
        onQueryChange={view.setQuery}
        onDecisionFilterChange={view.setDecisionFilter}
        onRiskFilterChange={view.setRiskFilter}
        onRiskScoreFilterChange={view.setRiskScoreFilter}
        onToolFilterChange={view.setToolFilter}
        onExecutionFilterChange={view.setExecutionFilter}
        onReset={view.resetAuditFilters}
        onCopyFiltered={view.copyFilteredAuditEvidence}
      />

      <UiRow gutter={[24, 24]}>
        <UiCol xs={24} md={10}>
          <AuditLogList
            logs={view.filteredLogs}
            selectedLogId={view.selectedLogId}
            onSelectLog={view.setSelectedLogId}
          />
        </UiCol>
        <UiCol xs={24} md={14}>
          <AuditLogDetail log={view.selectedLog} copied={view.copied} onCopy={view.copyEvidence} />
        </UiCol>
      </UiRow>
    </PanelCard>
  );
}
