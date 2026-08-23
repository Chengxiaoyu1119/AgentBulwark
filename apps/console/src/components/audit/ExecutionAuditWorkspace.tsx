import { Col, Row, Typography } from 'antd';
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
          <Typography.Text type="secondary">正在定位</Typography.Text>
          <Typography.Text code>{view.activeAuditLinkId}</Typography.Text>
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

      <Row gutter={[24, 24]}>
        <Col xs={24} md={10}>
          <AuditLogList
            logs={view.filteredLogs}
            selectedLogId={view.selectedLogId}
            onSelectLog={view.setSelectedLogId}
          />
        </Col>
        <Col xs={24} md={14}>
          <AuditLogDetail log={view.selectedLog} copied={view.copied} onCopy={view.copyEvidence} />
        </Col>
      </Row>
    </PanelCard>
  );
}
