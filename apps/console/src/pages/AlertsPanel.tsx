import { Col, Flex, Row, Typography } from 'antd';
import { AlertDetail } from '../components/alerts/AlertDetail';
import { AlertFilterBar } from '../components/alerts/AlertFilterBar';
import { AlertList } from '../components/alerts/AlertList';
import { AlertSummaryCards } from '../components/alerts/AlertSummaryCards';
import { useAlertsViewModel } from '../components/alerts/useAlertsViewModel';
import { PanelCard, UiButton } from '../components/ui';
import type { AlertItem } from '../types';

export function AlertsPanel({
  alerts,
  refresh,
  embedded = false
}: {
  alerts: AlertItem[];
  refresh: () => void;
  embedded?: boolean;
}) {
  const view = useAlertsViewModel({ alerts });

  return (
    <div className="zh-page-stack">
      {!embedded ? (
        <PanelCard variant="borderless">
          <Flex justify="space-between" align="center">
            <Typography.Title level={3} className="zh-title-flush">
              实时告警与阻断记录
            </Typography.Title>
            <UiButton onClick={refresh}>刷新告警</UiButton>
          </Flex>
        </PanelCard>
      ) : null}

      <AlertSummaryCards
        total={alerts.length}
        criticalCount={view.criticalCount}
        blockedCount={view.blockedCount}
        controlledCount={view.askedCount + view.isolatedCount}
      />

      <PanelCard variant="borderless">
        <AlertFilterBar
          query={view.query}
          severityFilter={view.severityFilter}
          riskScoreFilter={view.riskScoreFilter}
          decisionFilter={view.decisionFilter}
          policyFilter={view.policyFilter}
          scenarioFilter={view.scenarioFilter}
          policies={view.policies}
          scenarios={view.scenarios}
          copiedFiltered={view.copiedFiltered}
          onQueryChange={view.setQuery}
          onSeverityFilterChange={view.setSeverityFilter}
          onRiskScoreFilterChange={view.setRiskScoreFilter}
          onDecisionFilterChange={view.setDecisionFilter}
          onPolicyFilterChange={view.setPolicyFilter}
          onScenarioFilterChange={view.setScenarioFilter}
          onReset={view.resetAlertFilters}
          onCopyFiltered={view.copyFilteredAlerts}
        />

        <Row gutter={[24, 24]}>
          <Col xs={24} md={10}>
            <AlertList
              alerts={view.filteredAlerts}
              selectedAlertId={view.selectedAlert?.id}
              onSelectAlert={view.setSelectedAlertId}
            />
          </Col>
          <Col xs={24} md={14}>
            <AlertDetail alert={view.selectedAlert} copied={view.copied} onCopy={view.copyAlertEvidence} />
          </Col>
        </Row>
      </PanelCard>
    </div>
  );
}
