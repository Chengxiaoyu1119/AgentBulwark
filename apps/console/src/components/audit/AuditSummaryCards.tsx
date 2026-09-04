import { UiCol, UiRow } from '../ui';
import { MetricCard as Metric } from '../ui';

interface AuditSummaryCardsProps {
  total: number;
  controlledCount: number;
  highRiskCount: number;
  executedCount: number;
  receiptCount?: number;
  unconfirmedCount?: number;
}

export function AuditSummaryCards({
  total,
  controlledCount,
  highRiskCount,
  executedCount,
  receiptCount = 0,
  unconfirmedCount = 0
}: AuditSummaryCardsProps) {
  return (
    <UiRow gutter={[16, 16]}>
      <UiCol xs={24} sm={12} md={6}>
        <Metric label="审计记录" value={`${total}`} tone="cyan" />
      </UiCol>
      <UiCol xs={24} sm={12} md={6}>
        <Metric label="已管控" value={`${controlledCount}`} tone="green" />
      </UiCol>
      <UiCol xs={24} sm={12} md={6}>
        <Metric label="高危/极高" value={`${highRiskCount}`} tone="red" />
      </UiCol>
      <UiCol xs={24} sm={12} md={6}>
        <Metric label="实际执行" value={`${executedCount}`} tone="amber" />
      </UiCol>
      <UiCol xs={24} sm={12} md={6}>
        <Metric label="外部回执" value={`${receiptCount}/${total}`} tone="cyan" />
      </UiCol>
      <UiCol xs={24} sm={12} md={6}>
        <Metric label="待确认回执" value={`${unconfirmedCount}`} tone={unconfirmedCount ? 'red' : 'green'} />
      </UiCol>
    </UiRow>
  );
}
