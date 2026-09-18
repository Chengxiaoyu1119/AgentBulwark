import { Card, Statistic } from 'antd';

export type MetricCardProps = {
  label: string;
  value: string | number;
  tone?: 'green' | 'red' | 'amber' | 'cyan' | 'default';
  suffix?: string;
};

export function MetricCard({ label, value, tone = 'default', suffix }: MetricCardProps) {
  return (
    <Card variant="borderless" className={`zh-metric-card zh-metric-card--${tone}`}>
      <Statistic title={label} value={value} suffix={suffix} />
    </Card>
  );
}
