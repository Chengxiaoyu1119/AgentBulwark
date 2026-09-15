import { ArrowRight, CircleAlert, Clock3, ExternalLink, Radio } from 'lucide-react';
import {
  LabelTag,
  MetricCard,
  PanelCard,
  RuntimeConnectionBadge,
  UiAlert,
  UiButton,
  UiDataState,
  UiSpace,
  UiTypography
} from '../components/ui';
import { formatTraceTime, traceDecisionColor, traceLabel } from '../components/gateway/gatewayTraceModel';
import type { RuntimeEventConnection } from '../app/runtimeEventConnection';
import type { OperationalConnection } from '../app/useAppData';
import type { OperationalOverview } from '../types';

type Props = {
  overview: OperationalOverview;
  connection?: OperationalConnection;
  liveConnection?: RuntimeEventConnection;
  onOpenEvents?: (requestId?: string) => void;
  onOpenSettings?: () => void;
};

const DECISION_LABELS = [
  { key: '允许', label: '允许', tone: 'green' },
  { key: '拒绝', label: '拒绝', tone: 'red' },
  { key: '询问', label: '待审批', tone: 'orange' },
  { key: '隔离', label: '隔离', tone: 'cyan' }
] as const;

const DATA_STATUS_META = {
  live: { label: 'LIVE', title: '运营数据实时接入', color: 'success' },
  degraded: { label: 'DEGRADED', title: '运营数据部分降级', color: 'warning' },
  stale: { label: 'STALE', title: '显示最后一次成功快照', color: 'warning' },
  empty: { label: 'EMPTY', title: '等待真实受控请求', color: 'default' }
} as const;

function metricValue(value: number | null | undefined) {
  return value === null || value === undefined ? '—' : value;
}

export function OperationalDashboard({ overview, connection, liveConnection, onOpenEvents, onOpenSettings }: Props) {
  const summary = overview.summary;
  const actions = (overview.action_queue ?? []).filter((action) => action.kind !== 'readiness');
  const activities = overview.activity ?? [];
  const trend = overview.trend ?? [];
  const dataStatus = connection?.stale ? 'stale' : (overview.data_status ?? 'empty');
  const statusMeta = DATA_STATUS_META[dataStatus as keyof typeof DATA_STATUS_META] ?? DATA_STATUS_META.empty;
  const auditAvailable = !overview.source_errors?.some((item) => item.source === 'audit_logs');
  const hasSourceErrors = Boolean(overview.source_errors?.length);
  const lastUpdated = overview.updated_at ? formatTraceTime(overview.updated_at) : '尚未记录真实活动';
  const maxTrendCount = Math.max(...trend.map((item) => item.request_count), 1);
  const hasTrendActivity = trend.some((item) => item.request_count > 0);

  return (
    <div className="zh-page-stack zh-ops-dashboard">
      <div className="zh-soft-surface zh-action-row zh-ops-status-strip" role="status">
        <div className="zh-ui-stack zh-ui-stack--align-center zh-ui-stack--gap-sm zh-flex-min zh-ops-status-strip__main">
          <span className={`zh-ops-live-dot zh-ops-live-dot--${dataStatus}`} aria-hidden="true" />
          <div className="zh-flex-min">
            <UiTypography.Text strong>{statusMeta.title}</UiTypography.Text>
            <UiTypography.Text type="secondary" className="zh-text-meta zh-text-block zh-ops-status-strip__meta">
              窗口 {overview.window?.key ?? '1h'} · 最近活动 {lastUpdated}
            </UiTypography.Text>
          </div>
        </div>
        <UiSpace wrap size={8}>
          {liveConnection ? <RuntimeConnectionBadge connection={liveConnection} /> : null}
          <LabelTag color={statusMeta.color}>{statusMeta.label}</LabelTag>
          <UiTypography.Text type="secondary" className="zh-text-meta">
            数据来自真实网关审计与运行回执
          </UiTypography.Text>
        </UiSpace>
      </div>

      {hasSourceErrors ? (
        <UiAlert
          type="warning"
          showIcon
          title="部分运营数据读取失败"
          description="页面没有把读取失败转换成零指标；请查看连接状态并重新读取。"
        />
      ) : null}

      <div className="zh-meta-grid zh-ops-metric-grid">
        <MetricCard label="请求量" value={metricValue(summary.request_count)} tone="cyan" />
        <MetricCard
          label="控制率"
          value={
            summary.control_rate === null || summary.control_rate === undefined
              ? metricValue(summary.block_rate)
              : `${summary.control_rate}%`
          }
          tone="amber"
        />
        <MetricCard label="待人工复核" value={metricValue(summary.pending_review_count)} tone="red" />
        <MetricCard label="未确认执行" value={metricValue(summary.execution_unconfirmed_count)} tone="red" />
      </div>

      <div className="zh-panel-grid zh-ops-overview-grid">
        <PanelCard
          title="实时请求流"
          subtitle="按最新时间显示真实请求；点击记录查看原始 Trace。"
          className="zh-ops-activity-panel"
          extra={<Radio size={16} aria-label="实时活动" />}
        >
          {activities.length ? (
            <div className="zh-panel-stack zh-ops-activity-list">
              {activities.slice(0, 6).map((activity) => {
                const requestId = traceLabel(activity.request_id || activity.trace_id, '未知请求');
                return (
                  <button
                    type="button"
                    className="zh-action-row zh-ops-activity-item"
                    key={`${activity.source_app ?? 'gateway'}-${requestId}`}
                    aria-label="打开最近活动详情"
                    title={requestId}
                    onClick={() => onOpenEvents?.(activity.request_id || activity.trace_id)}
                  >
                    <span
                      className={`zh-ops-live-dot zh-ops-activity-status zh-ops-activity-status--${traceDecisionColor(traceLabel(activity.decision, '未知'))}`}
                      aria-hidden="true"
                    />
                    <span className="zh-action-row__content zh-ui-stack zh-ui-stack--vertical zh-ui-stack--gap-xs zh-ops-activity-copy">
                      <span className="zh-ops-activity-title">
                        <strong>{requestId}</strong>
                        <LabelTag color={traceDecisionColor(traceLabel(activity.decision, '未知'))}>
                          {traceLabel(activity.decision, '未知')}
                        </LabelTag>
                      </span>
                      <span className="zh-text-meta zh-ops-activity-meta">
                        {traceLabel(activity.source_app, 'gateway')} ·{' '}
                        {traceLabel(activity.model || activity.provider, 'unknown')} ·{' '}
                        {formatTraceTime(activity.last_seen)}
                      </span>
                    </span>
                    <ExternalLink size={15} aria-hidden="true" />
                  </button>
                );
              })}
            </div>
          ) : (
            <UiDataState status="empty" title="等待第一条真实请求" description="请求经过网关后会自动出现在实时流中。" />
          )}
        </PanelCard>

        <PanelCard
          title="需要处理"
          subtitle="只显示当前审批、执行和证据状态产生的动作。"
          className="zh-ops-action-panel"
          extra={<CircleAlert size={16} aria-label="需要处理" />}
        >
          {actions.length ? (
            <div className="zh-panel-stack zh-ops-action-list">
              {actions.map((action) => {
                const requestId = action.request_ids[0];
                const actionButton =
                  requestId && onOpenEvents ? (
                    <UiButton size="small" icon={<ArrowRight size={14} />} onClick={() => onOpenEvents(requestId)}>
                      查看事件
                    </UiButton>
                  ) : action.kind === 'readiness' && onOpenSettings ? (
                    <UiButton size="small" onClick={onOpenSettings}>
                      打开设置
                    </UiButton>
                  ) : null;
                return (
                  <div className="zh-action-row zh-ops-action-row" key={action.id}>
                    <div className="zh-ops-action-row__icon" aria-hidden="true">
                      <CircleAlert size={16} />
                    </div>
                    <div className="zh-action-row__content zh-ui-stack zh-ui-stack--vertical zh-ui-stack--gap-xs zh-ops-action-row__copy">
                      <UiSpace size={8} wrap>
                        <UiTypography.Text strong>{action.title}</UiTypography.Text>
                        <LabelTag color={action.tone === 'danger' ? 'error' : 'warning'}>{action.count}</LabelTag>
                      </UiSpace>
                      <UiTypography.Text type="secondary">{action.description}</UiTypography.Text>
                    </div>
                    {actionButton}
                  </div>
                );
              })}
            </div>
          ) : (
            <UiDataState
              status="empty"
              title="当前没有待处理动作"
              description="新的审批、异常或证据状态会自动出现在这里。"
            />
          )}
        </PanelCard>
      </div>

      <div className="zh-panel-grid zh-ops-overview-grid">
        <PanelCard
          title="处置态势"
          subtitle="按请求级最终决策统计，重复审计阶段不会重复计数。"
          className="zh-ops-decision-panel"
          extra={
            <UiTypography.Text type="secondary">
              {metricValue(summary.provider_failure_count)} 次 Provider 异常
            </UiTypography.Text>
          }
        >
          <div className="zh-panel-stack zh-ops-decision-list">
            {DECISION_LABELS.map((item) => {
              const value = auditAvailable ? (overview.decision_distribution?.[item.key] ?? 0) : null;
              const total = Math.max(summary.request_count ?? 0, 1);
              return (
                <div className="zh-ops-decision-row" key={item.key}>
                  <div className="zh-action-row zh-flex-min zh-ops-decision-row__label">
                    <span className={`zh-ops-decision-mark zh-ops-decision-mark--${item.tone}`} aria-hidden="true" />
                    <UiTypography.Text>{item.label}</UiTypography.Text>
                    <UiTypography.Text type="secondary">{metricValue(value)}</UiTypography.Text>
                  </div>
                  {value === null ? (
                    <div className="zh-ops-decision-bar zh-ops-decision-bar--unknown" aria-hidden="true">
                      —
                    </div>
                  ) : (
                    <div className={`zh-ops-decision-bar zh-ops-decision-bar--${item.tone}`} aria-hidden="true">
                      <span style={{ width: `${Math.round((value / total) * 100)}%` }} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </PanelCard>

        <PanelCard
          title="实时趋势"
          subtitle="当前窗口内的真实请求分布；空桶表示该时间段没有记录。"
          className="zh-ops-trend-panel"
          extra={<Clock3 size={16} aria-label="时间窗口" />}
        >
          {hasTrendActivity ? (
            <div className="zh-ops-trend" aria-label="真实请求时间趋势">
              {trend.map((bucket) => {
                const height = Math.min(100, Math.max(0, (bucket.request_count * 100) / maxTrendCount));
                return (
                  <div
                    className="zh-ops-trend__bucket"
                    key={bucket.bucket_start}
                    title={`${formatTraceTime(bucket.bucket_start)} · ${bucket.request_count} 请求`}
                  >
                    <span className="zh-ops-trend__bar" style={{ height: `${height}%` }} />
                  </div>
                );
              })}
            </div>
          ) : (
            <UiDataState
              status="empty"
              title="当前窗口暂无真实请求"
              description="收到第一条受控请求后，趋势会从真实记录生成。"
            />
          )}
          <div className="zh-action-row zh-ops-trend__legend">
            <UiTypography.Text type="secondary">
              {overview.window?.start_at ? formatTraceTime(overview.window.start_at) : '窗口开始'}
            </UiTypography.Text>
            <UiTypography.Text type="secondary">
              {overview.window?.end_at ? formatTraceTime(overview.window.end_at) : '现在'}
            </UiTypography.Text>
          </div>
        </PanelCard>
      </div>
    </div>
  );
}
