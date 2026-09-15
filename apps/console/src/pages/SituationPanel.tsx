import { ArrowLeft, Moon, Radio, Sun } from 'lucide-react';
import { formatTraceTime, traceDecisionColor, traceLabel } from '../components/gateway/gatewayTraceModel';
import {
  LabelTag,
  MetricCard,
  PanelCard,
  RuntimeConnectionBadge,
  UiAlert,
  UiButton,
  UiDataState,
  UiProgress,
  UiSpace,
  UiTypography
} from '../components/ui';
import { idleRuntimeEventConnection, type RuntimeEventConnection } from '../app/runtimeEventConnection';
import type { AppTheme } from '../app/themePreference';
import type { OperationalConnection } from '../app/useAppData';
import type { OperationalOverview } from '../types';

type Props = {
  overview: OperationalOverview;
  connection: OperationalConnection;
  theme: AppTheme;
  onThemeChange: (theme: AppTheme) => void;
  onExit: () => void;
  onOpenEvents?: (requestId?: string) => void;
  onOpenSettings?: () => void;
  liveConnection?: RuntimeEventConnection;
};

export function SituationPanel({
  overview,
  connection,
  theme,
  onThemeChange,
  onExit,
  onOpenEvents,
  onOpenSettings,
  liveConnection: externalLiveConnection
}: Props) {
  const liveConnection = externalLiveConnection ?? idleRuntimeEventConnection;
  const summary = overview.summary;
  const actions = (overview.action_queue ?? []).filter((action) => action.kind !== 'readiness');
  const activities = overview.activity ?? [];
  const dataStatus = connection.stale ? 'stale' : (overview.data_status ?? 'empty');
  const auditAvailable = !overview.source_errors?.some((item) => item.source === 'audit_logs');

  return (
    <div className="zh-page-stack zh-situation-page">
      <header className="zh-action-row zh-situation-header">
        <div className="zh-ui-stack zh-ui-stack--align-center zh-ui-stack--gap-md zh-situation-heading">
          <UiButton
            type="text"
            icon={<ArrowLeft size={18} />}
            onClick={onExit}
            aria-label="退出态势模式"
            title="退出态势模式"
          />
          <div className="zh-ui-stack zh-ui-stack--vertical zh-ui-stack--gap-xs">
            <UiTypography.Title level={2} className="zh-zero-margin">
              安全态势
            </UiTypography.Title>
            <UiTypography.Text type="secondary">Agent Runtime Gateway · 真实运行状态</UiTypography.Text>
          </div>
        </div>
        <UiSpace wrap size={8}>
          <RuntimeConnectionBadge connection={liveConnection} />
          <UiButton
            type="text"
            icon={theme === 'light' ? <Moon size={17} /> : <Sun size={17} />}
            onClick={() => onThemeChange(theme === 'light' ? 'dark' : 'light')}
            aria-label={theme === 'light' ? '切换深色模式' : '切换浅色模式'}
            title={theme === 'light' ? '切换深色模式' : '切换浅色模式'}
          />
        </UiSpace>
      </header>

      {dataStatus === 'degraded' || dataStatus === 'stale' ? (
        <UiAlert
          type="warning"
          showIcon
          title={dataStatus === 'stale' ? '态势显示最后一次成功快照' : '态势数据部分降级'}
          description="部分数据源读取失败，页面保留可确认的真实事实。"
        />
      ) : null}

      <section className="zh-soft-surface zh-action-row zh-situation-hero" aria-label="当前安全态势">
        <div>
          <UiTypography.Text type="secondary">当前窗口</UiTypography.Text>
          <UiTypography.Title level={1} className="zh-zero-margin">
            {overview.window?.key ?? '1h'}
          </UiTypography.Title>
          <UiTypography.Text type="secondary">
            最后活动 {overview.updated_at ? formatTraceTime(overview.updated_at) : '尚未记录真实请求'}
          </UiTypography.Text>
        </div>
        <div className="zh-ui-stack zh-ui-stack--vertical zh-ui-stack--gap-sm zh-situation-hero__summary">
          <LabelTag color={dataStatus === 'live' ? 'success' : dataStatus === 'empty' ? 'default' : 'warning'}>
            {dataStatus === 'live' ? '运行中' : dataStatus === 'empty' ? '等待接入' : '需要关注'}
          </LabelTag>
          <UiTypography.Text type="secondary">所有数字均来自 operational 审计、审批和执行回执。</UiTypography.Text>
        </div>
      </section>

      <div className="zh-meta-grid zh-ops-metric-grid zh-situation-metrics">
        <MetricCard label="请求" value={summary.request_count ?? '—'} tone="cyan" />
        <MetricCard label="允许" value={summary.allowed_count ?? '—'} tone="green" />
        <MetricCard label="受控" value={summary.controlled_count ?? '—'} tone="amber" />
        <MetricCard
          label="待处理"
          value={
            summary.pending_review_count === null || summary.execution_unconfirmed_count === null
              ? '—'
              : (summary.pending_review_count ?? 0) + (summary.execution_unconfirmed_count ?? 0)
          }
          tone="red"
        />
      </div>

      <div className="zh-panel-grid zh-situation-grid">
        <PanelCard title="决策分布" subtitle="按请求级最终处置显示。">
          <div className="zh-panel-stack zh-ops-decision-list">
            {['允许', '拒绝', '询问', '隔离'].map((decision) => {
              const value = auditAvailable ? (overview.decision_distribution?.[decision] ?? 0) : null;
              const total = Math.max(summary.request_count ?? 0, 1);
              return (
                <div className="zh-ops-decision-row" key={decision}>
                  <div className="zh-action-row zh-flex-min zh-ops-decision-row__label">
                    <span
                      className={`zh-ops-decision-mark zh-ops-decision-mark--${traceDecisionColor(decision)}`}
                      aria-hidden="true"
                    />
                    <UiTypography.Text>{decision}</UiTypography.Text>
                    <UiTypography.Text type="secondary">{value ?? '—'}</UiTypography.Text>
                  </div>
                  {value === null ? (
                    <div className="zh-ops-decision-bar zh-ops-decision-bar--unknown" aria-hidden="true">
                      —
                    </div>
                  ) : (
                    <UiProgress percent={Math.round((value / total) * 100)} showInfo={false} size="small" />
                  )}
                </div>
              );
            })}
          </div>
        </PanelCard>

        <PanelCard title="实时请求流" subtitle="实时事件连接触发刷新，数据仍来自持久化证据。">
          {activities.length ? (
            <div className="zh-panel-stack zh-ops-activity-list">
              {activities.slice(0, 6).map((activity) => (
                <button
                  type="button"
                  className="zh-action-row zh-ops-activity-item"
                  key={`${activity.source_app ?? 'gateway'}-${activity.request_id ?? activity.trace_id}`}
                  onClick={() => onOpenEvents?.(activity.request_id || activity.trace_id)}
                >
                  <span
                    className={`zh-ops-live-dot zh-ops-activity-status zh-ops-activity-status--${traceDecisionColor(traceLabel(activity.decision, '未知'))}`}
                    aria-hidden="true"
                  />
                  <span className="zh-action-row__content zh-ui-stack zh-ui-stack--vertical zh-ui-stack--gap-xs zh-ops-activity-copy">
                    <span className="zh-ops-activity-title">
                      <strong>{traceLabel(activity.request_id || activity.trace_id, '未知请求')}</strong>
                      <LabelTag color={traceDecisionColor(traceLabel(activity.decision, '未知'))}>
                        {traceLabel(activity.decision, '未知')}
                      </LabelTag>
                    </span>
                    <span className="zh-text-meta zh-ops-activity-meta">{formatTraceTime(activity.last_seen)}</span>
                  </span>
                  <Radio size={15} aria-hidden="true" />
                </button>
              ))}
            </div>
          ) : (
            <UiDataState status="empty" title="等待第一条真实请求" description="请求经过网关后会自动出现在态势流中。" />
          )}
        </PanelCard>
      </div>

      <PanelCard title="风险与边界" subtitle="只显示需要操作员关注的真实状态。">
        {actions.length ? (
          <div className="zh-panel-stack zh-situation-actions">
            {actions.map((action) => (
              <div className="zh-action-row zh-ops-action-row" key={action.id}>
                <div className="zh-action-row__content zh-ui-stack zh-ui-stack--vertical zh-ui-stack--gap-xs zh-ops-action-row__copy">
                  <UiSpace size={8} wrap>
                    <UiTypography.Text strong>{action.title}</UiTypography.Text>
                    <LabelTag color={action.tone === 'danger' ? 'error' : 'warning'}>{action.count}</LabelTag>
                  </UiSpace>
                  <UiTypography.Text type="secondary">{action.description}</UiTypography.Text>
                </div>
                {action.request_ids[0] && onOpenEvents ? (
                  <UiButton size="small" onClick={() => onOpenEvents?.(action.request_ids[0])}>
                    查看事件
                  </UiButton>
                ) : action.kind === 'readiness' && onOpenSettings ? (
                  <UiButton size="small" onClick={onOpenSettings}>
                    打开设置
                  </UiButton>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <UiAlert type="success" showIcon title="当前没有待处理风险动作。" />
        )}
      </PanelCard>

      <UiTypography.Text
        type="secondary"
        className="zh-ui-stack zh-ui-stack--align-center zh-ui-stack--gap-sm zh-situation-footer"
      >
        连接状态：{liveConnection.message} · 数据状态：{connection.message}
      </UiTypography.Text>
    </div>
  );
}
