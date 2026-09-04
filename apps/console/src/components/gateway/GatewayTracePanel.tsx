import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { UiFlex, UiSpace, UiTypography } from '../ui';
import { RefreshCw, Search } from 'lucide-react';
import { request } from '../../app/apiRequest';
import { safeUiErrorSummary } from '../../app/apiRequestSupport';
import { useRuntimeEventRefresh } from '../../app/useRuntimeEventRefresh';
import {
  PanelCard,
  RuntimeConnectionBadge,
  RuntimeConnectionNotice,
  UiDataState,
  UiButton,
  UiInput,
  UiSelect
} from '../ui';
import { GatewayTraceDetails } from './GatewayTraceDetails';
import { GatewayTraceTable } from './GatewayTraceTable';
import {
  CONTROLLED_DECISIONS,
  gatewayRequestId,
  traceLabel,
  type GatewayTrace,
  type GatewayTraceIndex
} from './gatewayTraceModel';

type Props = {
  refreshSignal?: string;
  onCreateRequest?: () => void;
  onOpenApproval?: (auditId: string) => void;
  mode?: 'traffic' | 'events';
  pendingApprovalCount?: number | string;
};

export function GatewayTracePanel({
  refreshSignal = '',
  onCreateRequest,
  onOpenApproval,
  mode = 'traffic',
  pendingApprovalCount = '—'
}: Props) {
  const [index, setIndex] = useState<GatewayTraceIndex>({ traces: [], summary: {} });
  const [selected, setSelected] = useState<GatewayTrace | null>(null);
  const [loading, setLoading] = useState(false);
  const [listError, setListError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [query, setQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState(mode === 'events' ? '全部受控' : '全部');
  const [providerFilter, setProviderFilter] = useState('全部');
  const traceRequestSequence = useRef(0);
  const detailRequestSequence = useRef(0);

  const loadTraces = useCallback(async () => {
    const sequence = ++traceRequestSequence.current;
    setLoading(true);
    setListError('');
    try {
      const nextIndex = await request<GatewayTraceIndex>('/api/gateway/traces?limit=50', undefined, {
        retry: 0,
        timeoutMs: 8_000
      });
      if (sequence !== traceRequestSequence.current) return;
      setIndex(nextIndex);
    } catch (requestError) {
      if (sequence !== traceRequestSequence.current) return;
      // A failed refresh invalidates the previous snapshot. Operators must not
      // mistake stale traces for current runtime traffic.
      setIndex({ traces: [], summary: {} });
      detailRequestSequence.current += 1;
      setSelected(null);
      setDetailError('');
      setListError(safeUiErrorSummary(requestError, '实时流量读取失败。'));
    } finally {
      if (sequence === traceRequestSequence.current) setLoading(false);
    }
  }, []);

  // Keep the event loop alive even when the first snapshot fails. The
  // connection owner already stops permanently for auth/permission failures
  // and backs off transient failures, so disabling it here would strand the
  // page until an operator manually refreshes it.
  const liveConnection = useRuntimeEventRefresh(loadTraces);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadTraces(), 0);
    return () => window.clearTimeout(timer);
  }, [loadTraces, refreshSignal]);

  async function openTrace(trace: GatewayTrace) {
    const requestId = gatewayRequestId(trace);
    if (!requestId) return;
    const sequence = ++detailRequestSequence.current;
    setSelected(trace);
    setDetailError('');
    try {
      const detail = await request<GatewayTrace>(`/api/gateway/traces/${encodeURIComponent(requestId)}`, undefined, {
        retry: 0,
        timeoutMs: 8_000
      });
      if (sequence === detailRequestSequence.current) setSelected(detail);
    } catch (requestError) {
      if (sequence === detailRequestSequence.current) {
        setDetailError(safeUiErrorSummary(requestError, '请求详情读取失败。'));
      }
    }
  }

  function closeTrace() {
    detailRequestSequence.current += 1;
    setSelected(null);
    setDetailError('');
  }

  const traces = useMemo(() => (Array.isArray(index.traces) ? index.traces : []), [index.traces]);
  const providers = useMemo(
    () => [...new Set(traces.map((trace) => traceLabel(trace.provider, 'unknown')))].sort(),
    [traces]
  );
  const filteredTraces = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return traces.filter((trace) => {
      const searchable = [
        trace.request_id,
        trace.agent_id,
        trace.session_id,
        trace.provider,
        trace.model,
        trace.primary_policy_id
      ]
        .join(' ')
        .toLowerCase();
      const matchesMode = mode !== 'events' || CONTROLLED_DECISIONS.has(traceLabel(trace.decision));
      return (
        matchesMode &&
        (!needle || searchable.includes(needle)) &&
        (decisionFilter === '全部' || decisionFilter === '全部受控' || trace.decision === decisionFilter) &&
        (providerFilter === '全部' || traceLabel(trace.provider, 'unknown') === providerFilter)
      );
    });
  }, [decisionFilter, mode, providerFilter, query, traces]);

  const summary = index.summary ?? {};
  const decisionDistribution = summary.decision_distribution ?? {};
  const isolatedCount = decisionDistribution['隔离'] ?? 0;
  const rejectedCount = decisionDistribution['拒绝'] ?? 0;

  return (
    <>
      <PanelCard
        title={mode === 'events' ? '事件列表' : '实时请求'}
        subtitle={
          mode === 'events'
            ? '点击一条事件，查看输入、模型、工具与执行的完整处置链'
            : '这里展示运营数据库的实时流量；实验样本与历史报告在对应页面查看'
        }
        className="zh-traffic-panel"
        extra={
          <UiSpace>
            <RuntimeConnectionBadge connection={liveConnection} />
            <UiButton size="small" icon={<RefreshCw size={14} />} loading={loading} onClick={() => void loadTraces()}>
              刷新
            </UiButton>
          </UiSpace>
        }
      >
        <RuntimeConnectionNotice connection={liveConnection} />
        <div className="zh-traffic-metrics">
          {mode === 'events' ? (
            <>
              <TrafficMetric label="受控事件" value={summary.controlled_count ?? 0} tone="danger" />
              <TrafficMetric label="已阻断" value={rejectedCount} />
              <TrafficMetric
                label="待处理"
                value={pendingApprovalCount}
                tone={Number(pendingApprovalCount) > 0 ? 'warning' : 'default'}
              />
              <TrafficMetric label="已隔离" value={isolatedCount} />
            </>
          ) : (
            <>
              <TrafficMetric label="请求" value={summary.request_count ?? 0} />
              <TrafficMetric label="正常" value={summary.allowed_count ?? 0} tone="success" />
              <TrafficMetric label="受控" value={summary.controlled_count ?? 0} tone="danger" />
              <TrafficMetric label="执行回执" value={summary.receipt_count ?? 0} />
            </>
          )}
        </div>

        <UiFlex gap={10} wrap="wrap" className="zh-traffic-filters">
          <UiInput
            prefix={<Search size={15} aria-hidden="true" />}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索请求、Agent、会话或策略"
            allowClear
            className="zh-traffic-search"
          />
          <UiSelect
            value={decisionFilter}
            onChange={setDecisionFilter}
            options={(mode === 'events'
              ? ['全部受控', '拒绝', '询问', '隔离']
              : ['全部', '允许', '拒绝', '询问', '隔离']
            ).map((value) => ({ value, label: `处置：${value}` }))}
            className="zh-traffic-filter"
            aria-label="按处置筛选"
          />
          <UiSelect
            value={providerFilter}
            onChange={setProviderFilter}
            options={['全部', ...providers].map((value) => ({ value, label: `Provider：${value}` }))}
            className="zh-traffic-filter"
            aria-label="按 Provider 筛选"
          />
          <UiTypography.Text type="secondary" className="zh-traffic-filter-count">
            当前显示 {filteredTraces.length} / {index.total_available ?? traces.length}
          </UiTypography.Text>
        </UiFlex>

        {listError ? (
          <UiDataState
            status="error"
            title="实时流量读取失败"
            description={listError}
            action={
              <UiButton size="small" onClick={() => void loadTraces()} loading={loading}>
                重试读取
              </UiButton>
            }
          />
        ) : loading && !traces.length ? (
          <UiDataState status="loading" title="正在读取实时请求…" />
        ) : !traces.length ? (
          <UiDataState
            status="empty"
            title={mode === 'events' ? '安全事件将在首次受控请求后显示' : '等待第一条请求'}
            description={
              mode === 'events'
                ? '被阻断、隔离或需要处理的真实请求会自动出现在这里。'
                : '接入应用后，请求与处置结果会实时出现在这里。'
            }
            action={
              onCreateRequest ? (
                <UiButton type="primary" onClick={onCreateRequest}>
                  发送验证请求
                </UiButton>
              ) : undefined
            }
          />
        ) : (
          <GatewayTraceTable traces={filteredTraces} onOpen={(trace) => void openTrace(trace)} />
        )}
      </PanelCard>
      <GatewayTraceDetails trace={selected} error={detailError} onClose={closeTrace} onOpenApproval={onOpenApproval} />
    </>
  );
}

function TrafficMetric({
  label,
  value,
  tone = 'default'
}: {
  label: string;
  value: number | string;
  tone?: 'default' | 'success' | 'warning' | 'danger';
}) {
  return (
    <div className={`zh-traffic-metric zh-traffic-metric--${tone}`}>
      <UiTypography.Text type="secondary">{label}</UiTypography.Text>
      <strong>{value}</strong>
    </div>
  );
}
