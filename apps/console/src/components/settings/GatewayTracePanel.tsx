import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Flex, Space, Typography } from 'antd';
import { Activity, Radio, RefreshCw, Search } from 'lucide-react';
import { request, subscribeRuntimeEvents } from '../../app/apiRequest';
import { LabelTag, PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';
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
  mode?: 'traffic' | 'events';
};

export function GatewayTracePanel({ refreshSignal = '', onCreateRequest, mode = 'traffic' }: Props) {
  const [index, setIndex] = useState<GatewayTraceIndex>({ traces: [], summary: {} });
  const [selected, setSelected] = useState<GatewayTrace | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState(mode === 'events' ? '全部受控' : '全部');
  const [providerFilter, setProviderFilter] = useState('全部');
  const [liveStatus, setLiveStatus] = useState<'connecting' | 'connected' | 'offline'>('connecting');
  const [liveReady, setLiveReady] = useState(false);
  const refreshTimerRef = useRef<number | undefined>(undefined);

  const loadTraces = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setIndex(
        await request<GatewayTraceIndex>('/api/gateway/traces?limit=50', undefined, {
          retry: 0,
          timeoutMs: 8_000
        })
      );
      setLiveReady(true);
    } catch (requestError) {
      setLiveReady(false);
      setLiveStatus('offline');
      setError(requestError instanceof Error ? requestError.message : '实时流量读取失败。');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadTraces(), 0);
    return () => window.clearTimeout(timer);
  }, [loadTraces, refreshSignal]);

  useEffect(() => {
    if (!liveReady) return undefined;
    let stopped = false;
    let controller: AbortController | undefined;
    const connect = async () => {
      while (!stopped) {
        controller = new AbortController();
        setLiveStatus('connecting');
        try {
          setLiveStatus('connected');
          await subscribeRuntimeEvents(() => {
            if (refreshTimerRef.current !== undefined) window.clearTimeout(refreshTimerRef.current);
            refreshTimerRef.current = window.setTimeout(() => void loadTraces(), 300);
          }, controller.signal);
        } catch {
          if (!stopped) setLiveStatus('offline');
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
  }, [liveReady, loadTraces]);

  async function openTrace(trace: GatewayTrace) {
    const requestId = gatewayRequestId(trace);
    if (!requestId) return;
    setSelected(trace);
    try {
      setSelected(
        await request<GatewayTrace>(`/api/gateway/traces/${encodeURIComponent(requestId)}`, undefined, {
          retry: 0,
          timeoutMs: 8_000
        })
      );
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '请求详情读取失败。');
    }
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
  const reviewCount = traces.filter((trace) => traceLabel(trace.decision) === '询问').length;
  const isolatedCount = traces.filter((trace) => traceLabel(trace.decision) === '隔离').length;
  const rejectedCount = traces.filter((trace) => traceLabel(trace.decision) === '拒绝').length;

  return (
    <>
      <PanelCard
        title={mode === 'events' ? '事件列表' : '实时请求'}
        subtitle={
          mode === 'events'
            ? '点击一条事件，查看输入、模型、工具与执行的完整处置链'
            : '运营数据库实时流量；实验样本和历史报告不会进入这里'
        }
        className="zh-traffic-panel"
        extra={
          <Space>
            <LabelTag color={liveStatus === 'connected' ? 'green' : liveStatus === 'connecting' ? 'blue' : 'red'}>
              <Radio size={12} aria-hidden="true" />{' '}
              {liveStatus === 'connected' ? '实时连接' : liveStatus === 'connecting' ? '连接中' : '连接中断'}
            </LabelTag>
            <UiButton size="small" icon={<RefreshCw size={14} />} loading={loading} onClick={() => void loadTraces()}>
              刷新
            </UiButton>
          </Space>
        }
      >
        <div className="zh-traffic-metrics">
          {mode === 'events' ? (
            <>
              <TrafficMetric label="受控事件" value={summary.controlled_count ?? 0} tone="danger" />
              <TrafficMetric label="已阻断" value={rejectedCount} />
              <TrafficMetric label="待处理" value={reviewCount} tone={reviewCount ? 'warning' : 'default'} />
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

        <Flex gap={10} wrap="wrap" className="zh-traffic-filters">
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
          <Typography.Text type="secondary" className="zh-traffic-filter-count">
            当前显示 {filteredTraces.length} / {index.total_available ?? traces.length}
          </Typography.Text>
        </Flex>

        {error ? <UiAlert type="warning" showIcon title={error} className="zh-mb-12" /> : null}
        {!traces.length && !loading ? (
          <div className="zh-traffic-empty">
            <Activity size={28} aria-hidden="true" />
            <Typography.Title level={4} className="zh-title-flush">
              {mode === 'events' ? '当前没有安全事件' : '等待第一条请求'}
            </Typography.Title>
            <Typography.Text type="secondary">
              {mode === 'events'
                ? '被阻断、隔离或需要处理的真实请求会自动出现在这里。'
                : '接入应用后，请求与处置结果会实时出现在这里。'}
            </Typography.Text>
            {onCreateRequest ? (
              <UiButton type="primary" onClick={onCreateRequest}>
                发送验证请求
              </UiButton>
            ) : null}
          </div>
        ) : (
          <GatewayTraceTable traces={filteredTraces} onOpen={(trace) => void openTrace(trace)} />
        )}
      </PanelCard>
      <GatewayTraceDetails trace={selected} onClose={() => setSelected(null)} />
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
      <Typography.Text type="secondary">{label}</Typography.Text>
      <strong>{value}</strong>
    </div>
  );
}
