import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Col, Flex, Row, Space, Typography } from 'antd';
import { Activity, Radio, RefreshCw, Search } from 'lucide-react';
import { request, subscribeRuntimeEvents } from '../../app/apiRequest';
import { LabelTag, MetricCard, PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';
import { GatewayTraceDetails } from './GatewayTraceDetails';
import { GatewayTraceTable } from './GatewayTraceTable';
import { gatewayRequestId, traceLabel, type GatewayTrace, type GatewayTraceIndex } from './gatewayTraceModel';

type Props = {
  refreshSignal?: string;
  onCreateRequest?: () => void;
};

export function GatewayTracePanel({ refreshSignal = '', onCreateRequest }: Props) {
  const [index, setIndex] = useState<GatewayTraceIndex>({ traces: [], summary: {} });
  const [selected, setSelected] = useState<GatewayTrace | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('全部');
  const [providerFilter, setProviderFilter] = useState('全部');
  const [liveStatus, setLiveStatus] = useState<'connecting' | 'connected' | 'offline'>('connecting');
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
    } catch (requestError) {
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
  }, [loadTraces]);

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
      return (
        (!needle || searchable.includes(needle)) &&
        (decisionFilter === '全部' || trace.decision === decisionFilter) &&
        (providerFilter === '全部' || traceLabel(trace.provider, 'unknown') === providerFilter)
      );
    });
  }, [decisionFilter, providerFilter, query, traces]);

  const summary = index.summary ?? {};

  return (
    <>
      <PanelCard
        title="实时网关流量"
        subtitle="只显示当前运营数据库中的真实请求；实验、固定样本和历史报告不会进入本视图"
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
        <Row gutter={[12, 12]} className="zh-traffic-metrics">
          <Col xs={12} md={6} xl={5}>
            <MetricCard label="请求总数" value={summary.request_count ?? 0} tone="cyan" />
          </Col>
          <Col xs={12} md={6} xl={5}>
            <MetricCard label="受控请求" value={summary.controlled_count ?? 0} tone="red" />
          </Col>
          <Col xs={12} md={6} xl={5}>
            <MetricCard label="Provider 调用" value={summary.provider_called_count ?? 0} tone="green" />
          </Col>
          <Col xs={12} md={6} xl={5}>
            <MetricCard
              label="Tool Call / 回执"
              value={`${summary.tool_call_count ?? 0} / ${summary.receipt_count ?? 0}`}
              tone="amber"
            />
          </Col>
          <Col xs={12} md={6} xl={4}>
            <MetricCard
              label="最高风险"
              value={summary.max_risk_score ?? 0}
              tone={(summary.max_risk_score ?? 0) >= 70 ? 'red' : 'default'}
            />
          </Col>
        </Row>

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
            options={['全部', '允许', '拒绝', '询问', '隔离'].map((value) => ({ value, label: `处置：${value}` }))}
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
              运营流量仍为空
            </Typography.Title>
            <Typography.Text type="secondary">
              发送第一条真实网关请求后，请求、策略和执行证据会实时出现在这里。
            </Typography.Text>
            {onCreateRequest ? (
              <UiButton type="primary" onClick={onCreateRequest}>
                新建验证请求
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
