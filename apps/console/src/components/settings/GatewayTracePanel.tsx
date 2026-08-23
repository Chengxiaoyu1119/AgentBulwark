import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Col, Drawer, Flex, Row, Space, Typography, type TableColumnsType } from 'antd';
import { Activity, CircleCheck, Radio, RefreshCw, Search, ShieldX, Wrench } from 'lucide-react';
import { request, subscribeRuntimeEvents } from '../../app/apiRequest';
import {
  LabelTag,
  MetaGrid,
  MetricCard,
  PanelCard,
  UiAlert,
  UiButton,
  UiInput,
  UiSelect,
  UiTable
} from '../ui';

export type GatewayTraceStage = {
  audit_id?: string;
  audit_hash?: string;
  timestamp?: string;
  stage?: string;
  decision?: string;
  policy_id?: string;
  risk_score?: number;
  tool?: string;
  provider_called?: boolean | null;
  provider_call_id?: string;
  execution_status?: string;
  execution_evidence?: string;
  execution_observed_by_server?: boolean;
  execution_receipt_present?: boolean;
};

export type GatewayTrace = {
  trace_id?: string;
  request_id?: string;
  session_id?: string;
  agent_id?: string;
  status?: string;
  decision?: string;
  provider_called?: boolean | null;
  provider?: string;
  provider_profile?: string;
  model?: string;
  request_hash?: string;
  provider_request_hash?: string;
  provider_response_hash?: string;
  provider_response_id?: string;
  controlled_stage_count?: number;
  stage_count?: number;
  risk_score?: number;
  primary_policy_id?: string;
  tool_call_stage_count?: number;
  server_observed_execution_count?: number;
  receipt_count?: number;
  first_seen?: string;
  last_seen?: string;
  stages?: GatewayTraceStage[];
};

type GatewayTraceSummary = {
  request_count?: number;
  controlled_count?: number;
  allowed_count?: number;
  provider_failure_count?: number;
  provider_called_count?: number;
  tool_call_count?: number;
  receipt_count?: number;
  max_risk_score?: number;
};

type GatewayTraceIndex = {
  traces?: GatewayTrace[];
  count?: number;
  total_available?: number;
  summary?: GatewayTraceSummary;
};

type Props = {
  refreshSignal?: string;
  onCreateRequest?: () => void;
};

const CONTROLLED_DECISIONS = new Set(['拒绝', '询问', '隔离']);

function label(value: unknown, fallback = '—') {
  return value === undefined || value === null || value === '' ? fallback : String(value);
}

function decisionColor(decision: string) {
  return CONTROLLED_DECISIONS.has(decision) ? 'red' : decision === '允许' ? 'green' : 'blue';
}

function shortHash(value: unknown) {
  const text = typeof value === 'string' ? value : '';
  return text ? `${text.slice(0, 12)}…` : '—';
}

function formatTime(value: unknown) {
  const text = typeof value === 'string' ? value : '';
  if (!text) return '—';
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? text : date.toLocaleString('zh-CN', { hour12: false });
}

function requestIdOf(trace: GatewayTrace) {
  return String(trace.request_id || trace.trace_id || '').trim();
}

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
    const requestId = requestIdOf(trace);
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
    () => [...new Set(traces.map((trace) => label(trace.provider, 'unknown')))].sort(),
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
        (providerFilter === '全部' || label(trace.provider, 'unknown') === providerFilter)
      );
    });
  }, [decisionFilter, providerFilter, query, traces]);

  const columns: TableColumnsType<GatewayTrace> = [
    {
      title: '时间 / 请求',
      key: 'request',
      width: 230,
      render: (_, trace) => (
        <button type="button" className="zh-traffic-request-link" onClick={() => void openTrace(trace)}>
          <span>{formatTime(trace.last_seen)}</span>
          <strong>{requestIdOf(trace) || 'unknown-request'}</strong>
        </button>
      )
    },
    {
      title: 'Agent / 会话',
      key: 'agent',
      width: 180,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text>{label(trace.agent_id, '未绑定 Agent')}</Typography.Text>
          <Typography.Text type="secondary" ellipsis>
            {label(trace.session_id, '无会话')}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: 'Provider / 模型',
      key: 'provider',
      width: 180,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text>{label(trace.provider, trace.provider_called === false ? 'Provider 前阻断' : '未知')}</Typography.Text>
          <Typography.Text type="secondary" ellipsis>
            {label(trace.model)}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '处置',
      dataIndex: 'decision',
      width: 92,
      render: (value) => <LabelTag color={decisionColor(label(value))}>{label(value)}</LabelTag>
    },
    {
      title: '风险 / 策略',
      key: 'risk',
      width: 160,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text strong className="zh-tabular-nums">
            {trace.risk_score ?? 0}
          </Typography.Text>
          <Typography.Text type="secondary" ellipsis>
            {label(trace.primary_policy_id, '未命中策略')}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '执行证据',
      key: 'evidence',
      width: 150,
      render: (_, trace) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text>{trace.tool_call_stage_count ?? 0} 个 Tool Call</Typography.Text>
          <Typography.Text type="secondary">{trace.receipt_count ?? 0} 个回执</Typography.Text>
        </Space>
      )
    }
  ];

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
          <UiTable<GatewayTrace>
            rowKey={(trace) => requestIdOf(trace)}
            columns={columns}
            dataSource={filteredTraces}
            size="small"
            pagination={{ pageSize: 10, showSizeChanger: false }}
            scroll={{ x: 990 }}
          />
        )}
      </PanelCard>

      <Drawer
        title="请求安全详情"
        size="large"
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        destroyOnHidden
      >
        {selected ? (
          <div className="zh-traffic-detail">
            <Flex justify="space-between" align="center" gap={12} wrap="wrap">
              <div>
                <Typography.Text type="secondary">请求 ID</Typography.Text>
                <Typography.Title level={4} className="zh-title-flush zh-code-sm">
                  {requestIdOf(selected)}
                </Typography.Title>
              </div>
              <LabelTag color={decisionColor(label(selected.decision))}>{label(selected.decision)}</LabelTag>
            </Flex>

            <MetaGrid
              columns={2}
              items={[
                { key: 'time', label: '最后时间', value: formatTime(selected.last_seen) },
                { key: 'agent', label: 'Agent', value: label(selected.agent_id, '未绑定') },
                { key: 'session', label: '会话', value: label(selected.session_id) },
                { key: 'provider', label: 'Provider', value: label(selected.provider, '未调用') },
                { key: 'model', label: '模型', value: label(selected.model) },
                { key: 'policy', label: '主要策略', value: label(selected.primary_policy_id) },
                { key: 'risk', label: '最高风险', value: selected.risk_score ?? 0 },
                { key: 'receipt', label: '执行回执', value: selected.receipt_count ?? 0 },
                { key: 'request-hash', label: '请求 Hash', value: shortHash(selected.request_hash) },
                { key: 'response-hash', label: '响应 Hash', value: shortHash(selected.provider_response_hash) }
              ]}
            />

            <div>
              <Typography.Title level={5}>处置时间线</Typography.Title>
              <ol className="zh-traffic-timeline">
                {(selected.stages ?? []).map((stage, indexValue) => (
                  <li key={`${stage.audit_id || stage.stage}-${indexValue}`}>
                    <span className="zh-traffic-timeline__icon" aria-hidden="true">
                      {stage.execution_receipt_present ? (
                        <CircleCheck size={16} />
                      ) : stage.provider_call_id ? (
                        <Wrench size={16} />
                      ) : CONTROLLED_DECISIONS.has(label(stage.decision)) ? (
                        <ShieldX size={16} />
                      ) : (
                        <Activity size={16} />
                      )}
                    </span>
                    <div>
                      <Flex justify="space-between" gap={8} wrap="wrap">
                        <Typography.Text strong>{label(stage.stage, `阶段 ${indexValue + 1}`)}</Typography.Text>
                        <Typography.Text type="secondary">{formatTime(stage.timestamp)}</Typography.Text>
                      </Flex>
                      <Space wrap size={[6, 4]}>
                        <LabelTag color={decisionColor(label(stage.decision))}>{label(stage.decision)}</LabelTag>
                        {stage.policy_id ? <LabelTag>{stage.policy_id}</LabelTag> : null}
                        {stage.tool ? <LabelTag>{stage.tool}</LabelTag> : null}
                        {stage.execution_status ? <LabelTag>{stage.execution_status}</LabelTag> : null}
                      </Space>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        ) : null}
      </Drawer>
    </>
  );
}
