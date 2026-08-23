import { useCallback, useEffect, useState } from 'react';
import { Flex, Space, Typography } from 'antd';
import { RefreshCw } from 'lucide-react';
import { request } from '../../app/apiRequest';
import { LabelTag, PanelCard, UiAlert, UiButton } from '../ui';

type GatewayTraceStage = {
  audit_id?: string;
  timestamp?: string;
  stage?: string;
  decision?: string;
  policy_id?: string;
  provider_called?: boolean | null;
  provider_call_id?: string;
  execution_status?: string;
  execution_evidence?: string;
};

type GatewayTrace = {
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
  provider_response_hash?: string;
  controlled_stage_count?: number;
  tool_stage_count?: number;
  server_observed_execution_count?: number;
  receipt_count?: number;
  first_seen?: string;
  last_seen?: string;
  stages?: GatewayTraceStage[];
};

type GatewayTraceIndex = {
  traces?: GatewayTrace[];
  count?: number;
  total_available?: number;
};

type Props = {
  refreshSignal?: string;
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

export function GatewayTracePanel({ refreshSignal = '' }: Props) {
  const [traces, setTraces] = useState<GatewayTrace[]>([]);
  const [selected, setSelected] = useState<GatewayTrace | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const loadTraces = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await request<GatewayTraceIndex>('/api/gateway/traces?limit=12', undefined, {
        retry: 0,
        timeoutMs: 8_000
      });
      setTraces(Array.isArray(data.traces) ? data.traces : []);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '最近网关 Trace 读取失败。');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Defer the network state transition to the next task.  Besides avoiding
    // a render directly from the effect body, this also prevents a rapid
    // request/compare sequence from synchronously cascading through the
    // settings page before the current paint has completed.
    const timer = window.setTimeout(() => {
      void loadTraces();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadTraces, refreshSignal]);

  async function openTrace(trace: GatewayTrace) {
    const requestId = String(trace.request_id || trace.trace_id || '').trim();
    if (!requestId) return;
    setSelected(trace);
    try {
      const detail = await request<GatewayTrace>(`/api/gateway/traces/${encodeURIComponent(requestId)}`, undefined, {
        retry: 0,
        timeoutMs: 8_000
      });
      setSelected(detail);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Trace 详情读取失败。');
    }
  }

  return (
    <PanelCard
      title="最近网关 Trace"
      subtitle="把一次请求的 Provider 前检查、Provider 响应、tool call、执行回执串成可定位时间线"
      extra={
        <UiButton size="small" icon={<RefreshCw size={14} />} loading={loading} onClick={() => void loadTraces()}>
          刷新
        </UiButton>
      }
    >
      {error ? <UiAlert type="warning" showIcon title={error} className="zh-mb-12" /> : null}
      {!traces.length && !loading ? (
        <UiAlert
          type="info"
          showIcon
          title="暂无网关 Trace"
          description="先从上方发送一次真实 Provider 请求；这里不会用本地样本伪造运行记录。"
        />
      ) : (
        <Flex vertical gap={12}>
          <div className="zh-gateway-trace-list" role="list">
            {traces.map((trace) => {
              const requestId = String(trace.request_id || trace.trace_id || '');
              const decision = label(trace.decision);
              const isSelected = selected?.request_id === requestId;
              return (
                <div role="listitem" key={requestId || trace.trace_id || decision}>
                  <button
                    type="button"
                    className={`zh-gateway-trace-item${isSelected ? ' zh-gateway-trace-item--selected' : ''}`}
                    onClick={() => void openTrace(trace)}
                    aria-pressed={isSelected}
                    aria-label={`打开网关 Trace ${requestId || 'unknown-request'}`}
                  >
                    <Flex justify="space-between" align="center" gap={12} wrap="wrap" style={{ width: '100%' }}>
                      <Space size={8} wrap>
                        <LabelTag variant="filled" color={decisionColor(decision)}>
                          {decision}
                        </LabelTag>
                        <Typography.Text code>{requestId || 'unknown-request'}</Typography.Text>
                        <Typography.Text type="secondary">{label(trace.provider, 'Provider 未调用')}</Typography.Text>
                        <Typography.Text type="secondary">{label(trace.model)}</Typography.Text>
                      </Space>
                      <Typography.Text type="secondary">
                        {trace.provider_called === true
                          ? 'Provider 已调用'
                          : trace.provider_called === false
                            ? 'Provider 未调用'
                            : '调用未知'}
                      </Typography.Text>
                    </Flex>
                  </button>
                </div>
              );
            })}
          </div>

          {selected ? (
            <PanelCard title="Trace 详情" size="small" type="inner">
              <div className="zh-meta-grid zh-meta-grid--2">
                {[
                  ['请求 ID', selected.request_id || selected.trace_id],
                  ['会话', selected.session_id],
                  ['Agent', selected.agent_id],
                  ['状态', selected.status],
                  ['Provider', selected.provider],
                  ['Provider 配置档', selected.provider_profile],
                  ['模型', selected.model],
                  ['请求 Hash', shortHash(selected.request_hash)],
                  ['Provider 响应 Hash', shortHash(selected.provider_response_hash)],
                  ['受控阶段', selected.controlled_stage_count],
                  ['Tool Call 阶段', selected.tool_stage_count],
                  ['服务端执行', selected.server_observed_execution_count],
                  ['回执数量', selected.receipt_count],
                  ['开始', selected.first_seen],
                  ['结束', selected.last_seen]
                ].map(([name, value]) => (
                  <div className="zh-meta-grid__item" key={String(name)}>
                    <Typography.Text type="secondary" className="zh-meta-grid__label">
                      {String(name)}
                    </Typography.Text>
                    <Typography.Text className="zh-meta-grid__value">{label(value)}</Typography.Text>
                  </div>
                ))}
              </div>
              {Array.isArray(selected.stages) && selected.stages.length > 0 ? (
                <Space orientation="vertical" size={6} className="zh-full-width zh-mt-12">
                  <Typography.Text strong>阶段时间线</Typography.Text>
                  {selected.stages.map((stage, index) => (
                    <Flex key={`${stage.audit_id || 'stage'}-${index}`} justify="space-between" gap={12} wrap="wrap">
                      <Space size={8} wrap>
                        <Typography.Text code>{label(stage.stage)}</Typography.Text>
                        <Typography.Text>{label(stage.decision)}</Typography.Text>
                        <Typography.Text type="secondary">{label(stage.policy_id)}</Typography.Text>
                        {stage.provider_call_id ? (
                          <Typography.Text type="secondary">call:{stage.provider_call_id}</Typography.Text>
                        ) : null}
                      </Space>
                      <Typography.Text type="secondary">{label(stage.timestamp)}</Typography.Text>
                    </Flex>
                  ))}
                </Space>
              ) : null}
            </PanelCard>
          ) : null}
        </Flex>
      )}
    </PanelCard>
  );
}
