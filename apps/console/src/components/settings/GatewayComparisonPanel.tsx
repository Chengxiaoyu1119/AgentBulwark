import { isValidElement, type ReactNode } from 'react';
import { Flex, Row, Col, Space, Typography } from 'antd';
import { GitCompareArrows } from 'lucide-react';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import { LabelTag, PanelCard, UiAlert, UiButton } from '../ui';

export type GatewayComparisonResult = {
  baseline?: Record<string, unknown>;
  guarded?: Record<string, unknown>;
  invariants?: Record<string, unknown>;
  verdict?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  request_hash?: string;
  [key: string]: unknown;
};

type Props = {
  result: GatewayComparisonResult | null;
  canCompare?: boolean;
  canCausalCompare?: boolean;
  loading: boolean;
  error: string;
  onRun: (executionMode?: 'observation' | 'sandbox-causal') => void;
};

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function stringValue(value: unknown, fallback = '—') {
  if (value === undefined || value === null || value === '') return fallback;
  return String(value);
}

function boolLabel(value: unknown, fallback = '未观测') {
  if (value === true) return '是';
  if (value === false) return '否';
  return fallback;
}

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2);
}

function decisionTone(decision: string): 'green' | 'red' | 'warning' | 'blue' {
  if (decision === '允许') return 'green';
  if (decision === '拒绝' || decision === '隔离') return 'red';
  if (decision === '询问') return 'warning';
  return 'blue';
}

function responsePreview(branch: Record<string, unknown>) {
  return pretty(branch.response ?? { response_shape: branch.response_shape });
}

export function GatewayComparisonPanel({ result, canCompare, canCausalCompare, loading, error, onRun }: Props) {
  const baseline = record(result?.baseline);
  const guarded = record(result?.guarded);
  const verdict = record(result?.verdict);
  const invariants = record(result?.invariants);
  const evidence = record(result?.evidence);
  const decision = stringValue(guarded.decision, '未观测');
  const causalObserved = verdict.causal_control_observed === true;
  const protectedAuditIds = Array.isArray(guarded.audit_ids)
    ? guarded.audit_ids.filter((item): item is string => typeof item === 'string' && Boolean(item.trim()))
    : [];

  return (
    <PanelCard
      title="同请求验证（按需）"
      subtitle="非生产请求路径：同一目标 Provider、同一模型可见请求；观察模式只比较协议，因果模式在隔离沙箱中计数执行效果"
    >
      <Flex justify="space-between" align="center" gap={12} wrap="wrap" className="zh-mb-12">
        <Typography.Text type="secondary">
          这条验证只用于建立“无防护 Provider
          产生了什么”与“智安哨实际控制了什么”的因果证据，不参与生产请求，也不是离线评测或本地样本回放。
        </Typography.Text>
        <Space wrap>
          <UiButton
            icon={<GitCompareArrows size={16} />}
            loading={loading}
            disabled={canCompare === false}
            onClick={() => onRun('observation')}
          >
            运行同请求对照
          </UiButton>
          <UiButton
            type="primary"
            loading={loading}
            disabled={canCausalCompare === false}
            onClick={() => onRun('sandbox-causal')}
          >
            运行因果对照（沙箱）
          </UiButton>
        </Space>
      </Flex>
      {canCompare === false ? (
        <UiAlert
          type="warning"
          showIcon
          title="当前身份不能运行无防护基线对照"
          description="同请求对照只允许 analyst 或 admin；普通 executor 仍可直接调用受保护网关。"
          className="zh-mb-12"
        />
      ) : null}
      {canCausalCompare === false ? (
        <UiAlert
          type="info"
          showIcon
          title="因果对照需要 admin"
          description="因果模式会在服务端隔离沙箱中执行无防护分支并记录执行计数；analyst 仍可运行只观察模式。"
          className="zh-mb-12"
        />
      ) : null}
      {error ? <UiAlert type="error" showIcon title={error} className="zh-mb-12" /> : null}
      {!result ? (
        <UiAlert
          type="info"
          showIcon
          title="尚未运行对照"
          description="先在上方编辑真实 OpenAI 请求；点击后会先经过智安哨透明网关，再对同一模型可见请求做一次只观察基线。"
        />
      ) : (
        <Space orientation="vertical" size={16} className="zh-full-width">
          <Flex justify="space-between" align="center" gap={12} wrap="wrap">
            <Space wrap>
              <LabelTag variant="filled" color={causalObserved ? 'green' : 'warning'}>
                {causalObserved ? '因果控制已观测' : '对照未形成完整因果证据'}
              </LabelTag>
              <Typography.Text type="secondary">请求哈希：{stringValue(result.request_hash)}</Typography.Text>
              <Typography.Text type="secondary">模式：{stringValue(result.execution_mode)}</Typography.Text>
            </Space>
            <Typography.Text type="secondary">
              证据事件：{evidence.persisted === true ? `#${stringValue(evidence.event_id)}` : '未落库'}
            </Typography.Text>
          </Flex>

          <Row gutter={[16, 16]} align="stretch">
            <Col xs={24} xl={12}>
              <PanelCard
                title="无防护 Provider"
                subtitle="真实 Provider 直连；因果模式在隔离沙箱中执行并只返回计数/哈希"
              >
                <Space orientation="vertical" size={10} className="zh-full-width">
                  <div className="zh-meta-grid zh-meta-grid--2">
                    <Meta label="Provider" value={baseline.provider} />
                    <Meta label="模型" value={baseline.response_model || baseline.requested_model} />
                    <Meta label="Provider 是否调用" value={boolLabel(baseline.provider_called)} />
                    <Meta label="Tool call 数量" value={record(baseline.response_shape).returned_tool_call_count} />
                    <Meta label="执行事实" value={baseline.tool_execution} />
                    <Meta
                      label="已执行 / 完成"
                      value={`${stringValue(record(baseline.execution).executed_count, '0')} / ${stringValue(
                        record(baseline.execution).completed_count,
                        '0'
                      )}`}
                    />
                    <Meta label="副作用状态变化" value={boolLabel(record(baseline.execution).state_changed)} />
                    <Meta label="请求哈希一致" value={boolLabel(baseline.request_hash === result.request_hash)} />
                  </div>
                  <pre className="zh-evidence-code-block">{responsePreview(baseline)}</pre>
                </Space>
              </PanelCard>
            </Col>
            <Col xs={24} xl={12}>
              <PanelCard title="智安哨网关" subtitle="同请求经过输入/Provider 输出/tool call 闸门">
                <Space orientation="vertical" size={10} className="zh-full-width">
                  <div className="zh-meta-grid zh-meta-grid--2">
                    <Meta
                      label="决策"
                      value={
                        <LabelTag variant="filled" color={decisionTone(decision)}>
                          {decision}
                        </LabelTag>
                      }
                    />
                    <Meta label="Provider 是否调用" value={boolLabel(guarded.provider_called)} />
                    <Meta label="阶段" value={guarded.request_stage} />
                    <Meta label="Tool call 数量" value={record(guarded.response_shape).returned_tool_call_count} />
                    <Meta label="执行前强制阻断" value={boolLabel(guarded.decision_enforced_before_tool_execution)} />
                    <Meta label="策略" value={guarded.policy_id} />
                    <Meta
                      label="已执行 / 完成"
                      value={`${stringValue(record(guarded.execution).executed_count, '0')} / ${stringValue(
                        record(guarded.execution).completed_count,
                        '0'
                      )}`}
                    />
                    <Meta label="副作用状态变化" value={boolLabel(record(guarded.execution).state_changed)} />
                  </div>
                  <pre className="zh-evidence-code-block">{responsePreview(guarded)}</pre>
                  {protectedAuditIds.length > 0 ? (
                    <Space wrap>
                      {protectedAuditIds.slice(0, 8).map((auditId, index) => (
                        <AuditDeepLinkButton key={auditId} auditId={auditId}>
                          {protectedAuditIds.length === 1 ? '打开受保护审计' : `打开受保护审计 ${index + 1}`}
                        </AuditDeepLinkButton>
                      ))}
                    </Space>
                  ) : null}
                </Space>
              </PanelCard>
            </Col>
          </Row>

          <PanelCard title="判定依据" subtitle="只把已观测事实写入结论，不把 Provider 拒答当作防护成功">
            <div className="zh-meta-grid zh-meta-grid--2">
              <Meta label="基线观察到 Tool call" value={boolLabel(verdict.baseline_tool_call_observed)} />
              <Meta label="网关已控制" value={boolLabel(verdict.guarded_controlled)} />
              <Meta label="网关未返回 Tool call" value={boolLabel(verdict.guarded_tool_call_withheld)} />
              <Meta label="同 Provider 请求" value={boolLabel(invariants.same_provider_request)} />
              <Meta label="同 Provider" value={boolLabel(invariants.same_provider)} />
              <Meta label="同 Tool call" value={boolLabel(invariants.same_tool_call)} />
              <Meta label="基线执行已观测" value={boolLabel(record(baseline.execution).execution_observed)} />
              <Meta label="受保护执行已观测" value={boolLabel(record(guarded.execution).execution_observed)} />
              <Meta label="基线状态已变化" value={boolLabel(verdict.baseline_state_changed)} />
              <Meta label="受保护状态已变化" value={boolLabel(verdict.guarded_state_changed)} />
              <Meta
                label="副作用是否被抑制"
                value={
                  <LabelTag variant="filled" color={verdict.side_effect_suppressed === true ? 'green' : 'warning'}>
                    {verdict.side_effect_suppressed === true ? '已观测' : '未形成证据'}
                  </LabelTag>
                }
              />
              <Meta label="证据完整" value={boolLabel(verdict.evidence_complete)} />
            </div>
            <Typography.Text type="secondary" className="zh-meta-block zh-mt-12">
              观察模式不会执行 Tool call；因果模式只在智安哨隔离沙箱内执行，实际外部连接器仍不在本对照范围。
            </Typography.Text>
          </PanelCard>
        </Space>
      )}
    </PanelCard>
  );
}

function Meta({ label, value }: { label: string; value: unknown }) {
  const rendered: ReactNode = isValidElement(value) ? value : stringValue(value);
  return (
    <div className="zh-meta-grid__item">
      <Typography.Text type="secondary" className="zh-meta-grid__label">
        {label}
      </Typography.Text>
      <Typography.Text className="zh-meta-grid__value">{rendered}</Typography.Text>
    </div>
  );
}
