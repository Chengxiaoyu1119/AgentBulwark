import { Flex, Space, Typography } from 'antd';
import { Play } from 'lucide-react';
import { LabelTag, PanelCard, UiAlert, UiButton } from '../ui';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import type { GatewayToolExecutionResult } from '../../types';

type Props = {
  result: Record<string, unknown> | null;
  metadata: Record<string, unknown>;
  blocked: boolean;
  decision: string;
  toolDecisions: unknown[];
  toolDefinitionFindings: unknown[];
  toolArgumentFindings: unknown[];
  toolResultFindings: unknown[];
  responsePreview: string;
  executableToolDecision: Record<string, unknown> | null;
  executionResult: GatewayToolExecutionResult | null;
  executionError: string;
  executingTool: boolean;
  onExecuteTool: () => void;
  followupResult: Record<string, unknown> | null;
  followingUp: boolean;
  onFollowupToolResult: () => void;
};

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2);
}

function text(value: unknown, fallback = '—') {
  if (value === undefined || value === null || value === '') return fallback;
  return String(value);
}

function networkRouteLabel(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return '未观测';
  const observation = value as Record<string, unknown>;
  if (observation.verified_public_route === true) return '仅含公网地址';
  if (observation.checked === true) return String(observation.address_classification || '未通过');
  return '未观测';
}

function auditReferences(metadata: Record<string, unknown>, toolDecisions: unknown[]) {
  const values: string[] = [];
  const append = (value: unknown) => {
    const normalized = typeof value === 'string' ? value.trim() : '';
    if (normalized && !values.includes(normalized)) values.push(normalized);
  };

  append(metadata.audit_id);
  append(metadata.gateway_audit_id);
  if (Array.isArray(metadata.audit_ids)) metadata.audit_ids.forEach(append);
  toolDecisions.forEach((item) => {
    if (item && typeof item === 'object') append((item as Record<string, unknown>).audit_id);
  });
  return values.slice(0, 16);
}

export function GatewayEvidencePanel({
  result,
  metadata,
  blocked,
  decision,
  toolDecisions,
  toolDefinitionFindings,
  toolArgumentFindings,
  toolResultFindings,
  responsePreview,
  executableToolDecision,
  executionResult,
  executionError,
  executingTool,
  onExecuteTool,
  followupResult,
  followingUp,
  onFollowupToolResult
}: Props) {
  const callerDeclaredReceiptCount = Number(metadata.tool_receipts_caller_declared ?? 0);
  const callerDeclaredReceiptUsed =
    metadata.tool_receipt_evidence === 'caller-declared' || callerDeclaredReceiptCount > 0;
  const receiptTrustPolicy =
    metadata.tool_receipt_server_observed_required === true
      ? '仅服务端观察'
      : metadata.tool_receipt_server_observed_required === false
        ? '调用方声明兼容'
        : '未知';
  const auditIds = auditReferences(metadata, toolDecisions);

  return (
    <PanelCard title="处置证据" subtitle="Provider 前后同一请求的可追踪结果" className="zh-full-height">
      {!result ? (
        <UiAlert
          type="info"
          showIcon
          title="尚未发送请求"
          description="把真实 Agent 的 OpenAI 请求或自定义 Payload 粘贴到左侧发送；这里会显示是否到达 Provider、策略阶段、工具处置、执行边界和审计 Hash。"
        />
      ) : (
        <Space orientation="vertical" size={16} className="zh-full-width">
          <Flex justify="space-between" align="center">
            <Typography.Text strong>最终决策</Typography.Text>
            <LabelTag variant="filled" color={blocked ? 'red' : 'green'}>
              {decision}
            </LabelTag>
          </Flex>
          <div className="zh-meta-grid zh-meta-grid--2">
            {[
              ['阶段', metadata.request_stage],
              [
                'Provider 是否调用',
                metadata.provider_called === true ? '是' : metadata.provider_called === false ? '否' : '未知'
              ],
              ['Provider', metadata.provider],
              ['Provider 路由类别', metadata.provider_endpoint_scope],
              ['Provider 网络路由核验', networkRouteLabel(metadata.provider_network_observation)],
              ['策略', metadata.policy_id],
              ['风险分', metadata.risk_score],
              ['审计 ID', metadata.audit_id],
              ['网关审计 ID', metadata.gateway_audit_id],
              ['网关证据类型', metadata.gateway_contract_evidence],
              ['源码/配置指纹', metadata.gateway_evidence_fingerprint],
              ['服务启动时间', metadata.gateway_runtime_started_at],
              ['证据范围', metadata.evidence_scope],
              ['请求哈希', metadata.request_hash],
              ['初始请求哈希', metadata.initial_request_hash],
              ['Provider 请求哈希', metadata.provider_request_hash],
              ['Provider 响应哈希', metadata.provider_response_hash],
              ['Provider 响应 ID', metadata.provider_response_id],
              ['执行模式', metadata.execution_mode],
              ['托管状态', metadata.managed_status],
              ['托管轮次', metadata.managed_rounds],
              [
                '托管回执数量',
                Array.isArray(metadata.managed_tool_executions) ? metadata.managed_tool_executions.length : 0
              ],
              ['托管审计数量', Array.isArray(metadata.managed_audit_ids) ? metadata.managed_audit_ids.length : 0],
              ['工具回执要求', metadata.tool_receipt_required === true ? '是' : '否'],
              ['回执信任策略', receiptTrustPolicy],
              ['本次回执来源', metadata.tool_receipt_evidence],
              ['已验证回执', metadata.tool_receipts_verified ?? 0],
              ['服务端观察回执', metadata.tool_receipts_server_observed ?? 0],
              ['调用方声明回执', metadata.tool_receipts_caller_declared ?? 0],
              ['工具执行前强制阻断', metadata.decision_enforced_before_tool_execution === true ? '是' : '否'],
              ['执行边界', metadata.execution_boundary],
              ['执行事实', metadata.execution_outcome],
              ['工具执行', metadata.tool_execution],
              ['工具参数扫描', toolArgumentFindings.length ? `${toolArgumentFindings.length} 项命中` : '未命中'],
              ['工具结果扫描', toolResultFindings.length ? `${toolResultFindings.length} 项隔离` : '未命中'],
              ['原因', metadata.reason]
            ].map(([label, value]) => (
              <div key={String(label)} className="zh-meta-grid__item">
                <Typography.Text type="secondary" className="zh-meta-grid__label">
                  {String(label)}
                </Typography.Text>
                <Typography.Text className="zh-meta-grid__value">{text(value)}</Typography.Text>
              </div>
            ))}
          </div>
          {auditIds.length > 0 ? (
            <Flex justify="space-between" align="center" gap={12} wrap="wrap">
              <Typography.Text strong>审计精确定位</Typography.Text>
              <Space wrap>
                {auditIds.map((auditId, index) => (
                  <AuditDeepLinkButton key={auditId} auditId={auditId}>
                    {auditIds.length === 1 ? '打开本次审计' : `打开审计 ${index + 1}`}
                  </AuditDeepLinkButton>
                ))}
              </Space>
            </Flex>
          ) : null}
          {callerDeclaredReceiptUsed ? (
            <UiAlert
              type="warning"
              showIcon
              title="本次工具结果仅有调用方声明"
              description="Hash/HMAC 只证明声明内容与审计记录绑定，不代表智安哨观察到实际工具执行。"
            />
          ) : null}
          {toolDecisions.length > 0 && <EvidenceBlock title="Tool call 处置" value={toolDecisions} />}
          {toolDefinitionFindings.length > 0 && <EvidenceBlock title="工具定义扫描" value={toolDefinitionFindings} />}
          {toolArgumentFindings.length > 0 && (
            <EvidenceBlock title="Provider 工具参数扫描" value={toolArgumentFindings} />
          )}
          {toolResultFindings.length > 0 && <EvidenceBlock title="工具结果上下文扫描" value={toolResultFindings} />}
          {Array.isArray(metadata.managed_tool_executions) && metadata.managed_tool_executions.length > 0 && (
            <EvidenceBlock title="服务端托管执行回执" value={metadata.managed_tool_executions} />
          )}
          {Array.isArray(metadata.managed_round_evidence) && metadata.managed_round_evidence.length > 0 && (
            <EvidenceBlock title="托管 Provider 轮次证据" value={metadata.managed_round_evidence} />
          )}
          {executableToolDecision && (
            <PanelCard
              title="服务端执行闸门"
              subtitle="仅执行已审计且决策为允许的 Provider tool call；隔离调用只保留证据"
              className="zh-mt-12"
            >
              <Flex justify="space-between" align="center" gap={12} wrap="wrap">
                <Typography.Text type="secondary">
                  这是闭环中的实际执行步骤，默认进入智安哨本地沙箱，不接受浏览器重新提交的工具参数。
                </Typography.Text>
                <UiButton type="primary" icon={<Play size={16} />} loading={executingTool} onClick={onExecuteTool}>
                  服务端沙箱执行
                </UiButton>
              </Flex>
              {executionError && <UiAlert type="error" showIcon title={executionError} className="zh-mt-12" />}
              {executionResult && (
                <Space orientation="vertical" size={8} className="zh-full-width zh-mt-12">
                  <Typography.Text strong>
                    执行事实：{executionResult.execution_observed_by_server ? '服务端观察' : '调用方声明'}
                  </Typography.Text>
                  <Typography.Text type="secondary">
                    回执：{text(executionResult.receipt?.receipt_hash)} · 结果哈希：
                    {text(executionResult.tool_result_hash)}
                  </Typography.Text>
                  <pre className="zh-evidence-code-block">
                    {executionResult.tool_result || pretty(executionResult.execution_result)}
                  </pre>
                  <Flex justify="space-between" align="center" gap={12} wrap="wrap">
                    <Typography.Text type="secondary">
                      回灌会携带已验证回执，重新经过工具结果扫描后才到达 Provider。
                    </Typography.Text>
                    <UiButton loading={followingUp} onClick={onFollowupToolResult}>
                      回灌结果并继续对话
                    </UiButton>
                  </Flex>
                  {followupResult && (
                    <>
                      <Typography.Text strong>回灌后的 Provider 响应</Typography.Text>
                      <pre className="zh-evidence-code-block">{pretty(followupResult.choices ?? followupResult)}</pre>
                    </>
                  )}
                </Space>
              )}
            </PanelCard>
          )}
          <Typography.Text strong>返回摘要</Typography.Text>
          <pre className="zh-evidence-code-block">{responsePreview}</pre>
        </Space>
      )}
    </PanelCard>
  );
}

function EvidenceBlock({ title, value }: { title: string; value: unknown }) {
  return (
    <>
      <Typography.Text strong>{title}</Typography.Text>
      <pre className="zh-evidence-code-block">{pretty(value)}</pre>
    </>
  );
}
