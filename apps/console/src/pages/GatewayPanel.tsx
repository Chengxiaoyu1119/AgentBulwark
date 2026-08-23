import { Col, Flex, Row, Typography } from 'antd';
import { PanelCard } from '../components/ui';
import { GatewayComparisonPanel } from '../components/settings/GatewayComparisonPanel';
import { GatewayEvidencePanel } from '../components/settings/GatewayEvidencePanel';
import { GatewayMcpPanel } from '../components/settings/GatewayMcpPanel';
import { GatewayRequestPanel, GatewayRequestPresets } from '../components/settings/GatewayRequestPanel';
import { GatewayRuntimeStatus } from '../components/settings/GatewayRuntimeStatus';
import { GatewayTracePanel } from '../components/settings/GatewayTracePanel';
import { useGatewayPanelController } from '../app/useGatewayPanelController';

export function GatewayPanel() {
  const {
    payload,
    setPayload,
    result,
    error,
    loading,
    executingTool,
    executionResult,
    executionError,
    followupResult,
    followingUp,
    comparisonResult,
    comparisonError,
    comparing,
    runtimeStatus,
    runtimeStatusError,
    sessionId,
    setSessionId,
    managedMode,
    setManagedMode,
    metadata,
    canExecuteManagedTools,
    canCompare,
    canCausalCompare,
    decision,
    blocked,
    toolDecisions,
    toolDefinitionFindings,
    toolArgumentFindings,
    toolResultFindings,
    executableToolDecision,
    responsePreview,
    sendRequest,
    runComparison,
    executeToolCall,
    followupToolResult
  } = useGatewayPanelController();

  return (
    <div className="zh-page-stack">
      <PanelCard variant="borderless">
        <Flex justify="space-between" align="flex-start" gap={16} wrap="wrap">
          <div className="zh-flex-min">
            <Typography.Title level={3} className="zh-title-flush">
              LLM API / MCP 安全网关
            </Typography.Title>
            <Typography.Paragraph type="secondary" className="zh-text-body zh-mt-8 zh-mb-0">
              这里直接调用 <Typography.Text code>POST /v1/chat/completions</Typography.Text>
              ，不是本地演示器；同一安全边界也支持
              <Typography.Text code>POST /v1/responses</Typography.Text>{' '}
              的文本/函数调用子集。请求会经过鉴权、消息与工具契约校验、Provider 前注入检查、真实 Provider，再经过输出与
              tool call 闸门。 只读 observer 凭证只能查看模型目录；发送请求需要 executor、analyst 或 admin 凭证。
            </Typography.Paragraph>
          </div>
          <GatewayRequestPresets onSelect={setPayload} />
        </Flex>
      </PanelCard>

      <GatewayRuntimeStatus status={runtimeStatus} error={runtimeStatusError} />

      <GatewayTracePanel
        refreshSignal={String(
          metadata.request_id || comparisonResult?.comparison_id || metadata.gateway_evidence_fingerprint || ''
        )}
      />

      <Row gutter={[16, 16]} align="stretch">
        <Col xs={24} xl={12}>
          <GatewayRequestPanel
            payload={payload}
            onPayloadChange={setPayload}
            sessionId={sessionId}
            onSessionIdChange={setSessionId}
            managedMode={managedMode}
            onManagedModeChange={setManagedMode}
            canGenerate={runtimeStatus?.security_context?.can_generate}
            canExecuteManagedTools={canExecuteManagedTools}
            identityText={
              runtimeStatus?.security_context
                ? `当前身份：${runtimeStatus.security_context.role || 'unknown'} / ${
                    runtimeStatus.security_context.agent_id || '未绑定 Agent'
                  }`
                : undefined
            }
            loading={loading}
            error={error}
            onSubmit={() => void sendRequest()}
          />
        </Col>

        <Col xs={24} xl={12}>
          <GatewayEvidencePanel
            result={result}
            metadata={metadata}
            blocked={blocked}
            decision={decision}
            toolDecisions={toolDecisions}
            toolDefinitionFindings={toolDefinitionFindings}
            toolArgumentFindings={toolArgumentFindings}
            toolResultFindings={toolResultFindings}
            responsePreview={responsePreview}
            executableToolDecision={executableToolDecision}
            executionResult={executionResult}
            executionError={executionError}
            executingTool={executingTool}
            onExecuteTool={() => void executeToolCall()}
            followupResult={followupResult}
            followingUp={followingUp}
            onFollowupToolResult={() => void followupToolResult()}
          />
        </Col>
      </Row>

      <GatewayComparisonPanel
        result={comparisonResult}
        canCompare={canCompare}
        canCausalCompare={canCausalCompare}
        loading={comparing}
        error={comparisonError}
        onRun={(executionMode) => void runComparison(executionMode)}
      />

      <GatewayMcpPanel runtimeStatus={runtimeStatus} sessionId={sessionId} onSessionIdChange={setSessionId} />
    </div>
  );
}
