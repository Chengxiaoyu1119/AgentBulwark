import { useRef } from 'react';
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
  const requestSectionRef = useRef<HTMLDivElement>(null);
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
      <PanelCard variant="borderless" className="zh-gateway-hero">
        <Flex justify="space-between" align="flex-start" gap={16} wrap="wrap">
          <div className="zh-flex-min">
            <Typography.Title level={3} className="zh-title-flush">
              实时流量与执行闸门
            </Typography.Title>
            <Typography.Paragraph type="secondary" className="zh-text-body zh-mt-8 zh-mb-0">
              观察进入 <Typography.Text code>/v1/chat/completions</Typography.Text>、
              <Typography.Text code>/v1/responses</Typography.Text> 与 MCP 的真实请求，在 Provider 前后、Tool Call 和执行回执阶段完成控制。
              当前视图只读取运营数据库，不混入实验脚本和固定样本。
            </Typography.Paragraph>
          </div>
        </Flex>
      </PanelCard>

      <GatewayTracePanel
        refreshSignal={String(
          metadata.request_id || comparisonResult?.comparison_id || metadata.gateway_evidence_fingerprint || ''
        )}
        onCreateRequest={() => requestSectionRef.current?.scrollIntoView({ block: 'start' })}
      />

      <div ref={requestSectionRef} className="zh-gateway-composer">
        <Flex justify="space-between" align="center" gap={12} wrap="wrap" className="zh-gateway-composer__head">
          <div>
            <Typography.Title level={4} className="zh-title-flush">
              发起验证请求
            </Typography.Title>
            <Typography.Text type="secondary">请求结果会立即写入上方实时流量并绑定当前运行指纹。</Typography.Text>
          </div>
          <GatewayRequestPresets onSelect={setPayload} />
        </Flex>

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
      </div>

      <details className="zh-gateway-runtime-details">
        <summary>运行配置与边界状态</summary>
        <GatewayRuntimeStatus status={runtimeStatus} error={runtimeStatusError} />
      </details>

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
