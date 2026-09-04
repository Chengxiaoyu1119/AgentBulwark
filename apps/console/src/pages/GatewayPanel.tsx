import { useMemo, useState } from 'react';
import { UiDrawer, UiFlex, UiTypography } from '../components/ui';
import { PlugZap, Send } from 'lucide-react';
import { CopyButton, LabelTag, PageHeader, UiButton, UiTabs } from '../components/ui';
import { GatewayEvidencePanel } from '../components/gateway/GatewayEvidencePanel';
import { GatewayMcpPanel } from '../components/gateway/GatewayMcpPanel';
import { GatewayRequestPanel, GatewayRequestPresets } from '../components/gateway/GatewayRequestPanel';
import { GatewayRuntimeStatus } from '../components/gateway/GatewayRuntimeStatus';
import { GatewaySetupFlow } from '../components/gateway/GatewaySetupFlow';
import { GatewayTracePanel } from '../components/gateway/GatewayTracePanel';
import { useGatewayPanelController } from '../app/useGatewayPanelController';
type DrawerMode = 'setup' | 'verify' | null;
type ProtectionChannel = 'openai' | 'mcp';
export function GatewayPanel({ onOpenSettings }: { onOpenSettings?: () => void }) {
  const [drawerMode, setDrawerMode] = useState<DrawerMode>(null);
  const [setupStep, setSetupStep] = useState(0);
  const [channel, setChannel] = useState<ProtectionChannel>('openai');
  const controller = useGatewayPanelController();
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
    runtimeStatus,
    runtimeStatusError,
    sessionId,
    setSessionId,
    managedMode,
    setManagedMode,
    streamProgress,
    metadata,
    canExecuteManagedTools,
    decision,
    blocked,
    toolDecisions,
    toolDefinitionFindings,
    toolArgumentFindings,
    toolResultFindings,
    executableToolDecision,
    responsePreview,
    sendRequest,
    cancelStream,
    executeToolCall,
    followupToolResult
  } = controller;
  const readiness = useMemo(() => {
    const provider = Boolean(
      runtimeStatus?.models?.target?.some((item) => item.configured && item.mode === 'real-api')
    );
    const gateway = runtimeStatus?.proxy?.enabled === true && Boolean(runtimeStatus?.gateway_evidence?.fingerprint);
    const toolBoundary =
      runtimeStatus?.proxy?.tool_receipts_required === true &&
      runtimeStatus.proxy.server_observed_receipts_required === true;
    return { provider, gateway, toolBoundary };
  }, [runtimeStatus]);
  const protectionReady = readiness.provider && readiness.gateway && readiness.toolBoundary;
  const mcpReady =
    runtimeStatus?.mcp?.configured === true &&
    runtimeStatus.mcp.enabled === true &&
    runtimeStatus.mcp.guard_enabled === true;
  const channelReady = channel === 'openai' ? protectionReady : mcpReady;

  return (
    <div className="zh-product-page">
      <PageHeader
        title="请求防护"
        badge={
          <LabelTag color={channelReady ? 'green' : 'warning'}>{channelReady ? '防护已配置' : '等待接入'}</LabelTag>
        }
        description="统一验证模型 API 与 MCP 工具调用，实时查看放行、阻断、隔离和执行证据。"
        actions={
          channel === 'openai' ? (
            <>
              <UiButton icon={<Send size={16} />} onClick={() => setDrawerMode('verify')}>
                验证防护
              </UiButton>
              <UiButton type="primary" icon={<PlugZap size={16} />} onClick={() => setDrawerMode('setup')}>
                接入应用
              </UiButton>
            </>
          ) : (
            <CopyButton text={`${window.location.origin}/api/mcp`}>复制 MCP 地址</CopyButton>
          )
        }
      />

      <GatewayRuntimeStatus status={runtimeStatus} error={runtimeStatusError} />

      <UiTabs
        className="zh-product-tabs"
        activeKey={channel}
        onChange={(key) => setChannel(key as ProtectionChannel)}
        items={[
          {
            key: 'openai',
            label: '模型 API',
            children: (
              <GatewayTracePanel
                refreshSignal={String(metadata.request_id || metadata.gateway_evidence_fingerprint || '')}
                onCreateRequest={() => setDrawerMode('verify')}
              />
            )
          },
          {
            key: 'mcp',
            label: 'MCP 工具',
            children: (
              <GatewayMcpPanel runtimeStatus={runtimeStatus} sessionId={sessionId} onSessionIdChange={setSessionId} />
            )
          }
        ]}
      />

      <UiDrawer
        title={drawerMode === 'setup' ? '接入应用' : '验证一条真实请求'}
        size="large"
        open={drawerMode !== null}
        onClose={() => setDrawerMode(null)}
        destroyOnHidden
        className="zh-workflow-drawer"
      >
        {drawerMode === 'setup' ? (
          <GatewaySetupFlow
            step={setupStep}
            onStepChange={setSetupStep}
            readiness={readiness}
            onOpenSettings={() => {
              setDrawerMode(null);
              onOpenSettings?.();
            }}
            onVerify={() => setDrawerMode('verify')}
          />
        ) : (
          <div className="zh-verify-workflow">
            <UiFlex justify="space-between" align="center" gap={12} wrap="wrap">
              <UiTypography.Text type="secondary">选择一个请求，也可以直接编辑 JSON。</UiTypography.Text>
              <GatewayRequestPresets onSelect={setPayload} />
            </UiFlex>
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
              streamProgress={streamProgress}
              error={error}
              onSubmit={() => void sendRequest()}
              onCancelStream={cancelStream}
            />
            {result ? (
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
            ) : null}
          </div>
        )}
      </UiDrawer>
    </div>
  );
}
