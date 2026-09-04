import { UiSpace, UiTypography } from '../ui';
import type { JsonObject } from '../../app/mcpConsoleContract';
import { useGatewayMcpController } from '../../app/useGatewayMcpController';
import { EvidenceCodeBlock, PanelCard, UiAlert } from '../ui';
import { GatewayMcpActions } from './GatewayMcpActions';
import { GatewayMcpEvidence } from './GatewayMcpEvidence';
import { GatewayMcpInputRequiredPanel } from './GatewayMcpInputRequiredPanel';
import { GatewayMcpRequestFields } from './GatewayMcpRequestFields';
import { GatewayMcpStreamEvidence } from './GatewayMcpStreamEvidence';
import { GatewayMcpSubscriptionPanel } from './GatewayMcpSubscriptionPanel';
import type { RuntimeStatus } from './GatewayRuntimeStatus';

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2);
}

export function GatewayMcpPanel({
  runtimeStatus,
  sessionId,
  onSessionIdChange
}: {
  runtimeStatus: RuntimeStatus | null;
  sessionId: string;
  onSessionIdChange: (value: string) => void;
}) {
  const controller = useGatewayMcpController({ sessionId });
  const {
    toolName,
    setToolName,
    argumentsText,
    setArgumentsText,
    contextUri,
    setContextUri,
    promptName,
    setPromptName,
    protocolVersion,
    changeProtocolVersion,
    modern,
    result,
    contextEvidence,
    error,
    loadingMethod,
    streamProgressEnabled,
    setStreamProgressEnabled,
    logLevel,
    setLogLevel,
    streamEvents,
    subscriptionFilters,
    setSubscriptionFilters,
    subscriptionResources,
    setSubscriptionResources,
    subscriptionStatus,
    subscriptionEvents,
    subscriptionError,
    inputRequired,
    send,
    resumeInputRequired,
    loadContextEvidence,
    startSubscription,
    stopSubscription
  } = controller;

  const configured = runtimeStatus?.mcp?.configured === true;
  const guardReady = runtimeStatus?.mcp?.guard_enabled === true;
  const canUseMcp = runtimeStatus?.security_context?.can_use_mcp;
  const canExecuteMcpTools = runtimeStatus?.security_context?.can_execute_mcp_tools;
  return (
    <PanelCard
      title="MCP JSON-RPC 实际入口"
      subtitle="直接调用 POST /api/mcp；工具与 resources/prompts 上下文都经过会话隔离和网关边界"
    >
      {!runtimeStatus ? (
        <UiAlert type="info" showIcon title="正在读取 MCP 运行状态。" />
      ) : !configured ? (
        <UiAlert
          type="warning"
          showIcon
          title="MCP 上游待配置"
          description="配置 MCP_GATEWAY_UPSTREAM_COMMAND 或 MCP_GATEWAY_ROUTES_JSON 后，这里会通过真实 tools、resources 和 prompts 请求生成证据。"
        />
      ) : !guardReady ? (
        <UiAlert
          type="error"
          showIcon
          title="MCP 上游已配置，强制监督待开启"
          description="将 MCP_GATEWAY_GUARD_ENABLED=true 并重启 API，即可执行受监督的真实 JSON-RPC 请求。"
        />
      ) : canUseMcp === false ? (
        <UiAlert
          type="info"
          showIcon
          title="当前操作员身份为查看角色"
          description="切换到 analyst、绑定 Agent 的 executor 或 admin 凭证后，即可发起 MCP 请求。"
        />
      ) : (
        <UiSpace orientation="vertical" size={16} className="zh-full-width">
          <UiTypography.Paragraph type="secondary" className="zh-mb-0">
            本面板使用当前 Agent 会话 ID：<UiTypography.Text code>{sessionId || '未设置'}</UiTypography.Text>
            。先执行协议发现或初始化并读取工具/上下文目录，再选择真实工具或上下文操作；错误响应、隔离决策、上下文白名单结果和
            audit_id 都会原样保留在证据区。
          </UiTypography.Paragraph>
          {canExecuteMcpTools === false ? (
            <UiAlert
              type="info"
              showIcon
              title="当前身份可以验证 MCP 目录与上下文；绑定 Agent 的 executor 或 admin 凭证可执行 tools/call。"
              description="工具执行需要绑定 Agent 的 executor 或 admin 凭证。"
            />
          ) : null}
          <GatewayMcpRequestFields
            protocolVersion={protocolVersion}
            sessionId={sessionId}
            toolName={toolName}
            argumentsText={argumentsText}
            contextUri={contextUri}
            promptName={promptName}
            streamProgressEnabled={streamProgressEnabled}
            logLevel={logLevel}
            onProtocolVersionChange={changeProtocolVersion}
            onSessionIdChange={(value) => {
              stopSubscription();
              onSessionIdChange(value);
            }}
            onToolNameChange={setToolName}
            onArgumentsTextChange={setArgumentsText}
            onContextUriChange={setContextUri}
            onPromptNameChange={setPromptName}
            onStreamProgressEnabledChange={setStreamProgressEnabled}
            onLogLevelChange={setLogLevel}
          />
          <GatewayMcpActions
            loadingMethod={loadingMethod}
            modern={modern}
            canExecuteTools={canExecuteMcpTools !== false}
            onSend={(method) => void send(method)}
            onLoadContextEvidence={() => void loadContextEvidence()}
          />
          {modern ? (
            <GatewayMcpSubscriptionPanel
              filters={subscriptionFilters}
              resourceSubscriptions={subscriptionResources}
              status={subscriptionStatus}
              events={subscriptionEvents}
              error={subscriptionError}
              onFilterChange={(key, selected) => setSubscriptionFilters((current) => ({ ...current, [key]: selected }))}
              onResourceSubscriptionsChange={setSubscriptionResources}
              onStart={() => void startSubscription()}
              onStop={stopSubscription}
            />
          ) : null}
          {error && <UiAlert type="error" showIcon title={error} />}
          {result && <GatewayMcpEvidence result={result} />}
          <GatewayMcpStreamEvidence events={streamEvents} />
          {inputRequired ? (
            <GatewayMcpInputRequiredPanel
              key={inputRequired.requestState}
              inputRequired={inputRequired}
              loading={loadingMethod === 'mrtr/resume'}
              onResume={(inputResponses) => void resumeInputRequired(inputResponses)}
            />
          ) : null}
          {contextEvidence && (
            <UiSpace orientation="vertical" size={8} className="zh-full-width">
              <UiTypography.Text strong>操作员专属 MCP 上下文证据</UiTypography.Text>
              <UiTypography.Text type="secondary">
                可见 {String((contextEvidence.summary as JsonObject | undefined)?.visible_context_count ?? 0)}{' '}
                项；已过滤 {String((contextEvidence.summary as JsonObject | undefined)?.filtered_context_count ?? 0)}{' '}
                项；会话范围 {String(contextEvidence.session_scope ?? '未标注')}。
              </UiTypography.Text>
              <EvidenceCodeBlock size="small" maxHeight="large">
                {pretty(contextEvidence)}
              </EvidenceCodeBlock>
            </UiSpace>
          )}
        </UiSpace>
      )}
    </PanelCard>
  );
}
