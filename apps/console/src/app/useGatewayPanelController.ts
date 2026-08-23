import { useEffect, useMemo, useState } from 'react';
import { request } from './apiRequest';
import { executeGatewayToolCall } from './gatewayApi';
import { DEFAULT_REQUEST, pretty, type GatewayResponse } from './gatewayPanelPresets';
import type { GatewayToolExecutionResult } from '../types';
import { type GatewayComparisonResult } from '../components/settings/GatewayComparisonPanel';
import { type RuntimeStatus } from '../components/settings/GatewayRuntimeStatus';
const CONTROLLED_DECISIONS = new Set(['拒绝', '询问', '隔离']);
function defaultGatewayModel(runtimeStatus: RuntimeStatus | null): string {
  return (
    runtimeStatus?.models?.target?.find(
      (item) => item.configured && item.mode === 'real-api' && typeof item.model === 'string' && item.model.trim()
    )?.model ?? ''
  );
}
export function useGatewayPanelController() {
  const [payload, setPayload] = useState(() => pretty(DEFAULT_REQUEST));
  const [result, setResult] = useState<GatewayResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [executingTool, setExecutingTool] = useState(false);
  const [executionResult, setExecutionResult] = useState<GatewayToolExecutionResult | null>(null);
  const [executionError, setExecutionError] = useState('');
  const [followupResult, setFollowupResult] = useState<GatewayResponse | null>(null);
  const [followingUp, setFollowingUp] = useState(false);
  const [comparisonResult, setComparisonResult] = useState<GatewayComparisonResult | null>(null);
  const [comparisonError, setComparisonError] = useState('');
  const [comparing, setComparing] = useState(false);
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus | null>(null);
  const [runtimeStatusError, setRuntimeStatusError] = useState('');
  const [sessionId, setSessionId] = useState('gateway-console-session');
  const [managedMode, setManagedMode] = useState(false);

  useEffect(() => {
    void request<RuntimeStatus>('/api/runtime_status', undefined, { retry: 0, timeoutMs: 5000 })
      .then(setRuntimeStatus)
      .catch((requestError) =>
        setRuntimeStatusError(requestError instanceof Error ? requestError.message : '运行状态读取失败。')
      );
  }, []);

  const metadata = result?.agent_supervisor ?? {};
  const canExecuteManagedTools = runtimeStatus?.security_context?.can_execute_managed_tools;
  const callerRole = runtimeStatus?.security_context?.role;
  const canCompare = callerRole ? callerRole === 'analyst' || callerRole === 'admin' : undefined;
  const canCausalCompare = callerRole ? callerRole === 'admin' : undefined;
  const decision = metadata.decision === undefined || metadata.decision === null ? '—' : String(metadata.decision);
  const blocked = CONTROLLED_DECISIONS.has(decision);
  const toolDecisions = Array.isArray(metadata.tool_decisions) ? metadata.tool_decisions : [];
  const toolDefinitionFindings = Array.isArray(metadata.tool_definition_scan) ? metadata.tool_definition_scan : [];
  const toolArgumentFindings = Array.isArray(metadata.tool_argument_findings) ? metadata.tool_argument_findings : [];
  const toolResultFindings = Array.isArray(metadata.tool_result_scan) ? metadata.tool_result_scan : [];
  const executableToolDecision = (() => {
    if (blocked || canExecuteManagedTools === false) return null;
    const candidate = toolDecisions.find((item) => {
      if (!item || typeof item !== 'object') return false;
      const row = item as Record<string, unknown>;
      return String(row.decision ?? '') === '允许' && Boolean(row.audit_id);
    });
    return candidate && typeof candidate === 'object' ? (candidate as Record<string, unknown>) : null;
  })();
  const responsePreview = useMemo(() => (result ? pretty(result.choices ?? result) : ''), [result]);
  async function sendRequest() {
    setError('');
    setResult(null);
    setExecutionResult(null);
    setExecutionError('');
    setFollowupResult(null);
    setComparisonResult(null);
    setComparisonError('');
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(payload) as Record<string, unknown>;
    } catch {
      setError('请求 JSON 格式不正确，请先修正编辑器内容。');
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setError('请求必须是 JSON 对象。');
      return;
    }
    if (parsed.stream === true) {
      setError('网关工作台先用非流式模式展示完整证据；请把 stream 设为 false 或删除该字段。');
      return;
    }
    if (managedMode && canExecuteManagedTools === false) {
      setError('当前身份没有服务端工具执行权限；请切换到绑定 Agent 的 executor 或 admin 凭证。');
      return;
    }
    const requestedModel = typeof parsed.model === 'string' ? parsed.model.trim() : '';
    if (!requestedModel) {
      const configuredModel = defaultGatewayModel(runtimeStatus);
      if (configuredModel) parsed.model = configuredModel;
      else {
        setError('请求体缺少 model，且运行状态没有可用的真实 Provider 模型；请先填写 model 或配置 Provider。');
        return;
      }
    }
    const supervisorOptions =
      parsed.agent_supervisor && typeof parsed.agent_supervisor === 'object' && !Array.isArray(parsed.agent_supervisor)
        ? { ...(parsed.agent_supervisor as Record<string, unknown>) }
        : {};
    supervisorOptions.mode = managedMode ? 'managed' : 'transparent';
    if (managedMode && supervisorOptions.max_tool_rounds === undefined) supervisorOptions.max_tool_rounds = 3;
    parsed.agent_supervisor = supervisorOptions;
    setLoading(true);
    try {
      const data = await request<GatewayResponse>(
        '/v1/chat/completions',
        {
          method: 'POST',
          headers: sessionId.trim() ? { 'X-Agent-Session-ID': sessionId.trim() } : undefined,
          body: JSON.stringify({ ...parsed, stream: false })
        },
        { retry: 0, timeoutMs: 90_000 }
      );
      setResult(data);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '网关请求失败。');
    } finally {
      setLoading(false);
    }
  }
  async function runComparison(executionMode: 'observation' | 'sandbox-causal' = 'observation') {
    setComparisonError('');
    setComparisonResult(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(payload) as Record<string, unknown>;
    } catch {
      setComparisonError('请求 JSON 格式不正确，请先修正编辑器内容。');
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setComparisonError('请求必须是 JSON 对象。');
      return;
    }
    if (parsed.stream === true) {
      setComparisonError('同请求对照只接受非流式请求。');
      return;
    }
    const requestedModel = typeof parsed.model === 'string' ? parsed.model.trim() : '';
    if (!requestedModel) {
      const configuredModel = defaultGatewayModel(runtimeStatus);
      if (configuredModel) parsed.model = configuredModel;
      else {
        setComparisonError('请求体缺少 model，且运行状态没有可用的真实 Provider 模型。');
        return;
      }
    }
    setComparing(true);
    try {
      const supervisorOptions =
        parsed.agent_supervisor &&
        typeof parsed.agent_supervisor === 'object' &&
        !Array.isArray(parsed.agent_supervisor)
          ? { ...(parsed.agent_supervisor as Record<string, unknown>) }
          : {};
      supervisorOptions.comparison_mode = executionMode;
      parsed.agent_supervisor = supervisorOptions;
      const data = await request<GatewayComparisonResult>(
        '/api/gateway/compare',
        {
          method: 'POST',
          headers: sessionId.trim() ? { 'X-Agent-Session-ID': sessionId.trim() } : undefined,
          body: JSON.stringify({ ...parsed, stream: false })
        },
        { retry: 0, timeoutMs: 120_000 }
      );
      setComparisonResult(data);
    } catch (requestError) {
      setComparisonError(requestError instanceof Error ? requestError.message : '同请求对照失败。');
    } finally {
      setComparing(false);
    }
  }
  async function executeToolCall() {
    if (!executableToolDecision) return;
    const auditId = String(executableToolDecision.audit_id ?? '');
    const agentId = String(metadata.agent_id ?? '').trim() || 'openai-compatible-proxy';
    if (!auditId || !sessionId.trim()) {
      setExecutionError('缺少网关审计 ID 或会话 ID，不能执行。');
      return;
    }
    setExecutingTool(true);
    setExecutionError('');
    try {
      const data = await executeGatewayToolCall(auditId, {
        agent_id: agentId,
        session_id: sessionId.trim(),
        provider_call_id: String(executableToolDecision.call_id ?? '')
      });
      setExecutionResult(data);
    } catch (requestError) {
      setExecutionError(requestError instanceof Error ? requestError.message : '服务端工具执行失败。');
    } finally {
      setExecutingTool(false);
    }
  }

  async function followupToolResult() {
    if (!executionResult || !executableToolDecision || !result) return;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(payload) as Record<string, unknown>;
    } catch {
      setExecutionError('原始请求 JSON 已失效，不能回灌工具结果。');
      return;
    }
    const originalMessages = Array.isArray(parsed.messages) ? parsed.messages : [];
    const firstChoice = Array.isArray(result.choices) ? result.choices[0] : null;
    const providerMessage =
      firstChoice &&
      typeof firstChoice === 'object' &&
      (firstChoice as Record<string, unknown>).message &&
      typeof (firstChoice as Record<string, unknown>).message === 'object'
        ? (firstChoice as Record<string, unknown>).message
        : null;
    const callId = String(executableToolDecision.call_id ?? '');
    if (!callId || !providerMessage) {
      setExecutionError('缺少 Provider assistant tool call，不能建立回灌消息。');
      return;
    }
    const supervisorOptions =
      parsed.agent_supervisor && typeof parsed.agent_supervisor === 'object'
        ? { ...(parsed.agent_supervisor as Record<string, unknown>) }
        : {};
    const previousReceipts =
      supervisorOptions.tool_receipts && typeof supervisorOptions.tool_receipts === 'object'
        ? { ...(supervisorOptions.tool_receipts as Record<string, unknown>) }
        : {};
    previousReceipts[callId] = { audit_id: executionResult.audit_id };
    setFollowingUp(true);
    setExecutionError('');
    try {
      const data = await request<GatewayResponse>(
        '/v1/chat/completions',
        {
          method: 'POST',
          headers: sessionId.trim() ? { 'X-Agent-Session-ID': sessionId.trim() } : undefined,
          body: JSON.stringify({
            ...parsed,
            stream: false,
            messages: [
              ...originalMessages,
              providerMessage,
              { role: 'tool', tool_call_id: callId, content: executionResult.tool_result }
            ],
            agent_supervisor: { ...supervisorOptions, mode: 'transparent', tool_receipts: previousReceipts }
          })
        },
        { retry: 0, timeoutMs: 90_000 }
      );
      setFollowupResult(data);
    } catch (requestError) {
      setExecutionError(requestError instanceof Error ? requestError.message : '工具结果回灌失败。');
    } finally {
      setFollowingUp(false);
    }
  }

  return {
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
  };
}
