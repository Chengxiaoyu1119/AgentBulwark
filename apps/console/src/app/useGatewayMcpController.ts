import { useLayoutEffect, useRef, useState } from 'react';
import { request } from './apiRequest';
import { safeUiDiagnostic, safeUiErrorSummary } from './apiRequestSupport';
import {
  extractMcpInputRequired,
  LEGACY_MCP_PROTOCOL_VERSION,
  MCP_CONSOLE_CLIENT_CAPABILITIES,
  MODERN_MCP_PROTOCOL_VERSION,
  type JsonObject,
  type McpConsoleMethod,
  type McpLogLevel,
  type McpProtocolVersion,
  type McpResponse
} from './mcpConsoleContract';
import { parseMcpJsonOrSseResponse } from './mcpConsoleStream';
import { useGatewayMcpSubscription } from './useGatewayMcpSubscription';

const DEFAULT_TOOL = 'file.read';
const DEFAULT_ARGUMENTS = JSON.stringify({ path: 'public/项目说明.md' }, null, 2);
const DEFAULT_CONTEXT_URI = 'file://public/example';
const DEFAULT_PROMPT_NAME = 'safe-summary';
const makeRequestId = (method: string) => `console-${method.replace(/[^a-z0-9/-]/gi, '-')}-${Date.now()}`;

function encodeMcpHeaderValue(value: string) {
  if (value === value.trim() && /^[\x20-\x7e]+$/.test(value)) return value;
  const bytes = new TextEncoder().encode(value);
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  return `=?base64?${window.btoa(binary)}?=`;
}

function mirroredName(method: McpConsoleMethod, params: JsonObject) {
  if (method === 'tools/call' || method === 'prompts/get') return String(params.name ?? '').trim();
  if (method === 'resources/read') return String(params.uri ?? '').trim();
  return '';
}

function stripRetryEnvelope(params: JsonObject) {
  return Object.fromEntries(
    Object.entries(params).filter(([key]) => !['_meta', 'inputResponses', 'requestState'].includes(key))
  );
}

export function useGatewayMcpController({ sessionId }: { sessionId: string }) {
  const [toolName, setToolName] = useState(DEFAULT_TOOL);
  const [argumentsText, setArgumentsText] = useState(DEFAULT_ARGUMENTS);
  const [contextUri, setContextUri] = useState(DEFAULT_CONTEXT_URI);
  const [promptName, setPromptName] = useState(DEFAULT_PROMPT_NAME);
  const [protocolVersion, setProtocolVersion] = useState<McpProtocolVersion>(MODERN_MCP_PROTOCOL_VERSION);
  const [result, setResult] = useState<McpResponse | null>(null);
  const [contextEvidence, setContextEvidence] = useState<JsonObject | null>(null);
  const [error, setError] = useState('');
  const [loadingMethod, setLoadingMethod] = useState('');
  const [streamProgressEnabled, setStreamProgressEnabled] = useState(false);
  const [logLevel, setLogLevel] = useState<McpLogLevel>('off');
  const [streamEvents, setStreamEvents] = useState<JsonObject[]>([]);
  const [loadingSessionId, setLoadingSessionId] = useState('');
  const [stateSessionId, setStateSessionId] = useState(sessionId);
  const requestSequence = useRef(0);
  const activeRequest = useRef<{ sequence: number; controller: AbortController } | null>(null);
  const modern = protocolVersion === MODERN_MCP_PROTOCOL_VERSION;
  const subscription = useGatewayMcpSubscription({ sessionId, enabled: modern });
  const inputRequired = extractMcpInputRequired(result?.response ?? null);

  if (stateSessionId !== sessionId) {
    setStateSessionId(sessionId);
    setResult(null);
    setContextEvidence(null);
    setError('');
    setLoadingSessionId('');
    setLoadingMethod('');
    setStreamEvents([]);
  }

  useLayoutEffect(() => {
    return () => {
      requestSequence.current += 1;
      activeRequest.current?.controller.abort();
      activeRequest.current = null;
    };
  }, [sessionId]);

  function beginRequest(loadingKey: string) {
    activeRequest.current?.controller.abort();
    const sequence = ++requestSequence.current;
    const controller = new AbortController();
    activeRequest.current = { sequence, controller };
    setLoadingSessionId(sessionId);
    setLoadingMethod(loadingKey);
    setStreamEvents([]);
    return { sequence, controller };
  }

  const ownsRequest = (sequence: number) => activeRequest.current?.sequence === sequence;

  function cancelActiveRequest() {
    requestSequence.current += 1;
    activeRequest.current?.controller.abort();
    activeRequest.current = null;
    setLoadingSessionId('');
    setLoadingMethod('');
  }

  function requireSession() {
    if (sessionId.trim()) return true;
    setError('MCP 会话 ID 不能为空；请先填写会话 ID，避免请求落到未绑定的临时会话。');
    return false;
  }

  function blockWhileInputRequired() {
    if (!inputRequired) return false;
    setError('当前 MCP 调用正在等待操作员输入，请先完成当前输入请求。');
    return true;
  }

  function requestHeaders(method: McpConsoleMethod, params: JsonObject) {
    const headers: Record<string, string> = { 'X-Agent-Session-ID': sessionId.trim() };
    if (!modern) return headers;
    headers.Accept = 'application/json, text/event-stream';
    headers['MCP-Protocol-Version'] = MODERN_MCP_PROTOCOL_VERSION;
    headers['Mcp-Method'] = method;
    const name = mirroredName(method, params);
    if (name) headers['Mcp-Name'] = encodeMcpHeaderValue(name);
    return headers;
  }

  function requestParams(method: McpConsoleMethod): JsonObject {
    if (method === 'initialize') {
      return {
        protocolVersion: LEGACY_MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'zhi-an-sentinel-console', version: '0.2.0' }
      };
    }
    if (method === 'tools/call') {
      if (!toolName.trim()) throw new Error('请填写要调用的 MCP 工具名称。');
      const parsed = JSON.parse(argumentsText) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('工具 arguments 必须是 JSON 对象。');
      }
      return { name: toolName.trim(), arguments: parsed as JsonObject };
    }
    if (method === 'resources/read') {
      if (!contextUri.trim()) throw new Error('请填写要读取的 MCP Resource URI。');
      return { uri: contextUri.trim() };
    }
    if (method === 'prompts/get') {
      if (!promptName.trim()) throw new Error('请填写要获取的 MCP Prompt 名称。');
      return { name: promptName.trim(), arguments: {} };
    }
    return {};
  }

  async function post(method: McpConsoleMethod, params: JsonObject, loadingKey: string = method) {
    const requestId = makeRequestId(method);
    const requestMeta: JsonObject = {
      'io.modelcontextprotocol/protocolVersion': MODERN_MCP_PROTOCOL_VERSION,
      'io.modelcontextprotocol/clientInfo': { name: 'zhi-an-sentinel-console', version: '0.2.0' },
      'io.modelcontextprotocol/clientCapabilities': MCP_CONSOLE_CLIENT_CAPABILITIES
    };
    if (method === 'tools/call' && streamProgressEnabled) requestMeta.progressToken = requestId;
    if (method === 'tools/call' && logLevel !== 'off') requestMeta['io.modelcontextprotocol/logLevel'] = logLevel;
    const body: JsonObject = {
      jsonrpc: '2.0',
      id: requestId,
      method,
      params: modern
        ? {
            ...params,
            _meta: requestMeta
          }
        : params
    };
    const { sequence, controller } = beginRequest(loadingKey);
    try {
      const response = await request<JsonObject>(
        '/api/mcp',
        {
          method: 'POST',
          headers: requestHeaders(method, params),
          body: JSON.stringify(body),
          signal: controller.signal
        },
        {
          retry: 0,
          timeoutMs: 30_000,
          responseParser: (rawResponse) =>
            parseMcpJsonOrSseResponse(
              rawResponse,
              (event) => ownsRequest(sequence) && setStreamEvents((current) => [...current.slice(-99), event])
            )
        }
      );
      if (ownsRequest(sequence)) {
        setResult({ method, request: body, response, receivedAt: new Date().toISOString() });
      }
    } catch (requestError) {
      if (ownsRequest(sequence)) setError(safeUiErrorSummary(requestError, 'MCP 网关请求失败。'));
    } finally {
      if (ownsRequest(sequence)) {
        activeRequest.current = null;
        setLoadingSessionId('');
        setLoadingMethod('');
      }
    }
  }

  async function send(method: McpConsoleMethod) {
    if (blockWhileInputRequired()) return;
    setError('');
    setContextEvidence(null);
    if (!requireSession()) return;
    try {
      await post(method, requestParams(method));
    } catch (parseError) {
      setError(safeUiDiagnostic(parseError) || 'MCP 请求参数格式不正确。');
    }
  }

  async function resumeInputRequired(inputResponses: JsonObject) {
    setError('');
    if (!requireSession() || !result || !inputRequired || !modern) return;
    const originalParams = result.request.params;
    if (!originalParams || typeof originalParams !== 'object' || Array.isArray(originalParams)) {
      setError('原始 MCP 请求参数已经失效，请重新发起调用。');
      return;
    }
    await post(
      result.method,
      {
        ...stripRetryEnvelope(originalParams as JsonObject),
        inputResponses,
        requestState: inputRequired.requestState
      },
      'mrtr/resume'
    );
  }

  async function loadContextEvidence() {
    if (blockWhileInputRequired()) return;
    setError('');
    setResult(null);
    if (!requireSession()) return;
    const { sequence, controller } = beginRequest('context/evidence');
    try {
      const response = await request<JsonObject>(
        '/api/mcp/context/evidence',
        { method: 'GET', headers: { 'X-Agent-Session-ID': sessionId.trim() }, signal: controller.signal },
        { retry: 0, timeoutMs: 30_000 }
      );
      if (ownsRequest(sequence)) setContextEvidence(response);
    } catch (requestError) {
      if (ownsRequest(sequence)) setError(safeUiErrorSummary(requestError, 'MCP 上下文证据读取失败。'));
    } finally {
      if (ownsRequest(sequence)) {
        activeRequest.current = null;
        setLoadingSessionId('');
        setLoadingMethod('');
      }
    }
  }

  function changeProtocolVersion(value: McpProtocolVersion) {
    if (blockWhileInputRequired()) return;
    subscription.stopSubscription();
    cancelActiveRequest();
    setProtocolVersion(value);
    setResult(null);
    setContextEvidence(null);
    setError('');
  }

  return {
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
    loadingMethod: loadingSessionId === sessionId ? loadingMethod : '',
    streamProgressEnabled,
    setStreamProgressEnabled,
    logLevel,
    setLogLevel,
    streamEvents,
    ...subscription,
    inputRequired,
    send,
    resumeInputRequired,
    loadContextEvidence
  };
}
