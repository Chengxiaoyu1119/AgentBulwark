import { useState } from 'react';
import { Col, Flex, Row, Space, Typography } from 'antd';
import { Play, RefreshCw, Send } from 'lucide-react';
import { request } from '../../app/apiRequest';
import { EvidenceCodeBlock, PanelCard, UiAlert, UiButton, UiInput } from '../ui';
import { GatewayMcpEvidence } from './GatewayMcpEvidence';
import type { RuntimeStatus } from './GatewayRuntimeStatus';

type JsonObject = Record<string, unknown>;

type McpMethod =
  | 'initialize'
  | 'tools/list'
  | 'tools/call'
  | 'resources/list'
  | 'resources/read'
  | 'resources/templates/list'
  | 'prompts/list'
  | 'prompts/get';

type McpResponse = {
  method: string;
  request: JsonObject;
  response: JsonObject | null;
  receivedAt: string;
};

const DEFAULT_TOOL = 'file.read';
const DEFAULT_ARGUMENTS = JSON.stringify({ path: 'public/项目说明.md' }, null, 2);
const DEFAULT_CONTEXT_URI = 'file://public/example';
const DEFAULT_PROMPT_NAME = 'safe-summary';

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2);
}

function makeRequestId(method: string) {
  return `console-${method.replace(/[^a-z0-9/-]/gi, '-')}-${Date.now()}`;
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
  const [toolName, setToolName] = useState(DEFAULT_TOOL);
  const [argumentsText, setArgumentsText] = useState(DEFAULT_ARGUMENTS);
  const [contextUri, setContextUri] = useState(DEFAULT_CONTEXT_URI);
  const [promptName, setPromptName] = useState(DEFAULT_PROMPT_NAME);
  const [result, setResult] = useState<McpResponse | null>(null);
  const [contextEvidence, setContextEvidence] = useState<JsonObject | null>(null);
  const [error, setError] = useState('');
  const [loadingMethod, setLoadingMethod] = useState('');

  const configured = runtimeStatus?.mcp?.configured === true;
  const guardReady = runtimeStatus?.mcp?.guard_enabled === true;

  function sessionHeaders() {
    const normalizedSession = sessionId.trim();
    return normalizedSession ? { 'X-Agent-Session-ID': normalizedSession } : undefined;
  }

  function requireSession() {
    if (sessionId.trim()) return true;
    setError('MCP 会话 ID 不能为空；请先填写会话 ID，避免请求落到未绑定的临时会话。');
    return false;
  }

  async function send(method: McpMethod) {
    setError('');
    setContextEvidence(null);
    if (!requireSession()) return;
    setLoadingMethod(method);
    let args: JsonObject = {};
    if (method === 'tools/call') {
      try {
        const parsed = JSON.parse(argumentsText) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('工具 arguments 必须是 JSON 对象。');
        }
        args = parsed as JsonObject;
      } catch (parseError) {
        setError(parseError instanceof Error ? parseError.message : '工具 arguments JSON 格式不正确。');
        setLoadingMethod('');
        return;
      }
      if (!toolName.trim()) {
        setError('请填写要调用的 MCP 工具名称。');
        setLoadingMethod('');
        return;
      }
    } else if (method === 'resources/read') {
      if (!contextUri.trim()) {
        setError('请填写要读取的 MCP Resource URI。');
        setLoadingMethod('');
        return;
      }
      args = { uri: contextUri.trim() };
    } else if (method === 'prompts/get') {
      if (!promptName.trim()) {
        setError('请填写要获取的 MCP Prompt 名称。');
        setLoadingMethod('');
        return;
      }
      args = { name: promptName.trim(), arguments: {} };
    }

    const body: JsonObject = {
      jsonrpc: '2.0',
      id: makeRequestId(method),
      method,
      params:
        method === 'initialize'
          ? {
              protocolVersion: '2025-06-18',
              capabilities: {},
              clientInfo: { name: 'zhi-an-sentinel-console', version: '0.2.0' }
            }
          : method === 'tools/call'
            ? { name: toolName.trim(), arguments: args }
            : {}
    };

    try {
      const response = await request<JsonObject>(
        '/api/mcp',
        {
          method: 'POST',
          headers: sessionHeaders(),
          body: JSON.stringify(body)
        },
        { retry: 0, timeoutMs: 30_000 }
      );
      setResult({ method, request: body, response, receivedAt: new Date().toISOString() });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'MCP 网关请求失败。');
    } finally {
      setLoadingMethod('');
    }
  }

  async function loadContextEvidence() {
    setError('');
    setResult(null);
    if (!requireSession()) return;
    setLoadingMethod('context/evidence');
    try {
      const response = await request<JsonObject>(
        '/api/mcp/context/evidence',
        { method: 'GET', headers: sessionHeaders() },
        { retry: 0, timeoutMs: 30_000 }
      );
      setContextEvidence(response);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'MCP 上下文证据读取失败。');
    } finally {
      setLoadingMethod('');
    }
  }

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
          title="当前没有配置 MCP 上游，真实 tools/list / tools/call 不会被伪造。"
          description="配置 MCP_GATEWAY_UPSTREAM_COMMAND 或 MCP_GATEWAY_ROUTES_JSON 后，再从这里执行真实 tools、resources 和 prompts 请求。"
        />
      ) : !guardReady ? (
        <UiAlert
          type="error"
          showIcon
          title="MCP 上游已配置，但强制监督未启用；面板不会发送工具请求。"
          description="保持 MCP_GATEWAY_GUARD_ENABLED=true，并重启 API 后再执行真实 JSON-RPC。"
        />
      ) : (
        <Space orientation="vertical" size={16} className="zh-full-width">
          <Typography.Paragraph type="secondary" className="zh-mb-0">
            本面板复用上方 Agent 会话 ID：<Typography.Text code>{sessionId || '未设置'}</Typography.Text>
            。先初始化并读取工具/上下文目录，再选择真实工具或上下文操作；错误响应、隔离决策、上下文白名单结果和 audit_id
            都会原样保留在证据区。
          </Typography.Paragraph>
          <UiInput
            value={sessionId}
            onChange={(event) => onSessionIdChange(event.target.value)}
            placeholder="例如 agent-session-001"
            aria-label="MCP Agent 会话 ID"
          />
          <Row gutter={[12, 12]}>
            <Col xs={24} md={9}>
              <Typography.Text type="secondary" className="zh-meta-block">
                tools/call 工具名
              </Typography.Text>
              <UiInput value={toolName} onChange={(event) => setToolName(event.target.value)} />
            </Col>
            <Col xs={24} md={15}>
              <Typography.Text type="secondary" className="zh-meta-block">
                tools/call arguments（JSON 对象）
              </Typography.Text>
              <UiInput.TextArea
                value={argumentsText}
                onChange={(event) => setArgumentsText(event.target.value)}
                autoSize={{ minRows: 2, maxRows: 6 }}
                spellCheck={false}
                aria-label="MCP tools/call arguments"
              />
            </Col>
          </Row>
          <Row gutter={[12, 12]}>
            <Col xs={24} md={12}>
              <Typography.Text type="secondary" className="zh-meta-block">
                resources/read URI
              </Typography.Text>
              <UiInput value={contextUri} onChange={(event) => setContextUri(event.target.value)} />
            </Col>
            <Col xs={24} md={12}>
              <Typography.Text type="secondary" className="zh-meta-block">
                prompts/get 名称
              </Typography.Text>
              <UiInput value={promptName} onChange={(event) => setPromptName(event.target.value)} />
            </Col>
          </Row>
          <Flex gap={8} wrap="wrap">
            <UiButton
              icon={<Play size={16} />}
              loading={loadingMethod === 'initialize'}
              onClick={() => void send('initialize')}
            >
              initialize
            </UiButton>
            <UiButton
              icon={<RefreshCw size={16} />}
              loading={loadingMethod === 'tools/list'}
              onClick={() => void send('tools/list')}
            >
              tools/list
            </UiButton>
            <UiButton loading={loadingMethod === 'resources/list'} onClick={() => void send('resources/list')}>
              resources/list
            </UiButton>
            <UiButton loading={loadingMethod === 'resources/read'} onClick={() => void send('resources/read')}>
              resources/read
            </UiButton>
            <UiButton
              loading={loadingMethod === 'resources/templates/list'}
              onClick={() => void send('resources/templates/list')}
            >
              resource templates
            </UiButton>
            <UiButton loading={loadingMethod === 'prompts/list'} onClick={() => void send('prompts/list')}>
              prompts/list
            </UiButton>
            <UiButton loading={loadingMethod === 'prompts/get'} onClick={() => void send('prompts/get')}>
              prompts/get
            </UiButton>
            <UiButton loading={loadingMethod === 'context/evidence'} onClick={() => void loadContextEvidence()}>
              上下文 operator 证据
            </UiButton>
            <UiButton
              type="primary"
              icon={<Send size={16} />}
              loading={loadingMethod === 'tools/call'}
              onClick={() => void send('tools/call')}
            >
              tools/call
            </UiButton>
          </Flex>
          {error && <UiAlert type="error" showIcon title={error} />}
          {result && <GatewayMcpEvidence result={result} />}
          {contextEvidence && (
            <Space orientation="vertical" size={8} className="zh-full-width">
              <Typography.Text strong>operator-only MCP 上下文证据</Typography.Text>
              <Typography.Text type="secondary">
                可见 {String((contextEvidence.summary as JsonObject | undefined)?.visible_context_count ?? 0)}{' '}
                项；已过滤 {String((contextEvidence.summary as JsonObject | undefined)?.filtered_context_count ?? 0)}{' '}
                项；会话范围 {String(contextEvidence.session_scope ?? '未标注')}。
              </Typography.Text>
              <EvidenceCodeBlock size="small" maxHeight="large">
                {pretty(contextEvidence)}
              </EvidenceCodeBlock>
            </Space>
          )}
        </Space>
      )}
    </PanelCard>
  );
}
