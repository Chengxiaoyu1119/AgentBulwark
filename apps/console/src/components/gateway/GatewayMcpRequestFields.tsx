import { UiCol, UiRow } from '../ui';
import {
  LEGACY_MCP_PROTOCOL_VERSION,
  MODERN_MCP_PROTOCOL_VERSION,
  type McpLogLevel,
  type McpProtocolVersion
} from '../../app/mcpConsoleContract';
import { UiFieldLabel, UiInput, UiSelect, UiSwitch } from '../ui';

export function GatewayMcpRequestFields({
  protocolVersion,
  sessionId,
  toolName,
  argumentsText,
  contextUri,
  promptName,
  streamProgressEnabled,
  logLevel,
  onProtocolVersionChange,
  onSessionIdChange,
  onToolNameChange,
  onArgumentsTextChange,
  onContextUriChange,
  onPromptNameChange,
  onStreamProgressEnabledChange,
  onLogLevelChange
}: {
  protocolVersion: McpProtocolVersion;
  sessionId: string;
  toolName: string;
  argumentsText: string;
  contextUri: string;
  promptName: string;
  streamProgressEnabled: boolean;
  logLevel: McpLogLevel;
  onProtocolVersionChange: (value: McpProtocolVersion) => void;
  onSessionIdChange: (value: string) => void;
  onToolNameChange: (value: string) => void;
  onArgumentsTextChange: (value: string) => void;
  onContextUriChange: (value: string) => void;
  onPromptNameChange: (value: string) => void;
  onStreamProgressEnabledChange: (value: boolean) => void;
  onLogLevelChange: (value: McpLogLevel) => void;
}) {
  return (
    <>
      <UiRow gutter={[12, 12]}>
        <UiCol xs={24} md={10}>
          <UiFieldLabel>MCP 协议版本</UiFieldLabel>
          <UiSelect<McpProtocolVersion>
            value={protocolVersion}
            onChange={onProtocolVersionChange}
            options={[
              { value: MODERN_MCP_PROTOCOL_VERSION, label: '2026-07-28 现代协议' },
              { value: LEGACY_MCP_PROTOCOL_VERSION, label: '2025-06-18 兼容协议' }
            ]}
            aria-label="MCP 协议版本"
            className="zh-full-width"
          />
        </UiCol>
        <UiCol xs={24} md={14}>
          <UiFieldLabel>Agent 会话 ID</UiFieldLabel>
          <UiInput
            value={sessionId}
            onChange={(event) => onSessionIdChange(event.target.value)}
            placeholder="例如 agent-session-001"
            aria-label="MCP Agent 会话 ID"
          />
        </UiCol>
      </UiRow>
      <UiRow gutter={[12, 12]}>
        <UiCol xs={24} md={12}>
          <UiFieldLabel>tools/call 请求级实时进度</UiFieldLabel>
          <UiSwitch
            checked={streamProgressEnabled}
            onChange={onStreamProgressEnabledChange}
            disabled={protocolVersion !== MODERN_MCP_PROTOCOL_VERSION}
            aria-label="MCP 实时进度"
          />
        </UiCol>
        <UiCol xs={24} md={12}>
          <UiFieldLabel>请求级日志最低级别</UiFieldLabel>
          <UiSelect<McpLogLevel>
            value={logLevel}
            onChange={onLogLevelChange}
            disabled={protocolVersion !== MODERN_MCP_PROTOCOL_VERSION}
            options={[
              { value: 'off', label: '关闭日志' },
              { value: 'debug', label: 'debug 及以上' },
              { value: 'info', label: 'info 及以上' },
              { value: 'notice', label: 'notice 及以上' },
              { value: 'warning', label: 'warning 及以上' },
              { value: 'error', label: 'error 及以上' },
              { value: 'critical', label: 'critical 及以上' },
              { value: 'alert', label: 'alert 及以上' },
              { value: 'emergency', label: 'emergency 及以上' }
            ]}
            aria-label="MCP 日志级别"
            className="zh-full-width"
          />
        </UiCol>
      </UiRow>
      <UiRow gutter={[12, 12]}>
        <UiCol xs={24} md={9}>
          <UiFieldLabel>tools/call 工具名</UiFieldLabel>
          <UiInput
            value={toolName}
            onChange={(event) => onToolNameChange(event.target.value)}
            aria-label="MCP tools/call 工具名"
          />
        </UiCol>
        <UiCol xs={24} md={15}>
          <UiFieldLabel>tools/call arguments（JSON 对象）</UiFieldLabel>
          <UiInput.TextArea
            value={argumentsText}
            onChange={(event) => onArgumentsTextChange(event.target.value)}
            autoSize={{ minRows: 2, maxRows: 6 }}
            spellCheck={false}
            aria-label="MCP tools/call arguments"
          />
        </UiCol>
      </UiRow>
      <UiRow gutter={[12, 12]}>
        <UiCol xs={24} md={12}>
          <UiFieldLabel>resources/read URI</UiFieldLabel>
          <UiInput
            value={contextUri}
            onChange={(event) => onContextUriChange(event.target.value)}
            aria-label="MCP resources/read URI"
          />
        </UiCol>
        <UiCol xs={24} md={12}>
          <UiFieldLabel>prompts/get 名称</UiFieldLabel>
          <UiInput
            value={promptName}
            onChange={(event) => onPromptNameChange(event.target.value)}
            aria-label="MCP prompts/get 名称"
          />
        </UiCol>
      </UiRow>
    </>
  );
}
