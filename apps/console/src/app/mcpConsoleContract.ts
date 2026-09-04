export type JsonObject = Record<string, unknown>;

export type McpProtocolVersion = '2026-07-28' | '2025-06-18';
export type McpLogLevel =
  | 'off'
  | 'debug'
  | 'info'
  | 'notice'
  | 'warning'
  | 'error'
  | 'critical'
  | 'alert'
  | 'emergency';

export type McpConsoleMethod =
  | 'server/discover'
  | 'initialize'
  | 'tools/list'
  | 'tools/call'
  | 'resources/list'
  | 'resources/read'
  | 'resources/templates/list'
  | 'prompts/list'
  | 'prompts/get'
  | 'subscriptions/listen';

export type McpSubscriptionFilters = {
  toolsListChanged: boolean;
  promptsListChanged: boolean;
  resourcesListChanged: boolean;
};
export type McpSubscriptionStatus = 'idle' | 'connecting' | 'active' | 'closed' | 'error';

export type McpResponse = {
  method: McpConsoleMethod;
  request: JsonObject;
  response: JsonObject | null;
  receivedAt: string;
};

export type McpInputRequired = {
  requestState: string;
  inputRequests: JsonObject;
};

export const MODERN_MCP_PROTOCOL_VERSION: McpProtocolVersion = '2026-07-28';
export const LEGACY_MCP_PROTOCOL_VERSION: McpProtocolVersion = '2025-06-18';

export const MCP_CONSOLE_CLIENT_CAPABILITIES: JsonObject = {
  sampling: {},
  elicitation: {},
  roots: {}
};

export function extractMcpInputRequired(response: JsonObject | null): McpInputRequired | null {
  const result = response?.result;
  if (!result || typeof result !== 'object' || Array.isArray(result)) return null;
  const record = result as JsonObject;
  const inputRequests = record.inputRequests;
  const requestState = record.requestState;
  if (
    record.resultType !== 'input_required' ||
    typeof requestState !== 'string' ||
    !requestState ||
    !inputRequests ||
    typeof inputRequests !== 'object' ||
    Array.isArray(inputRequests)
  ) {
    return null;
  }
  return { requestState, inputRequests: inputRequests as JsonObject };
}
