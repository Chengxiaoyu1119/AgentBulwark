import { useEffect, useRef, useState } from 'react';
import { request } from './apiRequest';
import { safeUiErrorSummary } from './apiRequestSupport';
import {
  MCP_CONSOLE_CLIENT_CAPABILITIES,
  MODERN_MCP_PROTOCOL_VERSION,
  type JsonObject,
  type McpSubscriptionFilters,
  type McpSubscriptionStatus
} from './mcpConsoleContract';
import { parseMcpSubscriptionStream } from './mcpConsoleStream';

const DEFAULT_FILTERS: McpSubscriptionFilters = {
  toolsListChanged: true,
  promptsListChanged: true,
  resourcesListChanged: true
};

export function useGatewayMcpSubscription({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const [subscriptionFilters, setSubscriptionFilters] = useState(DEFAULT_FILTERS);
  const [subscriptionResources, setSubscriptionResources] = useState('');
  const [subscriptionStatus, setSubscriptionStatus] = useState<McpSubscriptionStatus>('idle');
  const [subscriptionEvents, setSubscriptionEvents] = useState<JsonObject[]>([]);
  const [subscriptionError, setSubscriptionError] = useState('');
  const subscriptionAbortRef = useRef<AbortController | null>(null);

  useEffect(() => () => subscriptionAbortRef.current?.abort(), []);

  async function startSubscription() {
    if (!enabled || subscriptionAbortRef.current) return;
    if (!sessionId.trim()) {
      setSubscriptionError('MCP 会话 ID 不能为空；订阅必须绑定明确的 Agent 会话。');
      return;
    }
    const resourceSubscriptions = [
      ...new Set(
        subscriptionResources
          .split(/[\n,]/)
          .map((item) => item.trim())
          .filter(Boolean)
      )
    ];
    if (resourceSubscriptions.length > 128) {
      setSubscriptionError('Resource 订阅不能超过 128 项。');
      return;
    }
    const notifications: JsonObject = {};
    for (const [key, selected] of Object.entries(subscriptionFilters)) if (selected) notifications[key] = true;
    if (resourceSubscriptions.length) notifications.resourceSubscriptions = resourceSubscriptions;
    if (!Object.keys(notifications).length) {
      setSubscriptionError('请至少选择一种目录变更或填写一个 Resource URI。');
      return;
    }

    const requestId = `console-subscriptions-listen-${Date.now()}`;
    const params: JsonObject = {
      notifications,
      _meta: {
        'io.modelcontextprotocol/protocolVersion': MODERN_MCP_PROTOCOL_VERSION,
        'io.modelcontextprotocol/clientInfo': { name: 'zhi-an-sentinel-console', version: '0.2.0' },
        'io.modelcontextprotocol/clientCapabilities': MCP_CONSOLE_CLIENT_CAPABILITIES
      }
    };
    const controller = new AbortController();
    subscriptionAbortRef.current = controller;
    setSubscriptionEvents([]);
    setSubscriptionError('');
    setSubscriptionStatus('connecting');
    try {
      await request<void>(
        '/api/mcp',
        {
          method: 'POST',
          headers: {
            'X-Agent-Session-ID': sessionId.trim(),
            Accept: 'application/json, text/event-stream',
            'MCP-Protocol-Version': MODERN_MCP_PROTOCOL_VERSION,
            'Mcp-Method': 'subscriptions/listen'
          },
          body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method: 'subscriptions/listen', params }),
          signal: controller.signal
        },
        {
          retry: 0,
          timeoutMs: 0,
          responseParser: (response) =>
            parseMcpSubscriptionStream(response, (event) => {
              if (event.method === 'notifications/subscriptions/acknowledged') setSubscriptionStatus('active');
              setSubscriptionEvents((current) => [...current.slice(-99), event]);
            })
        }
      );
      if (!controller.signal.aborted) setSubscriptionStatus('closed');
    } catch (requestError) {
      if (!controller.signal.aborted) {
        setSubscriptionStatus('error');
        setSubscriptionError(safeUiErrorSummary(requestError, 'MCP 订阅连接失败。'));
      }
    } finally {
      if (subscriptionAbortRef.current === controller) subscriptionAbortRef.current = null;
    }
  }

  function stopSubscription() {
    const controller = subscriptionAbortRef.current;
    subscriptionAbortRef.current = null;
    controller?.abort();
    setSubscriptionStatus('idle');
    setSubscriptionError('');
  }

  return {
    subscriptionFilters,
    setSubscriptionFilters,
    subscriptionResources,
    setSubscriptionResources,
    subscriptionStatus,
    subscriptionEvents,
    subscriptionError,
    startSubscription,
    stopSubscription
  };
}
