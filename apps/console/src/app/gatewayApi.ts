import type { GatewayToolExecutionResult } from '../types';
import { request } from './apiRequest';

export async function executeGatewayToolCall(
  auditId: string,
  payload: { agent_id: string; session_id: string; provider_call_id?: string }
): Promise<GatewayToolExecutionResult> {
  return request<GatewayToolExecutionResult>(
    `/api/gateway/tool_calls/${encodeURIComponent(auditId)}/execute`,
    {
      method: 'POST',
      body: JSON.stringify(payload)
    },
    { retry: 0, timeoutMs: 30_000 }
  );
}
