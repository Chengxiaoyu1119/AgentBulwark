export type GatewayTraceStage = {
  audit_id?: string;
  audit_hash?: string;
  timestamp?: string;
  stage?: string;
  decision?: string;
  policy_id?: string;
  risk_score?: number;
  tool?: string;
  provider_called?: boolean | null;
  provider_call_id?: string;
  execution_status?: string;
  execution_evidence?: string;
  execution_observed_by_server?: boolean;
  execution_receipt_present?: boolean;
};

export type GatewayTrace = {
  trace_id?: string;
  request_id?: string;
  session_id?: string;
  agent_id?: string;
  status?: string;
  decision?: string;
  provider_called?: boolean | null;
  provider?: string;
  provider_profile?: string;
  model?: string;
  request_hash?: string;
  provider_request_hash?: string;
  provider_response_hash?: string;
  provider_response_id?: string;
  controlled_stage_count?: number;
  stage_count?: number;
  risk_score?: number;
  primary_policy_id?: string;
  tool_call_stage_count?: number;
  server_observed_execution_count?: number;
  receipt_count?: number;
  first_seen?: string;
  last_seen?: string;
  stages?: GatewayTraceStage[];
};

export type GatewayTraceSummary = {
  request_count?: number;
  controlled_count?: number;
  allowed_count?: number;
  provider_failure_count?: number;
  provider_called_count?: number;
  tool_call_count?: number;
  receipt_count?: number;
  max_risk_score?: number;
  decision_distribution?: Record<string, number>;
  provider_distribution?: Record<string, number>;
};

export type GatewayTraceIndex = {
  traces?: GatewayTrace[];
  count?: number;
  total_available?: number;
  summary?: GatewayTraceSummary;
};

export const CONTROLLED_DECISIONS = new Set(['拒绝', '询问', '隔离']);

export function traceLabel(value: unknown, fallback = '—') {
  return value === undefined || value === null || value === '' ? fallback : String(value);
}

export function traceDecisionColor(decision: string) {
  return CONTROLLED_DECISIONS.has(decision) ? 'red' : decision === '允许' ? 'green' : 'blue';
}

export function shortTraceHash(value: unknown) {
  const text = typeof value === 'string' ? value : '';
  return text ? `${text.slice(0, 12)}…` : '—';
}

export function formatTraceTime(value: unknown) {
  const text = typeof value === 'string' ? value : '';
  if (!text) return '—';
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? text : date.toLocaleString('zh-CN', { hour12: false });
}

export function gatewayRequestId(trace: GatewayTrace) {
  return String(trace.request_id || trace.trace_id || '').trim();
}
