import type { GuardDecision, RiskLevel } from './common';
import type { Scenario } from './surface';

export interface AlertItem {
  id: string;
  run_id: string;
  severity: RiskLevel;
  title: string;
  decision: GuardDecision;
  evidence: string;
  created_at: string;
  scenario_id?: string;
  scenario_title?: string;
  surface_id?: string;
  target?: string;
  policy_id?: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  recommendation?: string;
  tool_output?: {
    executed?: boolean;
    sandboxed?: boolean;
    simulated?: boolean;
    output?: string;
  };
  risk_score?: number;
  risk_factors?: string[];
  anomaly_score?: number;
  anomaly_signals?: string[];
}

export interface AuditLog {
  id: string;
  run_id: string;
  step: number;
  tool: string;
  arguments: Record<string, unknown>;
  standard_capability?: string;
  standard_arguments?: Record<string, unknown>;
  tool_mapping?: Record<string, unknown> | null;
  execution_receipt_expected?: boolean;
  decision: GuardDecision;
  risk_level: RiskLevel;
  policy_id: string;
  reason: string;
  recommendation: string;
  risk_score?: number;
  risk_factors?: string[];
  anomaly_score?: number;
  anomaly_signals?: string[];
  previous_hash?: string;
  audit_hash?: string;
  tool_call_hash?: string;
  execution_status?:
    | 'completed'
    | 'failed'
    | 'not_executed'
    | 'awaiting_receipt'
    | 'server_sandbox_completed'
    | 'not_applicable'
    | string;
  execution_target?: 'real' | 'sandbox' | 'none' | 'unknown' | string;
  gateway_execution_claim_status?: 'running' | 'completed' | 'unknown' | string;
  execution_receipt?: ExecutionReceipt | null;
  execution_evidence?: 'server-observed' | 'caller-declared-required' | 'not-executed-observed' | string;
  execution_observed_by_server?: boolean;
  stage_context?: Record<string, unknown>;
  tool_output: {
    executed: boolean;
    sandboxed: boolean;
    simulated?: boolean;
    execution_target?: string;
    executor?: string;
    container_image?: string;
    exit_code?: number | null;
    timed_out?: boolean;
    output: string;
  };
  timestamp: string;
}

export interface ExecutionReceipt {
  receipt_id: string;
  audit_id: string;
  run_id: string;
  agent_id: string;
  tool_call_hash: string;
  status: 'completed' | 'failed' | 'not_executed' | string;
  execution_target: 'real' | 'sandbox' | 'none' | string;
  result_hash?: string;
  duration_ms?: number;
  error?: string;
  decision?: GuardDecision | string;
  policy_id?: string;
  audit_hash?: string;
  request_hash?: string;
  receipt_hash?: string;
  receipt_signature?: string;
  receipt_signature_key_id?: string;
  execution_evidence?: 'caller-declared' | 'server-observed' | string;
  execution_observed_by_server?: boolean;
  agent_followed_decision?: boolean;
  execution_confirmed?: boolean;
  control_verified?: boolean;
  created_at?: string;
  event_id?: number;
}

export interface GatewayExecutionClaim {
  audit_id: string;
  claim_id: string;
  agent_id: string;
  session_id: string;
  tool_call_hash: string;
  status: 'running' | 'completed' | 'unknown' | string;
  created_at: string;
  completed_at: string;
  receipt_id: string;
}

export interface ExecutionInventory {
  generated_at: string;
  summary: {
    total: number;
    completed: number;
    failed: number;
    not_executed: number;
    decision_followed: number;
    control_verified: number;
    caller_declared: number;
    server_observed: number;
    signed: number;
    gateway_unknown: number;
  };
  receipts: ExecutionReceipt[];
  gateway_execution_claims: GatewayExecutionClaim[];
}

export interface GatewayToolExecutionResult {
  audit_id: string;
  idempotent: boolean;
  provider_call_id?: string;
  execution_evidence: string;
  execution_observed_by_server: boolean;
  execution_result: Record<string, unknown>;
  tool_result: string;
  tool_result_hash: string;
  receipt?: ExecutionReceipt | null;
}

export interface AuditHashVerification {
  run_id: string;
  scenario_id: string;
  created_at: string;
  valid: boolean;
  checked: number;
  failures: Array<{
    step: number;
    reason: string;
  }>;
  first_hash?: string;
  last_hash?: string;
}

export interface AgentTrace {
  id: string;
  agent: string;
  role: string;
  message: string;
  status: string;
  timestamp: string;
}

export interface RunResult {
  run_id: string;
  created_at: string;
  scenario: Scenario;
  guard_enabled: boolean;
  agent_trace: AgentTrace[];
  audit_logs: AuditLog[];
  alerts: AlertItem[];
  attack_success: boolean;
  metrics: {
    attack_success_rate: number;
    blocked_count: number;
    asked_count: number;
    isolated_count: number;
    detection_latency_ms: number;
    false_positive_rate: number;
  };
}

export interface CompareResult {
  scenario_id: string;
  without_guard: RunResult;
  with_guard: RunResult;
  summary: {
    attack_success_reduced: boolean;
    blocked_or_controlled: boolean;
  };
}

export interface BatchCompareResult {
  scenario_ids: string[];
  comparisons: CompareResult[];
  summary: {
    total: number;
    exposed_without_guard: number;
    controlled_with_guard: number;
    attack_success_reduced: number;
    control_rate: number;
    avg_latency_ms: number;
    blocked_count: number;
    asked_count: number;
    isolated_count: number;
  };
}
