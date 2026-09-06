import type { GuardDecision, RiskLevel } from './common';

export interface AlertItem {
  id: string;
  run_id?: string;
  severity: RiskLevel | string;
  title?: string;
  decision: GuardDecision | string;
  evidence?: string;
  created_at: string;
  risk_score?: number;
}

export interface AuditLog {
  id: string;
  run_id: string;
  step?: number;
  tool: string;
  arguments?: Record<string, unknown>;
  standard_capability?: string;
  standard_arguments?: Record<string, unknown>;
  tool_mapping?: Record<string, unknown> | null;
  execution_receipt_expected?: boolean;
  decision: GuardDecision | string;
  risk_level: RiskLevel | string;
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
  execution_status?: string;
  execution_target?: string;
  gateway_execution_claim_status?: string;
  execution_receipt?: ExecutionReceipt | null;
  execution_evidence?: string;
  execution_observed_by_server?: boolean;
  stage_context?: Record<string, unknown>;
  tool_output?: {
    executed?: boolean;
    output?: string;
    execution_target?: string;
    executor?: string;
    exit_code?: number | null;
    timed_out?: boolean;
  };
  timestamp: string;
  created_at?: string;
  source_app?: string;
}

export interface ExecutionReceipt {
  receipt_id: string;
  audit_id: string;
  run_id: string;
  agent_id: string;
  tool_call_hash: string;
  status: 'completed' | 'failed' | 'not_executed' | string;
  execution_target: 'real' | 'local-runtime' | 'external' | 'none' | string;
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
  summary: Record<string, number>;
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
  run_id?: string;
  created_at?: string;
  valid: boolean;
  checked: number;
  failures: Array<{ step?: number; reason: string }>;
  first_hash?: string;
  last_hash?: string;
}
