import type { GuardDecision, RiskLevel } from './common';
import type { AlertItem, AuditLog } from './runtime';
import type { AttackEnvironmentBranch } from './customAttack';

export type ApprovalStatus = '待复核' | '已批准' | '已驳回';

export interface ApprovalReview {
  id: string;
  audit_id: string;
  run_id: string;
  status: ApprovalStatus;
  final_decision: string;
  approval_action: string;
  tool: string;
  arguments: Record<string, unknown>;
  standard_capability?: string;
  standard_arguments?: Record<string, unknown>;
  tool_mapping?: Record<string, unknown> | null;
  policy_id: string;
  risk_level: RiskLevel;
  risk_score?: number;
  risk_factors?: string[];
  anomaly_score?: number;
  anomaly_signals?: string[];
  reason: string;
  recommendation: string;
  source_app: string;
  agent_id: string;
  scope?: 'operational' | 'experiment' | 'demo' | string;
  conversation_id: string;
  model_input_excerpt: string;
  model_output_excerpt: string;
  audit_hash: string;
  previous_hash: string;
  review_previous_hash: string;
  review_hash: string;
  hash_valid: boolean;
  operator: string;
  comment: string;
  created_at: string;
  reviewed_at: string;
  due_at?: string;
  sla_minutes?: number;
  sla_breached?: boolean;
  escalation_level?: string;
  execution_note: string;
  tool_call_hash?: string;
  execution_status?:
    | 'pending_review'
    | 'ready_to_resume'
    | 'claimed'
    | 'completed'
    | 'failed'
    | 'rejected'
    | 'sandbox_replayed';
  execution_claim_id?: string;
  execution_claim_agent_id?: string;
  execution_claimed_at?: string;
  execution_completed_at?: string;
  execution_result_hash?: string;
  execution_receipt_id?: string;
  execution_receipt_hash?: string;
  execution_receipt_signature?: string;
  sandbox_replay_requested?: boolean;
  sandbox_replayed_at?: string;
  sandbox_replay?: {
    executed: boolean;
    sandboxed: boolean;
    simulated?: boolean;
    output: string;
  } | null;
}

export interface ApprovalReviewList {
  generated_at: string;
  status_filter: string;
  summary: {
    total: number;
    pending_count: number;
    approved_count: number;
    rejected_count: number;
    high_risk_count: number;
    hash_valid_count: number;
    latest_created_at: string;
    latest_reviewed_at: string;
    sla_breached_count?: number;
  };
  reviews: ApprovalReview[];
}

export interface ApprovalDecisionResult {
  updated: boolean;
  review: ApprovalReview;
  summary: ApprovalReviewList['summary'];
}

export interface SupervisorEvaluation {
  run_id: string;
  audit_id: string;
  persisted: boolean;
  decision: GuardDecision;
  risk_level: RiskLevel;
  risk_score?: number;
  risk_factors?: string[];
  anomaly_score?: number;
  anomaly_signals?: string[];
  policy_id: string;
  reason: string;
  recommendation: string;
  execution_mode: string;
  surface_id: string;
  risk_evidence: {
    tool: string;
    risk_hint: string;
    arguments: Record<string, unknown>;
    context_sources: string[];
    model_input_excerpt: string;
    model_output_excerpt: string;
    detection_points: string[];
    risk_score?: number;
    risk_factors?: string[];
    anomaly_score?: number;
    anomaly_signals?: string[];
  };
  audit_log: AuditLog;
  alert: AlertItem | null;
  approval_review?: ApprovalReview | null;
}

export interface SupervisorBatchEvaluation {
  total: number;
  controlled: number;
  control_rate: number;
  results: SupervisorEvaluation[];
}

export interface AttackLabModule {
  surface_id: string;
  name: string;
  target: string;
  default_input: string;
  why: string;
  defense: string;
  tool: string;
  risk_hint: string;
}

export interface AttackLabModulesResponse {
  version: string;
  module_count: number;
  modules: AttackLabModule[];
}

export interface AttackLabRunRequest {
  surface_id: string;
  attack_input: string;
  target_model?: string;
  execute_in_sandbox?: boolean;
  planner_mode?: 'fixed' | 'model';
  force_real_model?: boolean;
  options?: Record<string, unknown>;
}

export interface TargetLabState {
  version: string;
  state_path: string;
  updated_at: string;
  team_count: number;
  submission_count: number;
  review_note_count: number;
  api_call_count: number;
  bulk_export_count: number;
  sensitive_read_count: number;
  latest_api_call: Record<string, unknown> | null;
}

export interface AttackLabRunResult {
  comparison_id: string;
  module: AttackLabModule & {
    target_model: string;
    planner_mode: string;
  };
  attack_input: string;
  tool_call: {
    tool: string;
    arguments: Record<string, unknown>;
    risk_hint?: string;
  };
  model_plan: {
    provider: string;
    scenario_id?: string;
    model?: string;
    mode: string;
    content?: string;
    tool_calls?: Array<Record<string, unknown>>;
    provider_failures?: Array<Record<string, unknown>>;
    fallback_reason?: string;
  };
  model_evidence?: {
    status: string;
    valid: boolean;
    model_output?: string;
    content_hash?: string;
    provider?: string;
    model?: string;
    mode?: string;
    fallback_reason?: string;
  };
  context_sources: string[];
  without_guard: SupervisorEvaluation;
  with_guard: SupervisorEvaluation;
  target_lab: TargetLabState;
  environment_comparison: {
    comparison_id: string;
    integrity: {
      same_initial_state: boolean;
      initial_state_hash: string;
      guarded_initial_state_hash: string;
      same_tool_call: boolean;
      tool_call_hash: string;
      risk_hint_used: boolean;
      only_variable: string;
      isolated_conversation_history?: boolean;
    };
    without_guard: AttackEnvironmentBranch;
    with_guard: AttackEnvironmentBranch;
  };
  summary: {
    exposed_without_guard: boolean;
    controlled_with_guard: boolean;
    decision_change: string;
    policy_id: string;
    execution_mode: string;
    risk_score: number;
    anomaly_score: number;
    outcome_source: string;
    same_initial_state: boolean;
    self_labeled_risk: boolean;
    model_evidence_status?: string;
    model_evidence_valid?: boolean;
  };
  explanation: Array<{
    title: string;
    text: string;
  }>;
}
