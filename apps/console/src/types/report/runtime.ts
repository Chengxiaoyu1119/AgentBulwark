export interface RealModelEvaluationBranch {
  decision: string;
  controlled: boolean;
  policy_id: string;
  risk_score: number;
  anomaly_score: number;
  supervisor_latency_ms: number;
  attack_success: boolean;
  executor_called: boolean;
  execution_status: string;
  execution_target: string;
  audit_id: string;
  audit_hash: string;
  result_hash: string;
  receipt_hash: string;
  receipt_signature?: string;
  receipt_control_verified: boolean;
  initial_state_hash?: string;
  after_state_hash?: string;
  state_changed?: boolean;
  step_count?: number;
  decisions?: string[];
  policies?: string[];
  audit_ids?: string[];
  audit_hashes?: string[];
  result_hashes?: string[];
  receipt_hashes?: string[];
  receipt_complete?: boolean;
  steps?: RealModelEvaluationBranch[];
  attack_outcome?: {
    source?: string;
    assertions?: Array<{
      tool?: string;
      observed?: boolean;
      reason?: string;
      executed?: boolean;
      sandboxed?: boolean;
      fixture_source?: string;
    }>;
  };
}

export interface RealModelEvaluationCase {
  id: string;
  label: 'attack' | 'benign' | string;
  provider: string;
  model?: string;
  mode: string;
  tool_call: {
    tool?: string;
    arguments?: Record<string, unknown>;
  } | null;
  tool_calls?: Array<{
    tool?: string;
    arguments?: Record<string, unknown>;
  }>;
  model_tool_call_count?: number;
  tool_sequence_hash?: string;
  task_aligned?: boolean;
  expected_control_match?: boolean;
  benign_task_completed?: boolean;
  causal_integrity_valid?: boolean;
  provider_evidence_complete?: boolean;
  decision: string;
  controlled: boolean;
  expected_control: boolean;
  risk_score: number;
  anomaly_score: number;
  model_latency_ms?: number;
  supervisor_latency_ms?: number | null;
  provider_failures?: Array<Record<string, unknown>>;
  tool_call_hash?: string;
  attack_reproduced?: boolean;
  defense_effective?: boolean;
  receipt_complete?: boolean;
  real_model_evidence_valid?: boolean;
  evidence_gaps?: string[];
  baseline?: RealModelEvaluationBranch;
  guarded?: RealModelEvaluationBranch;
  causal_integrity?: {
    same_initial_state: boolean;
    same_tool_call: boolean;
    same_tool_sequence?: boolean;
    isolated_conversation_history?: boolean;
    initial_state_hash: string;
    tool_call_hash: string;
    tool_sequence_hash?: string;
  };
  model_chain?: Array<{
    stage: string;
    provider: string;
    model: string;
    mode: string;
    finish_reason?: string;
    content_hash: string;
    reasoning_content_hash?: string;
    request_hash?: string;
    provider_response_hash?: string;
    provider_response_id?: string;
    provider_created?: number | string | null;
    system_fingerprint?: string;
    tool_call?: {
      tool?: string;
      arguments?: Record<string, unknown>;
    } | null;
    tool_call_count?: number;
    requires_additional_tool_call: boolean;
    tool_call_parse_issues?: string[];
    provider_failures?: Array<Record<string, unknown>>;
  }>;
}

export interface RealModelEvaluation {
  schema_version?: string;
  evaluation_id?: string;
  generated_at: string;
  method?: {
    evidence_scope?: string;
    gateway_path_exercised?: boolean;
    gateway_contract_note?: string;
    tool_source?: string;
    blind_rule?: string;
    causal_rule?: string;
    metric_rule?: string;
    safety_boundary?: string;
  };
  summary: {
    case_count: number;
    attack_case_count: number;
    benign_case_count: number;
    model_tool_call_success_count: number;
    model_tool_call_count?: number;
    multi_step_case_count?: number;
    task_alignment_count?: number;
    task_alignment_rate?: number;
    expected_control_match_count?: number;
    expected_control_match_rate?: number;
    benign_task_completed_count?: number;
    benign_task_completion_rate?: number;
    causal_integrity_count?: number;
    causal_integrity_rate?: number;
    provider_evidence_complete_count?: number;
    provider_evidence_coverage_rate?: number;
    attack_control_rate: number;
    benign_false_positive_rate: number;
    avg_supervisor_latency_ms: number;
    p50_supervisor_latency_ms: number;
    p95_supervisor_latency_ms: number;
    provider_modes: string[];
    real_api_case_count: number;
    fallback_case_count: number;
    provider_failure_count: number;
    real_api_ready: boolean;
    attack_reproduced_count?: number;
    attack_reproduced_rate?: number;
    defense_effective_count?: number;
    defense_effective_rate?: number;
    real_api_coverage_rate?: number;
    real_api_evidence_valid_count?: number;
    real_api_evidence_coverage_rate?: number;
    real_api_attack_control_rate?: number;
    real_api_benign_false_positive_rate?: number;
    real_api_task_alignment_rate?: number;
    strict_real_api_ready?: boolean;
    receipt_complete_count?: number;
    receipt_complete_rate?: number;
    report_integrity_valid?: boolean;
    report_freshness_valid?: boolean;
    evidence_verdict?: 'pass' | 'partial' | 'fallback' | string;
    gateway_contract_evidence?: 'pass' | 'partial' | 'not_measured' | string;
  };
  provider_health?: {
    real_api_success_count: number;
    fallback_count: number;
    failures: Array<Record<string, unknown>>;
  };
  evidence_manifest?: {
    case_definitions_sha256?: string;
    policy_snapshot_sha256?: string;
    runtime_snapshot_sha256?: string;
    result_set_sha256?: string;
    case_count?: number;
    policy_count?: number;
  };
  report_hash?: string;
  integrity_verification?: {
    report_hash_valid: boolean;
    result_set_valid: boolean;
    case_definitions_valid: boolean;
    valid: boolean;
  };
  freshness_verification?: {
    case_definitions_current?: boolean;
    policy_snapshot_current?: boolean;
    runtime_snapshot_valid?: boolean;
    runtime_snapshot_current?: boolean;
    current: boolean;
  };
  results: RealModelEvaluationCase[];
}
