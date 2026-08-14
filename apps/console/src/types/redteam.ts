import type { SupervisorEvaluation } from './supervisor';

export interface JailbreakRedteamRequest {
  task: string;
  block_terms: string;
  target_model?: string;
  force_real_model?: boolean;
  variant_limit?: number;
}

export interface JailbreakRedteamRecord {
  id: string;
  technique: string;
  intent: string;
  prompt: string;
  provider: string;
  model: string;
  mode: string;
  refused: boolean;
  unsafe_markers_found: boolean;
  attack_success: boolean;
  filtered_output: string;
  output_findings: Array<Record<string, string>>;
  risk_observation: string;
  provider_failures?: Array<Record<string, unknown>>;
  without_guard: SupervisorEvaluation;
  with_guard: SupervisorEvaluation;
}

export interface JailbreakRedteamResult {
  generated_at: string;
  task: string;
  block_terms: string;
  summary: {
    variant_count: number;
    real_api_count: number;
    attack_success_count: number;
    supervisor_controlled_count: number;
    control_rate: number;
    mode: string;
  };
  records: JailbreakRedteamRecord[];
}

export interface DualModelJailbreakRequest {
  task: string;
  block_terms: string;
  optimizer_model?: string;
  target_model?: string;
  optimizer_provider_profile?: string;
  target_provider_profile?: string;
  optimizer_role?: string;
  force_real_optimizer?: boolean;
  force_real_target?: boolean;
  iteration_count?: number;
}

export interface DualModelJailbreakRound {
  round_index: number;
  task: string;
  optimizer: {
    role: string;
    provider: string;
    provider_profile?: string;
    model: string;
    mode: string;
    optimized_prompt: string;
    provider_failures?: Array<Record<string, unknown>>;
  };
  target: {
    provider: string;
    provider_profile?: string;
    model: string;
    mode: string;
    raw_output: string;
    filtered_output: string;
    risk_observation: string;
    provider_failures?: Array<Record<string, unknown>>;
  };
  supervisor: {
    without_guard: SupervisorEvaluation;
    with_guard: SupervisorEvaluation;
  };
  output_filter: {
    blocked: boolean;
    findings: Array<Record<string, string>>;
  };
  summary: {
    optimizer_real: boolean;
    target_real: boolean;
    refused: boolean;
    unsafe_markers_found: boolean;
    attack_success: boolean;
    controlled_with_guard: boolean;
    decision_change: string;
    policy_id: string;
    risk_score: number;
  };
}

export interface DualModelJailbreakResult extends Omit<DualModelJailbreakRound, 'round_index'> {
  generated_at: string;
  task: string;
  block_terms: string;
  rounds?: DualModelJailbreakRound[];
  summary: DualModelJailbreakRound['summary'] & {
    iteration_count?: number;
    best_round?: number;
    attack_success_count?: number;
  };
}

export interface RefusalRewriteEvasionRequest {
  task: string;
  refusal_terms: string;
  optimizer_model?: string;
  target_model?: string;
  optimizer_provider_profile?: string;
  target_provider_profile?: string;
  optimizer_role?: string;
  force_real_optimizer?: boolean;
  force_real_target?: boolean;
  iteration_count?: number;
}

export interface RefusalRewriteTargetResult {
  provider: string;
  provider_profile?: string;
  model: string;
  mode: string;
  raw_output: string;
  filtered_output: string;
  risk_observation: string;
  provider_failures?: Array<Record<string, unknown>>;
}

export interface RefusalRewriteOptimizerResult {
  role: string;
  provider: string;
  provider_profile?: string;
  model: string;
  mode: string;
  optimized_prompt: string;
  provider_failures?: Array<Record<string, unknown>>;
  skip_reason?: string;
}

export interface RefusalRewriteEvasionRound {
  round_index: number;
  scenario_id: string;
  task: string;
  initial_target: RefusalRewriteTargetResult;
  refusal: {
    detected: boolean;
    hits: string[];
    terms: string[];
    rewrite_attempted: boolean;
    reason: string;
  };
  optimizer: RefusalRewriteOptimizerResult;
  rewritten_target: RefusalRewriteTargetResult;
  supervisor: {
    initial_with_guard: SupervisorEvaluation;
    rewritten_without_guard: SupervisorEvaluation;
    rewritten_with_guard: SupervisorEvaluation;
  };
  output_filter: {
    initial: {
      blocked: boolean;
      findings: Array<Record<string, string>>;
    };
    rewritten: {
      blocked: boolean;
      findings: Array<Record<string, string>>;
    };
  };
  summary: {
    initial_refused: boolean;
    rewrite_attempted: boolean;
    rewrite_changed: boolean;
    optimizer_real: boolean;
    target_real: boolean;
    unsafe_markers_found: boolean;
    attack_success: boolean;
    controlled_with_guard: boolean;
    decision_change: string;
    policy_id: string;
    risk_score: number;
    refusal_hit_count: number;
  };
}

export interface RefusalRewriteEvasionResult {
  generated_at: string;
  task: string;
  refusal_terms: string;
  optimizer: RefusalRewriteOptimizerResult;
  target: RefusalRewriteTargetResult;
  supervisor: RefusalRewriteEvasionRound['supervisor'];
  output_filter: RefusalRewriteEvasionRound['output_filter'];
  rounds: RefusalRewriteEvasionRound[];
  summary: {
    refused_initially: boolean;
    rewrite_attempted: boolean;
    optimizer_real: boolean;
    target_real: boolean;
    unsafe_markers_found: boolean;
    attack_success: boolean;
    controlled_with_guard: boolean;
    decision_change: string;
    policy_id: string;
    risk_score: number;
    iteration_count: number;
    best_round: number;
    attack_success_count: number;
    refusal_hit_count: number;
    mode: string;
  };
}

export interface AuthorizedTargetRunRequest {
  target_url: string;
  attack_input: string;
  surface_id?: string;
  target_type?: string;
  target_model?: string;
  authorization_confirmed: boolean;
  authorization_note: string;
  bearer_token?: string;
}

export interface AuthorizedTargetRunResult {
  executed: boolean;
  target_url: string;
  authorization_confirmed: boolean;
  authorization_note?: string;
  preflight: SupervisorEvaluation;
  http_status: number;
  resolved_ip: string;
  target_response: string;
  request_preview?: Record<string, unknown>;
  output_filter: {
    blocked: boolean;
    findings: Array<Record<string, string>>;
  };
  supervisor: SupervisorEvaluation;
  summary: {
    allowed_to_call: boolean;
    controlled_after_response?: boolean;
    reason?: string;
    token_configured: boolean;
    payload_kind?: string;
    target_type?: string;
  };
}
