import type { GuardDecision } from './common';
import type { ExecutionReceipt } from './runtime';
import type { SupervisorEvaluation } from './supervisor';

export interface AttackEnvironmentSnapshot {
  state_hash: string;
  outbox_count: number;
  active_memory_count: number;
  quarantined_memory_count: number;
  api_call_count: number;
  bulk_export_count: number;
  sensitive_read_count: number;
  workspace_file_count: number;
}

export interface AttackEnvironmentChange {
  key: string;
  label: string;
  before: number;
  after: number;
  details?: string[];
}

export interface AttackEnvironmentBranch {
  before: AttackEnvironmentSnapshot;
  after: AttackEnvironmentSnapshot;
  changed: boolean;
  changes: AttackEnvironmentChange[];
  decision: GuardDecision;
  executor_called: boolean;
  effect_observed?: boolean;
  attack_success: boolean;
  effect_reason: string;
  audit_id: string;
  audit_hash: string;
}

export interface CustomAttackCompareRequest {
  payload: string;
  tool: string;
  arguments: Record<string, unknown>;
  command?: string;
  agent_id?: string;
  agent_role?: string;
  context_sources?: string[];
  execution_mode?: 'sandbox' | 'external_receipt';
}

export interface ExternalExecutionReceiptRequest {
  receipt_id: string;
  agent_id: string;
  tool_call: { tool: string; arguments: Record<string, unknown> };
  status: 'completed' | 'failed' | 'not_executed';
  execution_target: 'real' | 'sandbox' | 'none';
  result_hash: string;
  duration_ms: number;
  error: string;
}

export interface ExternalExecutionReceiptResult {
  persisted: boolean;
  idempotent: boolean;
  event_id: number;
  receipt: ExecutionReceipt;
}

export interface ExternalExecutionReceiptState {
  audit_id: string;
  receipt: ExecutionReceipt | null;
}

export interface CustomAttackCompareResult {
  comparison_id: string;
  request: CustomAttackCompareRequest & {
    agent_id: string;
    agent_role: string;
    context_sources: string[];
    command: string;
    execution_mode: 'sandbox' | 'external_receipt';
  };
  tool_call: { tool: string; arguments: Record<string, unknown>; risk_hint?: string };
  without_guard: SupervisorEvaluation;
  with_guard: SupervisorEvaluation;
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
    execution_status: string;
    receipt_required: boolean;
    receipts_complete: boolean;
    same_initial_state: boolean;
    tool_call_hash: string;
  };
  audit: {
    without_guard: { audit_id: string; audit_hash: string };
    with_guard: { audit_id: string; audit_hash: string };
  };
  receipts: {
    without_guard: ExecutionReceipt | null;
    with_guard: ExecutionReceipt | null;
  };
}

export interface CustomAttackChainResult {
  source_comparison_id: string;
  source_comparison_trust: 'verified';
  source_comparison_evidence?: {
    comparison_id: string;
    trust: 'verified';
    tool_call_hash: string;
    audit_ids: string[];
    audit_hashes: string[];
  };
  execution_id: string;
  conversation_id: string;
  request: CustomAttackCompareResult['request'];
  tool_call: CustomAttackCompareResult['tool_call'];
  guard_enabled: boolean;
  evaluation: SupervisorEvaluation;
  environment?: AttackEnvironmentBranch;
  audit: { audit_id: string; audit_hash: string };
  receipt: ExecutionReceipt;
  summary: {
    attack_success: boolean;
    controlled: boolean;
    decision: GuardDecision;
    policy_id: string;
    execution_status: string;
    stage_count: number;
    all_stages_audited: boolean;
    all_stages_receipted: boolean;
    shared_conversation_id: string;
    final_outcome?: 'controlled' | 'attack_success' | 'side_effect_only' | 'not_executed';
    evidence_complete?: boolean;
  };
  chain: Array<{ agent: string; status: string; evidence: string }>;
  stages: Array<{
    stage_id: string;
    stage_name: string;
    stage_role: string;
    agent_id: string;
    conversation_id: string;
    payload: string;
    tool_call: CustomAttackCompareResult['tool_call'];
    execution_attempted: boolean;
    artifact: ChainStageArtifact;
    evaluation: SupervisorEvaluation;
    stage_context?: Record<string, unknown>;
    audit: { audit_id: string; audit_hash: string };
    receipt: ExecutionReceipt;
    environment: AttackEnvironmentBranch;
  }>;
  chain_integrity?: {
    same_payload: boolean;
    same_tool_call: boolean;
    shared_conversation_id: boolean;
    initial_state_hash: string;
    final_state_hash: string;
    planner_tool_call_hash?: string;
    executor_tool_call_hash?: string;
    artifact_hashes_valid?: boolean;
    executor_consumed_planner_artifact?: boolean;
    supervisor_consumed_execution_artifact?: boolean;
    evaluator_consumed_prior_artifacts?: boolean;
    artifact_chain_valid?: boolean;
    chain_root_hash?: string;
  };
  artifacts?: ChainStageArtifact[];
  final_evaluation?: ChainStageArtifact;
}

export interface ChainStageArtifact {
  schema_version: 'agent-supervisor.custom-chain-artifact.v1';
  artifact_type: 'execution-plan' | 'execution-evidence' | 'supervisor-verdict' | 'evaluation-summary';
  producer_stage: string;
  input_artifact_hashes: string[];
  data: Record<string, unknown>;
  artifact_hash: string;
}
