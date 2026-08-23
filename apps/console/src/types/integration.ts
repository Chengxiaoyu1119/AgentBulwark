import type { GuardDecision, RiskLevel } from './common';
import type { ExecutionReceipt } from './runtime';

export interface ExternalAgentDemoRecord {
  task_id: string;
  title: string;
  tool: string;
  arguments: Record<string, unknown>;
  decision: string;
  policy_id: string;
  reason: string;
  executed: boolean;
  execution_target?: string;
  execution_status?: string;
  execution_evidence?: 'caller-declared' | 'server-observed' | string;
  execution_observed_by_server?: boolean;
  receipt_confirmed?: boolean;
  receipt_error?: string;
  execution_receipt?: ExecutionReceipt | null;
  tool_result: Record<string, unknown> | string | null;
  run_id?: string;
  audit_id?: string;
  audit_hash?: string;
  risk_level?: RiskLevel;
  risk_score?: number;
  anomaly_score?: number;
}

export interface ExternalAgentDemoResult {
  generated_at: string;
  supervisor_url: string;
  summary: {
    task_count: number;
    controlled_count: number;
    executed_count: number;
    control_rate: number;
    executed_tools: string[];
    audit_hash_count: number;
    audit_signature_count?: number;
    receipt_count?: number;
    receipt_confirmed_count?: number;
    receipt_unconfirmed_count?: number;
    caller_attested_count?: number;
    server_observed_count?: number;
    control_verified_count?: number;
  };
  records: ExternalAgentDemoRecord[];
  runtime_dir: string;
  json_path: string;
  markdown_path: string;
}

export interface ModelDrivenAgentResult {
  generated_at: string;
  task: string;
  scenario_id: string;
  agent_id: string;
  model_plan: {
    provider?: string;
    model?: string;
    mode?: string;
    finish_reason?: string;
    usage?: Record<string, unknown>;
    provider_failures?: Array<Record<string, unknown>>;
    request_hash?: string;
    provider_response_hash?: string;
    provider_response_id?: string;
    provider_created?: number | string | null;
    system_fingerprint?: string;
    tool_call_parse_issues?: string[];
    content_hash?: string;
    reasoning_content_hash?: string;
    response_hash?: string;
  };
  tool_call: {
    id: string;
    tool: string;
    arguments: Record<string, unknown>;
  };
  supervision: {
    run_id: string;
    audit_id: string;
    audit_hash?: string;
    audit_signature?: string;
    decision: GuardDecision;
    policy_id: string;
    reason: string;
    risk_score?: number;
  };
  execution: {
    status: string;
    target: string;
    duration_ms: number;
    result_hash?: string;
    output: Record<string, unknown>;
    error?: string;
  };
  receipt: ExecutionReceipt;
  model_followup: {
    provider?: string;
    model?: string;
    mode?: string;
    content: string;
    finish_reason?: string;
    is_final: boolean;
    requires_additional_tool_call: boolean;
    provider_failures?: Array<Record<string, unknown>>;
    request_hash?: string;
    provider_response_hash?: string;
    provider_response_id?: string;
    provider_created?: number | string | null;
    system_fingerprint?: string;
    tool_call_parse_issues?: string[];
    content_hash?: string;
    reasoning_content_hash?: string;
    response_hash?: string;
    output_filter: {
      blocked: boolean;
      findings: Array<Record<string, string>>;
    };
  };
  evidence_complete: boolean;
  real_model_evidence_valid: boolean;
  evidence_status: 'strict-real-api' | 'protocol-only' | 'incomplete' | string;
  evidence_gaps: string[];
  evidence_chain_hash: string;
  json_path: string;
  markdown_path: string;
}

export interface OpenClawIntegrationBundle {
  name: string;
  version: string;
  generated_at: string;
  purpose: string;
  endpoints: Array<{
    name: string;
    method: string;
    path: string;
    description: string;
  }>;
  event_contract: {
    required_fields: string[];
    optional_fields: string[];
    safe_default: string;
    tool_call: Record<string, string>;
  };
  adapter_code: string;
  sample_events: Record<string, unknown>[];
  validation: {
    cli: string;
    real_agent_cli?: string;
    plugin_validation_cli?: string;
    powershell: string;
    expected: {
      event_count: number;
      controlled_min: number;
      allowed_normal_read: boolean;
    };
  };
  acceptance_steps: string[];
  safety_boundary: string[];
}

export interface AgentIntegrationExample {
  id: string;
  name: string;
  framework: string;
  runtime_stage: string;
  endpoint: string;
  status: string;
  code: string;
}

export interface AgentIntegrationBundle {
  name: string;
  version: string;
  generated_at: string;
  purpose: string;
  decision_contract: Record<string, string>;
  event_contract: {
    required_fields: string[];
    recommended_fields: string[];
    safe_default: string;
  };
  examples: AgentIntegrationExample[];
  acceptance: string[];
}

export interface OpenClawCommandCheck {
  attempted: boolean;
  available: boolean;
  passed: boolean | null;
  command: string;
  stdout: string;
  stderr: string;
  skipped_reason: string;
}

export interface OpenClawPluginPackageResult {
  generated_at: string;
  package_dir: string;
  zip_path: string;
  markdown_path: string;
  file_count: number;
  summary: {
    name: string;
    version: string;
    generated_at: string;
    package_type: string;
    supervisor_url: string;
    core_hooks: string[];
    decision_mapping: Record<string, string>;
    install_commands: string[];
    runtime_checks: Record<string, boolean | number>;
    files: Array<{
      path: string;
      size: number;
    }>;
  };
}

export interface OpenClawPluginValidation {
  generated_at: string;
  package_dir: string;
  zip_path: string;
  markdown_path: string;
  static_passed: boolean;
  files_passed: boolean;
  node_syntax_passed: boolean;
  runtime_inspect_passed: boolean;
  overall_status: 'runtime-validated' | 'static-validated' | 'needs-fix' | string;
  file_checks: Record<string, boolean>;
  static_checks: Record<string, boolean | number>;
  node_check: OpenClawCommandCheck;
  openclaw_runtime_check: OpenClawCommandCheck;
  install_commands: string[];
  remaining_gap: string[];
  package: OpenClawPluginPackageResult;
}

export interface OpenClawPluginValidationWriteResult {
  generated_at: string;
  json_path: string;
  markdown_path: string;
  validation: OpenClawPluginValidation;
}
