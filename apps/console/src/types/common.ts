export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type GuardDecision = '允许' | '拒绝' | '询问' | '隔离';

export interface ModelStatus {
  profile?: string;
  provider: string;
  configured: boolean;
  model: string;
  mode: string;
  endpoint?: string;
}

export interface ModelProviderOption {
  id: string;
  label: string;
}

export interface ModelProfileRuntimeConfig {
  provider_priority: string[];
  model_overrides: Record<string, string>;
}

export interface ModelRuntimeConfig {
  real_api_enabled: boolean;
  real_api_enabled_source: 'runtime' | 'env' | string;
  allowed_providers: ModelProviderOption[];
  profiles: Record<string, ModelProfileRuntimeConfig>;
  config_path?: string;
}

export interface ModelRuntimeConfigUpdate {
  real_api_enabled?: boolean;
  profiles?: Record<
    string,
    {
      provider_priority?: string[];
      model_overrides?: Record<string, string>;
    }
  >;
}

export interface Policy {
  id: string;
  name: string;
  decision: GuardDecision;
  enabled: boolean;
  description: string;
  layer?: string;
  surface_ids?: string[];
  tools?: string[];
  risk_controls?: string[];
  demo_scenarios?: string[];
  disable_impact?: string;
}

export interface PolicySettings {
  anomaly_review_threshold: number;
  anomaly_reject_threshold: number;
  approval_sla_minutes: number;
  high_risk_auto_escalation: boolean;
  require_agent_capability_registration?: boolean;
  require_agent_model_registration?: boolean;
  require_agent_context_registration?: boolean;
  internal_email_domains: string[];
  sensitive_path_markers: string[];
  sensitive_api_markers: string[];
  agent_tool_allowlists: Record<string, string[]>;
  agent_api_allowlists?: Record<string, string[]>;
  agent_model_allowlists?: Record<string, string[]>;
  agent_context_allowlists?: Record<string, Record<string, string[]>>;
  agent_tool_mappings?: Record<string, Record<string, AgentToolMappingConfig>>;
}

export interface AgentToolMappingConfig {
  capability: string;
  argument_mapping: Record<string, string>;
  required_arguments: string[];
  risk_hint: string;
  description: string;
}

export interface PolicyVersion {
  id: number;
  policy_id: string;
  operator: string;
  comment: string;
  created_at: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

export interface PolicyConfig {
  policies: Policy[];
  settings: PolicySettings;
  versions: PolicyVersion[];
}

export interface AuthContext {
  role: 'admin' | 'analyst' | 'observer' | string;
  agent_id: string | null;
  permissions: {
    can_edit_policy: boolean;
    can_review_approval: boolean;
    can_execute_runtime: boolean;
    can_view: boolean;
  };
}

export interface ObservabilityMetrics {
  generated_at: string;
  window: Record<string, number>;
  summary: {
    run_count: number;
    controlled_count: number;
    control_rate: number;
    attack_success_count: number;
    avg_detection_latency_ms: number;
    max_detection_latency_ms: number;
    audit_log_count: number;
    pending_review_count: number;
    resolved_review_count: number;
    policy_version_count: number;
    execution_receipt_count?: number;
    execution_completed_count?: number;
    execution_failed_count?: number;
    execution_not_executed_count?: number;
    execution_unconfirmed_count?: number;
    execution_control_verified_count?: number;
  };
  decision_distribution: Record<string, number>;
  policy_hit_distribution: Record<string, number>;
  tool_distribution: Record<string, number>;
}

export interface MemoryGovernanceItem {
  id: string;
  source: string;
  content: string;
  status: 'active' | 'quarantined' | 'removed' | string;
  isolated: boolean;
  trust_score: number;
  created_at: string;
  updated_at?: string;
  updated_by?: string;
}

export interface MemoryGovernance {
  generated_at: string;
  summary: {
    total: number;
    active_count: number;
    quarantined_count: number;
    removed_count: number;
    avg_trust_score: number;
  };
  status_distribution: Record<string, number>;
  source_distribution: Record<string, number>;
  items_window?: {
    limit: number;
    returned: number;
    total: number;
  };
  items: MemoryGovernanceItem[];
}
