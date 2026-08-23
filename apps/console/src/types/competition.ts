import type { GuardDecision, RiskLevel } from './common';

export interface CompetitionReadinessCheck {
  id: string;
  title: string;
  category: string;
  status: 'passed' | 'warning' | 'blocked' | string;
  status_label: string;
  severity: string;
  weight: number;
  earned_score: number;
  evidence: string;
  details: Record<string, unknown>;
  next_action: string;
  artifact_paths: string[];
}

export interface CompetitionReadiness {
  project: string;
  generated_at: string;
  overall_status: string;
  status_label: string;
  verdict: string;
  production_ready?: boolean;
  production_claim_allowed?: boolean;
  completion_claim_allowed?: boolean;
  gateway_ready?: boolean;
  evaluation_ready?: boolean;
  production_verdict?: string;
  readiness_domains?: Record<
    string,
    {
      label?: string;
      status?: string;
      status_label?: string;
      required_for_gateway_claim?: boolean;
      check_count?: number;
      passed_count?: number;
      warning_count?: number;
      blocked_count?: number;
      configured?: boolean;
      probe_passed?: boolean;
      operator_evidence_requested?: boolean;
      operator_evidence_passed?: boolean | null;
      next_action?: string;
      gaps?: Array<{ id: string; title: string; status: string; next_action: string }>;
    }
  >;
  production_gaps?: Array<{
    id: string;
    title: string;
    status: string;
    severity: string;
    evidence: string;
    next_action: string;
  }>;
  readiness_score: number;
  summary: {
    check_count: number;
    passed_count: number;
    warning_count: number;
    blocker_count: number;
    surface_count: number;
    scenario_count: number;
    policy_count: number;
    benign_case_count: number;
    benign_false_positive_rate: number;
    benign_workflow_count: number;
    benign_workflow_false_positive_rate: number;
    recommended_threshold: number;
    approval_review_count: number;
    pending_approval_count: number;
    resolved_approval_count: number;
    demo_drill_stage_count: number;
    demo_drill_review_hash_count: number;
    roadmap_score: number;
    roadmap_p0_backlog_count: number;
  };
  checks: CompetitionReadinessCheck[];
  blockers: Array<{
    id: string;
    title: string;
    severity: string;
    evidence: string;
    next_action: string;
  }>;
  next_actions: Array<{
    id: string;
    severity: string;
    title: string;
    action: string;
  }>;
  acceptance_commands: string[];
  latest_package?: Record<string, unknown>;
}

export interface CompetitionReadinessWriteResult {
  generated_at: string;
  json_path: string;
  markdown_path: string;
  summary: CompetitionReadiness['summary'];
  readiness_score: number;
  overall_status: string;
  blockers: CompetitionReadiness['blockers'];
  readiness: CompetitionReadiness;
}

export interface DemoDrillStage {
  index: number;
  title: string;
  objective: string;
  tool: string;
  arguments: Record<string, unknown>;
  decision: GuardDecision;
  policy_id: string;
  risk_level: RiskLevel;
  risk_score?: number;
  anomaly_score?: number;
  reason: string;
  recommendation: string;
  run_id: string;
  audit_id: string;
  audit_hash: string;
  approval_review_id: string;
  approval_status: string;
  approval_action_label: string;
  review_hash: string;
  model_input_excerpt: string;
  execution_mode: string;
}

export interface DemoDrillResult {
  name: string;
  generated_at: string;
  started_at: string;
  summary: {
    stage_count: number;
    controlled_count: number;
    approved_count: number;
    rejected_count: number;
    audit_hash_count: number;
    review_hash_count: number;
    decisions: string[];
    policies: string[];
    max_risk_score: number;
    max_anomaly_score: number;
  };
  stages: DemoDrillStage[];
  demo_script: string[];
  acceptance_points: string[];
  json_path: string;
  markdown_path: string;
}
