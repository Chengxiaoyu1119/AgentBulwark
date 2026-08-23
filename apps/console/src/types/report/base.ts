import type { RiskLevel } from '../common';

export interface ReportSummary {
  generated_at: string;
  surface_count: number;
  scenario_count: number;
  run_count: number;
  guarded_run_count: number;
  attack_success_rate: number;
  control_rate: number;
  avg_latency_ms: number;
  enabled_policy_count: number;
  policy_count: number;
  benign_sample_count: number;
  false_positive_count: number;
  false_positive_rate: number;
  expected_match_rate: number;
  surface_conclusion_count: number;
  output_filter_case_count: number;
  output_filter_block_rate: number;
  attack_reproduced_rate?: number;
  defense_effective_rate?: number;
  evidence_complete_rate?: number;
  policy_ablation_control_drop?: number;
  policy_ablation_risk_exposed_count?: number;
  anomaly_recommended_threshold?: number;
  anomaly_attack_recall_rate?: number;
  anomaly_false_alarm_rate?: number;
  holdout_sample_count?: number;
  holdout_attack_recall_rate?: number;
  holdout_false_positive_rate?: number;
  holdout_expected_match_rate?: number;
  real_model_case_count?: number;
  real_model_tool_call_success_count?: number;
  real_model_api_case_count?: number;
  real_model_api_coverage_rate?: number;
  real_model_attack_reproduced_rate?: number;
  real_model_defense_effective_rate?: number;
  real_model_receipt_complete_rate?: number;
  real_model_task_alignment_rate?: number;
  real_model_expected_control_match_rate?: number;
  real_model_benign_task_completion_rate?: number;
  real_model_causal_integrity_rate?: number;
  real_model_provider_evidence_coverage_rate?: number;
  real_model_report_integrity_valid?: boolean;
  real_model_report_freshness_valid?: boolean;
  real_model_strict_ready?: boolean;
}

export interface ReportSurfaceCoverage {
  id: string;
  name: string;
  risk: RiskLevel;
  status: string;
  samples: number;
  scripts: number;
  scenario_count: number;
  demo_ready: boolean;
  defense: string;
}

export interface ReportScenarioMatrix {
  id: string;
  surface: string;
  title: string;
  severity: RiskLevel;
  target: string;
  has_adversarial_prompt: boolean;
  has_jailbreak_case: boolean;
  script_steps: number;
  tool_calls: number;
  last_attack_success: boolean | null;
  last_decision: string;
}

export interface ReportDeliverable {
  name: string;
  status: string;
  evidence: string;
}

export interface ReportCounterItem {
  policy_id?: string;
  decision?: string;
  count: number;
}
