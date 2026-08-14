import type { GuardDecision, RiskLevel } from '../common';

export interface SurfaceConclusion {
  surface_id: string;
  surface_name: string;
  risk: RiskLevel;
  status: string;
  attack_principle: string;
  entry_points: string[];
  protected_assets: string[];
  scenario_count: number;
  sample_count: number;
  script_count: number;
  tool_coverage: string[];
  run_count: number;
  guarded_run_count: number;
  controlled_run_count: number;
  attack_success_count: number;
  control_rate: number;
  attack_success_rate: number;
  avg_latency_ms: number;
  expected_decisions: Record<string, number>;
  expected_policies: Record<string, number>;
  representative_scenarios: Array<{
    id: string;
    title: string;
    target: string;
    severity: RiskLevel;
    tool_calls: number;
  }>;
  key_findings: string[];
  defense_conclusion: string;
  experiment_status: string;
}

export interface SurfaceConclusionReport {
  generated_at: string;
  summary: {
    surface_count: number;
    conclusion_count: number;
    with_run_evidence_count: number;
    scenario_count: number;
    tool_count: number;
  };
  conclusions: SurfaceConclusion[];
}

export interface OutputFilterCase {
  scenario_id: string;
  surface_id: string;
  title: string;
  severity: RiskLevel;
  risk_hint: string;
  filter_type: string;
  adversarial_prompt: string;
  jailbreak_case: string;
  without_guard: {
    decision: GuardDecision;
    policy_id: string;
    risk_level: RiskLevel;
    evidence: string;
  };
  with_guard: {
    decision: GuardDecision;
    policy_id: string;
    risk_level: RiskLevel;
    reason: string;
    recommendation: string;
  };
  blocked: boolean;
  comparison: string;
}

export interface OutputFilterEvidence {
  generated_at: string;
  summary: {
    case_count: number;
    blocked_count: number;
    block_rate: number;
    policy_distribution: Record<string, number>;
  };
  cases: OutputFilterCase[];
}

export interface AttackEffectAssertion {
  tool: string;
  observed: boolean;
  reason: string;
  executed: boolean;
  sandboxed: boolean;
  fixture_source: string;
}

export interface AttackEffectivenessCase {
  scenario_id: string;
  surface_id: string;
  surface_name: string;
  title: string;
  severity: RiskLevel;
  target: string;
  attack_reproduced_without_guard: boolean;
  defense_effective_with_guard: boolean;
  expected_decision_match: boolean;
  evidence_complete: boolean;
  evidence_gaps: string[];
  without_guard: {
    run_id: string;
    created_at: string;
    attack_success: boolean;
    guard_enabled: boolean;
    decisions: string[];
    policies: string[];
    risk_scores: number[];
    anomaly_scores?: number[];
    audit_hashes?: string[];
    alert_count: number;
    attack_outcome_source?: string;
    attack_assertions?: AttackEffectAssertion[];
  } | null;
  with_guard: {
    run_id: string;
    created_at: string;
    attack_success: boolean;
    guard_enabled: boolean;
    decisions: string[];
    policies: string[];
    risk_scores: number[];
    anomaly_scores?: number[];
    audit_hashes?: string[];
    alert_count: number;
    attack_outcome_source?: string;
    attack_assertions?: AttackEffectAssertion[];
  } | null;
  unguarded_hash_status?: {
    valid: boolean;
    checked: number;
    failures: Array<{ step: number; reason: string }>;
  };
  guarded_hash_status?: {
    valid: boolean;
    checked: number;
    failures: Array<{ step: number; reason: string }>;
  };
  expected_decisions: Array<{
    tool: string;
    decision: GuardDecision;
    policy_id: string;
    risk_level: RiskLevel;
    risk_score?: number;
    anomaly_score?: number;
  }>;
  observed_decisions: Array<{
    tool?: string;
    decision?: GuardDecision;
    policy_id?: string;
    risk_level?: RiskLevel;
    risk_score?: number;
    anomaly_score?: number;
  }>;
}

export interface RequirementAlignmentItem {
  id: string;
  requirement: string;
  expected: string;
  status: string;
  evidence: string;
}

export interface AttackEffectiveness {
  generated_at: string;
  summary: {
    scenario_count: number;
    surface_count: number;
    attack_reproduced_count: number;
    attack_reproduced_rate: number;
    defense_effective_count: number;
    defense_effective_rate: number;
    expected_match_count: number;
    expected_match_rate: number;
    evidence_complete_count: number;
    evidence_complete_rate: number;
    controlled_surface_distribution: Record<string, number>;
  };
  cases: AttackEffectivenessCase[];
  requirement_alignment: RequirementAlignmentItem[];
}
