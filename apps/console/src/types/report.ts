import type { RunResult } from './runtime';
import type {
  ReportCounterItem,
  ReportDeliverable,
  ReportScenarioMatrix,
  ReportSummary,
  ReportSurfaceCoverage
} from './report/base';
import type { BenignEvaluation, BenignWorkflowEvaluation } from './report/benign';
import type { AttackEffectiveness, OutputFilterEvidence, SurfaceConclusionReport } from './report/evidence';
import type { CompetitionPackage } from './report/package';
import type { AnomalyCalibration, PolicyAblation, ProjectRoadmap } from './report/roadmap';
import type { RealModelEvaluation } from './report/runtime';

export interface AdversarialHoldout {
  schema_version: string;
  label_source: string;
  generated_at: string;
  summary: {
    sample_count: number;
    attack_count: number;
    benign_count: number;
    true_positive: number;
    false_negative: number;
    false_positive: number;
    true_negative: number;
    attack_recall_rate: number;
    benign_false_positive_rate: number;
    precision: number;
    expected_match_count: number;
    expected_match_rate: number;
  };
  records: Array<{
    id: string;
    label: 'attack' | 'benign';
    decision: string;
    policy_id: string;
    risk_score: number;
    anomaly_score: number;
    predicted_attack: boolean;
    expected_match: boolean;
  }>;
}

export * from './report/base';
export * from './report/benign';
export * from './report/evidence';
export * from './report/roadmap';
export * from './report/package';
export * from './report/runtime';

export interface ReportData {
  markdown: string;
  summary: ReportSummary;
  surface_coverage: ReportSurfaceCoverage[];
  scenario_matrix: ReportScenarioMatrix[];
  deliverables: ReportDeliverable[];
  policy_hits: ReportCounterItem[];
  decision_counts: ReportCounterItem[];
  benign_evaluation: BenignEvaluation;
  benign_workflow_evaluation?: BenignWorkflowEvaluation;
  surface_conclusions: SurfaceConclusionReport;
  output_filter_evidence: OutputFilterEvidence;
  attack_effectiveness?: AttackEffectiveness;
  policy_ablation?: PolicyAblation;
  anomaly_calibration?: AnomalyCalibration;
  adversarial_holdout?: AdversarialHoldout;
  project_roadmap?: ProjectRoadmap;
  real_model_evaluation?: RealModelEvaluation | null;
  runs: RunResult[];
  competition_package?: CompetitionPackage;
}
