import type { BatchCompareResult, ReportData } from '../types';
import { request } from './apiRequest';

export type AttackEffectivenessRunResult = {
  run_result: BatchCompareResult;
  attack_effectiveness: NonNullable<ReportData['attack_effectiveness']>;
};

export async function runAttackEffectivenessEvidence(): Promise<AttackEffectivenessRunResult> {
  return request<AttackEffectivenessRunResult>(
    '/api/evaluations/attack_effectiveness/run',
    {
      method: 'POST',
      body: JSON.stringify({})
    },
    { timeoutMs: 180000, retry: 0 }
  );
}

export type GapRerunResult = {
  generated_at: string;
  target_scenario_ids: string[];
  run_result: BatchCompareResult;
  before: {
    evidence_gap_count: number;
    evidence_complete_rate: number;
    defense_effective_rate: number;
  };
  after: {
    evidence_gap_count: number;
    evidence_complete_rate: number;
    defense_effective_rate: number;
    roadmap_score: number;
    high_priority_gap_count: number;
    p0_backlog_count: number;
  };
  artifacts: {
    surface_pack_index: string;
    briefing_sheet_index: string;
    roadmap_json: string;
    roadmap_markdown: string;
  };
};

export async function runGapRerunEvidence(): Promise<GapRerunResult> {
  return request<GapRerunResult>(
    '/api/evaluations/gap_rerun/run',
    {
      method: 'POST',
      body: JSON.stringify({})
    },
    { timeoutMs: 240000, retry: 0 }
  );
}

export type PolicyAblationWriteResult = NonNullable<ReportData['policy_ablation']> & {
  json_path?: string;
  markdown_path?: string;
};

export async function writePolicyAblationEvidence(): Promise<PolicyAblationWriteResult> {
  return request<PolicyAblationWriteResult>(
    '/api/evaluations/policy_ablation/write',
    {
      method: 'POST',
      body: JSON.stringify({})
    },
    { timeoutMs: 240000, retry: 0 }
  );
}

export type EvidenceWriteResult = {
  generated_at: string;
  json_path?: string;
  markdown_path?: string;
  summary?: Record<string, unknown>;
};

export async function writeAnomalyCalibrationEvidence(): Promise<EvidenceWriteResult> {
  return request<EvidenceWriteResult>(
    '/api/evaluations/anomaly_calibration/write',
    {
      method: 'POST',
      body: JSON.stringify({})
    },
    { timeoutMs: 120000, retry: 0 }
  );
}

export async function writeProjectRoadmapEvidence(): Promise<EvidenceWriteResult> {
  return request<EvidenceWriteResult>(
    '/api/project_roadmap/write',
    {
      method: 'POST',
      body: JSON.stringify({})
    },
    { timeoutMs: 120000, retry: 0 }
  );
}

export type BriefingSheetExportResult = {
  generated_at: string;
  ok: boolean;
  format: 'png' | 'pdf' | 'both';
  reason?: string;
  summary: {
    surface_count: number;
    html_file_count: number;
    exported_surface_count: number;
    png_count: number;
    pdf_count: number;
    output_dir: string;
  };
  export: {
    file_count?: number;
    files?: Array<{
      html_path: string;
      surface_id: string;
      png_path?: string;
      pdf_path?: string;
    }>;
  };
};

export async function writeBriefingSheetExports(
  format: 'png' | 'pdf' | 'both' = 'both'
): Promise<BriefingSheetExportResult> {
  return request<BriefingSheetExportResult>(
    `/api/attack_surfaces/briefing_sheets/export?format=${encodeURIComponent(format)}`,
    {
      method: 'POST',
      body: JSON.stringify({})
    },
    { timeoutMs: 240000, retry: 0 }
  );
}

export async function fetchBriefingSheetExports(): Promise<BriefingSheetExportResult> {
  return request<BriefingSheetExportResult>('/api/attack_surfaces/briefing_sheets/export', undefined, {
    timeoutMs: 45000,
    retry: 0
  });
}

export type RealModelEvaluationWriteResult = Omit<EvidenceWriteResult, 'summary'> & {
  summary?: {
    case_count?: number;
    real_api_case_count?: number;
    real_api_coverage_rate?: number;
    attack_reproduced_rate?: number;
    defense_effective_rate?: number;
    receipt_complete_rate?: number;
    task_alignment_rate?: number;
    strict_real_api_ready?: boolean;
    evidence_verdict?: string;
  };
  evaluation?: {
    summary?: Record<string, unknown>;
    results?: unknown[];
  };
};

export async function writeRealModelEvaluationEvidence(forceReal = true): Promise<RealModelEvaluationWriteResult> {
  return request<RealModelEvaluationWriteResult>(
    '/api/evaluations/real_model/write',
    {
      method: 'POST',
      body: JSON.stringify({ force_real: forceReal })
    },
    { timeoutMs: 180000, retry: 0 }
  );
}
