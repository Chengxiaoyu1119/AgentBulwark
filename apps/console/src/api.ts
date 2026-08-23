import type {
  AlertItem,
  ApprovalDecisionResult,
  ApprovalReviewList,
  AttackCaseDataset,
  AttackChain,
  AttackChainCompareResult,
  AttackChainRunResult,
  AuditHashVerification,
  AuditLog,
  BatchCompareResult,
  CompareResult,
  CompetitionReadiness,
  CompetitionReadinessWriteResult,
  DemoDrillResult,
  ExternalAgentDemoResult,
  ModelRuntimeConfig,
  ModelRuntimeConfigUpdate,
  OpenClawIntegrationBundle,
  OpenClawPluginPackageResult,
  OpenClawPluginValidationWriteResult,
  Overview,
  Policy,
  ReportData,
  RunResult,
  Scenario,
  StudentCompetitionAttackProfile,
  SupervisorBatchEvaluation,
  SupervisorEvaluation,
  SurfaceEvidencePack,
  SurfaceEvidencePackIndex,
  SurfaceEvidencePackWriteResult
} from './types';
import { offlineOverview, offlinePolicies, offlineScenarios } from './fallback';
import { ApiError, request } from './app/apiRequest';
export { ApiError, setAuthTokenProvider, subscribeRuntimeEvents } from './app/apiRequest';
export * from './app/attackLabApi';
export * from './app/governanceApi';
export * from './app/reportEvaluationApi';
export type { ApiErrorCode, RequestOptions } from './app/apiRequest';

function shouldUseFallback(error: unknown) {
  if (!(error instanceof ApiError)) {
    return true;
  }
  return error.code === 'network_error' || error.code === 'timeout';
}

function fallbackOrThrow<T>(error: unknown, fallback: T): T {
  if (shouldUseFallback(error)) {
    return fallback;
  }
  throw error;
}

export async function fetchHealth(): Promise<boolean> {
  try {
    const health = await request<{ ok: boolean }>('/api/health', undefined, { retry: 0, timeoutMs: 5000 });
    return health.ok === true;
  } catch {
    return false;
  }
}

export async function fetchOverview(): Promise<Overview> {
  try {
    return await request<Overview>('/api/overview');
  } catch (error) {
    return fallbackOrThrow(error, offlineOverview);
  }
}

export async function fetchScenarios(): Promise<Scenario[]> {
  try {
    return await request<Scenario[]>('/api/scenarios');
  } catch (error) {
    // A failed live catalog must not silently turn historical fixtures into
    // current security evidence.  The UI shows an empty/offline state until
    // the backend can supply the actual scenario definitions.
    return fallbackOrThrow(error, offlineScenarios);
  }
}

export async function fetchStudentCompetitionAttackMap(): Promise<StudentCompetitionAttackProfile[]> {
  try {
    return await request<StudentCompetitionAttackProfile[]>('/api/student_competition_attack_map');
  } catch (error) {
    return fallbackOrThrow(error, offlineOverview.student_competition_attack_map ?? []);
  }
}

export async function fetchPolicies(): Promise<Policy[]> {
  try {
    return await request<Policy[]>('/api/policies');
  } catch (error) {
    return fallbackOrThrow(error, offlinePolicies);
  }
}

export async function fetchAuditLogs(limit = 100): Promise<AuditLog[]> {
  try {
    return await request<AuditLog[]>(`/api/audit_logs?limit=${limit}`);
  } catch (error) {
    return fallbackOrThrow(error, offlineOverview.audit_logs);
  }
}

export async function verifyRunAuditHash(runId: string): Promise<AuditHashVerification> {
  return request<AuditHashVerification>(`/api/runs/${encodeURIComponent(runId)}/audit_hash/verify`);
}

export async function fetchAlerts(limit = 100): Promise<AlertItem[]> {
  try {
    return await request<AlertItem[]>(`/api/alerts?limit=${limit}`);
  } catch (error) {
    return fallbackOrThrow(error, offlineOverview.alerts);
  }
}

export async function fetchApprovalReviews(status = '全部', limit = 100): Promise<ApprovalReviewList> {
  return request<ApprovalReviewList>(`/api/approvals?status=${encodeURIComponent(status)}&limit=${limit}`);
}

export async function decideApprovalReview(
  reviewId: string,
  action: 'approve' | 'reject',
  comment = '已完成人工复核，按当前安全策略处置。'
): Promise<ApprovalDecisionResult> {
  return request<ApprovalDecisionResult>(`/api/approvals/${encodeURIComponent(reviewId)}/decision`, {
    method: 'POST',
    body: JSON.stringify({
      action,
      operator: 'security-reviewer',
      comment
    })
  });
}

export async function updatePolicyEnabled(policyId: string, enabled: boolean): Promise<Policy> {
  return request<Policy>(`/api/policies/${policyId}`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled, operator: 'security-admin', comment: enabled ? '启用策略' : '停用策略' })
  });
}

export async function updatePolicyDetail(
  policyId: string,
  payload: Partial<Policy> & { operator?: string; comment?: string }
): Promise<Policy> {
  return request<Policy>(`/api/policies/${policyId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
}

export async function runScenario(scenarioId: string, guardEnabled: boolean): Promise<RunResult> {
  return request<RunResult>('/api/run', {
    method: 'POST',
    body: JSON.stringify({ scenario_id: scenarioId, guard_enabled: guardEnabled })
  });
}

export async function compareScenario(scenarioId: string): Promise<CompareResult> {
  return request<CompareResult>('/api/compare', {
    method: 'POST',
    body: JSON.stringify({ scenario_id: scenarioId, guard_enabled: true })
  });
}

export async function batchCompareScenarios(scenarioIds?: string[]): Promise<BatchCompareResult> {
  return request<BatchCompareResult>('/api/batch_compare', {
    method: 'POST',
    body: JSON.stringify({ scenario_ids: scenarioIds })
  });
}

export async function fetchAttackChains(): Promise<AttackChain[]> {
  return request<AttackChain[]>('/api/attack_chains');
}

export async function runAttackChain(chainId: string, guardEnabled = true): Promise<AttackChainRunResult> {
  return request<AttackChainRunResult>(`/api/attack_chains/${encodeURIComponent(chainId)}/run`, {
    method: 'POST',
    body: JSON.stringify({ guard_enabled: guardEnabled })
  });
}

export async function compareAttackChain(chainId: string): Promise<AttackChainCompareResult> {
  return request<AttackChainCompareResult>(`/api/attack_chains/${encodeURIComponent(chainId)}/compare`, {
    method: 'POST',
    body: JSON.stringify({})
  });
}

export async function fetchReport(): Promise<ReportData> {
  return request<ReportData>('/api/report', undefined, { timeoutMs: 45000, retry: 0 });
}

export async function fetchAttackCaseDataset(): Promise<AttackCaseDataset> {
  return request<AttackCaseDataset>('/api/datasets/attack_cases');
}

export async function fetchModelConfig(): Promise<ModelRuntimeConfig> {
  return request<ModelRuntimeConfig>('/api/model_config');
}

export async function updateModelConfig(payload: ModelRuntimeConfigUpdate): Promise<ModelRuntimeConfig> {
  return request<ModelRuntimeConfig>('/api/model_config', {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
}

export async function fetchSurfaceEvidencePack(surfaceId: string): Promise<SurfaceEvidencePack> {
  return request<SurfaceEvidencePack>(`/api/attack_surfaces/${encodeURIComponent(surfaceId)}/evidence_pack`);
}

export async function fetchSurfaceEvidencePackIndex(): Promise<SurfaceEvidencePackIndex> {
  return request<SurfaceEvidencePackIndex>('/api/attack_surfaces/evidence_packs');
}

export async function writeAllSurfaceEvidencePacks(): Promise<SurfaceEvidencePackWriteResult> {
  return request<SurfaceEvidencePackWriteResult>('/api/attack_surfaces/evidence_packs/write', {
    method: 'POST',
    body: JSON.stringify({})
  });
}

export async function fetchOpenClawIntegrationBundle(): Promise<OpenClawIntegrationBundle> {
  return request<OpenClawIntegrationBundle>('/api/integrations/openclaw/bundle');
}

export async function writeOpenClawPluginPackage(): Promise<OpenClawPluginPackageResult> {
  return request<OpenClawPluginPackageResult>('/api/integrations/openclaw/plugin_package/write', {
    method: 'POST',
    body: JSON.stringify({})
  });
}

export async function writeOpenClawPluginValidation(): Promise<OpenClawPluginValidationWriteResult> {
  return request<OpenClawPluginValidationWriteResult>(
    '/api/integrations/openclaw/plugin_package/validation/write?inspect_runtime=true',
    {
      method: 'POST',
      body: JSON.stringify({})
    }
  );
}

export async function fetchCompetitionReadiness(): Promise<CompetitionReadiness> {
  return request<CompetitionReadiness>('/api/readiness');
}

export async function writeCompetitionReadiness(): Promise<CompetitionReadinessWriteResult> {
  return request<CompetitionReadinessWriteResult>('/api/readiness/write', {
    method: 'POST',
    body: JSON.stringify({})
  });
}

export async function fetchDemoDrill(): Promise<DemoDrillResult> {
  return request<DemoDrillResult>('/api/demo_drill');
}

export async function runDemoDrill(): Promise<DemoDrillResult> {
  return request<DemoDrillResult>('/api/demo_drill/run', {
    method: 'POST',
    body: JSON.stringify({})
  });
}

export async function runExternalAgentDemo(): Promise<ExternalAgentDemoResult> {
  return request<ExternalAgentDemoResult>('/api/integrations/agents/minimal_demo', {
    method: 'POST',
    body: JSON.stringify({})
  });
}

export async function evaluateSupervisorEvent(event: Record<string, unknown>): Promise<SupervisorEvaluation> {
  return request<SupervisorEvaluation>('/api/runtime/evaluate', {
    method: 'POST',
    body: JSON.stringify(event)
  });
}

export async function evaluateSupervisorBatch(
  events: Record<string, unknown>[],
  options: { execute_in_sandbox?: boolean } = {}
): Promise<SupervisorBatchEvaluation> {
  return request<SupervisorBatchEvaluation>('/api/runtime/batch_evaluate', {
    method: 'POST',
    body: JSON.stringify({
      events,
      execute_in_sandbox: options.execute_in_sandbox ?? false
    })
  });
}
