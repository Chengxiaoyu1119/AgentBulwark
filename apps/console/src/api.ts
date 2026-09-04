import type {
  AlertItem,
  AttackCaseDataset,
  AttackChain,
  AttackChainCompareResult,
  AttackChainRunResult,
  AuditHashVerification,
  BatchCompareResult,
  CompareResult,
  CompetitionReadiness,
  CompetitionReadinessWriteResult,
  DemoDrillResult,
  ExternalAgentDemoResult,
  OpenClawIntegrationBundle,
  OpenClawPluginPackageResult,
  OpenClawPluginValidationWriteResult,
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
import { request } from './app/apiRequest';
export { ApiError, setAuthTokenProvider, subscribeRuntimeEvents } from './app/apiRequest';
export * from './app/attackLabApi';
export * from './app/governanceApi';
export * from './app/operationalApi';
export * from './app/reportEvaluationApi';
export type { ApiErrorCode, RequestOptions } from './app/apiRequest';

export async function fetchScenarios(): Promise<Scenario[]> {
  return request<Scenario[]>('/api/scenarios');
}

export async function fetchStudentCompetitionAttackMap(): Promise<StudentCompetitionAttackProfile[]> {
  return request<StudentCompetitionAttackProfile[]>('/api/student_competition_attack_map');
}

export async function fetchPolicies(): Promise<Policy[]> {
  return request<Policy[]>('/api/policies');
}

export async function verifyRunAuditHash(runId: string): Promise<AuditHashVerification> {
  return request<AuditHashVerification>(`/api/runs/${encodeURIComponent(runId)}/audit_hash/verify`);
}

export async function fetchAlerts(limit = 100): Promise<AlertItem[]> {
  return request<AlertItem[]>(`/api/alerts?limit=${limit}`);
}

export async function updatePolicyEnabled(policyId: string, enabled: boolean): Promise<Policy> {
  return request<Policy>(`/api/policies/${policyId}`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled, comment: enabled ? '启用策略' : '停用策略' })
  });
}

export async function updatePolicyDetail(
  policyId: string,
  payload: Partial<Policy> & { comment?: string }
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
