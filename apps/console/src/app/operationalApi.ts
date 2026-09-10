import type {
  ApprovalDecisionResult,
  ApprovalReviewList,
  AuditLog,
  ExecutionInventory,
  ModelProfileId,
  ModelStatus,
  ModelRuntimeConfig,
  ModelRuntimeConfigUpdate,
  ModelProviderProbeRequest,
  ModelProviderProbeResult,
  Overview
} from '../types';
import { ApiError, request } from './apiRequest';

export async function fetchHealth(): Promise<boolean> {
  try {
    const health = await request<{ ok: boolean }>('/api/health', undefined, { retry: 0, timeoutMs: 5_000 });
    return health.ok === true;
  } catch (error) {
    // A reachable backend that rejects the current session is not offline.
    // Preserve the HTTP error so the authentication gate can invalidate it.
    if (error instanceof ApiError && error.code === 'http_error') throw error;
    return false;
  }
}

export function fetchOverview(): Promise<Overview> {
  return request<Overview>('/api/overview');
}

export function fetchAuditLogs(limit = 100): Promise<AuditLog[]> {
  return request<AuditLog[]>(`/api/audit_logs?limit=${limit}`);
}

export function fetchExecutionInventory(limit = 200): Promise<ExecutionInventory> {
  return request<ExecutionInventory>(`/api/runtime/executions?limit=${limit}`);
}

export function fetchApprovalReviews(status = '全部', limit = 100): Promise<ApprovalReviewList> {
  return request<ApprovalReviewList>(`/api/approvals?status=${encodeURIComponent(status)}&limit=${limit}`);
}

export function decideApprovalReview(
  reviewId: string,
  action: 'approve' | 'reject',
  comment = '已完成人工复核，按当前安全策略处置。'
): Promise<ApprovalDecisionResult> {
  return request<ApprovalDecisionResult>(`/api/approvals/${encodeURIComponent(reviewId)}/decision`, {
    method: 'POST',
    body: JSON.stringify({ action, comment })
  });
}

export function fetchModelConfig(): Promise<ModelRuntimeConfig> {
  return request<ModelRuntimeConfig>('/api/model_config');
}

export function fetchModelStatuses(profile?: ModelProfileId): Promise<ModelStatus[]> {
  const query = profile ? `?profile=${encodeURIComponent(profile)}` : '';
  return request<ModelStatus[]>(`/api/models${query}`);
}

export function updateModelConfig(payload: ModelRuntimeConfigUpdate): Promise<ModelRuntimeConfig> {
  return request<ModelRuntimeConfig>('/api/model_config', {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
}

export function probeModelProvider(payload: ModelProviderProbeRequest): Promise<ModelProviderProbeResult> {
  return request<ModelProviderProbeResult>('/api/model_probe', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}
