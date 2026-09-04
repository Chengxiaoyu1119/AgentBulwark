import type {
  AgentIntegrationBundle,
  AuthContext,
  MemoryGovernance,
  ObservabilityMetrics,
  PolicyConfig,
  PolicySettings
} from '@/types';
import { request } from './apiRequest';

export async function fetchAuthContext(): Promise<AuthContext> {
  return request<AuthContext>('/api/auth/context');
}

export async function fetchPolicyConfig(): Promise<PolicyConfig> {
  return request<PolicyConfig>('/api/policy_config');
}

export async function updatePolicySettings(
  payload: Partial<PolicySettings> & { comment?: string }
): Promise<PolicySettings> {
  return request<PolicySettings>('/api/policy_settings', {
    method: 'PATCH',
    body: JSON.stringify(payload)
  });
}

export async function fetchAgentIntegrationBundle(): Promise<AgentIntegrationBundle> {
  return request<AgentIntegrationBundle>('/api/integrations/agents/bundle');
}

export async function fetchObservabilityMetrics(): Promise<ObservabilityMetrics> {
  return request<ObservabilityMetrics>('/api/observability/metrics');
}

export async function fetchMemoryGovernance(): Promise<MemoryGovernance> {
  return request<MemoryGovernance>('/api/memory_governance');
}

export async function updateMemoryStatus(
  memoryId: string,
  status: string
): Promise<{ updated: boolean; event_id?: number }> {
  return request<{ updated: boolean; event_id?: number }>(`/api/memory_governance/${encodeURIComponent(memoryId)}`, {
    method: 'PATCH',
    body: JSON.stringify({ status })
  });
}

export async function rollbackLatestMemory(): Promise<{ updated: boolean; reason?: string; event_id?: number }> {
  return request<{ updated: boolean; reason?: string; event_id?: number }>('/api/memory_governance/rollback_latest', {
    method: 'POST',
    body: JSON.stringify({})
  });
}
