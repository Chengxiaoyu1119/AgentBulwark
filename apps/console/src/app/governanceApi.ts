import type {
  AgentIntegrationBundle,
  AgentRegistration,
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

export interface PolicyLifecycleResult {
  valid?: boolean;
  published?: boolean;
  rolled_back?: boolean;
  source_version?: number;
  policy_id: string;
  resource?: string;
  impact_preview?: {
    changed_fields: string[];
    affected_agents: string[];
    affected_tools: string[];
    affected_models: string[];
    possible_request_types: string[];
  };
  config?: PolicySettings;
}

export function validatePolicySettings(settings: PolicySettings): Promise<PolicyLifecycleResult> {
  return request<PolicyLifecycleResult>('/api/policies/validate', {
    method: 'POST',
    body: JSON.stringify({ settings })
  });
}

export function publishPolicySettings(settings: PolicySettings, comment: string): Promise<PolicyLifecycleResult> {
  return request<PolicyLifecycleResult>('/api/policies/publish', {
    method: 'POST',
    body: JSON.stringify({ settings, comment })
  });
}

export function rollbackPolicyVersion(version: number): Promise<PolicyLifecycleResult> {
  return request<PolicyLifecycleResult>(`/api/policies/${version}/rollback`, { method: 'POST' });
}

export function fetchAgents(): Promise<AgentRegistration[]> {
  return request<AgentRegistration[]>('/api/agents');
}

export function createAgent(payload: { agent_id: string; display_name?: string }): Promise<AgentRegistration> {
  return request<AgentRegistration>('/api/agents', { method: 'POST', body: JSON.stringify(payload) });
}

export function rotateAgentToken(agentId: string): Promise<AgentRegistration> {
  return request<AgentRegistration>(`/api/agents/${encodeURIComponent(agentId)}/rotate-token`, { method: 'POST' });
}

export function revokeAgent(agentId: string): Promise<AgentRegistration> {
  return request<AgentRegistration>(`/api/agents/${encodeURIComponent(agentId)}/revoke`, { method: 'POST' });
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
