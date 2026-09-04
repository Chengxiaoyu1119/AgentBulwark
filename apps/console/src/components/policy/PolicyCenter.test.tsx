import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { Policy } from '@/types';
import { PolicyCenter } from './PolicyCenter';

vi.mock('@/api', () => ({
  fetchAuthContext: vi.fn().mockResolvedValue({
    role: 'admin',
    agent_id: null,
    permissions: {
      can_edit_policy: true,
      can_review_approval: true,
      can_execute_runtime: true,
      can_view: true
    }
  }),
  fetchMemoryGovernance: vi.fn().mockResolvedValue({
    summary: { total: 0, active_count: 0, quarantined_count: 0, removed_count: 0, avg_trust_score: 0 },
    status_distribution: {},
    source_distribution: {},
    generated_at: '',
    items: []
  }),
  fetchObservabilityMetrics: vi.fn().mockResolvedValue({
    summary: {
      run_count: 0,
      controlled_count: 0,
      control_rate: 0,
      attack_success_count: 0,
      avg_detection_latency_ms: 0,
      max_detection_latency_ms: 0,
      audit_log_count: 0,
      pending_review_count: 0,
      resolved_review_count: 0,
      policy_version_count: 1
    }
  }),
  fetchPolicyConfig: vi.fn().mockResolvedValue({
    settings: {
      anomaly_review_threshold: 55,
      anomaly_reject_threshold: 85,
      approval_sla_minutes: 30,
      high_risk_auto_escalation: true,
      internal_email_domains: ['internal.example'],
      sensitive_path_markers: ['secret'],
      sensitive_api_markers: ['admin'],
      agent_tool_allowlists: { 'report-agent': ['file.read'] }
    }
  }),
  rollbackLatestMemory: vi.fn(),
  updateMemoryStatus: vi.fn(),
  updatePolicyDetail: vi.fn(),
  updatePolicyEnabled: vi.fn(),
  updatePolicySettings: vi.fn()
}));

const policies: Policy[] = [
  {
    id: 'path-boundary',
    name: '文件沙箱边界',
    decision: '拒绝',
    enabled: true,
    description: '限制敏感文件访问。',
    layer: '工具调用前',
    surface_ids: ['tool-abuse'],
    tools: ['file.read']
  }
];

describe('PolicyCenter', () => {
  it('keeps policy rules, business boundaries, tool allowlists and memory governance in one page', async () => {
    render(<PolicyCenter policies={policies} setPolicies={vi.fn()} />);

    expect(screen.getByText('防护策略中心')).toBeInTheDocument();
    expect(await screen.findByText('业务安全边界')).toBeInTheDocument();
    expect(await screen.findByText('Agent 工具最小权限')).toBeInTheDocument();
    expect(screen.getByText('记忆治理')).toBeInTheDocument();
  });
});
