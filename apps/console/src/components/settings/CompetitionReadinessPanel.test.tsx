import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { CompetitionReadiness } from '@/types';
import { openAuthenticatedResource } from '../../app/apiRequest';
import { CompetitionReadinessPanel } from './CompetitionReadinessPanel';

vi.mock('../../app/apiRequest', () => ({
  openAuthenticatedResource: vi.fn()
}));

const readiness = {
  project: '智安哨',
  generated_at: '2026-08-21T00:00:00Z',
  overall_status: 'ready',
  status_label: '通过',
  verdict: '当前证据可复核',
  production_ready: true,
  production_claim_allowed: true,
  completion_claim_allowed: true,
  production_verdict: '生产主线已就绪',
  readiness_score: 100,
  readiness_domains: {
    mcp_adapter: {
      label: 'MCP 可选适配器',
      configured: true,
      probe_passed: true,
      operator_evidence_requested: true,
      operator_evidence_passed: true
    }
  },
  summary: {
    check_count: 1,
    passed_count: 1,
    warning_count: 0,
    blocker_count: 0,
    surface_count: 1,
    scenario_count: 1,
    policy_count: 1,
    benign_case_count: 1,
    benign_false_positive_rate: 0,
    benign_workflow_count: 1,
    benign_workflow_false_positive_rate: 0,
    recommended_threshold: 55,
    approval_review_count: 1,
    pending_approval_count: 0,
    resolved_approval_count: 1,
    demo_drill_stage_count: 1,
    demo_drill_review_hash_count: 1,
    roadmap_score: 100,
    roadmap_p0_backlog_count: 0
  },
  checks: [],
  blockers: [],
  next_actions: [],
  acceptance_commands: []
} as CompetitionReadiness;

describe('CompetitionReadinessPanel', () => {
  it('opens report artifacts through the authenticated request path', async () => {
    vi.mocked(openAuthenticatedResource).mockResolvedValue(undefined);
    render(
      <CompetitionReadinessPanel
        competitionReadiness={readiness}
        competitionReadinessOutput={null}
        checkingReadiness={false}
        handleRunReadiness={vi.fn()}
      />
    );

    await userEvent.click(screen.getByRole('button', { name: '查看体检 JSON' }));

    expect(openAuthenticatedResource).toHaveBeenCalledWith('/api/readiness');
  });

  it('shows MCP protocol and operator evidence separately', () => {
    render(
      <CompetitionReadinessPanel
        competitionReadiness={readiness}
        competitionReadinessOutput={null}
        checkingReadiness={false}
        handleRunReadiness={vi.fn()}
      />
    );

    expect(screen.getByText('MCP 适配器证据')).toBeInTheDocument();
    expect(screen.getByText('基础探针已通过')).toBeInTheDocument();
    expect(screen.getByText('operator 工具/上下文证据已通过')).toBeInTheDocument();
  });

  it('shows production gaps with evidence and next action', () => {
    const leastPrivilegeCheck = {
      id: 'agent-tool-least-privilege',
      title: 'Agent 工具、模型、API 与 MCP 上下文最小权限配置',
      category: '运行治理',
      status: 'warning',
      status_label: '需补强',
      severity: 'P1',
      weight: 8,
      earned_score: 5.2,
      evidence: '当前四项边界共同绑定 0 个 Agent。',
      details: { missing_bindings: { 'fixture-agent': ['context'] } },
      next_action: '登记 Agent 的 MCP 上下文范围。',
      artifact_paths: []
    } as CompetitionReadiness['checks'][number];

    render(
      <CompetitionReadinessPanel
        competitionReadiness={{
          ...readiness,
          checks: [leastPrivilegeCheck],
          production_ready: false,
          production_gaps: [
            {
              id: 'agent-tool-least-privilege',
              title: 'Agent 工具、模型、API 与 MCP 上下文最小权限配置',
              status: 'warning',
              severity: 'P1',
              evidence: 'MCP 上下文白名单数量为 0。',
              next_action: '登记 Agent 的 MCP 上下文范围。'
            }
          ]
        }}
        competitionReadinessOutput={null}
        checkingReadiness={false}
        handleRunReadiness={vi.fn()}
      />
    );

    expect(screen.getByText('生产主线缺口')).toBeInTheDocument();
    expect(screen.getByText('MCP 上下文白名单数量为 0。')).toBeInTheDocument();
    expect(screen.getByText('待补齐的 Agent 绑定')).toBeInTheDocument();
    expect(screen.getByText('fixture-agent：缺少 MCP 上下文范围')).toBeInTheDocument();
    expect(screen.getByText('下一步：登记 Agent 的 MCP 上下文范围。')).toBeInTheDocument();
  });

  it('separates production readiness from whole-project completion', () => {
    render(
      <CompetitionReadinessPanel
        competitionReadiness={{
          ...readiness,
          production_ready: true,
          completion_claim_allowed: false,
          summary: { ...readiness.summary, warning_count: 1, blocker_count: 1 }
        }}
        competitionReadinessOutput={null}
        checkingReadiness={false}
        handleRunReadiness={vi.fn()}
      />
    );

    expect(screen.getAllByText('生产主线已就绪')).toHaveLength(2);
    expect(screen.getByText('整体交付仍有待办')).toBeInTheDocument();
    expect(screen.getByText(/当前有 1 个阻塞项、1 个需补强项/)).toBeInTheDocument();
  });
});
