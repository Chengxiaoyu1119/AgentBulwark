import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApprovalReview, ApprovalReviewList, AuthContext, AuditLog, ExecutionInventory } from '../types';
import { request } from '../app/apiRequest';
import {
  decideApprovalReview,
  fetchApprovalReviews,
  fetchAuditLogs,
  fetchExecutionInventory
} from '../app/operationalApi';
import { SecurityEventsPanel } from './SecurityEventsPanel';

vi.mock('../app/apiRequest', () => ({
  request: vi.fn(),
  subscribeRuntimeEvents: vi.fn(
    (_onEvent, signal: AbortSignal) =>
      new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }))
  )
}));

vi.mock('../app/operationalApi', () => ({
  fetchAuditLogs: vi.fn().mockResolvedValue([]),
  fetchExecutionInventory: vi.fn(),
  fetchApprovalReviews: vi.fn(),
  decideApprovalReview: vi.fn()
}));

const trace = {
  request_id: 'gateway-review-request',
  agent_id: 'e2e-agent',
  session_id: 'review-session',
  decision: '询问',
  status: 'controlled',
  provider_called: true,
  provider: 'fixture-provider',
  model: 'fixture-model',
  primary_policy_id: 'external-mail',
  risk_score: 88,
  tool_call_stage_count: 1,
  receipt_count: 0,
  last_seen: '2026-08-23T10:00:00Z',
  stages: [
    {
      audit_id: 'audit-review-1',
      stage: 'tool-call',
      decision: '询问',
      policy_id: 'external-mail',
      tool: 'mail.send',
      provider_called: true,
      provider_call_id: 'provider-call-1'
    }
  ]
};

const authContext: AuthContext = {
  role: 'analyst',
  agent_id: null,
  permissions: {
    can_edit_policy: false,
    can_review_approval: true,
    can_execute_runtime: false,
    can_view: true
  }
};

function executionInventory(status: 'completed' | 'unknown' = 'completed'): ExecutionInventory {
  return {
    generated_at: '2026-08-23T10:00:00Z',
    summary: {
      total: 1,
      completed: status === 'completed' ? 1 : 0,
      failed: 0,
      not_executed: 0,
      decision_followed: 1,
      control_verified: 1,
      caller_declared: 0,
      server_observed: 1,
      signed: 1,
      gateway_unknown: status === 'unknown' ? 1 : 0
    },
    receipts: [],
    gateway_execution_claims: [
      {
        audit_id: 'audit-uncertain-1',
        claim_id: 'claim-uncertain-1',
        agent_id: 'e2e-agent',
        session_id: 'uncertain-session',
        tool_call_hash: 'c'.repeat(64),
        status,
        created_at: '2026-08-23T10:00:00Z',
        completed_at: '2026-08-23T10:00:01Z',
        receipt_id: ''
      }
    ]
  };
}

function approval(status: ApprovalReview['status']): ApprovalReview {
  return {
    id: 'review-1',
    audit_id: 'audit-review-1',
    run_id: 'run-review-1',
    status,
    final_decision: status === '待复核' ? '等待人工确认' : '允许',
    approval_action: status === '待复核' ? '' : 'approve',
    tool: 'mail.send',
    arguments: {},
    policy_id: 'external-mail',
    risk_level: 'high',
    reason: '外部邮件需要人工确认。',
    recommendation: '核对收件人与业务目的。',
    source_app: 'openai-compatible-proxy',
    agent_id: 'e2e-agent',
    conversation_id: 'review-session',
    model_input_excerpt: '',
    model_output_excerpt: '',
    audit_hash: 'a'.repeat(64),
    previous_hash: '',
    review_previous_hash: 'a'.repeat(64),
    review_hash: 'b'.repeat(64),
    hash_valid: true,
    operator: status === '待复核' ? '' : 'security-reviewer',
    comment: '',
    created_at: '2026-08-23T10:00:00Z',
    reviewed_at: status === '待复核' ? '' : '2026-08-23T10:01:00Z',
    execution_note: '',
    execution_status: status === '待复核' ? 'pending_review' : 'ready_to_resume'
  };
}

function queue(status: ApprovalReview['status']): ApprovalReviewList {
  const review = approval(status);
  return {
    generated_at: '2026-08-23T10:00:00Z',
    status_filter: '全部',
    summary: {
      total: 1,
      pending_count: status === '待复核' ? 1 : 0,
      approved_count: status === '已批准' ? 1 : 0,
      rejected_count: 0,
      high_risk_count: 1,
      hash_valid_count: 1,
      latest_created_at: review.created_at,
      latest_reviewed_at: review.reviewed_at
    },
    reviews: [review]
  };
}

describe('SecurityEventsPanel', () => {
  beforeEach(() => {
    let approvalStatus: ApprovalReview['status'] = '待复核';
    vi.mocked(request).mockReset();
    vi.mocked(request).mockImplementation(async (path) => {
      if (path === '/api/gateway/traces?limit=50') {
        return { traces: [trace], summary: { controlled_count: 1 }, count: 1, total_available: 1 };
      }
      if (path === '/api/gateway/traces/gateway-review-request') return trace;
      throw new Error(`unexpected request: ${path}`);
    });
    vi.mocked(fetchAuditLogs).mockReset();
    vi.mocked(fetchAuditLogs).mockResolvedValue([]);
    vi.mocked(fetchApprovalReviews).mockReset();
    vi.mocked(fetchApprovalReviews).mockImplementation(async () => queue(approvalStatus));
    vi.mocked(decideApprovalReview).mockReset();
    vi.mocked(decideApprovalReview).mockImplementation(async () => {
      approvalStatus = '已批准';
      return { updated: true, review: approval(approvalStatus), summary: queue(approvalStatus).summary };
    });
    vi.mocked(fetchExecutionInventory).mockReset();
    vi.mocked(fetchExecutionInventory).mockResolvedValue(executionInventory());
  });

  it('moves from a questioning trace to the matching operational review and approves it', async () => {
    const user = userEvent.setup();
    render(<SecurityEventsPanel authContext={authContext} />);

    expect(await screen.findByRole('tab', { name: '风险事件' })).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByRole('tab', { name: '待人工复核（1）' })).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: /gateway-review-request/ }));
    await user.click(await screen.findByRole('button', { name: '处理人工复核' }));

    expect(screen.getByRole('tab', { name: '待人工复核（1）' })).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByText('已定位复核单 review-1')).toBeInTheDocument();
    expect(screen.getByText('审计 ID：audit-review-1')).toBeInTheDocument();
    expect(screen.getByText('mail.send')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '批准恢复' }));
    expect(decideApprovalReview).not.toHaveBeenCalled();
    expect(screen.getByText('批准后允许 Agent 恢复执行？')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /确\s*认/ }));

    expect(decideApprovalReview).toHaveBeenCalledWith(
      'review-1',
      'approve',
      '生产复核：确认可由原始 Agent 按最小权限恢复一次。'
    );
    expect((await screen.findAllByText('已批准')).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('等待Agent恢复')).toBeInTheDocument();
  });

  it('clears the previous audit snapshot when a live refresh fails', async () => {
    vi.mocked(fetchAuditLogs).mockReset();
    vi.mocked(fetchAuditLogs).mockResolvedValueOnce([{} as AuditLog]);
    render(<SecurityEventsPanel authContext={authContext} />);

    expect(await screen.findByRole('tab', { name: '执行审计' })).toBeInTheDocument();
    vi.mocked(fetchAuditLogs).mockRejectedValueOnce(new Error('审计服务暂时不可用'));
    await userEvent.click(screen.getByRole('button', { name: '刷新事件' }));

    expect(await screen.findByText('审计服务暂时不可用')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '执行审计' })).toBeInTheDocument();
  });

  it('surfaces unknown side-effect claims as operator reconciliation work', async () => {
    vi.mocked(fetchExecutionInventory).mockResolvedValue(executionInventory('unknown'));
    render(<SecurityEventsPanel authContext={authContext} />);

    const auditTab = await screen.findByRole('tab', { name: '执行审计（待核查 1）' });
    await userEvent.click(auditTab);

    expect(await screen.findByText('工具副作用状态不确定，禁止自动重试')).toBeInTheDocument();
    expect(screen.getByText('audit-uncertain-1')).toBeInTheDocument();
    expect(screen.getByText('待核查状态')).toBeInTheDocument();
    expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(1);
  });
});
