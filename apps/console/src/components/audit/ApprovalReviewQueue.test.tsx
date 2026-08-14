import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ApprovalReview, ApprovalReviewList } from '@/types';
import { ApprovalReviewQueue } from './ApprovalReviewQueue';

function review(index: number, overrides: Partial<ApprovalReview> = {}): ApprovalReview {
  return {
    id: `review-${index}`,
    audit_id: `audit-${index}`,
    run_id: `run-${index}`,
    status: '待复核',
    final_decision: '询问',
    approval_action: '',
    tool: `operational-tool-${index}`,
    arguments: {},
    policy_id: 'bulk-action-review',
    risk_level: 'high',
    reason: `reason-${index}`,
    recommendation: '人工复核',
    source_app: 'test',
    agent_id: 'agent-test',
    scope: 'operational',
    conversation_id: `conversation-${index}`,
    model_input_excerpt: '',
    model_output_excerpt: '',
    audit_hash: `audit-hash-${index}`,
    previous_hash: '',
    review_previous_hash: '',
    review_hash: `review-hash-${index}`,
    hash_valid: true,
    operator: '',
    comment: '',
    created_at: `2026-08-12T10:${String(index).padStart(2, '0')}:00Z`,
    reviewed_at: '',
    execution_note: '',
    ...overrides
  };
}

function queue(reviews: ApprovalReview[]): ApprovalReviewList {
  return {
    generated_at: '',
    status_filter: '全部',
    summary: {
      total: reviews.length,
      pending_count: reviews.filter((item) => item.status === '待复核').length,
      approved_count: reviews.filter((item) => item.status === '已批准').length,
      rejected_count: reviews.filter((item) => item.status === '已驳回').length,
      high_risk_count: reviews.length,
      hash_valid_count: reviews.length,
      latest_created_at: '',
      latest_reviewed_at: ''
    },
    reviews
  };
}

describe('ApprovalReviewQueue', () => {
  it('starts with operational pending work and limits the first page to eight records', async () => {
    const reviews = [
      ...Array.from({ length: 10 }, (_, index) => review(index)),
      review(20, { tool: 'experiment-tool', scope: 'experiment' }),
      review(21, { tool: 'approved-tool', status: '已批准' })
    ];
    const user = userEvent.setup();

    render(
      <ApprovalReviewQueue
        queue={queue(reviews)}
        reviews={reviews}
        loading={false}
        error=""
        busyId=""
        copiedApprovalId=""
        onRefresh={vi.fn()}
        onDecision={vi.fn()}
        onCopy={vi.fn()}
      />
    );

    expect(screen.getByText('当前范围 10 条 · 每页最多 8 条')).toBeInTheDocument();
    expect(screen.getByText('第 1/2 页 · 显示 1-8 条')).toBeInTheDocument();
    expect(screen.queryByText('experiment-tool')).not.toBeInTheDocument();
    expect(screen.queryByText('approved-tool')).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: '批准恢复' })).toHaveLength(8);

    await user.click(screen.getByRole('button', { name: '下一页' }));

    expect(screen.getByText('第 2/2 页 · 显示 9-10 条')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: '批准恢复' })).toHaveLength(2);
  });

  it('keeps experiment history out of the default business work queue', () => {
    const reviews = [review(1, { tool: 'experiment-tool', scope: 'experiment' })];

    render(
      <ApprovalReviewQueue
        queue={queue(reviews)}
        reviews={reviews}
        loading={false}
        error=""
        busyId=""
        copiedApprovalId=""
        onRefresh={vi.fn()}
        onDecision={vi.fn()}
        onCopy={vi.fn()}
      />
    );

    expect(screen.queryByText('experiment-tool')).not.toBeInTheDocument();
    expect(screen.getByText('当前范围 0 条 · 每页最多 8 条')).toBeInTheDocument();
    expect(screen.getByText(/当前待办范围为空/)).toBeInTheDocument();
  });
});
