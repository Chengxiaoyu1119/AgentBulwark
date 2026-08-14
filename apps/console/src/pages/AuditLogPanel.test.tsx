import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AuditLogPanel } from './AuditLogPanel';

vi.mock('../api', () => ({
  fetchApprovalReviews: vi.fn().mockResolvedValue({
    generated_at: '',
    status_filter: '全部',
    summary: {
      total: 0,
      pending_count: 0,
      approved_count: 0,
      rejected_count: 0,
      high_risk_count: 0,
      hash_valid_count: 0,
      latest_created_at: '',
      latest_reviewed_at: ''
    },
    reviews: []
  }),
  decideApprovalReview: vi.fn()
}));

describe('AuditLogPanel', () => {
  it('unifies reviews, risk events, and audit records in one workspace', async () => {
    render(<AuditLogPanel logs={[]} alerts={[]} refresh={vi.fn()} refreshAlerts={vi.fn()} />);

    expect(screen.getByText('安全事件、人工复核与执行审计')).toBeInTheDocument();
    expect(await screen.findByRole('tab', { name: '业务待办（0）' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '风险事件（0）' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: '调用审计（0）' })).toBeInTheDocument();
  });

  it('opens the audit tab directly when an audit deep link is present', async () => {
    window.history.replaceState(null, '', '#/audit?audit_id=audit-123');
    render(<AuditLogPanel logs={[]} alerts={[]} refresh={vi.fn()} refreshAlerts={vi.fn()} />);

    expect(await screen.findByRole('tab', { name: '调用审计（0）' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('audit-123')).toBeInTheDocument();
  });
});
