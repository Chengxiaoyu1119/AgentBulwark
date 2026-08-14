import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { AuditLog } from '@/types';
import { AuditLogList } from './AuditLogList';

function auditLog(index: number): AuditLog {
  return {
    id: `audit-${index}`,
    run_id: `run-${index}`,
    step: index,
    tool: `audit-tool-${index}`,
    arguments: {},
    decision: '允许',
    risk_level: 'low',
    policy_id: 'default',
    reason: `reason-${index}`,
    recommendation: '',
    tool_output: { executed: true, sandboxed: false, output: '' },
    timestamp: `2026-08-12T10:${String(index).padStart(2, '0')}:00Z`
  };
}

describe('AuditLogList', () => {
  it('paginates large audit sets and keeps record selection available', async () => {
    const user = userEvent.setup();
    const onSelectLog = vi.fn();
    render(<AuditLogList logs={Array.from({ length: 13 }, (_, index) => auditLog(index))} onSelectLog={onSelectLog} />);

    expect(screen.getByText('共 13 条 · 每页最多 12 条')).toBeInTheDocument();
    expect(screen.getByText('第 1/2 页 · 显示 1-12 条')).toBeInTheDocument();
    expect(screen.queryByText('audit-tool-12')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '下一页' }));
    await user.click(screen.getByText('audit-tool-12'));

    expect(screen.getByText('第 2/2 页 · 显示 13-13 条')).toBeInTheDocument();
    expect(onSelectLog).toHaveBeenNthCalledWith(1, '');
    expect(onSelectLog).toHaveBeenLastCalledWith('audit-12');
  });

  it('opens the page containing a deep-linked audit record', () => {
    render(
      <AuditLogList
        logs={Array.from({ length: 13 }, (_, index) => auditLog(index))}
        selectedLogId="audit-12"
        onSelectLog={vi.fn()}
      />
    );

    expect(screen.getByText('audit-tool-12')).toBeInTheDocument();
    expect(screen.getByText('第 2/2 页 · 显示 13-13 条')).toBeInTheDocument();
  });
});
