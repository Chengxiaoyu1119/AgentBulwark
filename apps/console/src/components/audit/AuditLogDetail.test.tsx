import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AuditLog } from '@/types';
import { AuditLogDetail } from './AuditLogDetail';

function audit(evidence_status: AuditLog['evidence_status'] = 'unknown'): AuditLog {
  return {
    id: 'audit-1',
    run_id: 'run-1',
    step: 1,
    tool: 'file.write',
    arguments: { path: 'public/marker.txt' },
    decision: '允许',
    risk_level: 'medium',
    policy_id: 'default-allow',
    reason: '调用通过监督，但执行结果未形成可信回执。',
    recommendation: '核查实际副作用。',
    execution_status: 'unknown',
    execution_target: 'unknown',
    gateway_execution_claim_status: 'unknown',
    evidence_status,
    tool_output: { executed: false, output: '执行状态未知。' },
    timestamp: '2026-08-23T10:00:00Z'
  };
}

describe('AuditLogDetail', () => {
  it('labels an uncertain side effect as reconciliation work', () => {
    render(<AuditLogDetail log={audit()} copied={false} onCopy={vi.fn()} />);

    expect(screen.getByText('状态不确定·需核查')).toBeInTheDocument();
    expect(screen.getByText('工具副作用状态不确定，禁止自动重试')).toBeInTheDocument();
    expect(screen.getByText('未知')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /核验证据/ })).not.toBeInTheDocument();
  });

  it('renders the server-provided evidence status without a verification action', () => {
    render(<AuditLogDetail log={audit('verified')} copied={false} onCopy={vi.fn()} />);

    expect(screen.getByText('已验证')).toBeInTheDocument();
    expect(screen.queryByText('重新核验证据')).not.toBeInTheDocument();
  });

  it('surfaces an invalid server-provided evidence status', () => {
    render(<AuditLogDetail log={audit('invalid')} copied={false} onCopy={vi.fn()} />);

    expect(screen.getByText('无效')).toBeInTheDocument();
    expect(screen.getByText('证据无效，已停止自动放行。')).toBeInTheDocument();
  });
});
