import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AuditLog } from '@/types';
import { AuditLogDetail } from './AuditLogDetail';

function uncertainAudit(): AuditLog {
  return {
    id: 'audit-uncertain-1',
    run_id: 'run-uncertain-1',
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
    tool_output: {
      executed: false,
      sandboxed: true,
      output: '执行状态未知。'
    },
    timestamp: '2026-08-23T10:00:00Z'
  };
}

describe('AuditLogDetail', () => {
  it('labels an uncertain side effect as reconciliation work instead of a normal pending receipt', () => {
    render(<AuditLogDetail log={uncertainAudit()} copied={false} onCopy={vi.fn()} />);

    expect(screen.getByText('状态不确定·需核查')).toBeInTheDocument();
    expect(screen.getByText('工具副作用状态不确定，禁止自动重试')).toBeInTheDocument();
    expect(screen.queryByText(/等待外部回执/)).not.toBeInTheDocument();
  });
});
