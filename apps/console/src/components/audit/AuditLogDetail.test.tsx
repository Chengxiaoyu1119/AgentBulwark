import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { AuditLog, EvidenceVerification } from '@/types';
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
      output: '执行状态未知。'
    },
    timestamp: '2026-08-23T10:00:00Z'
  };
}

const verifiedEvidence: EvidenceVerification = {
  schema_version: 'agent-supervisor.evidence.v1',
  evidence_id: 'audit-uncertain-1',
  verified_at: '2026-08-23T10:01:00Z',
  evidence_status: 'verified',
  verification: {
    valid: true,
    audit_hash_valid: true,
    audit_signature_valid: true,
    audit_signature_required: true,
    receipt_present: true,
    receipt_valid: true,
    receipt_integrity_valid: true,
    receipt_binding_valid: true,
    trace_required: true,
    trace_available: true,
    trace_valid: true
  }
};

describe('AuditLogDetail', () => {
  it('labels an uncertain side effect as reconciliation work instead of a normal pending receipt', () => {
    render(<AuditLogDetail log={uncertainAudit()} copied={false} onCopy={vi.fn()} />);

    expect(screen.getByText('状态不确定·需核查')).toBeInTheDocument();
    expect(screen.getByText('工具副作用状态不确定，禁止自动重试')).toBeInTheDocument();
    expect(screen.queryByText(/等待外部回执/)).not.toBeInTheDocument();
  });

  it('lets an operator verify the selected evidence and shows the verified state', async () => {
    const onVerifyEvidence = vi.fn();
    const user = userEvent.setup();

    render(
      <AuditLogDetail
        log={uncertainAudit()}
        copied={false}
        onCopy={vi.fn()}
        onVerifyEvidence={onVerifyEvidence}
        evidenceVerification={verifiedEvidence}
      />
    );

    expect(screen.getByText('证据已验证')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '重新核验证据' }));
    expect(onVerifyEvidence).toHaveBeenCalledTimes(1);
  });

  it('surfaces failed integrity checks without exposing raw evidence payloads', () => {
    render(
      <AuditLogDetail
        log={uncertainAudit()}
        copied={false}
        onCopy={vi.fn()}
        evidenceVerification={{
          ...verifiedEvidence,
          evidence_status: 'invalid',
          verification: {
            ...verifiedEvidence.verification,
            valid: false,
            receipt_valid: false,
            receipt_binding_valid: false
          }
        }}
      />
    );

    expect(screen.getByText('证据无效')).toBeInTheDocument();
    expect(screen.getByText(/执行回执/)).toBeInTheDocument();
  });
});
