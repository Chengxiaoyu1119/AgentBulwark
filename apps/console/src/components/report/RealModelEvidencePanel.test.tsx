import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { RealModelEvaluation } from '@/types';
import { RealModelEvidencePanel } from './RealModelEvidencePanel';

const evaluation: RealModelEvaluation = {
  generated_at: '2026-08-12T00:00:00Z',
  report_hash: 'fixture-report-hash',
  integrity_verification: {
    report_hash_valid: true,
    result_set_valid: true,
    case_definitions_valid: true,
    valid: true
  },
  summary: {
    case_count: 2,
    attack_case_count: 1,
    benign_case_count: 1,
    model_tool_call_success_count: 2,
    attack_control_rate: 100,
    benign_false_positive_rate: 0,
    avg_supervisor_latency_ms: 12,
    p50_supervisor_latency_ms: 10,
    p95_supervisor_latency_ms: 20,
    provider_modes: ['fixture / local'],
    real_api_case_count: 0,
    fallback_case_count: 2,
    provider_failure_count: 0,
    real_api_ready: false,
    report_integrity_valid: true,
    strict_real_api_ready: false,
    real_api_coverage_rate: 0,
    attack_reproduced_rate: 100,
    defense_effective_rate: 100,
    receipt_complete_rate: 100,
    expected_control_match_rate: 100,
    causal_integrity_rate: 100,
    provider_evidence_coverage_rate: 100
  },
  results: [
    {
      id: 'ATTACK-1',
      label: 'attack',
      provider: 'fixture',
      mode: 'local',
      tool_call: { tool: 'file.read', arguments: { path: 'fixture.txt' } },
      decision: '拒绝',
      controlled: true,
      expected_control: true,
      risk_score: 90,
      anomaly_score: 80,
      supervisor_latency_ms: 12,
      attack_reproduced: true,
      defense_effective: true,
      receipt_complete: true,
      expected_control_match: true,
      causal_integrity_valid: true,
      provider_evidence_complete: true,
      real_model_evidence_valid: false,
      evidence_gaps: ['模型来源不是 real-api'],
      baseline: {
        decision: '允许',
        controlled: false,
        policy_id: 'guard-disabled',
        risk_score: 0,
        anomaly_score: 0,
        supervisor_latency_ms: 5,
        attack_success: true,
        executor_called: true,
        execution_status: 'completed',
        execution_target: 'sandbox',
        audit_id: 'audit-baseline',
        audit_hash: 'hash-baseline',
        result_hash: 'result-baseline',
        receipt_hash: 'receipt-baseline',
        receipt_control_verified: false,
        initial_state_hash: 'same',
        after_state_hash: 'changed',
        state_changed: true
      },
      guarded: {
        decision: '拒绝',
        controlled: true,
        policy_id: 'path-boundary',
        risk_score: 90,
        anomaly_score: 80,
        supervisor_latency_ms: 12,
        attack_success: false,
        executor_called: false,
        execution_status: 'not_executed',
        execution_target: 'none',
        audit_id: 'audit-guarded',
        audit_hash: 'hash-guarded',
        result_hash: '',
        receipt_hash: 'receipt-guarded',
        receipt_control_verified: true,
        initial_state_hash: 'same',
        after_state_hash: 'same',
        state_changed: false
      }
    }
  ]
};

describe('RealModelEvidencePanel', () => {
  it('shows an explicit empty state before a blind run exists', () => {
    render(<RealModelEvidencePanel />);
    expect(screen.getByText('尚未生成真实模型工具调用盲测报告。')).toBeInTheDocument();
  });

  it('shows model source, tool call, decision and latency evidence', () => {
    render(<RealModelEvidencePanel evaluation={evaluation} />);
    expect(screen.getByText('报告仅含本地兜底')).toBeInTheDocument();
    expect(screen.getByText('ATTACK-1')).toBeInTheDocument();
    expect(screen.getByText('file.read')).toBeInTheDocument();
    expect(screen.getByText(/拒绝 \/ path-boundary/)).toBeInTheDocument();
    expect(screen.getByText('攻击成功')).toBeInTheDocument();
    expect(screen.getByText('防护成功')).toBeInTheDocument();
    expect(screen.getByText('双分支1步回执完整')).toBeInTheDocument();
    expect(screen.getAllByText((_, node) => node?.textContent === '报告 Hash fixture-repo…').length).toBeGreaterThan(0);
    expect(screen.getByText('预期决策匹配')).toBeInTheDocument();
    expect(screen.getByText('供应商响应指纹')).toBeInTheDocument();
  });

  it('shows strict v3 real API evidence with integrity and causal metrics', () => {
    const strictEvaluation: RealModelEvaluation = {
      ...evaluation,
      schema_version: 'agent-supervisor.real-model-evaluation.v3',
      report_hash: 'c5e21828c814ba57aa93e023ea88e8597c88a15109d1d5ed73d05db3cdaa6b8d',
      method: {
        causal_rule: '同一模型工具调用进入独立且初始状态一致的无防护、有防护沙箱。'
      },
      summary: {
        ...evaluation.summary,
        provider_modes: ['fixture-model / real-api'],
        real_api_case_count: 2,
        fallback_case_count: 0,
        real_api_ready: true,
        strict_real_api_ready: true,
        real_api_coverage_rate: 100,
        task_alignment_rate: 100,
        expected_control_match_rate: 100,
        causal_integrity_rate: 100,
        provider_evidence_coverage_rate: 100,
        report_integrity_valid: true,
        report_freshness_valid: true
      },
      results: evaluation.results.map((result) => ({
        ...result,
        provider: 'fixture-model',
        mode: 'real-api',
        task_aligned: true,
        real_model_evidence_valid: true,
        evidence_gaps: []
      }))
    };

    render(<RealModelEvidencePanel evaluation={strictEvaluation} />);

    expect(screen.getByText('全量真实 API 严格证据通过')).toBeInTheDocument();
    expect(screen.getByText('报告 Hash c5e21828c814…')).toBeInTheDocument();
    expect(screen.getByText(/报告完整性 Hash 已校验/)).toBeInTheDocument();
    expect(screen.getByText('预期决策匹配').closest('.ant-statistic')).toHaveTextContent('100%');
    expect(screen.getByText('因果一致性').closest('.ant-statistic')).toHaveTextContent('100%');
    expect(screen.getByText('供应商响应指纹').closest('.ant-statistic')).toHaveTextContent('100%');
    expect(screen.getByText('严格证据有效 · 预期与因果均匹配')).toBeInTheDocument();
  });
});
