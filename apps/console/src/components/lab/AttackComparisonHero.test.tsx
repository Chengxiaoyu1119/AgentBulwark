import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { AttackLabRunResult } from '../../types';
import { AttackComparisonHero } from './AttackComparisonHero';

const snapshot = {
  state_hash: 'state-hash-1234567890',
  outbox_count: 0,
  active_memory_count: 2,
  quarantined_memory_count: 0,
  api_call_count: 0,
  bulk_export_count: 0,
  sensitive_read_count: 0,
  workspace_file_count: 4
};

const result = {
  comparison_id: 'comparison-1',
  tool_call: {
    tool: 'mail.send',
    arguments: { to: 'external@example.com', body: 'sensitive fixture' }
  },
  model_plan: {
    provider: 'test-model',
    mode: 'real',
    model: 'test-model-v1'
  },
  environment_comparison: {
    comparison_id: 'comparison-1',
    integrity: {
      same_initial_state: true,
      initial_state_hash: 'initial-state-123456',
      guarded_initial_state_hash: 'initial-state-123456',
      same_tool_call: true,
      tool_call_hash: 'tool-call-123456',
      risk_hint_used: false,
      only_variable: 'guard_enabled',
      isolated_conversation_history: true
    },
    without_guard: {
      before: snapshot,
      after: { ...snapshot, state_hash: 'baseline-after', outbox_count: 1 },
      changed: true,
      changes: [{ key: 'outbox_count', label: '外发队列', before: 0, after: 1 }],
      decision: '允许',
      executor_called: true,
      attack_success: true,
      effect_reason: '外部邮件已进入受控外发队列',
      audit_id: 'audit-baseline-123456',
      audit_hash: 'hash-baseline'
    },
    with_guard: {
      before: snapshot,
      after: snapshot,
      changed: false,
      changes: [],
      decision: '询问',
      executor_called: false,
      attack_success: false,
      effect_reason: '工具未以允许决策产生执行效果',
      audit_id: 'audit-guarded-123456',
      audit_hash: 'hash-guarded'
    }
  }
} as unknown as AttackLabRunResult;

describe('AttackComparisonHero', () => {
  it('shows the successful baseline attack and protected outcome in the first comparison view', () => {
    render(<AttackComparisonHero result={result} />);

    expect(screen.getByText('攻击成功：危险动作已执行')).toBeInTheDocument();
    expect(screen.getByText('防护成功：危险动作未执行')).toBeInTheDocument();
    expect(screen.getByText('初始环境一致')).toBeInTheDocument();
    expect(screen.getByText('未携带风险答案标签')).toBeInTheDocument();
    expect(screen.getByText('会话历史隔离')).toBeInTheDocument();
    expect(screen.getByText('外发队列')).toBeInTheDocument();
  });

  it('treats a quarantined sandbox execution as a successful defense', () => {
    const isolated = JSON.parse(JSON.stringify(result)) as AttackLabRunResult;
    isolated.environment_comparison.with_guard.decision = '隔离';
    isolated.environment_comparison.with_guard.executor_called = true;
    isolated.environment_comparison.with_guard.attack_success = false;
    isolated.environment_comparison.with_guard.changed = true;

    render(<AttackComparisonHero result={isolated} />);

    expect(screen.getByText('防护成功：危险动作已隔离')).toBeInTheDocument();
    expect(screen.getByText('隔离执行器已调用')).toBeInTheDocument();
  });
});
