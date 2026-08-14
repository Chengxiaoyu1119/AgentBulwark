import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CustomAttackChainResult, CustomAttackCompareResult, ExecutionReceipt } from '../../types';
import { CustomAttackResultPanel } from './CustomAttackResultPanel';
import { CustomAttackWorkspace } from './CustomAttackWorkspace';

const runCustomAttackCompare = vi.fn();
const submitExternalExecutionReceipt = vi.fn();
const fetchExternalExecutionReceipt = vi.fn();
const runCustomAttackChain = vi.fn();

vi.mock('../../api', () => ({
  fetchAttackLabModules: vi.fn().mockResolvedValue({ modules: [] }),
  runAttackLabModule: vi.fn(),
  runCustomAttackCompare: (...args: unknown[]) => runCustomAttackCompare(...args),
  submitExternalExecutionReceipt: (...args: unknown[]) => submitExternalExecutionReceipt(...args),
  fetchExternalExecutionReceipt: (...args: unknown[]) => fetchExternalExecutionReceipt(...args),
  runCustomAttackChain: (...args: unknown[]) => runCustomAttackChain(...args)
}));

describe('custom runtime entry', () => {
  beforeEach(() => {
    runCustomAttackCompare.mockReset();
    submitExternalExecutionReceipt.mockReset();
    fetchExternalExecutionReceipt.mockReset();
    runCustomAttackChain.mockReset();
    runCustomAttackCompare.mockImplementation(() => new Promise(() => undefined));
  });

  it('submits caller-authored payload, tool, arguments and execution mode', async () => {
    const user = userEvent.setup();
    render(<CustomAttackWorkspace onNotice={() => undefined} />);

    expect(screen.getByText('自定义 Agent 攻击执行')).toBeInTheDocument();

    await user.clear(screen.getByDisplayValue('file.read'));
    await user.type(screen.getByPlaceholderText('file.read / code.run / mail.send'), 'mail.send');
    const jsonEditor = screen.getByDisplayValue(/competition-teams/);
    fireEvent.change(jsonEditor, { target: { value: '{"to":"outside@example.com","body":"payload"}' } });
    await user.click(screen.getByRole('button', { name: '执行自定义攻防' }));

    await waitFor(() => expect(runCustomAttackCompare).toHaveBeenCalledTimes(1));
    expect(runCustomAttackCompare).toHaveBeenCalledWith(
      expect.objectContaining({
        tool: 'mail.send',
        arguments: { to: 'outside@example.com', body: 'payload' },
        execution_mode: 'sandbox'
      })
    );
  });

  it('rejects invalid JSON before calling the backend', async () => {
    const user = userEvent.setup();
    let notice = '';
    const onNotice = (value: string) => {
      notice = value;
    };
    render(<CustomAttackWorkspace onNotice={onNotice} />);
    const jsonEditor = screen.getByDisplayValue(/competition-teams/);
    fireEvent.change(jsonEditor, { target: { value: '{broken' } });
    await user.click(screen.getByRole('button', { name: '执行自定义攻防' }));

    expect(notice).toMatch(/JSON 参数格式错误/);
    expect(runCustomAttackCompare).not.toHaveBeenCalled();
  });

  it('submits and refreshes both external execution receipts', async () => {
    const comparison = externalReceiptComparison();
    runCustomAttackCompare.mockResolvedValueOnce(comparison);
    submitExternalExecutionReceipt.mockResolvedValue({ persisted: true, idempotent: false, event_id: 1 });
    fetchExternalExecutionReceipt
      .mockResolvedValueOnce({ audit_id: 'audit-without', receipt: externalReceipt('completed', 'real') })
      .mockResolvedValueOnce({ audit_id: 'audit-guarded', receipt: externalReceipt('not_executed', 'none') });
    const user = userEvent.setup();
    render(<CustomAttackWorkspace onNotice={() => undefined} />);

    await user.click(screen.getByRole('combobox', { name: '' }));
    await user.click(screen.getByText('只监督，等待外部 Agent 回执'));
    await user.click(screen.getByRole('button', { name: '执行自定义攻防' }));
    expect(await screen.findByText('外部 Agent 执行回执')).toBeInTheDocument();

    const hashInput = screen.getByPlaceholderText('64 位十六进制 Hash');
    await user.type(hashInput, 'a'.repeat(64));
    await user.click(screen.getByRole('button', { name: '提交关闭智安哨分支回执' }));

    await waitFor(() => expect(submitExternalExecutionReceipt).toHaveBeenCalledTimes(1));
    expect(submitExternalExecutionReceipt).toHaveBeenCalledWith(
      'audit-without',
      expect.objectContaining({
        agent_id: 'custom-attack-agent',
        status: 'completed',
        execution_target: 'real',
        result_hash: 'a'.repeat(64)
      })
    );
    await waitFor(() => expect(fetchExternalExecutionReceipt).toHaveBeenCalledTimes(2));
    expect(await screen.findAllByText('已确认')).toHaveLength(2);
  });

  it('does not treat two non-execution receipts as a verified attack comparison', async () => {
    const comparison = externalReceiptComparison();
    comparison.receipts = {
      without_guard: externalReceipt('not_executed', 'none'),
      with_guard: externalReceipt('not_executed', 'none')
    };
    comparison.summary.receipts_complete = true;
    comparison.summary.receipt_required = false;

    render(<CustomAttackResultPanel result={comparison} onResultChange={() => undefined} onNotice={() => undefined} />);

    expect(screen.getByText('回执闭环')).toBeInTheDocument();
    expect(screen.getByText('证据不足')).toBeInTheDocument();
  });

  it('continues the exact custom result through the Agent chain endpoint', async () => {
    const comparison = externalReceiptComparison();
    runCustomAttackCompare.mockResolvedValueOnce(comparison);
    runCustomAttackChain.mockResolvedValueOnce({
      source_comparison_id: comparison.comparison_id,
      execution_id: 'chain-execution',
      conversation_id: 'chain-conversation',
      request: comparison.request,
      tool_call: comparison.tool_call,
      summary: {
        decision: '询问',
        controlled: true,
        attack_success: false,
        policy_id: 'external-mail',
        execution_status: 'not_executed',
        stage_count: 2,
        all_stages_audited: true,
        all_stages_receipted: true,
        shared_conversation_id: 'chain-conversation'
      },
      receipt: externalReceipt('not_executed', 'none'),
      audit: { audit_id: 'chain-audit', audit_hash: 'chain-hash' },
      chain: [
        { agent: '规划 Agent', status: 'completed', evidence: '接收当前 Payload' },
        { agent: '行为监督器', status: '询问', evidence: '外发需确认' }
      ],
      stages: [
        chainStage('planner', '规划 Agent', false, comparison),
        chainStage('behavior-supervisor', '行为监督器', false, comparison)
      ],
      chain_integrity: {
        same_payload: true,
        same_tool_call: true,
        shared_conversation_id: true,
        initial_state_hash: 'initial-hash',
        final_state_hash: 'final-hash',
        artifact_hashes_valid: true,
        executor_consumed_planner_artifact: true,
        supervisor_consumed_execution_artifact: true,
        evaluator_consumed_prior_artifacts: true,
        artifact_chain_valid: true,
        chain_root_hash: 'root-hash'
      }
    });
    const user = userEvent.setup();
    render(<CustomAttackWorkspace onNotice={() => undefined} />);

    await user.click(screen.getByRole('button', { name: '执行自定义攻防' }));
    await user.click(await screen.findByRole('button', { name: '用当前 Payload 运行多 Agent 链' }));

    await waitFor(() => expect(runCustomAttackChain).toHaveBeenCalledWith(comparison));
    expect(await screen.findByText('当前 Payload 的多 Agent 链证据')).toBeInTheDocument();
    expect(screen.getAllByText(/仅监督留痕/)).toHaveLength(2);
    expect(screen.getByText('计划、执行、监督、汇总产物已逐级校验')).toBeInTheDocument();
  });
});

function externalReceiptComparison(): CustomAttackCompareResult {
  const evaluation = (decision: '允许' | '询问', auditId: string) => ({
    decision,
    audit_id: auditId,
    execution_status: 'awaiting_receipt',
    audit_log: {
      tool_output: { executed: false, sandboxed: false, output: '' },
      execution_status: 'not_executed'
    }
  });
  return {
    comparison_id: 'comparison-1',
    request: {
      payload: 'payload',
      tool: 'mail.send',
      arguments: { to: 'outside@example.com' },
      command: '',
      agent_id: 'custom-attack-agent',
      agent_role: 'attacker',
      context_sources: ['user-payload'],
      execution_mode: 'external_receipt'
    },
    tool_call: { tool: 'mail.send', arguments: { to: 'outside@example.com' } },
    without_guard: evaluation('允许', 'audit-without'),
    with_guard: evaluation('询问', 'audit-guarded'),
    environment_comparison: {
      integrity: { same_initial_state: true, only_variable: 'guard_enabled', tool_call_hash: 'tool-hash' },
      without_guard: {
        changed: false,
        changes: [],
        decision: '允许',
        executor_called: false,
        attack_success: false,
        effect_reason: '',
        audit_id: 'audit-without',
        audit_hash: ''
      },
      with_guard: {
        changed: false,
        changes: [],
        decision: '询问',
        executor_called: false,
        attack_success: false,
        effect_reason: '',
        audit_id: 'audit-guarded',
        audit_hash: ''
      }
    },
    summary: {
      exposed_without_guard: false,
      controlled_with_guard: true,
      decision_change: '允许 -> 询问',
      policy_id: 'external-mail',
      execution_status: 'awaiting_receipt',
      receipt_required: true,
      receipts_complete: false,
      same_initial_state: true,
      tool_call_hash: 'tool-hash'
    },
    audit: {
      without_guard: { audit_id: 'audit-without', audit_hash: 'hash-without' },
      with_guard: { audit_id: 'audit-guarded', audit_hash: 'hash-guarded' }
    },
    receipts: { without_guard: null, with_guard: null }
  } as unknown as CustomAttackCompareResult;
}

function chainStage(
  stageId: string,
  stageName: string,
  executionAttempted: boolean,
  comparison: CustomAttackCompareResult
): CustomAttackChainResult['stages'][number] {
  return {
    stage_id: stageId,
    stage_name: stageName,
    stage_role: stageId,
    agent_id: `custom-attack-agent::${stageId}`,
    conversation_id: 'chain-conversation',
    payload: comparison.request.payload,
    tool_call: comparison.tool_call,
    execution_attempted: executionAttempted,
    artifact: {
      schema_version: 'agent-supervisor.custom-chain-artifact.v1',
      artifact_type:
        stageId === 'planner'
          ? 'execution-plan'
          : stageId === 'executor'
            ? 'execution-evidence'
            : stageId === 'behavior-supervisor'
              ? 'supervisor-verdict'
              : 'evaluation-summary',
      producer_stage: stageId,
      input_artifact_hashes: [],
      data: {},
      artifact_hash: `artifact-${stageId}`
    },
    evaluation: comparison.with_guard,
    audit: { audit_id: `audit-${stageId}`, audit_hash: `hash-${stageId}` },
    receipt: externalReceipt('not_executed', 'none'),
    environment: comparison.environment_comparison.with_guard
  } as CustomAttackChainResult['stages'][number];
}

function externalReceipt(status: string, executionTarget: string): ExecutionReceipt {
  return {
    receipt_id: `receipt-${status}`,
    audit_id: `audit-${status}`,
    run_id: 'run-1',
    agent_id: 'custom-attack-agent',
    tool_call_hash: 'tool-hash',
    status,
    execution_target: executionTarget,
    result_hash: status === 'completed' ? 'a'.repeat(64) : '',
    receipt_hash: 'receipt-hash'
  } as ExecutionReceipt;
}
