import { useState, type ReactNode } from 'react';
import { RefreshCw, Send } from 'lucide-react';
import { Descriptions, Typography } from 'antd';
import { fetchExternalExecutionReceipt, submitExternalExecutionReceipt } from '../../api';
import type { CustomAttackCompareResult, ExecutionReceipt } from '../../types';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import { DecisionPill, UiAlert, UiButton, UiInput, UiInputNumber, UiSelect } from '../ui';

type ReceiptBranch = 'without_guard' | 'with_guard';

export function ExternalReceiptWorkspace({
  result,
  onResultChange,
  onNotice,
  refresh
}: {
  result: CustomAttackCompareResult;
  onResultChange: (result: CustomAttackCompareResult) => void;
  onNotice: (message: string) => void;
  refresh?: () => Promise<unknown>;
}) {
  const [syncing, setSyncing] = useState(false);

  async function syncReceipts() {
    setSyncing(true);
    onNotice('');
    try {
      const [without, guarded] = await Promise.all([
        fetchExternalExecutionReceipt(result.audit.without_guard.audit_id),
        fetchExternalExecutionReceipt(result.audit.with_guard.audit_id)
      ]);
      const receipts = { without_guard: without.receipt, with_guard: guarded.receipt };
      onResultChange({
        ...result,
        receipts,
        summary: {
          ...result.summary,
          receipts_complete: Boolean(receipts.without_guard && receipts.with_guard),
          execution_status: receipts.with_guard?.status ?? 'awaiting_receipt',
          receipt_required: !receipts.without_guard || !receipts.with_guard
        }
      });
      await refresh?.();
      onNotice(receipts.without_guard && receipts.with_guard ? '双分支外部回执已同步。' : '已刷新，仍有分支等待回执。');
    } catch (error) {
      onNotice(`刷新外部回执失败：${error instanceof Error ? error.message : '未知错误'}`);
    } finally {
      setSyncing(false);
    }
  }

  return (
    <div className="zh-external-receipt-workspace">
      <div className="zh-external-receipt-workspace__header">
        <div>
          <Typography.Title level={5}>外部 Agent 执行回执</Typography.Title>
          <Typography.Text type="secondary">
            分别提交关闭防护与启用智安哨的真实执行结果；服务端校验 Agent、工具调用和决策一致性。
          </Typography.Text>
        </div>
        <UiButton icon={<RefreshCw size={16} />} loading={syncing} onClick={syncReceipts}>
          刷新双分支状态
        </UiButton>
      </div>
      <UiAlert
        type="info"
        showIcon
        title="result_hash 是外部 Agent 对原始执行结果计算的 64 位 SHA-256；允许分支可回传真实执行，拒绝或询问分支只能回传未执行。"
      />
      <div className="zh-custom-attack-proof-grid">
        <ExternalReceiptForm
          branch="without_guard"
          title="关闭智安哨分支"
          result={result}
          receipt={result.receipts.without_guard}
          onSubmitted={syncReceipts}
          onNotice={onNotice}
        />
        <ExternalReceiptForm
          branch="with_guard"
          title="启用智安哨分支"
          result={result}
          receipt={result.receipts.with_guard}
          onSubmitted={syncReceipts}
          onNotice={onNotice}
        />
      </div>
    </div>
  );
}

function ExternalReceiptForm({
  branch,
  title,
  result,
  receipt,
  onSubmitted,
  onNotice
}: {
  branch: ReceiptBranch;
  title: string;
  result: CustomAttackCompareResult;
  receipt: ExecutionReceipt | null;
  onSubmitted: () => Promise<void>;
  onNotice: (message: string) => void;
}) {
  const evaluation = branch === 'without_guard' ? result.without_guard : result.with_guard;
  const controlled = evaluation.decision === '拒绝' || evaluation.decision === '询问';
  const isolated = evaluation.decision === '隔离';
  const [status, setStatus] = useState<'completed' | 'failed' | 'not_executed'>(
    controlled ? 'not_executed' : 'completed'
  );
  const [target, setTarget] = useState<'real' | 'sandbox' | 'none'>(
    controlled ? 'none' : isolated ? 'sandbox' : 'real'
  );
  const [resultHash, setResultHash] = useState('');
  const [durationMs, setDurationMs] = useState(0);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const auditId = result.audit[branch].audit_id;

  async function submitReceipt() {
    setSubmitting(true);
    onNotice('');
    try {
      await submitExternalExecutionReceipt(auditId, {
        receipt_id: `${result.comparison_id}-${branch}`,
        agent_id: result.request.agent_id,
        tool_call: result.tool_call,
        status,
        execution_target: target,
        result_hash: status === 'not_executed' ? '' : resultHash.trim().toLowerCase(),
        duration_ms: durationMs,
        error
      });
      onNotice(`${title}回执已落库。`);
      await onSubmitted();
    } catch (submitError) {
      onNotice(`提交${title}回执失败：${submitError instanceof Error ? submitError.message : '未知错误'}`);
    } finally {
      setSubmitting(false);
    }
  }

  if (receipt) {
    return (
      <div className="zh-custom-attack-branch">
        <div className="zh-custom-attack-branch__header">
          <Typography.Text strong>{title}</Typography.Text>
          <Typography.Text type="success">已确认</Typography.Text>
        </div>
        <Descriptions column={1} size="small" bordered>
          <Descriptions.Item label="状态">{receipt.status}</Descriptions.Item>
          <Descriptions.Item label="目标">{receipt.execution_target}</Descriptions.Item>
          <Descriptions.Item label="结果 Hash">{receipt.result_hash || '-'}</Descriptions.Item>
          <Descriptions.Item label="回执 Hash">{receipt.receipt_hash || '-'}</Descriptions.Item>
        </Descriptions>
        <AuditDeepLinkButton auditId={auditId} size="small">
          精确查看执行回执
        </AuditDeepLinkButton>
      </div>
    );
  }

  return (
    <div className="zh-custom-attack-branch">
      <div className="zh-custom-attack-branch__header">
        <Typography.Text strong>{title}</Typography.Text>
        <DecisionPill decision={evaluation.decision} />
      </div>
      <Field label="执行状态">
        <UiSelect
          value={status}
          onChange={(value) => {
            setStatus(value);
            if (value === 'not_executed') setTarget('none');
            else if (target === 'none') setTarget(isolated ? 'sandbox' : 'real');
          }}
          options={
            controlled
              ? [{ label: '未执行', value: 'not_executed' }]
              : [
                  { label: '执行完成', value: 'completed' },
                  { label: '执行失败', value: 'failed' },
                  { label: '未执行', value: 'not_executed' }
                ]
          }
        />
      </Field>
      <Field label="执行目标">
        <UiSelect
          value={target}
          onChange={setTarget}
          options={
            status === 'not_executed'
              ? [{ label: '未执行', value: 'none' }]
              : isolated
                ? [{ label: '隔离环境', value: 'sandbox' }]
                : [
                    { label: '真实外部系统', value: 'real' },
                    { label: '外部沙箱', value: 'sandbox' }
                  ]
          }
        />
      </Field>
      {status !== 'not_executed' ? (
        <Field label="结果 SHA-256">
          <UiInput
            value={resultHash}
            onChange={(event) => setResultHash(event.target.value)}
            placeholder="64 位十六进制 Hash"
            maxLength={64}
          />
        </Field>
      ) : null}
      <Field label="耗时（毫秒）">
        <UiInputNumber
          min={0}
          max={86400000}
          value={durationMs}
          onChange={(value) => setDurationMs(Number(value ?? 0))}
          className="zh-full-width"
        />
      </Field>
      <Field label="错误或说明">
        <UiInput.TextArea value={error} onChange={(event) => setError(event.target.value)} rows={2} maxLength={2000} />
      </Field>
      <UiButton
        type="primary"
        icon={<Send size={16} />}
        loading={submitting}
        disabled={status !== 'not_executed' && !/^[0-9a-fA-F]{64}$/.test(resultHash.trim())}
        onClick={submitReceipt}
      >
        提交{title}回执
      </UiButton>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="zh-attack-lab__field">
      <Typography.Text strong>{label}</Typography.Text>
      {children}
    </div>
  );
}
