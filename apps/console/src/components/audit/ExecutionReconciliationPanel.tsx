import type { ExecutionInventory } from '@/types';
import { EvidenceList, MetaGrid, PanelCard, UiAlert, UiStack } from '../ui';

type ExecutionReconciliationPanelProps = {
  inventory: ExecutionInventory | null;
  error: string;
};

function formatTime(value: string) {
  if (!value) return '未记录';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('zh-CN', { hour12: false });
}

export function ExecutionReconciliationPanel({ inventory, error }: ExecutionReconciliationPanelProps) {
  const unknownClaims = inventory?.gateway_execution_claims.filter((claim) => claim.status === 'unknown') ?? [];

  return (
    <PanelCard
      variant="borderless"
      title="执行状态核查"
      subtitle="副作用状态不确定时禁止自动重试，由操作员按审计 ID 核查。"
    >
      <UiStack gap="md">
        {error ? <UiAlert type="warning" showIcon title="执行核查清单读取失败" description={error} /> : null}

        {inventory ? (
          <MetaGrid
            columns={3}
            items={[
              { key: 'receipt-total', label: '执行回执', value: inventory.summary.total },
              { key: 'server-observed', label: '服务端观察', value: inventory.summary.server_observed },
              { key: 'unknown', label: '待核查状态', value: inventory.summary.gateway_unknown }
            ]}
          />
        ) : null}

        {!error && inventory && unknownClaims.length === 0 ? (
          <UiAlert type="success" showIcon title="当前没有状态不确定的工具执行。" />
        ) : null}

        {unknownClaims.length > 0 ? (
          <UiAlert
            type="error"
            showIcon
            title="工具副作用状态不确定，禁止自动重试"
            description={`当前有 ${unknownClaims.length} 条执行占用需要人工核查。`}
          />
        ) : null}

        <EvidenceList
          emptyText={inventory || error ? '没有待核查执行。' : '正在读取执行核查清单…'}
          items={unknownClaims.map((claim) => ({
            key: claim.audit_id,
            title: claim.audit_id,
            description: '工具可能已经产生副作用，但最终状态没有形成可信回执。请核对目标系统后再决定后续处置。',
            tone: 'danger',
            tags: [
              { label: '状态不确定', color: 'error' },
              { label: `Agent：${claim.agent_id || '未记录'}` },
              { label: `会话：${claim.session_id || '未记录'}` }
            ],
            meta: `占用建立：${formatTime(claim.created_at)}；冻结时间：${formatTime(claim.completed_at)}；工具 Hash：${claim.tool_call_hash || '未记录'}`
          }))}
        />
      </UiStack>
    </PanelCard>
  );
}
