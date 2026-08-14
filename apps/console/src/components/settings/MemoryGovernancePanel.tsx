import { Flex, Space, Typography } from 'antd';
import type { MemoryGovernance } from '@/types';
import { LabelTag, PanelCard, UiAlert, UiButton } from '../ui';

type MemoryGovernancePanelProps = {
  memoryGovernance: MemoryGovernance | null;
  canReviewApproval: boolean;
  busyMemoryId?: string;
  onMemoryStatus: (memoryId: string, status: string) => void | Promise<void>;
  onRollbackMemory: () => void | Promise<void>;
};

export function MemoryGovernancePanel({
  memoryGovernance,
  canReviewApproval,
  busyMemoryId,
  onMemoryStatus,
  onRollbackMemory
}: MemoryGovernancePanelProps) {
  const items = memoryGovernance?.items ?? [];
  const actionDisabled = !canReviewApproval || Boolean(busyMemoryId);

  return (
    <PanelCard title="记忆治理" type="inner">
      <Flex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mb-16">
        <Space wrap>
          <LabelTag variant="filled" color="processing">
            活跃 {memoryGovernance?.summary.active_count ?? 0}
          </LabelTag>
          <LabelTag variant="filled" color="warning">
            隔离 {memoryGovernance?.summary.quarantined_count ?? 0}
          </LabelTag>
          <LabelTag variant="filled" color="default">
            移除 {memoryGovernance?.summary.removed_count ?? 0}
          </LabelTag>
          {memoryGovernance?.items_window ? (
            <LabelTag variant="filled" color="blue">
              已返回 {memoryGovernance.items_window.returned}/{memoryGovernance.items_window.total}
            </LabelTag>
          ) : null}
        </Space>
        <UiButton
          loading={busyMemoryId === '__rollback__'}
          disabled={actionDisabled}
          onClick={() => void onRollbackMemory()}
        >
          回滚最新非种子记忆
        </UiButton>
      </Flex>
      {items.length ? (
        <Space orientation="vertical" className="zh-full-width" size="middle">
          {items.slice(0, 8).map((item) => (
            <PanelCard key={item.id} size="small" bodyPadding={12}>
              <Flex justify="space-between" align="flex-start" wrap="wrap" gap={12}>
                <Space orientation="vertical" size={4} className="zh-settings-memory-copy">
                  <Space wrap>
                    <Typography.Text strong>{item.id}</Typography.Text>
                    <LabelTag variant="filled" color={item.status === 'active' ? 'success' : 'warning'}>
                      {item.status}
                    </LabelTag>
                    <LabelTag variant="filled" color="blue">
                      可信度 {item.trust_score}
                    </LabelTag>
                  </Space>
                  <Typography.Text type="secondary">{item.content}</Typography.Text>
                </Space>
                <Space wrap>
                  <UiButton
                    size="small"
                    loading={busyMemoryId === item.id}
                    disabled={actionDisabled}
                    onClick={() => void onMemoryStatus(item.id, 'active')}
                  >
                    恢复
                  </UiButton>
                  <UiButton
                    size="small"
                    loading={busyMemoryId === item.id}
                    disabled={actionDisabled}
                    onClick={() => void onMemoryStatus(item.id, 'quarantined')}
                  >
                    隔离
                  </UiButton>
                  <UiButton
                    size="small"
                    danger
                    loading={busyMemoryId === item.id}
                    disabled={actionDisabled}
                    onClick={() => void onMemoryStatus(item.id, 'removed')}
                  >
                    移除
                  </UiButton>
                </Space>
              </Flex>
            </PanelCard>
          ))}
        </Space>
      ) : (
        <UiAlert
          title="暂无记忆记录。运行记忆中毒或上下文隔离相关实验后，这里会出现可隔离、恢复或移除的记忆项。"
          type="info"
          showIcon
        />
      )}
    </PanelCard>
  );
}
