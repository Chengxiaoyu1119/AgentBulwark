import { UiFlex, UiSpace, UiTypography } from '../ui';
import { RadioTower, Square } from 'lucide-react';
import type { JsonObject, McpSubscriptionFilters, McpSubscriptionStatus } from '../../app/mcpConsoleContract';
import { EvidenceCodeBlock, LabelTag, PanelCard, UiAlert, UiButton, UiInput, UiSwitch } from '../ui';

const STATUS: Record<McpSubscriptionStatus, { color: string; label: string }> = {
  idle: { color: 'default', label: '未订阅' },
  connecting: { color: 'processing', label: '连接中' },
  active: { color: 'green', label: '订阅已连接' },
  closed: { color: 'warning', label: '服务端已结束' },
  error: { color: 'red', label: '连接失败' }
};

export function GatewayMcpSubscriptionPanel({
  filters,
  resourceSubscriptions,
  status,
  events,
  error,
  onFilterChange,
  onResourceSubscriptionsChange,
  onStart,
  onStop
}: {
  filters: McpSubscriptionFilters;
  resourceSubscriptions: string;
  status: McpSubscriptionStatus;
  events: JsonObject[];
  error: string;
  onFilterChange: (key: keyof McpSubscriptionFilters, selected: boolean) => void;
  onResourceSubscriptionsChange: (value: string) => void;
  onStart: () => void;
  onStop: () => void;
}) {
  const connected = status === 'connecting' || status === 'active';
  const acknowledged = events.some((event) => event.method === 'notifications/subscriptions/acknowledged');
  const notifications = events.filter((event) => event.method !== 'notifications/subscriptions/acknowledged');

  return (
    <PanelCard
      title="MCP 实时订阅"
      subtitle="监听工具、Prompt、Resource 目录变化和指定 Resource 更新；停止后立即释放会话租约"
      extra={<LabelTag color={STATUS[status].color}>{STATUS[status].label}</LabelTag>}
    >
      <UiSpace orientation="vertical" size={12} className="zh-full-width">
        <UiFlex gap={16} wrap="wrap">
          <UiSpace>
            <UiTypography.Text>工具目录变化</UiTypography.Text>
            <UiSwitch
              aria-label="订阅 MCP 工具目录变化"
              checked={filters.toolsListChanged}
              disabled={connected}
              onChange={(selected) => onFilterChange('toolsListChanged', selected)}
            />
          </UiSpace>
          <UiSpace>
            <UiTypography.Text>Prompt 目录变化</UiTypography.Text>
            <UiSwitch
              aria-label="订阅 MCP Prompt 目录变化"
              checked={filters.promptsListChanged}
              disabled={connected}
              onChange={(selected) => onFilterChange('promptsListChanged', selected)}
            />
          </UiSpace>
          <UiSpace>
            <UiTypography.Text>Resource 目录变化</UiTypography.Text>
            <UiSwitch
              aria-label="订阅 MCP Resource 目录变化"
              checked={filters.resourcesListChanged}
              disabled={connected}
              onChange={(selected) => onFilterChange('resourcesListChanged', selected)}
            />
          </UiSpace>
        </UiFlex>
        <UiInput.TextArea
          aria-label="MCP Resource 订阅 URI"
          placeholder="可选：每行一个 Resource URI，最多 128 项"
          value={resourceSubscriptions}
          disabled={connected}
          autoSize={{ minRows: 2, maxRows: 4 }}
          onChange={(event) => onResourceSubscriptionsChange(event.target.value)}
        />
        <UiFlex gap={8} wrap="wrap">
          <UiButton
            type="primary"
            icon={<RadioTower size={16} />}
            loading={status === 'connecting'}
            disabled={connected}
            onClick={onStart}
          >
            开始订阅
          </UiButton>
          <UiButton icon={<Square size={15} />} disabled={!connected} onClick={onStop}>
            停止订阅
          </UiButton>
        </UiFlex>
        {error ? <UiAlert type="error" showIcon title={error} /> : null}
        {status === 'closed' ? (
          <UiAlert type="warning" showIcon title="订阅流已由服务端结束，可检查上游状态后重新连接。" />
        ) : null}
        {events.length ? (
          <UiSpace orientation="vertical" size={8} className="zh-full-width">
            <UiAlert
              type="info"
              showIcon
              title={`MCP 订阅事件 ${notifications.length} 条`}
              description={`服务端确认：${acknowledged ? '已收到' : '等待中'}；浏览器最多保留最近 100 条消息。`}
            />
            <EvidenceCodeBlock size="small" maxHeight="large">
              {JSON.stringify(events, null, 2)}
            </EvidenceCodeBlock>
          </UiSpace>
        ) : null}
      </UiSpace>
    </PanelCard>
  );
}
