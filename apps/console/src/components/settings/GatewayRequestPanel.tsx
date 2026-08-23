import { Flex, Space, Typography } from 'antd';
import { Play, RotateCcw, ShieldAlert } from 'lucide-react';
import { PanelCard, UiAlert, UiButton, UiInput, UiSwitch } from '../ui';
import { DEFAULT_REQUEST, INJECTION_REQUEST, TOOL_ABUSE_REQUEST, pretty } from '../../app/gatewayPanelPresets';

type GatewayRequestPanelProps = {
  payload: string;
  onPayloadChange: (value: string) => void;
  sessionId: string;
  onSessionIdChange: (value: string) => void;
  managedMode: boolean;
  onManagedModeChange: (value: boolean) => void;
  canGenerate?: boolean;
  canExecuteManagedTools?: boolean;
  identityText?: string;
  loading: boolean;
  error: string;
  onSubmit: () => void;
};

export function GatewayRequestPanel({
  payload,
  onPayloadChange,
  sessionId,
  onSessionIdChange,
  managedMode,
  onManagedModeChange,
  canGenerate,
  canExecuteManagedTools,
  identityText,
  loading,
  error,
  onSubmit
}: GatewayRequestPanelProps) {
  return (
    <PanelCard
      title="请求体"
      subtitle={managedMode ? '发送到真实 Provider，并由服务端托管工具执行' : '发送到真实透明代理'}
      className="zh-full-height"
    >
      <Typography.Text type="secondary" className="zh-meta-block">
        Agent 会话 ID（通过 <Typography.Text code>X-Agent-Session-ID</Typography.Text> 发送，用于多轮回执绑定）
      </Typography.Text>
      {canGenerate === false && (
        <UiAlert
          type="warning"
          showIcon
          title="当前凭证只有观测权限，不能发起模型请求。"
          description={identityText || '请在右上角切换到已绑定 Agent 的 executor 凭证，或使用 analyst/admin 凭证。'}
          className="zh-mb-12"
        />
      )}
      <UiInput
        value={sessionId}
        onChange={(event) => onSessionIdChange(event.target.value)}
        placeholder="例如 agent-session-001"
        className="zh-mb-12"
      />
      <Flex justify="space-between" align="center" gap={12} wrap="wrap" className="zh-mb-12">
        <Flex align="center" gap={8}>
          <UiSwitch checked={managedMode} onChange={onManagedModeChange} disabled={canExecuteManagedTools === false} />
          <Typography.Text strong>服务端托管工具执行</Typography.Text>
        </Flex>
        <Typography.Text type="secondary">
          {canExecuteManagedTools === false
            ? '当前身份可生成模型响应，但没有服务端工具执行权限；请使用绑定 Agent 的 executor 或 admin 凭证。'
            : managedMode
              ? '允许的工具会在智安哨沙箱执行，回执校验后才回灌 Provider；拒绝/询问不会执行。'
              : '透明模式只返回已检查的 tool call，由接入方执行并提交回执。'}
        </Typography.Text>
      </Flex>
      <UiInput.TextArea
        value={payload}
        onChange={(event) => onPayloadChange(event.target.value)}
        autoSize={{ minRows: 22, maxRows: 36 }}
        spellCheck={false}
        className="zh-settings-editor"
      />
      <Flex justify="space-between" align="center" gap={12} wrap="wrap" className="zh-mt-16">
        <Typography.Text type="secondary">
          Provider 未配置时网关返回 502，并明确记录失败，不会切换本地模拟模型。
        </Typography.Text>
        <UiButton
          type="primary"
          icon={<Play size={16} />}
          loading={loading}
          onClick={onSubmit}
          disabled={canGenerate === false}
        >
          发送到网关
        </UiButton>
      </Flex>
      {error && <UiAlert type="error" showIcon title={error} className="zh-mt-16" />}
    </PanelCard>
  );
}

export function GatewayRequestPresets({ onSelect }: { onSelect: (value: string) => void }) {
  return (
    <Space wrap>
      <UiButton icon={<RotateCcw size={16} />} onClick={() => onSelect(pretty(DEFAULT_REQUEST))}>
        正常请求
      </UiButton>
      <UiButton icon={<ShieldAlert size={16} />} onClick={() => onSelect(pretty(INJECTION_REQUEST))}>
        注入测试
      </UiButton>
      <UiButton icon={<ShieldAlert size={16} />} onClick={() => onSelect(pretty(TOOL_ABUSE_REQUEST))}>
        工具越权测试
      </UiButton>
    </Space>
  );
}
