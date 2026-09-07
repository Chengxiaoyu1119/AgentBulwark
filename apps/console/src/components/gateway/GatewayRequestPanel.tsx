import { UiFlex, UiSpace, UiTypography } from '../ui';
import { Play, RotateCcw, ShieldAlert, Square } from 'lucide-react';
import { LabelTag, PanelCard, UiAlert, UiButton, UiFieldLabel, UiInput, UiSwitch } from '../ui';
import { DEFAULT_REQUEST, INJECTION_REQUEST, TOOL_ABUSE_REQUEST, pretty } from '../../app/gatewayPanelPresets';
import type { OpenAIStreamProgress } from '../../app/openaiChatStream';

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
  streamProgress: OpenAIStreamProgress | null;
  error: string;
  onSubmit: () => void;
  onCancelStream: () => void;
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
  streamProgress,
  error,
  onSubmit,
  onCancelStream
}: GatewayRequestPanelProps) {
  return (
    <PanelCard
      title="请求体"
      subtitle={managedMode ? '发送到真实 Provider，并由服务端托管工具执行' : '发送到真实透明代理'}
      className="zh-full-height"
    >
      <UiFieldLabel htmlFor="gateway-agent-session-id">
        Agent 会话 ID（通过 <UiTypography.Text code>X-Agent-Session-ID</UiTypography.Text> 发送，用于多轮回执绑定）
      </UiFieldLabel>
      {canGenerate === false && (
        <UiAlert
          type="warning"
          showIcon
          title="当前凭证为观测角色"
          description={
            identityText || '切换到已绑定 Agent 的 executor 凭证，或使用 analyst/admin 凭证后即可发起模型请求。'
          }
          className="zh-mb-12"
        />
      )}
      <UiInput
        id="gateway-agent-session-id"
        value={sessionId}
        onChange={(event) => onSessionIdChange(event.target.value)}
        placeholder="例如 agent-session-001"
        className="zh-mb-12"
      />
      <UiFlex justify="space-between" align="center" gap={12} wrap="wrap" className="zh-mb-12">
        <UiFlex align="center" gap={8}>
          <UiSwitch checked={managedMode} onChange={onManagedModeChange} disabled={canExecuteManagedTools === false} />
          <UiTypography.Text strong>服务端托管工具执行</UiTypography.Text>
        </UiFlex>
        <UiTypography.Text type="secondary">
          {canExecuteManagedTools === false
            ? '当前身份可以生成模型响应；绑定 Agent 的 executor 或 admin 凭证可开启服务端工具执行。'
            : managedMode
              ? '允许的工具会在智垒受限运行时执行，回执校验后才回灌 Provider；拒绝/询问不会执行。'
              : '透明模式只返回已检查的 tool call，由接入方执行并提交回执。'}
        </UiTypography.Text>
      </UiFlex>
      <UiInput.TextArea
        value={payload}
        onChange={(event) => onPayloadChange(event.target.value)}
        aria-label="网关请求 JSON"
        autoSize={{ minRows: 22, maxRows: 36 }}
        spellCheck={false}
        className="zh-settings-editor"
      />
      <UiFlex justify="space-between" align="center" gap={12} wrap="wrap" className="zh-mt-16">
        <UiTypography.Text type="secondary">
          Provider 未配置时网关返回 502 并记录失败；配置真实 Provider 后再发送即可。
        </UiTypography.Text>
        <UiButton
          type="primary"
          icon={<Play size={16} />}
          loading={loading}
          onClick={onSubmit}
          disabled={canGenerate === false}
        >
          发送到网关
        </UiButton>
      </UiFlex>
      {streamProgress && (
        <section className="zh-gateway-stream" aria-live="polite" aria-label="模型流式响应状态">
          <UiFlex justify="space-between" align="center" gap={12} wrap="wrap">
            <UiFlex align="center" gap={8} wrap="wrap">
              <UiTypography.Text strong>安全流实时预览</UiTypography.Text>
              <LabelTag
                color={
                  streamProgress.status === 'completed'
                    ? 'green'
                    : streamProgress.status === 'interrupted'
                      ? 'red'
                      : 'processing'
                }
              >
                {streamProgress.status === 'completed'
                  ? '已完成'
                  : streamProgress.status === 'interrupted'
                    ? '已中断'
                    : '接收中'}
              </LabelTag>
              <UiTypography.Text type="secondary">
                {streamProgress.chunkCount} 个安全Chunk · {streamProgress.characterCount} 字符
              </UiTypography.Text>
            </UiFlex>
            {loading && (
              <UiButton icon={<Square size={14} />} onClick={onCancelStream}>
                停止接收
              </UiButton>
            )}
          </UiFlex>
          <pre className="zh-evidence-code-block zh-gateway-stream__preview" aria-label="流式响应实时内容">
            {streamProgress.content || '已连接网关，正在等待内容通过安全窗口…'}
          </pre>
          <UiTypography.Text type="secondary">
            文本经过尾部安全窗口后增量显示；Tool Call参数、reasoning和Provider扩展会在完整监督前保持隐藏。
          </UiTypography.Text>
          {streamProgress.status === 'interrupted' && streamProgress.metadata.audit_id ? (
            <UiTypography.Text type="danger">中断审计 ID：{String(streamProgress.metadata.audit_id)}</UiTypography.Text>
          ) : null}
        </section>
      )}
      {error && <UiAlert type="error" showIcon title={error} className="zh-mt-16" />}
    </PanelCard>
  );
}

export function GatewayRequestPresets({ onSelect }: { onSelect: (value: string) => void }) {
  return (
    <UiSpace wrap>
      <UiButton icon={<RotateCcw size={16} />} onClick={() => onSelect(pretty(DEFAULT_REQUEST))}>
        正常请求
      </UiButton>
      <UiButton icon={<ShieldAlert size={16} />} onClick={() => onSelect(pretty(INJECTION_REQUEST))}>
        注入测试
      </UiButton>
      <UiButton icon={<ShieldAlert size={16} />} onClick={() => onSelect(pretty(TOOL_ABUSE_REQUEST))}>
        工具越权测试
      </UiButton>
    </UiSpace>
  );
}
