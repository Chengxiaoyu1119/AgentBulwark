import type { ReactNode } from 'react';
import { Bot, KeyRound, Network } from 'lucide-react';
import type { AgentIntegrationBundle } from '../../types';
import { CopyButton, LabelTag, PanelCard, UiAlert, UiButton, UiFlex, UiSpace, UiTypography } from '../ui';

export function ConnectionSettings({
  integration,
  loading,
  error
}: {
  integration: AgentIntegrationBundle | null;
  loading: boolean;
  error?: string;
}) {
  const baseUrl = `${window.location.origin}/v1`;
  const mcpUrl = `${window.location.origin}/api/mcp`;
  return (
    <div className="zh-settings-column">
      <PanelCard title="应用入口" subtitle="业务应用只需要修改模型地址，并使用独立的 Agent Token。">
        <div className="zh-endpoint-list">
          <EndpointRow icon={<Network size={18} />} label="OpenAI 兼容地址" value={baseUrl} />
          <EndpointRow icon={<Bot size={18} />} label="MCP 地址" value={mcpUrl} />
        </div>
      </PanelCard>

      <PanelCard title="身份边界" subtitle="控制台与业务 Agent 使用不同凭证，避免共享权限。">
        <div className="zh-identity-boundary">
          <KeyRound size={20} aria-hidden="true" />
          <div>
            <UiTypography.Text strong>一个 Agent，一个 Token</UiTypography.Text>
            <UiTypography.Paragraph type="secondary" className="zh-mb-0">
              当前操作员 Token 只保存在浏览器会话中；业务 Token 由后端绑定 Agent 身份、模型和工具权限。
            </UiTypography.Paragraph>
          </div>
        </div>
      </PanelCard>

      <PanelCard title="接入契约" subtitle="内容来自运行时接口，可直接用于配置业务 Agent。">
        {integration ? (
          <UiSpace orientation="vertical" size={14} className="zh-full-width">
            <UiFlex align="center" gap={8} wrap="wrap">
              <LabelTag color="green">{integration.version}</LabelTag>
              <UiTypography.Text>{integration.examples.length} 种接入方式可用</UiTypography.Text>
            </UiFlex>
            <UiTypography.Text type="secondary">
              必填字段：{integration.event_contract.required_fields.join('、')}
            </UiTypography.Text>
            <UiButton authenticatedHref="/api/integrations/agents/bundle">下载接入契约</UiButton>
          </UiSpace>
        ) : error ? (
          <UiAlert type="error" showIcon title="接入契约读取失败" description={error} />
        ) : loading ? (
          <UiAlert type="info" showIcon title="正在读取接入契约。" />
        ) : (
          <UiAlert type="warning" showIcon title="接入契约暂时没有返回内容。" />
        )}
      </PanelCard>
    </div>
  );
}

function EndpointRow({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="zh-endpoint-row">
      <span aria-hidden="true">{icon}</span>
      <div>
        <UiTypography.Text type="secondary">{label}</UiTypography.Text>
        <UiTypography.Text code>{value}</UiTypography.Text>
      </div>
      <CopyButton text={value}>复制</CopyButton>
    </div>
  );
}
