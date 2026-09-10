import { useEffect, useMemo, useState } from 'react';
import { request } from '../app/apiRequest';
import { safeUiErrorSummary } from '../app/apiRequestSupport';
import { GatewayRuntimeStatus, type RuntimeStatus } from '../components/gateway/GatewayRuntimeStatus';
import { GatewayTracePanel } from '../components/gateway/GatewayTracePanel';
import { CopyButton, LabelTag, PageHeader, PanelCard, UiAlert, UiFlex, UiTabs, UiTypography } from '../components/ui';

export function GatewayPanel({ onOpenSettings }: { onOpenSettings?: () => void }) {
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus | null>(null);
  const [runtimeStatusError, setRuntimeStatusError] = useState('');
  const [channel, setChannel] = useState<'openai' | 'mcp'>('openai');

  useEffect(() => {
    let active = true;
    void request<RuntimeStatus>('/api/runtime_status', undefined, { retry: 0, timeoutMs: 5000 })
      .then((status) => {
        if (active) setRuntimeStatus(status);
      })
      .catch((error) => {
        if (active) setRuntimeStatusError(safeUiErrorSummary(error, '运行状态读取失败。'));
      });
    return () => {
      active = false;
    };
  }, []);

  const readiness = useMemo(() => {
    const provider = Boolean(
      runtimeStatus?.models?.target?.some((item) => item.configured && item.mode === 'real-api')
    );
    const gateway =
      runtimeStatus?.proxy?.enabled === true &&
      Boolean(runtimeStatus?.gateway_evidence?.fingerprint) &&
      runtimeStatus?.proxy?.tool_receipts_required === true &&
      runtimeStatus?.proxy?.server_observed_receipts_required === true;
    const mcp =
      runtimeStatus?.mcp?.configured === true &&
      runtimeStatus.mcp.enabled === true &&
      runtimeStatus.mcp.guard_enabled === true;
    return { provider, gateway, mcp };
  }, [runtimeStatus]);
  const ready = (readiness.provider && readiness.gateway) || readiness.mcp;

  return (
    <div className="zh-product-page">
      <PageHeader
        title="请求防护"
        badge={<LabelTag color={ready ? 'green' : 'warning'}>{ready ? '运行中' : '等待接入'}</LabelTag>}
        description="Agent 请求经过策略、Provider 和工具边界后，真实流量会自动出现在活动记录中。"
        actions={<CopyButton text={`${window.location.origin}/v1`}>复制 OpenAI 地址</CopyButton>}
      />

      <GatewayRuntimeStatus status={runtimeStatus} error={runtimeStatusError} />

      <UiTabs
        className="zh-product-tabs"
        activeKey={channel}
        onChange={(key) => setChannel(key as 'openai' | 'mcp')}
        items={[
          {
            key: 'openai',
            label: '模型 API',
            children: <GatewayTracePanel refreshSignal={runtimeStatus?.gateway_evidence?.started_at ?? ''} />
          },
          {
            key: 'mcp',
            label: 'MCP 工具',
            children: <McpRuntimeSummary status={runtimeStatus} onOpenSettings={onOpenSettings} />
          }
        ]}
      />
    </div>
  );
}

function McpRuntimeSummary({ status, onOpenSettings }: { status: RuntimeStatus | null; onOpenSettings?: () => void }) {
  const configured = status?.mcp?.configured === true;
  const enabled = status?.mcp?.enabled === true;
  const guarded = status?.mcp?.guard_enabled === true;
  return (
    <PanelCard title="MCP 运行状态" subtitle="MCP 请求由业务 Agent 发起，控制台只展示真实会话和执行结果。">
      {!status ? <UiAlert type="info" showIcon title="正在读取 MCP 运行状态。" /> : null}
      {status && !configured ? (
        <UiAlert
          type="warning"
          showIcon
          title="MCP 上游待配置"
          description="请在设置中登记 MCP Server；配置完成后真实请求会自动进入活动记录。"
        />
      ) : null}
      {status && configured && !enabled ? <UiAlert type="warning" showIcon title="MCP 服务未启用" /> : null}
      {status && configured && enabled && !guarded ? (
        <UiAlert type="error" showIcon title="MCP 强制边界未开启" description="策略未闭合时不会向上游转发工具调用。" />
      ) : null}
      {status && configured && enabled && guarded ? (
        <UiFlex gap={16} wrap="wrap">
          <StatusLine label="网关" value="在线" />
          <StatusLine label="会话隔离" value={status.mcp?.session_isolation?.enabled ? '已启用' : '待确认'} />
          <StatusLine label="工具执行" value="由 Agent 请求触发" />
          <CopyButton text={`${window.location.origin}/api/mcp`}>复制 MCP 地址</CopyButton>
        </UiFlex>
      ) : null}
      {onOpenSettings && status && !configured ? (
        <UiTypography.Link onClick={onOpenSettings}>打开接入设置</UiTypography.Link>
      ) : null}
    </PanelCard>
  );
}

function StatusLine({ label, value }: { label: string; value: string }) {
  return (
    <UiTypography.Text>
      <strong>{label}</strong> · {value}
    </UiTypography.Text>
  );
}
