import { UiCol, UiFlex, UiRow, UiTypography } from '../ui';
import { LabelTag, PanelCard, UiAlert, UiFieldLabel } from '../ui';

export type RuntimeStatus = {
  backend?: {
    security_profile?: string;
  };
  security_context?: {
    role?: string;
    agent_id?: string;
    identity_bound?: boolean;
    can_generate?: boolean;
    can_execute_managed_tools?: boolean;
    can_use_mcp?: boolean;
    can_execute_mcp_tools?: boolean;
    can_view_console?: boolean;
  };
  models?: {
    real_api_enabled?: boolean;
    target?: Array<{ provider?: string; model?: string; configured?: boolean; mode?: string }>;
  };
  proxy?: {
    enabled?: boolean;
    mode?: string;
    auth_required?: boolean;
    tool_receipts_required?: boolean;
    server_observed_receipts_required?: boolean;
    reasoning_exposed?: boolean;
    executor_identity_required?: boolean;
    streaming?: {
      supported?: boolean;
      mode?: string;
      safety_window_chars?: number;
      tool_calls_buffered_until_final_supervision?: boolean;
      reasoning_buffered?: boolean;
    };
    resource_governance?: {
      enabled?: boolean;
      scope?: string;
      concurrency_per_agent?: number;
      token_budget_per_minute?: number;
      cost_budget_per_minute_usd?: number;
    };
  };
  gateway_evidence?: {
    fingerprint?: string;
    started_at?: string;
  };
  audit_integrity?: {
    hmac_configured?: boolean;
    receipt_signatures_required?: boolean;
    key_id?: string;
  };
  semantic_detector?: {
    enabled?: boolean;
    loaded?: boolean;
    model_file_present?: boolean;
    tokenizer_file_present?: boolean;
  };
  mcp?: {
    configured?: boolean;
    enabled?: boolean;
    guard_enabled?: boolean;
    resource_limits?: { os_enforced?: boolean; isolation_mode?: string };
    session_isolation?: {
      enabled?: boolean;
      scope?: string;
      active_sessions?: number;
      max_sessions?: number;
      child_process_per_session?: boolean;
    };
  };
};

type Props = {
  status: RuntimeStatus | null;
  error: string;
};

export function GatewayRuntimeStatus({ status, error }: Props) {
  const gatewayFingerprint = status?.gateway_evidence?.fingerprint?.trim() ?? '';
  const resourcePolicy = status?.proxy?.resource_governance;
  const securityContext = status?.security_context;
  const roleLabel = securityContext?.role || 'unknown';
  const agentLabel = securityContext?.agent_id || '未绑定 Agent';
  const productionProfile = status?.backend?.security_profile === 'production';
  const toolReceiptsRequired = status?.proxy?.tool_receipts_required === true;
  const serverObservedReceiptsRequired = status?.proxy?.server_observed_receipts_required === true;
  const strictReceiptBoundary = toolReceiptsRequired && serverObservedReceiptsRequired;
  const hmacConfigured = status?.audit_integrity?.hmac_configured === true;
  const receiptTrustLabel = strictReceiptBoundary
    ? '仅接受服务端观察'
    : serverObservedReceiptsRequired
      ? '策略配置不一致'
      : toolReceiptsRequired
        ? '调用方声明兼容'
        : '未强制回执';

  return (
    <PanelCard title="实时边界状态" subtitle="状态来自 /api/runtime_status，反映当前运行配置" className="zh-mb-24">
      {!status ? (
        <UiAlert
          type={error ? 'error' : 'info'}
          showIcon
          title={error ? '运行状态读取失败' : '正在读取网关运行状态。'}
          description={error || 'Provider、语义模型和 MCP 隔离状态会从运行时接口更新。'}
        />
      ) : (
        <UiFlex vertical gap={12}>
          {productionProfile && !strictReceiptBoundary ? (
            <UiAlert
              type="error"
              showIcon
              title="production 回执信任边界未闭合"
              description="模型可见的工具结果必须同时要求执行回执与服务端观察证据；调用方声明不等于实际执行事实。"
            />
          ) : null}
          <UiRow gutter={[12, 12]}>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="安全配置档"
                value={productionProfile ? 'production / 强制登记' : 'local / 兼容夹具'}
                tone={productionProfile ? 'green' : 'amber'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="当前身份"
                value={`${roleLabel} / ${agentLabel}`}
                tone={securityContext?.can_generate ? 'green' : 'amber'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="模型生成权限"
                value={securityContext?.can_generate ? '允许发起生成' : '仅可观测'}
                tone={securityContext?.can_generate ? 'green' : 'amber'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="托管工具执行权限"
                value={securityContext?.can_execute_managed_tools ? '允许服务端执行' : '不可执行'}
                tone={securityContext?.can_execute_managed_tools ? 'green' : 'amber'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="目标 Provider"
                value={
                  status.models?.target?.some((item) => item.configured && item.mode === 'real-api')
                    ? '真实 API 已配置'
                    : '未配置'
                }
                tone={
                  status.models?.target?.some((item) => item.configured && item.mode === 'real-api') ? 'green' : 'amber'
                }
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="透明代理"
                value={`${status.proxy?.mode ?? 'unknown'} / ${status.proxy?.enabled ? '启用' : '关闭'}`}
                tone={status.proxy?.enabled ? 'green' : 'red'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="Token 鉴权"
                value={status.proxy?.auth_required ? '已开启' : '本地免鉴权'}
                tone={status.proxy?.auth_required ? 'green' : 'red'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="工具结果信任"
                value={receiptTrustLabel}
                tone={strictReceiptBoundary ? 'green' : toolReceiptsRequired ? 'amber' : 'red'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="语义通道"
                value={
                  status.semantic_detector?.loaded
                    ? 'ONNX 已加载'
                    : status.semantic_detector?.enabled
                      ? '规则通道降级'
                      : '已关闭'
                }
                tone={status.semantic_detector?.loaded ? 'green' : 'amber'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="推理通道"
                value={status.proxy?.reasoning_exposed ? '已暴露（降级）' : '默认隐藏'}
                tone={status.proxy?.reasoning_exposed ? 'amber' : 'green'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="网关运行证据"
                value={gatewayFingerprint ? `已绑定 · ${gatewayFingerprint.slice(0, 12)}` : '未绑定'}
                tone={gatewayFingerprint ? 'green' : 'red'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="证据签名"
                value={hmacConfigured ? `HMAC 已启用 · ${status.audit_integrity?.key_id || '已配置'}` : '未配置 HMAC'}
                tone={hmacConfigured ? 'green' : 'amber'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="MCP 会话隔离"
                value={
                  status.mcp?.configured
                    ? status.mcp.session_isolation?.enabled
                      ? `${status.mcp.session_isolation.scope || 'Agent+Session'} / ${
                          status.mcp.session_isolation.active_sessions ?? 0
                        }/${status.mcp.session_isolation.max_sessions ?? 0} 会话`
                      : '共享上游（降级）'
                    : '未配置上游'
                }
                tone={!status.mcp?.configured ? 'blue' : status.mcp.session_isolation?.enabled ? 'green' : 'red'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="MCP 上游隔离"
                value={
                  status.mcp?.configured
                    ? status.mcp.resource_limits?.os_enforced
                      ? status.mcp.resource_limits.isolation_mode || 'OS 隔离'
                      : '未具备 OS 限制'
                    : '未配置上游'
                }
                tone={!status.mcp?.configured ? 'blue' : status.mcp.resource_limits?.os_enforced ? 'green' : 'red'}
              />
            </UiCol>
            <UiCol xs={24} sm={12} lg={6}>
              <StatusCard
                label="Agent 资源租约"
                value={
                  resourcePolicy?.enabled
                    ? `${resourcePolicy.scope || '共享'} · ${resourcePolicy.concurrency_per_agent ?? 0} 并发 / ${resourcePolicy.token_budget_per_minute ?? 0} Token/分`
                    : '未启用'
                }
                tone={resourcePolicy?.enabled ? 'green' : 'red'}
              />
            </UiCol>
          </UiRow>
        </UiFlex>
      )}
    </PanelCard>
  );
}

function StatusCard({
  label,
  value,
  tone
}: {
  label: string;
  value: string;
  tone: 'green' | 'amber' | 'red' | 'blue';
}) {
  return (
    <div className="zh-settings-status-card">
      <UiFieldLabel>{label}</UiFieldLabel>
      <UiFlex justify="space-between" align="center" gap={8}>
        <UiTypography.Text strong>{value}</UiTypography.Text>
        <LabelTag variant="filled" color={tone === 'amber' ? 'warning' : tone}>
          {tone === 'green' ? '已满足' : tone === 'red' ? '需处理' : tone === 'blue' ? '按需' : '降级'}
        </LabelTag>
      </UiFlex>
    </div>
  );
}
