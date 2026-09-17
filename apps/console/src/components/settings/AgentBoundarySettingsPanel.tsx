import { UiCol, UiCollapse, UiFlex, UiRow, UiSpace, UiSwitch, UiTypography } from '../ui';
import type { PolicySettings, PolicyVersion } from '@/types';
import { PanelCard, UiAlert, UiButton, UiFieldLabel, UiSelect } from '../ui';
import { AgentApiAllowlistEditor } from './AgentApiAllowlistEditor';
import { AgentContextAllowlistEditor } from './AgentContextAllowlistEditor';
import { AgentModelAllowlistEditor } from './AgentModelAllowlistEditor';
import { AgentToolAllowlistEditor } from './AgentToolAllowlistEditor';
import { AgentToolMappingEditor } from './AgentToolMappingEditor';
import { TaskProfileEditor } from './TaskProfileEditor';

type Props = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  saving: boolean;
  loading?: boolean;
  loadError?: string;
  onPatch: (patch: Partial<PolicySettings>) => void;
  onSave: () => void | Promise<void>;
  versions?: PolicyVersion[];
  onRollback?: (version: number) => void | Promise<void>;
  registeredAgentIds?: string[];
  selectedAgentId?: string | null;
};

export function AgentBoundarySettingsPanel({
  policySettings,
  canEdit,
  saving,
  loading = false,
  loadError,
  onPatch,
  onSave,
  versions = [],
  onRollback,
  registeredAgentIds = [],
  selectedAgentId = null
}: Props) {
  if (!policySettings) {
    return (
      <PanelCard title="业务安全边界" subtitle="先关闭未登记能力，再按 Agent 精确放行。">
        {loadError ? (
          <UiAlert type="error" showIcon title="业务安全边界读取失败" description={loadError} />
        ) : loading ? (
          <UiAlert type="info" showIcon title="正在读取业务安全边界。" />
        ) : (
          <UiAlert type="warning" showIcon title="业务安全边界暂时没有返回内容。" />
        )}
      </PanelCard>
    );
  }

  const settings = policySettings;
  const mappingCount = Object.values(policySettings?.agent_tool_mappings ?? {}).reduce(
    (total, mappings) => total + Object.keys(mappings).length,
    0
  );
  const taskProfileCount = Object.keys(policySettings.task_profiles ?? {}).length;
  const selectedBinding = selectedAgentId ? getAgentBinding(policySettings, selectedAgentId) : null;

  function establishSelectedBoundary() {
    if (!selectedAgentId || !canEdit) return;
    const toolAllowlists = { ...(settings.agent_tool_allowlists ?? {}) };
    const apiAllowlists = { ...(settings.agent_api_allowlists ?? {}) };
    const modelAllowlists = { ...(settings.agent_model_allowlists ?? {}) };
    const contextAllowlists = { ...(settings.agent_context_allowlists ?? {}) };
    if (!selectedBinding?.tools) toolAllowlists[selectedAgentId] = [];
    if (!selectedBinding?.api) apiAllowlists[selectedAgentId] = [];
    if (!selectedBinding?.models) modelAllowlists[selectedAgentId] = [];
    if (!selectedBinding?.context) {
      contextAllowlists[selectedAgentId] = { resources: [], resource_templates: [], prompts: [] };
    }
    onPatch({
      agent_tool_allowlists: toolAllowlists,
      agent_api_allowlists: apiAllowlists,
      agent_model_allowlists: modelAllowlists,
      agent_context_allowlists: contextAllowlists
    });
  }

  const knownAgentIds = new Set(
    [
      ...registeredAgentIds,
      ...Object.keys(settings.agent_tool_allowlists ?? {}),
      ...Object.keys(settings.agent_api_allowlists ?? {}),
      ...Object.keys(settings.agent_model_allowlists ?? {}),
      ...Object.keys(settings.agent_context_allowlists ?? {})
    ].filter((agentId) => agentId !== '*')
  );
  return (
    <PanelCard title="业务安全边界" subtitle="先关闭未登记能力，再按 Agent 精确放行。">
      <UiTypography.Paragraph type="secondary">
        配置内部邮箱域、敏感路径和高敏 API 边界。生产 Agent 应先登记能力，再发放绑定 Token。
      </UiTypography.Paragraph>
      {selectedAgentId && knownAgentIds.has(selectedAgentId) ? (
        <UiAlert
          type={selectedBinding?.complete ? 'success' : 'warning'}
          showIcon
          title={
            selectedBinding?.complete
              ? `Agent ${selectedAgentId} 已建立四类权限边界。`
              : `正在配置 Agent ${selectedAgentId}。`
          }
          description={
            selectedBinding?.complete
              ? '下方四类范围均已存在；请填写实际最小权限后保存并发布。空范围仍会拒绝对应请求。'
              : '先建立四类空边界，再填写工具、模型、API 主机和 MCP 上下文范围。空范围会拒绝对应请求，不会自动放行。'
          }
          action={
            selectedBinding?.complete ? undefined : (
              <UiButton disabled={!canEdit} onClick={establishSelectedBoundary}>
                建立空权限边界
              </UiButton>
            )
          }
          className="zh-mb-16"
        />
      ) : null}
      <UiRow gutter={[16, 16]} className="zh-mb-16">
        <UiCol xs={24} md={12}>
          <RegistrationSwitch
            checked={Boolean(policySettings?.require_agent_capability_registration)}
            disabled={!canEdit}
            onChange={(checked) => onPatch({ require_agent_capability_registration: checked })}
            title="未登记 Agent 工具默认拒绝"
            description="开启后，Agent 必须命中工具白名单；未登记身份不会继承默认放行。"
          />
        </UiCol>
        <UiCol xs={24} md={12}>
          <RegistrationSwitch
            checked={Boolean(policySettings?.require_agent_context_registration)}
            disabled={!canEdit}
            onChange={(checked) => onPatch({ require_agent_context_registration: checked })}
            title="未登记 Agent MCP 上下文默认拒绝"
            description="开启后，resources/prompts 只能读取当前 Agent 的上下文白名单。"
          />
        </UiCol>
        <UiCol xs={24} md={12}>
          <RegistrationSwitch
            checked={Boolean(policySettings?.require_agent_model_registration)}
            disabled={!canEdit}
            onChange={(checked) => onPatch({ require_agent_model_registration: checked })}
            title="未登记 Agent 模型默认拒绝"
            description="开启后，透明代理只能选择该 Agent 的模型白名单。"
          />
        </UiCol>
      </UiRow>
      <UiRow gutter={[16, 16]}>
        <BoundarySelect
          id="policy-internal-email-domains"
          label="内部邮箱域"
          value={policySettings?.internal_email_domains ?? []}
          placeholder="例如 company.example"
          disabled={!canEdit}
          onChange={(value) => onPatch({ internal_email_domains: value.map(String) })}
        />
        <BoundarySelect
          id="policy-sensitive-path-markers"
          label="敏感路径标记"
          value={policySettings?.sensitive_path_markers ?? []}
          placeholder="例如 vault、credentials"
          disabled={!canEdit}
          onChange={(value) => onPatch({ sensitive_path_markers: value.map(String) })}
        />
        <BoundarySelect
          id="policy-sensitive-api-markers"
          label="高敏 API 标记"
          value={policySettings?.sensitive_api_markers ?? []}
          placeholder="例如 payroll、admin"
          disabled={!canEdit}
          onChange={(value) => onPatch({ sensitive_api_markers: value.map(String) })}
        />
      </UiRow>
      <UiCollapse
        className="zh-permission-collapse"
        items={[
          {
            key: 'allowlists',
            label: 'Agent 工具最小权限',
            children: (
              <div className="zh-settings-column">
                <AgentToolAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentApiAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentModelAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentContextAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentToolMappingEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
              </div>
            )
          },
          {
            key: 'task-profiles',
            label: `任务授权${taskProfileCount ? `（${taskProfileCount}）` : ''}`,
            children: (
              <TaskProfileEditor
                policySettings={policySettings}
                canEdit={canEdit}
                agentIds={[...knownAgentIds].sort()}
                onPatch={onPatch}
              />
            )
          }
        ]}
      />
      <UiFlex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16">
        <UiTypography.Text type="secondary">
          已登记 {Object.keys(policySettings?.agent_tool_allowlists ?? {}).length} 个 Agent，{mappingCount} 条工具映射，
          {taskProfileCount} 个任务授权；保存会先执行发布预检。
        </UiTypography.Text>
        <UiButton type="primary" loading={saving} disabled={!canEdit} onClick={() => void onSave()}>
          校验并发布业务边界
        </UiButton>
      </UiFlex>
      {versions.length ? (
        <UiSpace orientation="vertical" size={8} className="zh-full-width zh-mt-16">
          <UiTypography.Text strong>最近策略变更</UiTypography.Text>
          {versions.slice(0, 3).map((version) => (
            <UiFlex key={version.id} justify="space-between" align="center" wrap="wrap">
              <UiTypography.Text type="secondary">
                v{version.id} · {version.policy_id} · {version.created_at.slice(0, 19).replace('T', ' ')}
              </UiTypography.Text>
              {canEdit && onRollback ? (
                <UiButton size="small" disabled={saving} onClick={() => void onRollback(version.id)}>
                  回滚到此版本
                </UiButton>
              ) : null}
            </UiFlex>
          ))}
        </UiSpace>
      ) : null}
    </PanelCard>
  );
}

function getAgentBinding(policySettings: PolicySettings, agentId: string) {
  const tools = agentId in (policySettings.agent_tool_allowlists ?? {});
  const api = agentId in (policySettings.agent_api_allowlists ?? {});
  const models = agentId in (policySettings.agent_model_allowlists ?? {});
  const context = agentId in (policySettings.agent_context_allowlists ?? {});
  return { tools, api, models, context, complete: tools && api && models && context };
}

function RegistrationSwitch({
  checked,
  disabled,
  onChange,
  title,
  description
}: {
  checked: boolean;
  disabled: boolean;
  onChange: (checked: boolean) => void;
  title: string;
  description: string;
}) {
  return (
    <div className="zh-settings-switch-row">
      <UiSwitch checked={checked} disabled={disabled} onChange={onChange} />
      <div>
        <UiTypography.Text strong>{title}</UiTypography.Text>
        <UiTypography.Paragraph type="secondary" className="zh-mb-0">
          {description}
        </UiTypography.Paragraph>
      </div>
    </div>
  );
}

function BoundarySelect({
  id,
  label,
  value,
  placeholder,
  disabled,
  onChange
}: {
  id: string;
  label: string;
  value: string[];
  placeholder: string;
  disabled: boolean;
  onChange: (value: unknown[]) => void;
}) {
  return (
    <UiCol xs={24} lg={8}>
      <UiFieldLabel htmlFor={id}>{label}</UiFieldLabel>
      <UiSelect
        id={id}
        mode="tags"
        value={value}
        onChange={onChange}
        className="zh-full-width"
        placeholder={placeholder}
        disabled={disabled}
      />
    </UiCol>
  );
}
