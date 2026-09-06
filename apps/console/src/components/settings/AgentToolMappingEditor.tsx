import { useState } from 'react';
import { UiCol, UiFlex, UiRow, UiSpace, UiTypography } from '../ui';
import type { AgentToolMappingConfig, PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiConfirmButton, UiFieldLabel, UiInput, UiSelect } from '../ui';

const capabilityOptions = [
  'file.read',
  'file.write',
  'mail.send',
  'api.call',
  'memory.write',
  'memory.read',
  'env.read',
  'model.respond'
].map((value) => ({ label: value, value }));

const defaultMapping: AgentToolMappingConfig = {
  capability: 'api.call',
  argument_mapping: { url: 'endpoint' },
  required_arguments: ['url'],
  risk_hint: 'custom_network_tool',
  description: '把外部浏览器或 HTTP 工具纳入统一网络访问策略。'
};

type Props = { policySettings: PolicySettings | null; canEdit: boolean; onPatch: (p: Partial<PolicySettings>) => void };
type NameDraft = { agentId: string; tool: string };
function mappingTags(mapping: Record<string, string>) {
  return Object.entries(mapping).map(([source, target]) => `${source}:${target}`);
}
function parseMappingTags(values: string[]) {
  const mapping: Record<string, string> = {};
  values.forEach((value) => {
    const normalized = value.replace('→', ':').replace('->', ':');
    const separator = normalized.indexOf(':');
    if (separator < 1) return;
    const source = normalized.slice(0, separator).trim();
    const target = normalized.slice(separator + 1).trim();
    if (source && target) mapping[source] = target;
  });
  return mapping;
}

export function AgentToolMappingEditor({ policySettings, canEdit, onPatch }: Props) {
  const registry = policySettings?.agent_tool_mappings ?? {};
  const [nameDrafts, setNameDrafts] = useState<Record<string, NameDraft>>({});
  const [nameErrors, setNameErrors] = useState<Record<string, { field: 'agent' | 'tool'; message: string }>>({});
  const entries = Object.entries(registry).flatMap(([agentId, mappings]) =>
    Object.entries(mappings).map(([tool, config]) => ({ agentId, tool, config }))
  );

  function patchRegistry(
    nextRegistry: PolicySettings['agent_tool_mappings'],
    nextAllowlists = policySettings?.agent_tool_allowlists
  ) {
    onPatch({ agent_tool_mappings: nextRegistry ?? {}, agent_tool_allowlists: nextAllowlists ?? {} });
  }

  function updateConfig(agentId: string, tool: string, patch: Partial<AgentToolMappingConfig>) {
    patchRegistry({
      ...registry,
      [agentId]: {
        ...registry[agentId],
        [tool]: { ...registry[agentId][tool], ...patch }
      }
    });
  }

  function renameEntry(agentId: string, tool: string, nextAgentValue: string, nextToolValue: string) {
    const nextAgentId = nextAgentValue.trim();
    const nextTool = nextToolValue.trim().toLowerCase();
    if (!nextAgentId || !nextTool || (nextAgentId === agentId && nextTool === tool)) return;
    if (registry[nextAgentId]?.[nextTool]) return;
    const config = registry[agentId]?.[tool];
    if (!config) return;
    const nextRegistry = Object.fromEntries(
      Object.entries(registry).map(([id, mappings]) => [id, { ...mappings }])
    ) as NonNullable<PolicySettings['agent_tool_mappings']>;
    delete nextRegistry[agentId][tool];
    if (!Object.keys(nextRegistry[agentId]).length) delete nextRegistry[agentId];
    nextRegistry[nextAgentId] = { ...nextRegistry[nextAgentId], [nextTool]: config };

    const allowlists = { ...(policySettings?.agent_tool_allowlists ?? {}) };
    if (allowlists[agentId]) allowlists[agentId] = allowlists[agentId].filter((item) => item !== tool);
    allowlists[nextAgentId] = Array.from(new Set([...(allowlists[nextAgentId] ?? []), nextTool]));
    patchRegistry(nextRegistry, allowlists);
  }

  function updateNameDraft(entryKey: string, agentId: string, tool: string, patch: Partial<NameDraft>) {
    setNameDrafts((current) => ({
      ...current,
      [entryKey]: { ...(current[entryKey] ?? { agentId, tool }), ...patch }
    }));
    setNameErrors((current) => {
      if (!current[entryKey]) return current;
      const next = { ...current };
      delete next[entryKey];
      return next;
    });
  }

  function commitNameDraft(entryKey: string, agentId: string, tool: string, field: 'agent' | 'tool') {
    const draft = nameDrafts[entryKey] ?? { agentId, tool };
    const nextAgentId = draft.agentId.trim();
    const nextTool = draft.tool.trim().toLowerCase();
    const emptyError = !nextAgentId
      ? { field: 'agent' as const, message: 'Agent ID 不能为空，原工具映射保持不变。' }
      : !nextTool
        ? { field: 'tool' as const, message: '原始工具名不能为空，原工具映射保持不变。' }
        : null;
    if (emptyError) {
      setNameDrafts((current) => ({ ...current, [entryKey]: { agentId, tool } }));
      setNameErrors((current) => ({ ...current, [entryKey]: emptyError }));
      return;
    }
    if ((nextAgentId !== agentId || nextTool !== tool) && registry[nextAgentId]?.[nextTool]) {
      setNameDrafts((current) => ({ ...current, [entryKey]: { agentId, tool } }));
      setNameErrors((current) => ({
        ...current,
        [entryKey]: {
          field,
          message: `工具映射 ${nextAgentId} / ${nextTool} 已存在，未覆盖目标映射。`
        }
      }));
      return;
    }
    setNameDrafts((current) => ({ ...current, [entryKey]: { agentId: nextAgentId, tool: nextTool } }));
    setNameErrors((current) => {
      if (!current[entryKey]) return current;
      const next = { ...current };
      delete next[entryKey];
      return next;
    });
    if (nextAgentId !== agentId || nextTool !== tool) {
      renameEntry(agentId, tool, nextAgentId, nextTool);
    }
  }

  function removeEntry(agentId: string, tool: string) {
    const nextRegistry = Object.fromEntries(
      Object.entries(registry).map(([id, mappings]) => [id, { ...mappings }])
    ) as NonNullable<PolicySettings['agent_tool_mappings']>;
    delete nextRegistry[agentId]?.[tool];
    if (nextRegistry[agentId] && !Object.keys(nextRegistry[agentId]).length) delete nextRegistry[agentId];
    const allowlists = { ...(policySettings?.agent_tool_allowlists ?? {}) };
    if (allowlists[agentId]) allowlists[agentId] = allowlists[agentId].filter((item) => item !== tool);
    patchRegistry(nextRegistry, allowlists);
  }

  function addEntry() {
    const agentId =
      Object.keys(registry)[0] ?? Object.keys(policySettings?.agent_tool_allowlists ?? {})[0] ?? 'agent-1';
    let index = entries.length + 1;
    let tool = entries.length ? `custom.tool_${index}` : 'browser.open';
    while (registry[agentId]?.[tool]) {
      index += 1;
      tool = `custom.tool_${index}`;
    }
    const allowlists = { ...(policySettings?.agent_tool_allowlists ?? {}) };
    allowlists[agentId] = Array.from(new Set([...(allowlists[agentId] ?? []), tool]));
    patchRegistry({ ...registry, [agentId]: { ...registry[agentId], [tool]: defaultMapping } }, allowlists);
  }

  return (
    <>
      <UiFlex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <UiTypography.Text strong>自定义工具能力映射</UiTypography.Text>
          <UiTypography.Text type="secondary" className="zh-meta-block">
            把 browser.open、database.query 等真实工具映射为标准安全能力；策略仍由服务端执行，Agent
            不能自行降低风险类型。
          </UiTypography.Text>
        </div>
        <UiButton disabled={!canEdit} onClick={addEntry}>
          新增工具映射
        </UiButton>
      </UiFlex>
      <UiSpace orientation="vertical" size="middle" className="zh-full-width">
        {entries.map(({ agentId, tool, config }) => {
          const entryKey = `${agentId}:${tool}`;
          const fieldIdPrefix = `agent-tool-mapping-${encodeURIComponent(agentId)}-${encodeURIComponent(tool)}`;
          const nameDraft = nameDrafts[entryKey] ?? { agentId, tool };
          const nameError = nameErrors[entryKey];
          return (
            <PanelCard key={entryKey} size="small" bodyPadding={12}>
              <UiRow gutter={[12, 12]} align="middle">
                <UiCol xs={24} lg={5}>
                  <UiFieldLabel>Agent ID</UiFieldLabel>
                  <UiInput
                    aria-label={`Agent ID：${agentId} / ${tool}`}
                    value={nameDraft.agentId}
                    status={nameError?.field === 'agent' ? 'error' : undefined}
                    disabled={!canEdit}
                    onChange={(event) => updateNameDraft(entryKey, agentId, tool, { agentId: event.target.value })}
                    onBlur={() => commitNameDraft(entryKey, agentId, tool, 'agent')}
                  />
                  {nameError?.field === 'agent' ? (
                    <UiTypography.Text type="danger" role="alert" className="zh-inline-field-error">
                      {nameError.message}
                    </UiTypography.Text>
                  ) : null}
                </UiCol>
                <UiCol xs={24} lg={5}>
                  <UiFieldLabel>原始工具名</UiFieldLabel>
                  <UiInput
                    aria-label={`原始工具名：${agentId} / ${tool}`}
                    value={nameDraft.tool}
                    status={nameError?.field === 'tool' ? 'error' : undefined}
                    disabled={!canEdit}
                    onChange={(event) => updateNameDraft(entryKey, agentId, tool, { tool: event.target.value })}
                    onBlur={() => commitNameDraft(entryKey, agentId, tool, 'tool')}
                  />
                  {nameError?.field === 'tool' ? (
                    <UiTypography.Text type="danger" role="alert" className="zh-inline-field-error">
                      {nameError.message}
                    </UiTypography.Text>
                  ) : null}
                </UiCol>
                <UiCol xs={24} lg={5}>
                  <UiFieldLabel htmlFor={`${fieldIdPrefix}-capability`}>标准安全能力</UiFieldLabel>
                  <UiSelect
                    id={`${fieldIdPrefix}-capability`}
                    value={config.capability}
                    options={capabilityOptions}
                    disabled={!canEdit}
                    onChange={(value) => updateConfig(agentId, tool, { capability: String(value) })}
                    className="zh-full-width"
                  />
                </UiCol>
                <UiCol xs={24} lg={7}>
                  <UiFieldLabel htmlFor={`${fieldIdPrefix}-argument-mapping`}>参数映射（原始:标准）</UiFieldLabel>
                  <UiSelect
                    id={`${fieldIdPrefix}-argument-mapping`}
                    mode="tags"
                    value={mappingTags(config.argument_mapping)}
                    disabled={!canEdit}
                    onChange={(value) =>
                      updateConfig(agentId, tool, { argument_mapping: parseMappingTags(value.map(String)) })
                    }
                    className="zh-full-width"
                    placeholder="例如 url:endpoint"
                  />
                </UiCol>
                <UiCol xs={24} lg={2}>
                  <UiConfirmButton
                    danger
                    disabled={!canEdit}
                    confirmTitle={`删除 Agent ${agentId} 的工具映射 ${tool}？`}
                    confirmDescription="保存权限设置后，外部工具名称将不再映射到标准安全能力。"
                    onConfirm={() => removeEntry(agentId, tool)}
                  >
                    删除
                  </UiConfirmButton>
                </UiCol>
                <UiCol xs={24} lg={8}>
                  <UiFieldLabel htmlFor={`${fieldIdPrefix}-required-arguments`}>必填原始参数</UiFieldLabel>
                  <UiSelect
                    id={`${fieldIdPrefix}-required-arguments`}
                    mode="tags"
                    value={config.required_arguments}
                    disabled={!canEdit}
                    onChange={(value) => updateConfig(agentId, tool, { required_arguments: value.map(String) })}
                    className="zh-full-width"
                    placeholder="例如 url"
                  />
                </UiCol>
                <UiCol xs={24} lg={8}>
                  <UiFieldLabel htmlFor={`${fieldIdPrefix}-risk-hint`}>固定风险提示</UiFieldLabel>
                  <UiInput
                    id={`${fieldIdPrefix}-risk-hint`}
                    value={config.risk_hint}
                    disabled={!canEdit}
                    onChange={(event) => updateConfig(agentId, tool, { risk_hint: event.target.value })}
                  />
                </UiCol>
                <UiCol xs={24} lg={8}>
                  <UiFieldLabel htmlFor={`${fieldIdPrefix}-description`}>用途说明</UiFieldLabel>
                  <UiInput
                    id={`${fieldIdPrefix}-description`}
                    value={config.description}
                    disabled={!canEdit}
                    onChange={(event) => updateConfig(agentId, tool, { description: event.target.value })}
                  />
                </UiCol>
              </UiRow>
            </PanelCard>
          );
        })}
        {!entries.length ? (
          <UiAlert
            title="当前没有自定义工具映射。未登记的工具会失败关闭；可新增 browser.open 示例并保存。"
            type="info"
            showIcon
          />
        ) : null}
      </UiSpace>
    </>
  );
}
