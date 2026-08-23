import { Col, Flex, Row, Space, Typography } from 'antd';
import type { AgentToolMappingConfig, PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';

const capabilityOptions = [
  'file.read',
  'file.write',
  'mail.send',
  'api.call',
  'code.run',
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

type AgentToolMappingEditorProps = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  onPatch: (patch: Partial<PolicySettings>) => void;
};

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

export function AgentToolMappingEditor({ policySettings, canEdit, onPatch }: AgentToolMappingEditorProps) {
  const registry = policySettings?.agent_tool_mappings ?? {};
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
      <Flex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <Typography.Text strong>自定义工具能力映射</Typography.Text>
          <Typography.Text type="secondary" className="zh-meta-block">
            把 browser.open、database.query 等真实工具映射为标准安全能力；策略仍由服务端执行，Agent
            不能自行降低风险类型。
          </Typography.Text>
        </div>
        <UiButton disabled={!canEdit} onClick={addEntry}>
          新增工具映射
        </UiButton>
      </Flex>
      <Space orientation="vertical" size="middle" className="zh-full-width">
        {entries.map(({ agentId, tool, config }) => (
          <PanelCard key={`${agentId}:${tool}`} size="small" bodyPadding={12}>
            <Row gutter={[12, 12]} align="middle">
              <Col xs={24} lg={5}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  Agent ID
                </Typography.Text>
                <UiInput
                  defaultValue={agentId}
                  disabled={!canEdit}
                  onBlur={(event) => renameEntry(agentId, tool, event.target.value, tool)}
                />
              </Col>
              <Col xs={24} lg={5}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  原始工具名
                </Typography.Text>
                <UiInput
                  defaultValue={tool}
                  disabled={!canEdit}
                  onBlur={(event) => renameEntry(agentId, tool, agentId, event.target.value)}
                />
              </Col>
              <Col xs={24} lg={5}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  标准安全能力
                </Typography.Text>
                <UiSelect
                  value={config.capability}
                  options={capabilityOptions}
                  disabled={!canEdit}
                  onChange={(value) => updateConfig(agentId, tool, { capability: String(value) })}
                  className="zh-full-width"
                />
              </Col>
              <Col xs={24} lg={7}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  参数映射（原始:标准）
                </Typography.Text>
                <UiSelect
                  mode="tags"
                  value={mappingTags(config.argument_mapping)}
                  disabled={!canEdit}
                  onChange={(value) =>
                    updateConfig(agentId, tool, { argument_mapping: parseMappingTags(value.map(String)) })
                  }
                  className="zh-full-width"
                  placeholder="例如 url:endpoint"
                />
              </Col>
              <Col xs={24} lg={2}>
                <UiButton danger disabled={!canEdit} onClick={() => removeEntry(agentId, tool)}>
                  删除
                </UiButton>
              </Col>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  必填原始参数
                </Typography.Text>
                <UiSelect
                  mode="tags"
                  value={config.required_arguments}
                  disabled={!canEdit}
                  onChange={(value) => updateConfig(agentId, tool, { required_arguments: value.map(String) })}
                  className="zh-full-width"
                  placeholder="例如 url"
                />
              </Col>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  固定风险提示
                </Typography.Text>
                <UiInput
                  value={config.risk_hint}
                  disabled={!canEdit}
                  onChange={(event) => updateConfig(agentId, tool, { risk_hint: event.target.value })}
                />
              </Col>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  用途说明
                </Typography.Text>
                <UiInput
                  value={config.description}
                  disabled={!canEdit}
                  onChange={(event) => updateConfig(agentId, tool, { description: event.target.value })}
                />
              </Col>
            </Row>
          </PanelCard>
        ))}
        {!entries.length ? (
          <UiAlert
            title="当前没有自定义工具映射。未登记的工具会失败关闭；可新增 browser.open 示例并保存。"
            type="info"
            showIcon
          />
        ) : null}
      </Space>
    </>
  );
}
