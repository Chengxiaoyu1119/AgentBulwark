import { Col, Flex, Row, Space, Typography } from 'antd';
import type { PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';

type ContextScope = Record<string, string[]>;

type Props = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  onPatch: (patch: Partial<PolicySettings>) => void;
};

const EMPTY_SCOPE: ContextScope = { resources: [], resource_templates: [], prompts: [] };

export function AgentContextAllowlistEditor({ policySettings, canEdit, onPatch }: Props) {
  const allowlists = policySettings?.agent_context_allowlists ?? {};
  const registeredAgentIds = Array.from(
    new Set(
      [
        ...Object.keys(policySettings?.agent_tool_allowlists ?? {}),
        ...Object.keys(policySettings?.agent_api_allowlists ?? {}),
        ...Object.keys(policySettings?.agent_model_allowlists ?? {}),
        ...Object.keys(policySettings?.agent_tool_mappings ?? {})
      ].filter((agentId) => agentId.trim() && agentId !== '*')
    )
  ).sort();
  const missingRegisteredAgentIds = registeredAgentIds.filter((agentId) => !(agentId in allowlists));

  function patchScope(agentId: string, kind: string, values: string[]) {
    const nextScope = { ...EMPTY_SCOPE, ...(allowlists[agentId] ?? {}), [kind]: values };
    onPatch({ agent_context_allowlists: { ...allowlists, [agentId]: nextScope } });
  }

  function renameAgent(currentId: string, nextValue: string) {
    const nextId = nextValue.trim();
    if (!nextId || nextId === currentId) return;
    const nextAllowlists = { ...allowlists, [nextId]: allowlists[currentId] ?? { ...EMPTY_SCOPE } };
    delete nextAllowlists[currentId];
    onPatch({ agent_context_allowlists: nextAllowlists });
  }

  function removeAgent(agentId: string) {
    const nextAllowlists = { ...allowlists };
    delete nextAllowlists[agentId];
    onPatch({ agent_context_allowlists: nextAllowlists });
  }

  function addAgent() {
    let index = Object.keys(allowlists).length + 1;
    let agentId = `agent-${index}`;
    while (agentId in allowlists) {
      index += 1;
      agentId = `agent-${index}`;
    }
    onPatch({ agent_context_allowlists: { ...allowlists, [agentId]: { ...EMPTY_SCOPE } } });
  }

  function addRegisteredAgents() {
    if (!missingRegisteredAgentIds.length) return;
    const nextAllowlists = { ...allowlists };
    missingRegisteredAgentIds.forEach((agentId) => {
      nextAllowlists[agentId] = { ...EMPTY_SCOPE };
    });
    onPatch({ agent_context_allowlists: nextAllowlists });
  }

  return (
    <>
      <Flex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <Typography.Text strong>Agent MCP 上下文白名单</Typography.Text>
          <Typography.Text type="secondary" className="zh-meta-block">
            resources/prompts 是模型可见上下文；生产 Agent 只能读取登记的 URI、模板或 prompt 名称，支持 * 通配。
          </Typography.Text>
        </div>
        <UiButton disabled={!canEdit} onClick={addAgent}>
          新增 Agent
        </UiButton>
      </Flex>
      <Space orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(allowlists).map(([agentId, rawScope]) => {
          const scope = { ...EMPTY_SCOPE, ...rawScope };
          return (
            <PanelCard key={agentId} size="small" bodyPadding={12}>
              <Row gutter={[12, 12]} align="middle">
                <Col xs={24} md={6}>
                  <Typography.Text type="secondary" className="zh-meta-block">
                    Agent ID
                  </Typography.Text>
                  <UiInput
                    defaultValue={agentId}
                    disabled={!canEdit}
                    onBlur={(event) => renameAgent(agentId, event.target.value)}
                  />
                </Col>
                <ContextField
                  label="Resource URI"
                  value={scope.resources}
                  placeholder="例如 file://public/*"
                  disabled={!canEdit}
                  onChange={(value) => patchScope(agentId, 'resources', value)}
                />
                <ContextField
                  label="Resource Template"
                  value={scope.resource_templates}
                  placeholder="例如 file://public/{name}"
                  disabled={!canEdit}
                  onChange={(value) => patchScope(agentId, 'resource_templates', value)}
                />
                <ContextField
                  label="Prompt 名称"
                  value={scope.prompts}
                  placeholder="例如 safe-summary-*"
                  disabled={!canEdit}
                  onChange={(value) => patchScope(agentId, 'prompts', value)}
                />
                <Col xs={24} md={2}>
                  <UiButton danger disabled={!canEdit} onClick={() => removeAgent(agentId)}>
                    删除
                  </UiButton>
                </Col>
              </Row>
            </PanelCard>
          );
        })}
        {!Object.keys(allowlists).length ? (
          <UiAlert
            title="当前没有 MCP 上下文白名单；生产 Agent 的 resources/read 与 prompts/get 会默认拒绝。"
            type="warning"
            showIcon
          />
        ) : null}
        {missingRegisteredAgentIds.length ? (
          <Flex align="center" justify="space-between" wrap="wrap" gap={12}>
            <UiAlert
              title={`已有 ${missingRegisteredAgentIds.length} 个 Agent 登记了其他权限，但还没有 MCP 上下文范围。`}
              description="先建立空范围，再为每个 Agent 填入明确的 Resource URI、模板或 Prompt 名称；空范围仍会拒绝所有上下文读取。"
              type="warning"
              showIcon
            />
            <UiButton disabled={!canEdit} onClick={addRegisteredAgents}>
              为已登记 Agent 建立空范围
            </UiButton>
          </Flex>
        ) : null}
      </Space>
    </>
  );
}

function ContextField({
  label,
  value,
  placeholder,
  disabled,
  onChange
}: {
  label: string;
  value: string[];
  placeholder: string;
  disabled: boolean;
  onChange: (value: string[]) => void;
}) {
  return (
    <Col xs={24} md={5}>
      <Typography.Text type="secondary" className="zh-meta-block">
        {label}
      </Typography.Text>
      <UiSelect
        mode="tags"
        value={value}
        disabled={disabled}
        onChange={(next) => onChange(next.map(String))}
        className="zh-full-width"
        placeholder={placeholder}
      />
    </Col>
  );
}
