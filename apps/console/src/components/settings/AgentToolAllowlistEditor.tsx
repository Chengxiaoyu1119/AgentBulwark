import { Col, Flex, Row, Space, Typography } from 'antd';
import type { PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';

const supportedToolOptions = [
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

type AgentToolAllowlistEditorProps = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  onPatch: (patch: Partial<PolicySettings>) => void;
};

export function AgentToolAllowlistEditor({ policySettings, canEdit, onPatch }: AgentToolAllowlistEditorProps) {
  const allowlists = policySettings?.agent_tool_allowlists ?? {};

  function patchAgentTools(agentId: string, tools: string[]) {
    onPatch({ agent_tool_allowlists: { ...allowlists, [agentId]: tools } });
  }

  function renameAgent(currentId: string, nextValue: string) {
    const nextId = nextValue.trim();
    if (!nextId || nextId === currentId) return;
    const nextAllowlists = { ...allowlists };
    const tools = nextAllowlists[currentId] ?? [];
    delete nextAllowlists[currentId];
    nextAllowlists[nextId] = tools;
    onPatch({ agent_tool_allowlists: nextAllowlists });
  }

  function removeAgent(agentId: string) {
    const nextAllowlists = { ...allowlists };
    delete nextAllowlists[agentId];
    onPatch({ agent_tool_allowlists: nextAllowlists });
  }

  function addAgent() {
    let index = Object.keys(allowlists).length + 1;
    let agentId = `agent-${index}`;
    while (agentId in allowlists) {
      index += 1;
      agentId = `agent-${index}`;
    }
    onPatch({ agent_tool_allowlists: { ...allowlists, [agentId]: ['file.read'] } });
  }

  return (
    <>
      <Flex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <Typography.Text strong>Agent 工具最小权限</Typography.Text>
          <Typography.Text type="secondary" className="zh-meta-block">
            每个 Agent 只获得完成职责所需的工具；使用 * 可设置未单独登记 Agent 的默认规则。
          </Typography.Text>
        </div>
        <UiButton disabled={!canEdit} onClick={addAgent}>
          新增 Agent
        </UiButton>
      </Flex>
      <Space orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(allowlists).map(([agentId, tools]) => (
          <PanelCard key={agentId} size="small" bodyPadding={12}>
            <Row gutter={[12, 12]} align="middle">
              <Col xs={24} md={7}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  Agent ID
                </Typography.Text>
                <UiInput
                  defaultValue={agentId}
                  disabled={!canEdit}
                  onBlur={(event) => renameAgent(agentId, event.target.value)}
                />
              </Col>
              <Col xs={24} md={14}>
                <Typography.Text type="secondary" className="zh-meta-block">
                  允许调用的工具
                </Typography.Text>
                <UiSelect
                  mode="multiple"
                  options={supportedToolOptions}
                  value={tools}
                  disabled={!canEdit}
                  onChange={(value) => patchAgentTools(agentId, value.map(String))}
                  className="zh-full-width"
                  placeholder="选择最小工具集合"
                />
              </Col>
              <Col xs={24} md={3}>
                <UiButton danger disabled={!canEdit} onClick={() => removeAgent(agentId)}>
                  删除
                </UiButton>
              </Col>
            </Row>
          </PanelCard>
        ))}
        {!Object.keys(allowlists).length ? (
          <UiAlert title="当前没有 Agent 工具白名单；新增一条规则后，未授权工具会被 tool-contract 拒绝。" type="warning" showIcon />
        ) : null}
      </Space>
    </>
  );
}
