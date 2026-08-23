import { Col, Flex, Row, Space, Typography } from 'antd';
import type { PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';

type AgentModelAllowlistEditorProps = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  onPatch: (patch: Partial<PolicySettings>) => void;
};

export function AgentModelAllowlistEditor({ policySettings, canEdit, onPatch }: AgentModelAllowlistEditorProps) {
  const allowlists = policySettings?.agent_model_allowlists ?? {};

  function patchAgentModels(agentId: string, models: string[]) {
    onPatch({ agent_model_allowlists: { ...allowlists, [agentId]: models } });
  }

  function renameAgent(currentId: string, nextValue: string) {
    const nextId = nextValue.trim();
    if (!nextId || nextId === currentId) return;
    const nextAllowlists = { ...allowlists };
    const models = nextAllowlists[currentId] ?? [];
    delete nextAllowlists[currentId];
    nextAllowlists[nextId] = models;
    onPatch({ agent_model_allowlists: nextAllowlists });
  }

  function removeAgent(agentId: string) {
    const nextAllowlists = { ...allowlists };
    delete nextAllowlists[agentId];
    onPatch({ agent_model_allowlists: nextAllowlists });
  }

  function addAgent() {
    let index = Object.keys(allowlists).length + 1;
    let agentId = `agent-${index}`;
    while (agentId in allowlists) {
      index += 1;
      agentId = `agent-${index}`;
    }
    onPatch({ agent_model_allowlists: { ...allowlists, [agentId]: [] } });
  }

  return (
    <>
      <Flex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <Typography.Text strong>Agent 模型白名单</Typography.Text>
          <Typography.Text type="secondary" className="zh-meta-block">
            绑定 Agent 只能选择登记的精确模型 ID；留空表示该 Agent 暂无可用模型，避免凭证被拿去切换任意 Provider 模型。
          </Typography.Text>
        </div>
        <UiButton disabled={!canEdit} onClick={addAgent}>
          新增 Agent
        </UiButton>
      </Flex>
      <Space orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(allowlists).map(([agentId, models]) => (
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
                  允许模型 ID
                </Typography.Text>
                <UiSelect
                  mode="tags"
                  value={models}
                  disabled={!canEdit}
                  onChange={(value) => patchAgentModels(agentId, value.map(String))}
                  className="zh-full-width"
                  placeholder="例如 deepseek-chat、gpt-4.1-mini"
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
          <UiAlert
            title="当前没有 Agent 模型白名单；生产 Agent 凭证尚未建立模型选择证据，建议先登记模型 ID。"
            type="warning"
            showIcon
          />
        ) : null}
      </Space>
    </>
  );
}
