import { Col, Flex, Row, Space, Typography } from 'antd';
import type { PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';

type AgentApiAllowlistEditorProps = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  onPatch: (patch: Partial<PolicySettings>) => void;
};

export function AgentApiAllowlistEditor({ policySettings, canEdit, onPatch }: AgentApiAllowlistEditorProps) {
  const allowlists = policySettings?.agent_api_allowlists ?? {};

  function patchAgentTargets(agentId: string, targets: string[]) {
    onPatch({ agent_api_allowlists: { ...allowlists, [agentId]: targets } });
  }

  function renameAgent(currentId: string, nextValue: string) {
    const nextId = nextValue.trim();
    if (!nextId || nextId === currentId) return;
    const nextAllowlists = { ...allowlists };
    const targets = nextAllowlists[currentId] ?? [];
    delete nextAllowlists[currentId];
    nextAllowlists[nextId] = targets;
    onPatch({ agent_api_allowlists: nextAllowlists });
  }

  function removeAgent(agentId: string) {
    const nextAllowlists = { ...allowlists };
    delete nextAllowlists[agentId];
    onPatch({ agent_api_allowlists: nextAllowlists });
  }

  function addAgent() {
    let index = Object.keys(allowlists).length + 1;
    let agentId = `agent-${index}`;
    while (agentId in allowlists) {
      index += 1;
      agentId = `agent-${index}`;
    }
    onPatch({ agent_api_allowlists: { ...allowlists, [agentId]: [] } });
  }

  return (
    <>
      <Flex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <Typography.Text strong>Agent 外部 API 主机白名单</Typography.Text>
          <Typography.Text type="secondary" className="zh-meta-block">
            相对路由默认视为本地能力；绝对 HTTP(S) 目标必须登记主机，未登记目标进入人工复核。
          </Typography.Text>
        </div>
        <UiButton disabled={!canEdit} onClick={addAgent}>
          新增 Agent
        </UiButton>
      </Flex>
      <Space orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(allowlists).map(([agentId, targets]) => (
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
                  允许主机 / Origin
                </Typography.Text>
                <UiSelect
                  mode="tags"
                  value={targets}
                  disabled={!canEdit}
                  onChange={(value) => patchAgentTargets(agentId, value.map(String))}
                  className="zh-full-width"
                  placeholder="例如 https://api.example.com 或 *.example.com"
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
            title="当前没有外部 API 主机登记；带身份的 Agent 调用绝对 HTTP(S) 目标会进入 external-api-allowlist 复核。"
            type="warning"
            showIcon
          />
        ) : null}
      </Space>
    </>
  );
}
