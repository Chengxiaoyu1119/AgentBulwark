import { useState } from 'react';
import { UiCol, UiFlex, UiRow, UiSpace, UiTypography } from '../ui';
import type { PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiConfirmButton, UiFieldLabel, UiInput, UiSelect } from '../ui';

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
    if (!nextId || nextId === currentId || nextId in allowlists) return;
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
      <UiFlex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <UiTypography.Text strong>Agent 模型白名单</UiTypography.Text>
          <UiFieldLabel>
            绑定 Agent 只能选择登记的精确模型 ID；留空表示该 Agent 暂无可用模型，避免凭证被拿去切换任意 Provider 模型。
          </UiFieldLabel>
        </div>
        <UiButton disabled={!canEdit} onClick={addAgent}>
          新增 Agent
        </UiButton>
      </UiFlex>
      <UiSpace orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(allowlists).map(([agentId, models]) => (
          <PanelCard key={agentId} size="small" bodyPadding={12}>
            <UiRow gutter={[12, 12]} align="middle">
              <UiCol xs={24} md={7}>
                <AgentIdField
                  agentId={agentId}
                  registeredAgentIds={Object.keys(allowlists)}
                  disabled={!canEdit}
                  onRename={(nextId) => renameAgent(agentId, nextId)}
                />
              </UiCol>
              <UiCol xs={24} md={14}>
                <UiFieldLabel htmlFor={`agent-models-${encodeURIComponent(agentId)}`}>允许模型 ID</UiFieldLabel>
                <UiSelect
                  id={`agent-models-${encodeURIComponent(agentId)}`}
                  mode="tags"
                  value={models}
                  disabled={!canEdit}
                  onChange={(value) => patchAgentModels(agentId, value.map(String))}
                  className="zh-full-width"
                  placeholder="例如 deepseek-chat、gpt-4.1-mini"
                />
              </UiCol>
              <UiCol xs={24} md={3}>
                <UiConfirmButton
                  danger
                  disabled={!canEdit}
                  confirmTitle={`删除 Agent ${agentId} 的模型白名单？`}
                  confirmDescription="保存权限设置后，该 Agent 将失去已登记的模型选择范围。"
                  onConfirm={() => removeAgent(agentId)}
                >
                  删除
                </UiConfirmButton>
              </UiCol>
            </UiRow>
          </PanelCard>
        ))}
        {!Object.keys(allowlists).length ? (
          <UiAlert
            title="当前没有 Agent 模型白名单；生产 Agent 凭证尚未建立模型选择证据，建议先登记模型 ID。"
            type="warning"
            showIcon
          />
        ) : null}
      </UiSpace>
    </>
  );
}

function AgentIdField({
  agentId,
  registeredAgentIds,
  disabled,
  onRename
}: {
  agentId: string;
  registeredAgentIds: string[];
  disabled: boolean;
  onRename: (nextId: string) => void;
}) {
  const [draft, setDraft] = useState(agentId);
  const [error, setError] = useState('');

  function commit() {
    const nextId = draft.trim();
    if (!nextId) {
      setDraft(agentId);
      setError('Agent ID 不能为空，原模型白名单保持不变。');
      return;
    }
    if (nextId !== agentId && registeredAgentIds.includes(nextId)) {
      setDraft(agentId);
      setError(`Agent ID ${nextId} 已存在，未覆盖原模型白名单。`);
      return;
    }
    setDraft(nextId);
    setError('');
    if (nextId !== agentId) onRename(nextId);
  }

  return (
    <>
      <UiFieldLabel>Agent ID</UiFieldLabel>
      <UiInput
        aria-label={`Agent ID：${agentId}`}
        value={draft}
        status={error ? 'error' : undefined}
        disabled={disabled}
        onChange={(event) => {
          setDraft(event.target.value);
          setError('');
        }}
        onBlur={commit}
      />
      {error ? (
        <UiTypography.Text type="danger" role="alert" className="zh-inline-field-error">
          {error}
        </UiTypography.Text>
      ) : null}
    </>
  );
}
