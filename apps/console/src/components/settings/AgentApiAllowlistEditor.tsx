import { useState } from 'react';
import { UiCol, UiFlex, UiRow, UiSpace, UiTypography } from '../ui';
import type { PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiConfirmButton, UiFieldLabel, UiInput, UiSelect } from '../ui';

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
    if (!nextId || nextId === currentId || nextId in allowlists) return;
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
      <UiFlex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <UiTypography.Text strong>Agent 外部 API 主机白名单</UiTypography.Text>
          <UiFieldLabel>相对路由默认视为本地能力；绝对 HTTP(S) 目标必须登记主机，未登记目标进入人工复核。</UiFieldLabel>
        </div>
        <UiButton disabled={!canEdit} onClick={addAgent}>
          新增 Agent
        </UiButton>
      </UiFlex>
      <UiSpace orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(allowlists).map(([agentId, targets]) => (
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
                <UiFieldLabel htmlFor={`agent-api-targets-${encodeURIComponent(agentId)}`}>
                  允许主机 / Origin
                </UiFieldLabel>
                <UiSelect
                  id={`agent-api-targets-${encodeURIComponent(agentId)}`}
                  mode="tags"
                  value={targets}
                  disabled={!canEdit}
                  onChange={(value) => patchAgentTargets(agentId, value.map(String))}
                  className="zh-full-width"
                  placeholder="例如 https://api.example.com 或 *.example.com"
                />
              </UiCol>
              <UiCol xs={24} md={3}>
                <UiConfirmButton
                  danger
                  disabled={!canEdit}
                  confirmTitle={`删除 Agent ${agentId} 的 API 白名单？`}
                  confirmDescription="保存权限设置后，该 Agent 的绝对 HTTP(S) 目标将不再有登记范围。"
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
            title="当前没有外部 API 主机登记；带身份的 Agent 调用绝对 HTTP(S) 目标会进入 external-api-allowlist 复核。"
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
      setError('Agent ID 不能为空，原 API 白名单保持不变。');
      return;
    }
    if (nextId !== agentId && registeredAgentIds.includes(nextId)) {
      setDraft(agentId);
      setError(`Agent ID ${nextId} 已存在，未覆盖原 API 白名单。`);
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
