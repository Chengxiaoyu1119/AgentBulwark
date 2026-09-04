import { useState } from 'react';
import { UiCol, UiFlex, UiRow, UiSpace, UiTypography } from '../ui';
import type { PolicySettings } from '@/types';
import { PanelCard, UiAlert, UiButton, UiConfirmButton, UiFieldLabel, UiInput, UiSelect } from '../ui';

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
    if (!nextId || nextId === currentId || nextId in allowlists) return;
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
      <UiFlex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <UiTypography.Text strong>Agent 工具最小权限</UiTypography.Text>
          <UiFieldLabel>每个 Agent 只获得完成职责所需的工具；使用 * 可设置未单独登记 Agent 的默认规则。</UiFieldLabel>
        </div>
        <UiButton disabled={!canEdit} onClick={addAgent}>
          新增 Agent
        </UiButton>
      </UiFlex>
      <UiSpace orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(allowlists).map(([agentId, tools]) => (
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
                <UiFieldLabel htmlFor={`agent-tools-${encodeURIComponent(agentId)}`}>允许调用的工具</UiFieldLabel>
                <UiSelect
                  id={`agent-tools-${encodeURIComponent(agentId)}`}
                  mode="multiple"
                  options={supportedToolOptions}
                  value={tools}
                  disabled={!canEdit}
                  onChange={(value) => patchAgentTools(agentId, value.map(String))}
                  className="zh-full-width"
                  placeholder="选择最小工具集合"
                />
              </UiCol>
              <UiCol xs={24} md={3}>
                <UiConfirmButton
                  danger
                  disabled={!canEdit}
                  confirmTitle={`删除 Agent ${agentId} 的工具白名单？`}
                  confirmDescription="保存权限设置后，该 Agent 将失去当前登记的工具能力。"
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
            title="当前没有 Agent 工具白名单；新增一条规则后，未授权工具会被 tool-contract 拒绝。"
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
      setError('Agent ID 不能为空，原工具白名单保持不变。');
      return;
    }
    if (nextId !== agentId && registeredAgentIds.includes(nextId)) {
      setDraft(agentId);
      setError(`Agent ID ${nextId} 已存在，未覆盖原工具白名单。`);
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
