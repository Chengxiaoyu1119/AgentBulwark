import { useState } from 'react';
import { UiCol, UiFlex, UiRow, UiSpace, UiSwitch, UiTypography } from '../ui';
import type { PolicySettings, TaskProfileConfig } from '@/types';
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

type Props = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  agentIds: string[];
  onPatch: (patch: Partial<PolicySettings>) => void;
};

const emptyProfile = (agentId: string, capabilities: string[]): TaskProfileConfig => ({
  agent_id: agentId,
  name: '新任务授权',
  enabled: true,
  allowed_capabilities: capabilities,
  allowed_file_paths: [],
  allowed_api_origins: [],
  allowed_email_domains: [],
  require_approval: false,
  expires_at: ''
});

export function TaskProfileEditor({ policySettings, canEdit, agentIds, onPatch }: Props) {
  const profiles = policySettings?.task_profiles ?? {};
  const availableAgents = agentIds.filter((agentId) => agentId && agentId !== '*');

  function patchProfile(taskId: string, patch: Partial<TaskProfileConfig>) {
    const current = profiles[taskId];
    if (!current) return;
    onPatch({ task_profiles: { ...profiles, [taskId]: { ...current, ...patch } } });
  }

  function renameProfile(currentId: string, nextId: string) {
    const normalized = nextId.trim();
    if (!normalized || normalized === currentId || normalized in profiles) return;
    const nextProfiles = { ...profiles, [normalized]: profiles[currentId] };
    delete nextProfiles[currentId];
    onPatch({ task_profiles: nextProfiles });
  }

  function removeProfile(taskId: string) {
    const nextProfiles = { ...profiles };
    delete nextProfiles[taskId];
    onPatch({ task_profiles: nextProfiles });
  }

  function addProfile() {
    const agentId = availableAgents[0];
    if (!agentId) return;
    let index = Object.keys(profiles).length + 1;
    let taskId = `task-${index}`;
    while (taskId in profiles) {
      index += 1;
      taskId = `task-${index}`;
    }
    const capabilities = (policySettings?.agent_tool_allowlists?.[agentId] ?? []).slice(0, 1);
    onPatch({ task_profiles: { ...profiles, [taskId]: emptyProfile(agentId, capabilities) } });
  }

  return (
    <>
      <UiFlex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16 zh-mb-16">
        <div>
          <UiTypography.Text strong>任务授权</UiTypography.Text>
          <UiFieldLabel>任务只能收窄已登记 Agent 的工具和目标范围；任务 ID 由宿主应用通过请求头提供。</UiFieldLabel>
        </div>
        <UiButton disabled={!canEdit || !availableAgents.length} onClick={addProfile}>
          新增任务
        </UiButton>
      </UiFlex>
      {!availableAgents.length ? (
        <UiAlert
          type="warning"
          showIcon
          title="先建立 Agent 权限边界"
          description="任务授权不能扩大 Agent 权限。请先为 Agent 保存工具、API、模型和 MCP 上下文边界。"
        />
      ) : null}
      <UiSpace orientation="vertical" size="middle" className="zh-full-width">
        {Object.entries(profiles).map(([taskId, profile]) => (
          <PanelCard key={taskId} size="small" bodyPadding={12}>
            <UiRow gutter={[12, 12]} align="middle">
              <UiCol xs={24} md={6}>
                <TaskIdField
                  taskId={taskId}
                  existingIds={Object.keys(profiles)}
                  disabled={!canEdit}
                  onRename={(nextId) => renameProfile(taskId, nextId)}
                />
              </UiCol>
              <UiCol xs={24} md={6}>
                <UiFieldLabel htmlFor={`task-name-${encodeURIComponent(taskId)}`}>任务名称</UiFieldLabel>
                <UiInput
                  id={`task-name-${encodeURIComponent(taskId)}`}
                  value={profile.name}
                  disabled={!canEdit}
                  onChange={(event) => patchProfile(taskId, { name: event.target.value })}
                />
              </UiCol>
              <UiCol xs={24} md={6}>
                <UiFieldLabel htmlFor={`task-agent-${encodeURIComponent(taskId)}`}>绑定 Agent</UiFieldLabel>
                <UiSelect
                  id={`task-agent-${encodeURIComponent(taskId)}`}
                  value={profile.agent_id || undefined}
                  options={availableAgents.map((value) => ({ label: value, value }))}
                  disabled={!canEdit}
                  onChange={(value) => patchProfile(taskId, { agent_id: String(value) })}
                  className="zh-full-width"
                  placeholder="选择已登记 Agent"
                />
              </UiCol>
              <UiCol xs={12} md={3}>
                <UiFieldLabel>启用</UiFieldLabel>
                <UiSwitch
                  checked={profile.enabled}
                  disabled={!canEdit}
                  onChange={(enabled) => patchProfile(taskId, { enabled })}
                />
              </UiCol>
              <UiCol xs={12} md={3}>
                <UiConfirmButton
                  danger
                  disabled={!canEdit}
                  confirmTitle={`删除任务授权 ${taskId}？`}
                  confirmDescription="保存并发布后，绑定 Agent 不再需要此任务 ID。"
                  onConfirm={() => removeProfile(taskId)}
                >
                  删除
                </UiConfirmButton>
              </UiCol>
              <UiCol xs={24} md={12}>
                <UiFieldLabel htmlFor={`task-capabilities-${encodeURIComponent(taskId)}`}>允许能力</UiFieldLabel>
                <UiSelect
                  id={`task-capabilities-${encodeURIComponent(taskId)}`}
                  mode="multiple"
                  options={capabilityOptions}
                  value={profile.allowed_capabilities}
                  disabled={!canEdit}
                  onChange={(value) => patchProfile(taskId, { allowed_capabilities: value.map(String) })}
                  className="zh-full-width"
                  placeholder="只能选择 Agent 已有能力"
                />
              </UiCol>
              <UiCol xs={24} md={12}>
                <UiFieldLabel htmlFor={`task-expiry-${encodeURIComponent(taskId)}`}>过期时间（可选）</UiFieldLabel>
                <UiInput
                  id={`task-expiry-${encodeURIComponent(taskId)}`}
                  value={profile.expires_at}
                  disabled={!canEdit}
                  placeholder="2026-09-16T18:00:00+08:00"
                  onChange={(event) => patchProfile(taskId, { expires_at: event.target.value })}
                />
              </UiCol>
              <ScopeTags
                id={`task-paths-${encodeURIComponent(taskId)}`}
                label="文件路径范围"
                value={profile.allowed_file_paths}
                disabled={!canEdit}
                placeholder="例如 public/*"
                onChange={(allowed_file_paths) => patchProfile(taskId, { allowed_file_paths })}
              />
              <ScopeTags
                id={`task-origins-${encodeURIComponent(taskId)}`}
                label="API Origin 范围"
                value={profile.allowed_api_origins}
                disabled={!canEdit}
                placeholder="例如 https://api.example.com"
                onChange={(allowed_api_origins) => patchProfile(taskId, { allowed_api_origins })}
              />
              <ScopeTags
                id={`task-domains-${encodeURIComponent(taskId)}`}
                label="邮件域范围"
                value={profile.allowed_email_domains}
                disabled={!canEdit}
                placeholder="例如 company.example"
                onChange={(allowed_email_domains) => patchProfile(taskId, { allowed_email_domains })}
              />
              <UiCol xs={24} md={6}>
                <UiFieldLabel>所有允许调用均需审批</UiFieldLabel>
                <UiSwitch
                  checked={profile.require_approval}
                  disabled={!canEdit}
                  onChange={(require_approval) => patchProfile(taskId, { require_approval })}
                />
              </UiCol>
            </UiRow>
          </PanelCard>
        ))}
        {!Object.keys(profiles).length && availableAgents.length ? (
          <UiAlert
            type="info"
            showIcon
            title="当前没有任务授权"
            description="未配置任务档案的 Agent 保持兼容行为；一旦绑定任务档案，后续请求必须携带 X-Agent-Task-ID。"
          />
        ) : null}
      </UiSpace>
    </>
  );
}

function TaskIdField({
  taskId,
  existingIds,
  disabled,
  onRename
}: {
  taskId: string;
  existingIds: string[];
  disabled: boolean;
  onRename: (nextId: string) => void;
}) {
  const [draft, setDraft] = useState(taskId);
  const [error, setError] = useState('');

  function commit() {
    const nextId = draft.trim();
    if (!nextId) {
      setDraft(taskId);
      setError('任务 ID 不能为空。');
      return;
    }
    if (nextId !== taskId && existingIds.includes(nextId)) {
      setDraft(taskId);
      setError('任务 ID 已存在，原任务未被覆盖。');
      return;
    }
    setError('');
    if (nextId !== taskId) onRename(nextId);
  }

  return (
    <>
      <UiFieldLabel>任务 ID</UiFieldLabel>
      <UiInput
        aria-label={`任务 ID：${taskId}`}
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

function ScopeTags({
  id,
  label,
  value,
  disabled,
  placeholder,
  onChange
}: {
  id: string;
  label: string;
  value: string[];
  disabled: boolean;
  placeholder: string;
  onChange: (value: string[]) => void;
}) {
  return (
    <UiCol xs={24} md={6}>
      <UiFieldLabel htmlFor={id}>{label}</UiFieldLabel>
      <UiSelect
        id={id}
        mode="tags"
        value={value}
        disabled={disabled}
        onChange={(next) => onChange(next.map(String))}
        className="zh-full-width"
        placeholder={placeholder}
      />
    </UiCol>
  );
}
