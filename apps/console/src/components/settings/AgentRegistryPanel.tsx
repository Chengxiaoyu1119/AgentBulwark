import { useEffect, useState } from 'react';
import { Plus, RefreshCw, ShieldOff } from 'lucide-react';
import { createAgent, fetchAgents, revokeAgent, rotateAgentToken } from '../../app/governanceApi';
import { safeUiErrorSummary } from '../../app/apiRequestSupport';
import type { AgentRegistration } from '../../types';
import {
  CopyButton,
  LabelTag,
  PanelCard,
  UiAlert,
  UiButton,
  UiConfirmButton,
  UiFlex,
  UiInput,
  UiSpace,
  UiTypography
} from '../ui';

export function AgentRegistryPanel({ canEdit }: { canEdit: boolean }) {
  const [agents, setAgents] = useState<AgentRegistration[]>([]);
  const [agentId, setAgentId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    try {
      setAgents(await fetchAgents());
    } catch (reason) {
      setError(safeUiErrorSummary(reason, 'Agent 接入状态读取失败。'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, []);

  async function run(action: string, callback: () => Promise<AgentRegistration>) {
    setBusy(action);
    setError('');
    try {
      const result = await callback();
      setAgents((current) => {
        const next = current.filter((item) => item.agent_id !== result.agent_id);
        return [result, ...next];
      });
      setToken(result.token ?? '');
      setAgentId('');
      setDisplayName('');
    } catch (reason) {
      setError(safeUiErrorSummary(reason, 'Agent 操作失败。'));
    } finally {
      setBusy('');
    }
  }

  return (
    <PanelCard title="Agent 接入" subtitle="Token 只在创建或轮换成功后显示一次，控制台不会保存密钥正文。">
      {error ? <UiAlert type="error" showIcon title={error} /> : null}
      {token ? (
        <UiAlert
          type="warning"
          showIcon
          title="请立即复制新 Token"
          description={
            <UiFlex gap={8} align="center" wrap="wrap">
              <UiTypography.Text code>{token}</UiTypography.Text>
              <CopyButton text={token}>复制 Token</CopyButton>
            </UiFlex>
          }
          className="zh-mb-16"
        />
      ) : null}
      {canEdit ? (
        <UiFlex gap={8} wrap="wrap" className="zh-mb-16">
          <UiInput
            aria-label="Agent ID"
            placeholder="Agent ID，例如 support-agent"
            value={agentId}
            onChange={(event) => setAgentId(event.target.value)}
          />
          <UiInput
            aria-label="Agent 名称"
            placeholder="显示名称（可选）"
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
          />
          <UiButton
            type="primary"
            icon={<Plus size={16} />}
            disabled={!agentId.trim()}
            loading={busy === 'create'}
            onClick={() =>
              void run('create', () => createAgent({ agent_id: agentId.trim(), display_name: displayName.trim() }))
            }
          >
            创建 Agent
          </UiButton>
        </UiFlex>
      ) : null}
      {loading ? <UiAlert type="info" showIcon title="正在读取 Agent 接入状态。" /> : null}
      {!loading && !agents.length ? (
        <UiAlert
          type="info"
          showIcon
          title="还没有注册 Agent"
          description="创建后可在这里查看状态、Token 前缀和策略绑定情况。"
        />
      ) : null}
      <UiSpace orientation="vertical" size={10} className="zh-full-width">
        {agents.map((agent) => (
          <div key={agent.agent_id} className="zh-settings-switch-row">
            <div>
              <UiTypography.Text strong>{agent.display_name}</UiTypography.Text>
              <UiTypography.Paragraph type="secondary" className="zh-mb-0">
                {agent.agent_id} · Token {agent.token_prefix}… · 最近请求{' '}
                {agent.last_request_at ? agent.last_request_at.slice(0, 19).replace('T', ' ') : '暂无'}
              </UiTypography.Paragraph>
            </div>
            <UiFlex gap={8} align="center" wrap="wrap">
              <LabelTag color={agent.status === 'active' ? 'green' : 'default'}>
                {agent.status === 'active' ? '启用' : '已撤销'}
              </LabelTag>
              <LabelTag color={agent.policy_binding?.ready ? 'green' : 'warning'}>
                {agent.policy_binding?.ready ? '已绑定策略' : '待绑定策略'}
              </LabelTag>
              {canEdit && agent.status === 'active' ? (
                <UiButton
                  size="small"
                  icon={<RefreshCw size={14} />}
                  loading={busy === `rotate:${agent.agent_id}`}
                  onClick={() => void run(`rotate:${agent.agent_id}`, () => rotateAgentToken(agent.agent_id))}
                >
                  轮换 Token
                </UiButton>
              ) : null}
              {canEdit && agent.status === 'active' ? (
                <UiConfirmButton
                  size="small"
                  danger
                  icon={<ShieldOff size={14} />}
                  confirmTitle="撤销这个 Agent 的 Token？"
                  onConfirm={() => void run(`revoke:${agent.agent_id}`, () => revokeAgent(agent.agent_id))}
                >
                  撤销
                </UiConfirmButton>
              ) : null}
            </UiFlex>
          </div>
        ))}
      </UiSpace>
    </PanelCard>
  );
}
