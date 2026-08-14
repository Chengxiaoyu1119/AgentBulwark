import { ArrowRight, CheckCircle2, Fingerprint, ShieldCheck, ShieldOff, XCircle } from 'lucide-react';
import { Col, Row, Space, Typography } from 'antd';
import type { AttackEnvironmentBranch, AttackLabRunResult } from '../../types';
import { DecisionPill, EvidenceCodeBlock, LabelTag, PanelCard } from '../ui';

type AttackComparisonHeroProps = {
  result: AttackLabRunResult;
};

function shortHash(value: string) {
  return value ? value.slice(0, 12) : '-';
}

function BranchEvidence({ branch, protectedMode }: { branch: AttackEnvironmentBranch; protectedMode: boolean }) {
  const isolatedInSandbox = protectedMode && branch.decision === '隔离' && branch.executor_called;
  const successfulDefense = protectedMode && !branch.attack_success && (!branch.executor_called || isolatedInSandbox);
  const exposed = !protectedMode && branch.attack_success && branch.executor_called;
  const positive = protectedMode ? successfulDefense : !exposed;
  const title = protectedMode
      ? successfulDefense
        ? isolatedInSandbox
          ? '防护成功：危险动作已隔离'
          : '防护成功：危险动作未执行'
      : '防护仍有缺口'
    : exposed
      ? '攻击成功：危险动作已执行'
      : '攻击未形成有效副作用';

  return (
    <div
      className={`zh-causal-branch ${protectedMode ? 'zh-causal-branch--protected' : 'zh-causal-branch--baseline'} ${
        positive ? 'zh-causal-branch--positive' : 'zh-causal-branch--negative'
      }`}
    >
      <div className="zh-causal-branch__header">
        <div className="zh-causal-branch__icon">
          {protectedMode ? <ShieldCheck size={24} /> : <ShieldOff size={24} />}
        </div>
        <div>
          <Typography.Text type="secondary">{protectedMode ? '启用智安哨' : '关闭智安哨'}</Typography.Text>
          <Typography.Title level={4}>{title}</Typography.Title>
        </div>
        {positive ? <CheckCircle2 size={22} /> : <XCircle size={22} />}
      </div>

      <div className="zh-causal-facts">
        <div>
          <span>监督决策</span>
          <DecisionPill decision={branch.decision} />
        </div>
        <div>
          <span>真实执行器</span>
          <strong className={branch.executor_called && !isolatedInSandbox ? 'zh-text-danger' : 'zh-text-success'}>
            {branch.executor_called ? (isolatedInSandbox ? '隔离执行器已调用' : '已调用') : '未调用'}
          </strong>
        </div>
        <div>
          <span>环境状态</span>
          <strong>{branch.changed ? '发生变化' : '保持不变'}</strong>
        </div>
        <div>
          <span>攻击结果</span>
          <strong className={branch.attack_success ? 'zh-text-danger' : 'zh-text-success'}>
            {branch.attack_success ? '成功' : '受控'}
          </strong>
        </div>
      </div>

      <div className="zh-causal-evidence">
        <Typography.Text strong>可验证副作用</Typography.Text>
        {branch.changes.length ? (
          branch.changes.map((change) => (
            <div key={change.key} className="zh-causal-change">
              <span>{change.label}</span>
              <strong>
                {change.before} <ArrowRight size={14} /> {change.after}
              </strong>
              {change.details?.length ? <small>{change.details.join('、')}</small> : null}
            </div>
          ))
        ) : (
          <div className="zh-causal-no-change">
            <CheckCircle2 size={16} /> 环境计数、文件、记忆和外发队列均未变化
          </div>
        )}
        <Typography.Paragraph type="secondary" className="zh-causal-effect-reason">
          {branch.effect_reason || '本次工具没有产生可验证副作用。'}
        </Typography.Paragraph>
      </div>

      <div className="zh-causal-proof-row">
        <span>审计 {shortHash(branch.audit_id)}</span>
        <span>结果状态 {shortHash(branch.after.state_hash)}</span>
      </div>
    </div>
  );
}

export function AttackComparisonHero({ result }: AttackComparisonHeroProps) {
  const comparison = result.environment_comparison;
  const integrity = comparison.integrity;
  const modelMode = result.model_plan.mode?.toLowerCase();
  const realModelEvidence =
    result.model_evidence?.valid ?? !['fixed', 'fallback', 'simulated'].includes(modelMode ?? '');
  const modelEvidenceLabel =
    result.model_evidence?.status === 'real-api'
      ? '真实模型规划有效'
      : result.model_evidence?.status === 'fallback'
        ? '模型规划回退'
        : result.model_evidence?.status === 'fixed'
          ? '固定规划器结果'
          : realModelEvidence
            ? '真实模型规划'
            : '模型证据未通过';

  return (
    <PanelCard
      title="同一攻击的因果对照"
      subtitle="两组使用相同输入、相同工具调用和相同初始环境，唯一变量是是否启用智安哨。"
      className="zh-attack-comparison-hero"
    >
      <div className="zh-comparison-integrity">
        <Space wrap size={[8, 8]}>
          <LabelTag color={integrity.same_initial_state ? 'success' : 'error'}>
            初始环境{integrity.same_initial_state ? '一致' : '不一致'}
          </LabelTag>
          <LabelTag color={integrity.same_tool_call ? 'success' : 'error'}>
            工具调用{integrity.same_tool_call ? '一致' : '不一致'}
          </LabelTag>
          <LabelTag color={integrity.risk_hint_used ? 'error' : 'processing'}>
            {integrity.risk_hint_used ? '携带风险答案标签' : '未携带风险答案标签'}
          </LabelTag>
          <LabelTag color={integrity.isolated_conversation_history === false ? 'error' : 'success'}>
            {integrity.isolated_conversation_history === false ? '会话历史串扰' : '会话历史隔离'}
          </LabelTag>
          <LabelTag color={realModelEvidence ? 'success' : 'warning'}>{modelEvidenceLabel}</LabelTag>
        </Space>
        <div className="zh-comparison-hashes">
          <Fingerprint size={16} />
          <span>初始状态 {shortHash(integrity.initial_state_hash)}</span>
          <span>工具调用 {shortHash(integrity.tool_call_hash)}</span>
        </div>
      </div>

      {result.model_plan.fallback_reason ? (
        <div className="zh-comparison-provenance-warning">
          本次模型没有生成有效工具调用：{result.model_plan.fallback_reason} 当前结果用于验证执行链，不计入真实模型证据。
        </div>
      ) : null}
      {result.model_evidence?.content_hash ? (
        <div className="zh-comparison-provenance-warning">
          模型输出证据 Hash：{result.model_evidence.content_hash}；该 Hash 用于证明工具调用输入来自本次规划响应。
        </div>
      ) : null}

      <div className="zh-comparison-tool-call">
        <div>
          <Typography.Text type="secondary">Agent实际提出的工具调用</Typography.Text>
          <Typography.Text strong>{result.tool_call.tool}</Typography.Text>
        </div>
        <EvidenceCodeBlock size="small" flush>
          {JSON.stringify(result.tool_call.arguments, null, 2)}
        </EvidenceCodeBlock>
      </div>

      <Row gutter={[18, 18]} align="stretch" className="zh-causal-grid">
        <Col xs={24} xl={12}>
          <BranchEvidence branch={comparison.without_guard} protectedMode={false} />
        </Col>
        <Col xs={24} xl={12}>
          <BranchEvidence branch={comparison.with_guard} protectedMode />
        </Col>
      </Row>
    </PanelCard>
  );
}
