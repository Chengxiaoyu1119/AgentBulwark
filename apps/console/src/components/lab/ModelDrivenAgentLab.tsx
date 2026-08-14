import { useState } from 'react';
import { Bot, Play } from 'lucide-react';
import { Col, Descriptions, Row, Space, Typography } from 'antd';
import { runModelDrivenAgent } from '../../api';
import type { ModelDrivenAgentResult } from '../../types';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import {
  DecisionPill,
  EvidenceCodeBlock,
  LabelTag,
  MetricCard,
  PanelCard,
  UiAlert,
  UiButton,
  UiInput,
  UiSwitch
} from '../ui';
import { ResultRunButton, RunResultEmptyState } from './RunResultActions';

type ModelDrivenAgentLabProps = {
  refresh?: () => Promise<unknown>;
};

const DEFAULT_TASK = '读取公开项目说明文件，并根据工具返回内容给出两句话摘要。';

export function ModelDrivenAgentLab({ refresh }: ModelDrivenAgentLabProps) {
  const [task, setTask] = useState(DEFAULT_TASK);
  const [targetModel, setTargetModel] = useState('');
  const [forceRealModel, setForceRealModel] = useState(true);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState('');
  const [result, setResult] = useState<ModelDrivenAgentResult | null>(null);

  async function runAgent() {
    setRunning(true);
    setNotice('');
    try {
      const nextResult = await runModelDrivenAgent({
        task,
        force_real_model: forceRealModel,
        target_model: targetModel
      });
      setResult(nextResult);
      await refresh?.();
    } catch (error) {
      setNotice(`模型驱动 Agent 运行失败：${error instanceof Error ? error.message : '未知错误'}`);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="zh-attack-lab">
      {notice ? <UiAlert type="warning" showIcon title={notice} className="zh-mb-24" /> : null}
      <Row gutter={[20, 20]} align="stretch">
        <Col xs={24} xl={8}>
          <PanelCard title="模型驱动 Agent" subtitle="模型真实产生工具调用" className="zh-full-height">
            <Space orientation="vertical" size={16} className="zh-full-width">
              <UiAlert
                type="info"
                showIcon
                title="链路：模型生成 tool_call → 智安哨决策 → 沙箱实际处置 → 执行回执 → 工具结果回灌模型。页面会明确标记 real-api 或 fallback。"
              />
              <div className="zh-attack-lab__field">
                <Typography.Text strong>Agent 任务</Typography.Text>
                <UiInput.TextArea
                  value={task}
                  onChange={(event) => setTask(event.target.value)}
                  rows={6}
                  maxLength={4000}
                  showCount
                />
              </div>
              <div className="zh-attack-lab__field">
                <Typography.Text strong>指定模型（可选）</Typography.Text>
                <UiInput
                  value={targetModel}
                  onChange={(event) => setTargetModel(event.target.value)}
                  placeholder="留空使用目标模型配置"
                />
              </div>
              <div className="zh-attack-lab__switch-row">
                <div>
                  <Typography.Text strong>优先真实模型</Typography.Text>
                  <Typography.Paragraph type="secondary" className="zh-attack-lab__hint">
                    接口或密钥不可用时会保留失败原因，并标记本地 fallback。
                  </Typography.Paragraph>
                </div>
                <UiSwitch checked={forceRealModel} onChange={setForceRealModel} />
              </div>
              <UiButton
                type="primary"
                icon={<Play size={16} />}
                loading={running}
                disabled={!task.trim()}
                onClick={runAgent}
              >
                运行完整 Agent 闭环
              </UiButton>
            </Space>
          </PanelCard>
        </Col>

        <Col xs={24} xl={16}>
          <PanelCard
            title="模型—监督—执行—回执证据"
            subtitle={result ? `${result.model_plan.provider} / ${result.model_plan.model}` : '等待运行'}
            className="zh-full-height"
            extra={
              <ResultRunButton
                hasResult={Boolean(result)}
                idleLabel="运行闭环"
                rerunLabel="重新运行"
                loading={running}
                disabled={!task.trim()}
                onClick={runAgent}
              />
            }
          >
            {result ? (
              <Space orientation="vertical" size={16} className="zh-full-width">
                <Row gutter={[12, 12]}>
                  <Col xs={12} lg={4}>
                    <MetricCard
                      label="模型来源"
                      value={result.model_plan.mode ?? 'unknown'}
                      tone={result.model_plan.mode === 'real-api' ? 'green' : 'amber'}
                    />
                  </Col>
                  <Col xs={12} lg={4}>
                    <MetricCard
                      label="结果回灌来源"
                      value={result.model_followup.mode ?? 'unknown'}
                      tone={result.model_followup.mode === 'real-api' ? 'green' : 'amber'}
                    />
                  </Col>
                  <Col xs={12} lg={4}>
                    <MetricCard label="监督决策" value={result.supervision.decision} tone="cyan" />
                  </Col>
                  <Col xs={12} lg={4}>
                    <MetricCard
                      label="实际处置"
                      value={`${result.execution.target}/${result.execution.status}`}
                      tone="amber"
                    />
                  </Col>
                  <Col xs={12} lg={4}>
                    <MetricCard
                      label="协议闭环"
                      value={result.evidence_complete ? '完整' : '待补充'}
                      tone={result.evidence_complete ? 'green' : 'red'}
                    />
                  </Col>
                  <Col xs={12} lg={4}>
                    <MetricCard
                      label="真实模型证据"
                      value={result.real_model_evidence_valid ? '有效' : '未通过'}
                      tone={result.real_model_evidence_valid ? 'green' : 'red'}
                    />
                  </Col>
                </Row>

                <UiAlert
                  type={result.real_model_evidence_valid ? 'success' : 'warning'}
                  showIcon
                  title={
                    result.real_model_evidence_valid
                      ? '规划与工具结果回灌均带有供应商原始响应指纹，且审计、执行结果、回执和回答已串成可校验 Hash 链。'
                      : `协议链路${result.evidence_complete ? '已闭合' : '尚未闭合'}，但这次运行不计入严格真实模型证据。`
                  }
                  description={result.evidence_gaps.length ? result.evidence_gaps.join('；') : undefined}
                />

                <PanelCard
                  type="inner"
                  title="逐步证据"
                  extra={<AuditDeepLinkButton auditId={result.supervision.audit_id} size="small" />}
                >
                  <Descriptions column={2} size="small" bordered>
                    <Descriptions.Item label="模型">
                      {result.model_plan.provider} / {result.model_plan.model}
                    </Descriptions.Item>
                    <Descriptions.Item label="模式">
                      <LabelTag color={result.model_plan.mode === 'real-api' ? 'success' : 'warning'}>
                        {result.model_plan.mode}
                      </LabelTag>
                    </Descriptions.Item>
                    <Descriptions.Item label="工具调用 ID">{result.tool_call.id}</Descriptions.Item>
                    <Descriptions.Item label="模型选择工具">{result.tool_call.tool}</Descriptions.Item>
                    <Descriptions.Item label="监督决策">
                      <DecisionPill decision={result.supervision.decision} />
                    </Descriptions.Item>
                    <Descriptions.Item label="策略">{result.supervision.policy_id}</Descriptions.Item>
                    <Descriptions.Item label="执行状态">
                      {result.execution.target} / {result.execution.status}
                    </Descriptions.Item>
                    <Descriptions.Item label="耗时">{result.execution.duration_ms} ms</Descriptions.Item>
                    <Descriptions.Item label="审计 Hash">{result.supervision.audit_hash}</Descriptions.Item>
                    <Descriptions.Item label="结果 Hash">{result.execution.result_hash || '-'}</Descriptions.Item>
                    <Descriptions.Item label="回执 Hash">{result.receipt.receipt_hash}</Descriptions.Item>
                    <Descriptions.Item label="回执签名">
                      {result.receipt.receipt_signature ? '已签名' : '本地未配置 HMAC'}
                    </Descriptions.Item>
                    <Descriptions.Item label="模型规划 Hash">
                      {result.model_plan.response_hash || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="模型回答 Hash">
                      {result.model_followup.response_hash || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="供应商规划响应 Hash">
                      {result.model_plan.provider_response_hash || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="供应商回灌响应 Hash">
                      {result.model_followup.provider_response_hash || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="证据状态">{result.evidence_status}</Descriptions.Item>
                    <Descriptions.Item label="证据链 Hash">{result.evidence_chain_hash || '-'}</Descriptions.Item>
                  </Descriptions>
                </PanelCard>

                <Row gutter={[16, 16]}>
                  <Col xs={24} lg={12}>
                    <Typography.Text strong>模型生成的工具调用</Typography.Text>
                    <EvidenceCodeBlock maxHeight="small">{JSON.stringify(result.tool_call, null, 2)}</EvidenceCodeBlock>
                  </Col>
                  <Col xs={24} lg={12}>
                    <Typography.Text strong>实际工具结果</Typography.Text>
                    <EvidenceCodeBlock maxHeight="small">
                      {JSON.stringify(result.execution.output, null, 2)}
                    </EvidenceCodeBlock>
                  </Col>
                </Row>

                <PanelCard type="inner" title="工具结果回灌后的模型回答">
                  <Space wrap className="zh-mb-12">
                    <LabelTag color={result.model_followup.mode === 'real-api' ? 'success' : 'warning'}>
                      {result.model_followup.mode}
                    </LabelTag>
                    <LabelTag color={result.model_followup.is_final ? 'success' : 'warning'}>
                      {result.model_followup.is_final ? '最终回答' : '请求额外工具，已暂停'}
                    </LabelTag>
                  </Space>
                  <Typography.Paragraph>{result.model_followup.content}</Typography.Paragraph>
                </PanelCard>

                <Typography.Text type="secondary" className="zh-settings-code-wrap">
                  {result.markdown_path}
                </Typography.Text>
              </Space>
            ) : (
              <RunResultEmptyState
                icon={<Bot size={28} />}
                title="等待模型生成真实工具调用"
                description="运行后会同时展示模型来源、原始 tool_call、监督决策、实际执行目标、结果 Hash、回执 Hash 和模型最终回答。"
                actionLabel="运行完整 Agent 闭环"
                loading={running}
                disabled={!task.trim()}
                onAction={runAgent}
              />
            )}
          </PanelCard>
        </Col>
      </Row>
    </div>
  );
}
