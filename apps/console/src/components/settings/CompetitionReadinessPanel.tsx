import { Col, Row, Space, Typography } from 'antd';
import { ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { openAuthenticatedResource } from '../../app/apiRequest';
import type { CompetitionReadiness, CompetitionReadinessWriteResult } from '@/types';
import { LabelTag, PanelCard, UiAlert, UiButton } from '../ui';
import { getMissingBindings } from './competitionReadinessUtils';
import { ReadinessClaimStatus } from './ReadinessClaimStatus';

interface CompetitionReadinessPanelProps {
  competitionReadiness: CompetitionReadiness | null;
  competitionReadinessOutput: CompetitionReadinessWriteResult | null;
  checkingReadiness: boolean;
  handleRunReadiness: () => void | Promise<void>;
}

export function CompetitionReadinessPanel({
  competitionReadiness,
  competitionReadinessOutput,
  checkingReadiness,
  handleRunReadiness
}: CompetitionReadinessPanelProps) {
  const [artifactError, setArtifactError] = useState('');
  const mcpAdapter = competitionReadiness?.readiness_domains?.mcp_adapter;
  const mcpConfigured = mcpAdapter?.configured === true;
  const mcpProbePassed = mcpAdapter?.probe_passed === true;
  const mcpOperatorEvidenceRequested = mcpAdapter?.operator_evidence_requested === true;
  const mcpOperatorEvidencePassed = mcpAdapter?.operator_evidence_passed === true;
  const productionGaps = competitionReadiness?.production_gaps ?? [];
  const missingBindings = getMissingBindings(competitionReadiness);
  const warningActions =
    competitionReadiness?.next_actions.filter((item) =>
      competitionReadiness.checks.some((check) => check.id === item.id && check.status === 'warning')
    ) ?? [];

  async function openArtifact(path: string) {
    setArtifactError('');
    try {
      await openAuthenticatedResource(path);
    } catch (error) {
      setArtifactError(error instanceof Error ? error.message : '报告打开失败。');
    }
  }
  return (
    <PanelCard
      title="AI Agent 安全就绪检查"
      extra={
        <UiButton
          type="primary"
          icon={<ShieldCheck size={16} />}
          onClick={handleRunReadiness}
          loading={checkingReadiness}
        >
          运行体检并写报告
        </UiButton>
      }
      type="inner"
    >
      <Typography.Paragraph type="secondary">
        检查 LLM API / MCP 执行边界、真实模型证据、工具与模型权限、误报和审计闭环。运行时防护不依赖报告；赛事材料与
        OpenClaw 仅作为可选适配或交付信息。
      </Typography.Paragraph>
      <Space className="zh-settings-action-row" wrap>
        <UiButton onClick={() => void openArtifact('/api/readiness')}>查看体检 JSON</UiButton>
        <UiButton onClick={() => void openArtifact('/api/readiness.md')}>查看体检 Markdown</UiButton>
        <LabelTag variant="filled" className="zh-settings-code-tag">
          POST /api/readiness/write
        </LabelTag>
      </Space>
      {artifactError && <UiAlert type="error" showIcon title={artifactError} />}
      {competitionReadiness ? (
        <>
          <Row gutter={[16, 16]} className="zh-settings-readiness-summary">
            <Col xs={12} md={6}>
              <Typography.Text type="secondary" className="zh-meta-block">
                就绪分
              </Typography.Text>
              <Typography.Title level={2} className="zh-settings-readiness-score">
                {competitionReadiness.readiness_score}%
              </Typography.Title>
            </Col>
            <Col xs={12} md={6}>
              <Typography.Text type="secondary" className="zh-meta-block">
                {competitionReadiness.status_label}
              </Typography.Text>
              <Typography.Text strong>{competitionReadiness.verdict}</Typography.Text>
            </Col>
            <Col xs={24} md={12}>
              <Space size="large" wrap className="zh-settings-readiness-counts">
                <div>
                  <Typography.Text type="secondary" className="zh-meta-block">
                    总项
                  </Typography.Text>
                  <Typography.Text strong>{competitionReadiness.summary.check_count}</Typography.Text>
                </div>
                <div>
                  <Typography.Text type="secondary" className="zh-meta-block">
                    通过
                  </Typography.Text>
                  <Typography.Text strong>{competitionReadiness.summary.passed_count}</Typography.Text>
                </div>
                <div>
                  <Typography.Text type="secondary" className="zh-meta-block">
                    需补强
                  </Typography.Text>
                  <Typography.Text strong>{competitionReadiness.summary.warning_count}</Typography.Text>
                </div>
                <div>
                  <Typography.Text type="secondary" className="zh-meta-block">
                    阻塞
                  </Typography.Text>
                  <Typography.Text strong>{competitionReadiness.summary.blocker_count}</Typography.Text>
                </div>
              </Space>
            </Col>
          </Row>
          <UiAlert
            title={competitionReadiness.production_ready ? '生产主线已就绪' : '生产主线尚未就绪'}
            type={competitionReadiness.production_ready ? 'success' : 'error'}
            showIcon
            className="zh-settings-blocker-alert"
            description={
              <Typography.Text>
                {competitionReadiness.production_verdict ??
                  '生产主线结论尚未生成；请以实时网关证据、鉴权、白名单和审计配置为准。'}
              </Typography.Text>
            }
          />
          <ReadinessClaimStatus readiness={competitionReadiness} />

          <PanelCard size="small" type="inner" title="生产主线缺口">
            {productionGaps.length === 0 ? (
              <UiAlert type="success" showIcon title="当前报告没有未闭合的生产主线缺口。" />
            ) : (
              <Space orientation="vertical" size="middle" className="zh-full-width">
                {productionGaps.map((gap) => (
                  <div key={gap.id} className="zh-settings-blocker-item">
                    <Space wrap>
                      <LabelTag variant="filled" color={gap.status === 'blocked' ? 'error' : 'warning'}>
                        {gap.severity}
                      </LabelTag>
                      <LabelTag variant="filled" color={gap.status === 'blocked' ? 'error' : 'warning'}>
                        {gap.status === 'blocked' ? '阻塞' : '需补强'}
                      </LabelTag>
                      <Typography.Text strong>{gap.title}</Typography.Text>
                    </Space>
                    <Typography.Text type="secondary" className="zh-settings-check-evidence">
                      {gap.evidence}
                    </Typography.Text>
                    {gap.id === 'agent-tool-least-privilege' && missingBindings.length > 0 ? (
                      <div className="zh-settings-blocker-action">
                        <Typography.Text strong>待补齐的 Agent 绑定</Typography.Text>
                        {missingBindings.map(({ agentId, boundaries }) => (
                          <div key={agentId}>
                            {agentId}：缺少 {boundaries.join('、')}
                          </div>
                        ))}
                      </div>
                    ) : null}
                    <div className="zh-settings-blocker-action">下一步：{gap.next_action}</div>
                  </div>
                ))}
              </Space>
            )}
          </PanelCard>

          <PanelCard size="small" type="inner" title="MCP 适配器证据">
            {!mcpAdapter ? (
              <Typography.Text type="secondary">当前报告没有 MCP 适配器状态。</Typography.Text>
            ) : (
              <Space wrap>
                <LabelTag variant="filled" color={mcpConfigured ? 'green' : 'blue'}>
                  {mcpConfigured ? 'MCP 上游已配置' : 'MCP 上游未配置'}
                </LabelTag>
                <LabelTag variant="filled" color={mcpProbePassed ? 'green' : mcpConfigured ? 'red' : 'blue'}>
                  {mcpProbePassed ? '基础探针已通过' : mcpConfigured ? '基础探针待处理' : '基础探针按需'}
                </LabelTag>
                <LabelTag
                  variant="filled"
                  color={mcpOperatorEvidencePassed ? 'green' : mcpOperatorEvidenceRequested ? 'red' : 'blue'}
                >
                  {mcpOperatorEvidencePassed
                    ? 'operator 工具/上下文证据已通过'
                    : mcpOperatorEvidenceRequested
                      ? 'operator 工具/上下文证据待处理'
                      : 'operator 证据未请求'}
                </LabelTag>
              </Space>
            )}
          </PanelCard>

          <Row gutter={[16, 16]}>
            {competitionReadiness.checks.map((check, idx) => (
              <Col xs={24} lg={12} key={idx}>
                <PanelCard
                  size="small"
                  className={
                    check.status === 'passed'
                      ? 'zh-settings-check-card--pass'
                      : check.status === 'blocked'
                        ? 'zh-settings-check-card--block'
                        : 'zh-settings-check-card--warning'
                  }
                >
                  <div className="zh-settings-check-head">
                    <Typography.Text type="secondary" className="zh-settings-meta-sm">
                      {check.category} · {check.severity}
                    </Typography.Text>
                    <LabelTag
                      variant="filled"
                      color={check.status === 'passed' ? 'success' : check.status === 'blocked' ? 'error' : 'warning'}
                    >
                      {check.status_label}
                    </LabelTag>
                  </div>
                  <Typography.Text strong className="zh-settings-check-title">
                    {check.title}
                  </Typography.Text>
                  <Typography.Text type="secondary" className="zh-settings-check-evidence">
                    {check.evidence}
                  </Typography.Text>
                </PanelCard>
              </Col>
            ))}
          </Row>
          {competitionReadiness.blockers.length > 0 && (
            <UiAlert
              title="阻断项 (Blockers)"
              type="error"
              showIcon
              className="zh-settings-blocker-alert"
              description={
                <div className="zh-column-stack">
                  {competitionReadiness.blockers.map((item, idx) => (
                    <div key={idx} className="zh-settings-blocker-item">
                      <Typography.Text strong>
                        {item.severity}: {item.title}
                      </Typography.Text>
                      <div className="zh-settings-blocker-action">{item.next_action}</div>
                    </div>
                  ))}
                </div>
              }
            />
          )}
          {competitionReadiness.blockers.length === 0 && warningActions.length > 0 && (
            <UiAlert
              title="还有需补强项"
              type="warning"
              showIcon
              className="zh-settings-blocker-alert"
              description={
                <div className="zh-column-stack">
                  {warningActions.map((item) => (
                    <div key={item.id} className="zh-settings-blocker-item">
                      <Typography.Text strong>
                        {item.severity}: {item.title}
                      </Typography.Text>
                      <div className="zh-settings-blocker-action">{item.action}</div>
                    </div>
                  ))}
                </div>
              }
            />
          )}
          <Space orientation="vertical" className="zh-settings-command-list">
            {competitionReadiness.acceptance_commands.map((command) => (
              <LabelTag variant="filled" key={command} className="zh-settings-code-tag">
                {command}
              </LabelTag>
            ))}
            {competitionReadinessOutput && (
              <Space wrap>
                <UiButton size="small" onClick={() => void openArtifact('/api/readiness.md')}>
                  打开报告
                </UiButton>
                <Typography.Text code className="zh-settings-code-wrap">
                  {competitionReadinessOutput.markdown_path}
                </Typography.Text>
              </Space>
            )}
            {competitionReadinessOutput && (
              <Space wrap>
                <UiButton size="small" onClick={() => void openArtifact('/api/readiness')}>
                  打开 JSON
                </UiButton>
                <Typography.Text code className="zh-settings-code-wrap">
                  {competitionReadinessOutput.json_path}
                </Typography.Text>
              </Space>
            )}
          </Space>
        </>
      ) : (
        <UiAlert title="暂无就绪结果。点击按钮后会生成本地 JSON 和 Markdown，并显示运行时缺口。" type="info" showIcon />
      )}
    </PanelCard>
  );
}
