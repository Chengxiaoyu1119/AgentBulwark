import { Col, Row, Space, Typography } from 'antd';
import { TerminalSquare } from 'lucide-react';
import { DecisionPill, LabelTag, MetricCard as Metric, PanelCard, UiAlert, UiButton } from '../ui';
import { SupervisorManualDebugPanel } from './SupervisorManualDebugPanel';
import type { ExternalAgentDemoResult, SupervisorBatchEvaluation, SupervisorEvaluation } from '@/types';

type SupervisorDebugTabProps = {
  externalAgentDemo: ExternalAgentDemoResult | null;
  runningExternalAgentDemo: boolean;
  handleRunExternalAgentDemo: () => void | Promise<void>;
  eventJson: string;
  setEventJson: (value: string) => void;
  batchJson: string;
  setBatchJson: (value: string) => void;
  evaluation: SupervisorEvaluation | null;
  batchEvaluation: SupervisorBatchEvaluation | null;
  evaluating: boolean;
  batchEvaluating: boolean;
  evaluateError: string;
  handleEvaluateEvent: () => void | Promise<void>;
  handleBatchEvaluate: () => void | Promise<void>;
  loadSingleExternalSample: () => void;
  loadBatchExternalSample: () => void;
  clearExternalResults: () => void;
};

export function SupervisorDebugTab({
  externalAgentDemo,
  runningExternalAgentDemo,
  handleRunExternalAgentDemo,
  eventJson,
  setEventJson,
  batchJson,
  setBatchJson,
  evaluation,
  batchEvaluation,
  evaluating,
  batchEvaluating,
  evaluateError,
  handleEvaluateEvent,
  handleBatchEvaluate,
  loadSingleExternalSample,
  loadBatchExternalSample,
  clearExternalResults
}: SupervisorDebugTabProps) {
  return (
    <Space orientation="vertical" size="large" className="zh-tab-stack">
      <PanelCard
        title="真实 Agent 工具调度验证"
        type="inner"
        extra={
          <UiButton
            type="primary"
            onClick={handleRunExternalAgentDemo}
            loading={runningExternalAgentDemo}
            icon={<TerminalSquare size={16} />}
          >
            运行真实 Agent 验证
          </UiButton>
        }
        className="zh-mb-24"
      >
        <Typography.Paragraph type="secondary">
          从页面直接运行最小外部 Agent，让监督器在工具执行前做允许、拒绝或询问决策，并生成可提交的证据文件。
        </Typography.Paragraph>
        <Space className="zh-settings-action-row" wrap>
          <LabelTag variant="filled" className="zh-settings-code-tag">
            POST /api/integrations/openclaw/minimal_agent_demo
          </LabelTag>
          <UiButton href="/api/integrations/openclaw/bundle" target="_blank">
            查看接入包
          </UiButton>
          <UiButton href="/api/integrations/openclaw/adapter.py" target="_blank">
            查看适配器代码
          </UiButton>
        </Space>

        {externalAgentDemo ? (
          <>
            <Row gutter={[16, 16]} className="zh-settings-row-mb-16">
              <Col xs={12} sm={8} md={4}>
                <Metric label="任务总数" value={`${externalAgentDemo.summary.task_count}`} />
              </Col>
              <Col xs={12} sm={8} md={4}>
                <Metric label="被控制" value={`${externalAgentDemo.summary.controlled_count}`} tone="green" />
              </Col>
              <Col xs={12} sm={8} md={4}>
                <Metric label="真实执行" value={`${externalAgentDemo.summary.executed_count}`} />
              </Col>
              <Col xs={12} sm={8} md={4}>
                <Metric label="控制率" value={`${externalAgentDemo.summary.control_rate}%`} tone="amber" />
              </Col>
              <Col xs={12} sm={8} md={4}>
                <Metric label="审计 hash" value={`${externalAgentDemo.summary.audit_hash_count}`} />
              </Col>
              <Col xs={12} sm={8} md={4}>
                <Metric
                  label="执行回执"
                  value={`${externalAgentDemo.summary.receipt_confirmed_count ?? 0}/${externalAgentDemo.summary.task_count}`}
                  tone={(externalAgentDemo.summary.receipt_unconfirmed_count ?? 0) > 0 ? 'red' : 'green'}
                />
              </Col>
              <Col xs={12} sm={8} md={4}>
                <Metric label="防护闭环" value={`${externalAgentDemo.summary.control_verified_count ?? 0}`} tone="green" />
              </Col>
            </Row>
            <Space orientation="vertical" className="zh-settings-stack zh-settings-stack--mb-24">
              <Space wrap>
                <LabelTag variant="filled" color="success">
                  证据已写入本地
                </LabelTag>
                <Typography.Text type="secondary" className="zh-settings-meta-sm">
                  页面展示的任务结果来自后端真实调度，不是前端静态回放。
                </Typography.Text>
              </Space>
              <Typography.Text code className="zh-settings-code-wrap">
                {externalAgentDemo.markdown_path}
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                {externalAgentDemo.json_path}
              </Typography.Text>
            </Space>
            <div className="zh-column-stack">
              {externalAgentDemo.records.map((record, index) => (
                <div key={index} className="zh-settings-record">
                  <Row className="zh-settings-row-full" align="top" gutter={[16, 16]}>
                    <Col xs={4} md={2}>
                      <Typography.Text strong className="zh-settings-record-index">
                        {String(index + 1).padStart(2, '0')}
                      </Typography.Text>
                    </Col>
                    <Col xs={20} md={10}>
                      <Typography.Text strong className="zh-settings-record-title">
                        {record.title}
                      </Typography.Text>
                      <Typography.Text type="secondary" className="zh-settings-record-meta">
                        {record.reason}
                      </Typography.Text>
                      <Typography.Text code className="zh-settings-code-wrap zh-settings-code-sm">
                        {record.tool} {JSON.stringify(record.arguments)}
                      </Typography.Text>
                    </Col>
                    <Col xs={24} md={12} className="zh-settings-align-right zh-settings-align-right-responsive">
                      <Space orientation="vertical" align="end" size={4}>
                        <DecisionPill decision={record.decision} />
                        <LabelTag variant="filled" color={record.executed ? 'success' : 'default'}>
                          {record.executed ? '已执行' : '未执行'}
                        </LabelTag>
                        <LabelTag variant="filled" color={record.receipt_confirmed ? 'success' : 'warning'}>
                          {record.receipt_confirmed ? `${record.execution_target ?? 'unknown'} / ${record.execution_status ?? 'unknown'}` : '回执未确认'}
                        </LabelTag>
                        <Typography.Text type="secondary" className="zh-settings-meta-sm">
                          {record.policy_id}
                        </Typography.Text>
                        <Typography.Text type="secondary" className="zh-settings-mono-sm">
                          {record.audit_hash ? record.audit_hash.slice(0, 12) : 'no-hash'}
                        </Typography.Text>
                        <Typography.Text type="secondary" className="zh-settings-mono-sm">
                          receipt {record.execution_receipt?.receipt_hash?.slice(0, 12) ?? 'unconfirmed'}
                        </Typography.Text>
                      </Space>
                    </Col>
                  </Row>
                </div>
              ))}
            </div>
          </>
        ) : (
          <UiAlert
            title="还没有运行真实 Agent 调度验证。点击按钮后，系统会自动跑 4 个工具调用并写入审计证据。"
            type="info"
            showIcon
          />
        )}
      </PanelCard>

      <SupervisorManualDebugPanel
        eventJson={eventJson}
        setEventJson={setEventJson}
        batchJson={batchJson}
        setBatchJson={setBatchJson}
        evaluation={evaluation}
        batchEvaluation={batchEvaluation}
        evaluating={evaluating}
        batchEvaluating={batchEvaluating}
        evaluateError={evaluateError}
        handleEvaluateEvent={handleEvaluateEvent}
        handleBatchEvaluate={handleBatchEvaluate}
        loadSingleExternalSample={loadSingleExternalSample}
        loadBatchExternalSample={loadBatchExternalSample}
        clearExternalResults={clearExternalResults}
      />
    </Space>
  );
}
