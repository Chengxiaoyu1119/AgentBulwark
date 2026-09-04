import { Col, Flex, Row, Space, Switch, Typography } from 'antd';
import type { AuthContext, MemoryGovernance, ObservabilityMetrics, PolicySettings } from '@/types';
import { LabelTag, MetricCard, PanelCard, UiAlert, UiButton, UiFieldLabel, UiInputNumber } from '../ui';
import { AgentBoundarySettingsPanel } from './AgentBoundarySettingsPanel';
import { MemoryGovernancePanel } from './MemoryGovernancePanel';
type RuntimeGovernanceTabProps = {
  authContext: AuthContext | null;
  policySettings: PolicySettings | null;
  metrics: ObservabilityMetrics | null;
  memoryGovernance: MemoryGovernance | null;
  savingSettings: boolean;
  refreshingGovernance: boolean;
  notice?: string;
  error?: string;
  busyMemoryId?: string;
  onSettingsChange: (settings: PolicySettings) => void;
  onSaveSettings: () => void | Promise<void>;
  onRefreshGovernance: () => void | Promise<void>;
  onMemoryStatus: (memoryId: string, status: string) => void | Promise<void>;
  onRollbackMemory: () => void | Promise<void>;
};
export function RuntimeGovernanceTab({
  authContext,
  policySettings,
  metrics,
  memoryGovernance,
  savingSettings,
  refreshingGovernance,
  notice,
  error,
  busyMemoryId,
  onSettingsChange,
  onSaveSettings,
  onRefreshGovernance,
  onMemoryStatus,
  onRollbackMemory
}: RuntimeGovernanceTabProps) {
  function patchSettings(patch: Partial<PolicySettings>) {
    if (!policySettings) return;
    onSettingsChange({ ...policySettings, ...patch });
  }
  const canEditPolicy = Boolean(authContext?.permissions.can_edit_policy);
  const canReviewApproval = Boolean(authContext?.permissions.can_review_approval);
  const memoryIsolated = (memoryGovernance?.summary.quarantined_count ?? 0) > 0;
  return (
    <Space orientation="vertical" size="large" className="zh-tab-stack">
      {error ? <UiAlert type="error" showIcon title={error} /> : null}
      {notice ? <UiAlert type="success" showIcon title={notice} /> : null}
      <PanelCard type="inner">
        <Flex justify="space-between" align="center" wrap="wrap" gap={16}>
          <Space orientation="vertical" size={4}>
            <Typography.Title level={4} className="zh-title-flush">
              策略运行状态
            </Typography.Title>
            <Typography.Text type="secondary">策略权限、运行指标和记忆治理统一在防护策略中维护。</Typography.Text>
          </Space>
          <UiButton loading={refreshingGovernance} onClick={() => void onRefreshGovernance()}>
            刷新治理状态
          </UiButton>
        </Flex>
        <Row gutter={[16, 16]} className="zh-settings-status-grid">
          <Col xs={24} sm={12} lg={6}>
            <div className="zh-settings-status-card">
              <UiFieldLabel>策略编辑</UiFieldLabel>
              <LabelTag variant="filled" color={canEditPolicy ? 'success' : 'warning'}>
                {canEditPolicy ? '允许修改' : '只读'}
              </LabelTag>
            </div>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <div className="zh-settings-status-card">
              <UiFieldLabel>人工复核</UiFieldLabel>
              <LabelTag variant="filled" color={canReviewApproval ? 'success' : 'warning'}>
                {canReviewApproval ? '可处理' : '不可处理'}
              </LabelTag>
            </div>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <div className="zh-settings-status-card">
              <UiFieldLabel>待复核队列</UiFieldLabel>
              <Typography.Text strong>{metrics?.summary.pending_review_count ?? 0} 条</Typography.Text>
            </div>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <div className="zh-settings-status-card">
              <UiFieldLabel>记忆隔离</UiFieldLabel>
              <LabelTag variant="filled" color={memoryIsolated ? 'warning' : 'success'}>
                {memoryIsolated ? '存在隔离项' : '无隔离项'}
              </LabelTag>
            </div>
          </Col>
        </Row>
      </PanelCard>
      <Row gutter={[16, 16]}>
        <Col xs={24} md={8}>
          <MetricCard label="当前角色" value={authContext?.role ?? 'unknown'} tone="cyan" />
        </Col>
        <Col xs={24} md={8}>
          <MetricCard label="策略版本" value={`${metrics?.summary.policy_version_count ?? 0}`} tone="green" />
        </Col>
        <Col xs={24} md={8}>
          <MetricCard label="运行控制率" value={`${metrics?.summary.control_rate ?? 0}%`} tone="amber" />
        </Col>
      </Row>
      <PanelCard title="策略阈值" type="inner">
        <Typography.Paragraph type="secondary">
          阈值会影响监督器对工具调用的处置：达到询问阈值进入人工复核，达到拒绝阈值直接阻断或隔离。
        </Typography.Paragraph>
        <Row gutter={[16, 16]}>
          <Col xs={24} sm={12} lg={6}>
            <UiFieldLabel htmlFor="policy-anomaly-review-threshold">异常询问阈值</UiFieldLabel>
            <UiInputNumber
              id="policy-anomaly-review-threshold"
              min={1}
              max={100}
              value={policySettings?.anomaly_review_threshold}
              disabled={!canEditPolicy}
              onChange={(value) => patchSettings({ anomaly_review_threshold: Number(value ?? 55) })}
              className="zh-full-width"
            />
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <UiFieldLabel htmlFor="policy-anomaly-reject-threshold">异常拒绝阈值</UiFieldLabel>
            <UiInputNumber
              id="policy-anomaly-reject-threshold"
              min={1}
              max={100}
              value={policySettings?.anomaly_reject_threshold}
              disabled={!canEditPolicy}
              onChange={(value) => patchSettings({ anomaly_reject_threshold: Number(value ?? 85) })}
              className="zh-full-width"
            />
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <UiFieldLabel htmlFor="policy-approval-sla-minutes">复核时限分钟</UiFieldLabel>
            <UiInputNumber
              id="policy-approval-sla-minutes"
              min={1}
              max={1440}
              value={policySettings?.approval_sla_minutes}
              disabled={!canEditPolicy}
              onChange={(value) => patchSettings({ approval_sla_minutes: Number(value ?? 30) })}
              className="zh-full-width"
            />
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <UiFieldLabel htmlFor="policy-high-risk-auto-escalation">高风险自动升级</UiFieldLabel>
            <div className="zh-settings-switch-row">
              <Switch
                id="policy-high-risk-auto-escalation"
                checked={Boolean(policySettings?.high_risk_auto_escalation)}
                disabled={!canEditPolicy}
                onChange={(checked) => patchSettings({ high_risk_auto_escalation: checked })}
              />
              <UiButton
                type="primary"
                loading={savingSettings}
                disabled={!canEditPolicy}
                onClick={() => void onSaveSettings()}
              >
                保存阈值
              </UiButton>
            </div>
          </Col>
        </Row>
      </PanelCard>
      <AgentBoundarySettingsPanel
        policySettings={policySettings}
        canEdit={canEditPolicy}
        saving={savingSettings}
        onPatch={patchSettings}
        onSave={onSaveSettings}
      />
      <PanelCard title="运行指标" type="inner">
        <Row gutter={[16, 16]}>
          <Col xs={12} md={6}>
            <MetricCard label="运行次数" value={`${metrics?.summary.run_count ?? 0}`} tone="cyan" />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard label="审计日志" value={`${metrics?.summary.audit_log_count ?? 0}`} tone="green" />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard label="待复核" value={`${metrics?.summary.pending_review_count ?? 0}`} tone="amber" />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard label="平均延迟" value={`${metrics?.summary.avg_detection_latency_ms ?? 0}ms`} tone="red" />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard label="外部执行回执" value={`${metrics?.summary.execution_receipt_count ?? 0}`} tone="cyan" />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard
              label="待确认执行"
              value={`${metrics?.summary.execution_unconfirmed_count ?? 0}`}
              tone={(metrics?.summary.execution_unconfirmed_count ?? 0) > 0 ? 'red' : 'green'}
            />
          </Col>
          <Col xs={12} md={6}>
            <MetricCard
              label="防护闭环证据"
              value={`${metrics?.summary.execution_control_verified_count ?? 0}`}
              tone="green"
            />
          </Col>
        </Row>
      </PanelCard>
      <MemoryGovernancePanel
        memoryGovernance={memoryGovernance}
        canReviewApproval={canReviewApproval}
        busyMemoryId={busyMemoryId}
        onMemoryStatus={onMemoryStatus}
        onRollbackMemory={onRollbackMemory}
      />
    </Space>
  );
}
