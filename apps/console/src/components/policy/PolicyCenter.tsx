import { useMemo, useState } from 'react';
import { Row, Col, Typography, Switch, Space, Descriptions, Flex } from 'antd';
import { updatePolicyDetail, updatePolicyEnabled } from '@/api';
import type { Policy } from '@/types';
import { DecisionPill, LabelTag, MetricCard as Metric, PanelCard, UiAlert, UiButton, UiInput, UiSelect } from '../ui';
import { RuntimeGovernanceTab } from '../settings/RuntimeGovernanceTab';
import { useRuntimeGovernanceController } from '../settings/useRuntimeGovernanceController';
import { PolicyDisableImpactPreview } from './PolicyDisableImpactPreview';

export function PolicyCenter({
  policies,
  setPolicies
}: {
  policies: Policy[];
  setPolicies: (policies: Policy[]) => void;
}) {
  const enabledCount = policies.filter((policy) => policy.enabled).length;
  const protectedSurfaceCount = useMemo(
    () => new Set(policies.flatMap((policy) => policy.surface_ids ?? [])).size,
    [policies]
  );
  const protectedToolCount = useMemo(() => new Set(policies.flatMap((policy) => policy.tools ?? [])).size, [policies]);
  const policyLayerCount = useMemo(
    () => new Set(policies.map((policy) => policy.layer).filter(Boolean)).size,
    [policies]
  );
  const [savingPolicyId, setSavingPolicyId] = useState('');
  const [policyError, setPolicyError] = useState('');
  const [editingPolicyId, setEditingPolicyId] = useState('');
  const [policyDraft, setPolicyDraft] = useState<Partial<Policy>>({});
  const [pendingDisablePolicyId, setPendingDisablePolicyId] = useState('');
  const governance = useRuntimeGovernanceController(setPolicyError);

  async function savePolicyEnabled(id: string, enabled: boolean) {
    const current = policies.find((policy) => policy.id === id);
    if (!current) return;
    const previousPolicies = policies;
    setPolicyError('');
    setSavingPolicyId(id);
    setPolicies(policies.map((policy) => (policy.id === id ? { ...policy, enabled } : policy)));
    try {
      const savedPolicy = await updatePolicyEnabled(id, enabled);
      setPolicies(previousPolicies.map((policy) => (policy.id === id ? savedPolicy : policy)));
      setPendingDisablePolicyId('');
    } catch {
      setPolicies(previousPolicies);
      setPolicyError('策略状态保存失败，页面已恢复到保存前状态。');
    } finally {
      setSavingPolicyId('');
    }
  }

  async function togglePolicy(id: string) {
    const current = policies.find((policy) => policy.id === id);
    if (!current) return;

    if (current.enabled) {
      setPolicyError('');
      setPendingDisablePolicyId(id);
      return;
    }

    await savePolicyEnabled(id, true);
  }

  function startEdit(policy: Policy) {
    setEditingPolicyId(policy.id);
    setPendingDisablePolicyId('');
    setPolicyDraft({
      description: policy.description,
      decision: policy.decision,
      layer: policy.layer
    });
    setPolicyError('');
  }

  async function savePolicyDetail(policy: Policy) {
    setSavingPolicyId(policy.id);
    setPolicyError('');
    try {
      const savedPolicy = await updatePolicyDetail(policy.id, {
        description: String(policyDraft.description ?? policy.description),
        decision: policyDraft.decision ?? policy.decision,
        layer: String(policyDraft.layer ?? policy.layer ?? ''),
        comment: '通过策略中心编辑策略详情'
      });
      setPolicies(policies.map((item) => (item.id === policy.id ? savedPolicy : item)));
      setEditingPolicyId('');
      setPolicyDraft({});
    } catch (error) {
      setPolicyError(error instanceof Error ? error.message : '策略详情保存失败。');
    } finally {
      setSavingPolicyId('');
    }
  }

  return (
    <div className="zh-page-stack">
      <Flex justify="space-between" align="center" wrap="wrap" gap={16}>
        <Space orientation="vertical" size={4}>
          <Typography.Title level={2} className="zh-title-flush">
            防护策略中心
          </Typography.Title>
          <Typography.Text type="secondary">
            {enabledCount}/{policies.length} 已启用
          </Typography.Text>
        </Space>
      </Flex>

      {policyError ? <UiAlert type="error" title={policyError} showIcon /> : null}

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={6}>
          <Metric label="策略层级" value={`${policyLayerCount}`} tone="cyan" />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Metric label="覆盖攻击面" value={`${protectedSurfaceCount}`} tone="green" />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Metric label="覆盖工具" value={`${protectedToolCount}`} tone="amber" />
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Metric
            label="停用策略"
            value={`${policies.length - enabledCount}`}
            tone={policies.length - enabledCount ? 'red' : 'green'}
          />
        </Col>
      </Row>

      <Row gutter={[24, 24]}>
        {policies.map((policy) => (
          <Col xs={24} sm={24} md={24} lg={12} xl={12} xxl={8} key={policy.id}>
            <PanelCard
              variant="borderless"
              className={`zh-policy-card${policy.enabled ? '' : ' zh-policy-card--disabled'}`}
            >
              <div className="zh-policy-card__head">
                <Space align="start">
                  <DecisionPill decision={policy.decision} />
                  <div className="zh-column-stack">
                    <Typography.Text strong className="zh-policy-card__title">
                      {policy.name}
                    </Typography.Text>
                    <Typography.Text type="secondary" className="zh-policy-card__id">
                      {policy.id}
                    </Typography.Text>
                  </div>
                </Space>
                <Switch
                  checked={policy.enabled}
                  disabled={Boolean(savingPolicyId)}
                  loading={savingPolicyId === policy.id}
                  onChange={() => void togglePolicy(policy.id)}
                  size="small"
                />
              </div>

              {editingPolicyId === policy.id ? (
                <Space orientation="vertical" size="small" className="zh-full-width zh-mb-16">
                  <UiInput.TextArea
                    value={String(policyDraft.description ?? '')}
                    onChange={(event) => setPolicyDraft({ ...policyDraft, description: event.target.value })}
                    autoSize={{ minRows: 3, maxRows: 5 }}
                  />
                  <Row gutter={[12, 12]}>
                    <Col xs={24} sm={12}>
                      <UiSelect
                        className="zh-full-width"
                        value={policyDraft.decision}
                        onChange={(value) => setPolicyDraft({ ...policyDraft, decision: value as Policy['decision'] })}
                        options={[
                          { label: '允许', value: '允许' },
                          { label: '询问', value: '询问' },
                          { label: '拒绝', value: '拒绝' },
                          { label: '隔离', value: '隔离' }
                        ]}
                      />
                    </Col>
                    <Col xs={24} sm={12}>
                      <UiInput
                        value={String(policyDraft.layer ?? '')}
                        onChange={(event) => setPolicyDraft({ ...policyDraft, layer: event.target.value })}
                        placeholder="策略层级"
                      />
                    </Col>
                  </Row>
                  <Space wrap>
                    <UiButton
                      size="small"
                      type="primary"
                      loading={savingPolicyId === policy.id}
                      onClick={() => void savePolicyDetail(policy)}
                    >
                      保存策略
                    </UiButton>
                    <UiButton size="small" onClick={() => setEditingPolicyId('')}>
                      取消
                    </UiButton>
                  </Space>
                </Space>
              ) : (
                <Typography.Paragraph type="secondary" className="zh-policy-card__description">
                  {policy.description}
                </Typography.Paragraph>
              )}

              <div
                className={`zh-policy-card__meta${
                  policy.risk_controls?.length || policy.disable_impact ? ' zh-policy-card__meta--spaced' : ''
                }`}
              >
                <Descriptions size="small" column={2} className="zh-description-flush">
                  <Descriptions.Item
                    label={
                      <Typography.Text type="secondary" className="zh-text-meta">
                        层级
                      </Typography.Text>
                    }
                  >
                    <Typography.Text strong>{policy.layer ?? '未标注'}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item
                    label={
                      <Typography.Text type="secondary" className="zh-text-meta">
                        攻击面
                      </Typography.Text>
                    }
                  >
                    <Typography.Text strong>{policy.surface_ids?.join(' / ') || '未绑定'}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item
                    label={
                      <Typography.Text type="secondary" className="zh-text-meta">
                        工具
                      </Typography.Text>
                    }
                    span={2}
                  >
                    <Typography.Text strong>{policy.tools?.join(' / ') || '未绑定'}</Typography.Text>
                  </Descriptions.Item>
                </Descriptions>
              </div>

              {policy.risk_controls?.length ? (
                <Space size={[0, 8]} wrap className={policy.disable_impact ? 'zh-mb-16' : undefined}>
                  {policy.risk_controls.map((item) => (
                    <LabelTag key={item} variant="filled" color="processing">
                      {item}
                    </LabelTag>
                  ))}
                </Space>
              ) : null}

              <PolicyDisableImpactPreview
                policy={policy}
                open={pendingDisablePolicyId === policy.id}
                saving={savingPolicyId === policy.id}
                onCancel={() => setPendingDisablePolicyId('')}
                onConfirm={() => void savePolicyEnabled(policy.id, false)}
              />
              {editingPolicyId !== policy.id ? (
                <div className="zh-mt-16">
                  <UiButton size="small" onClick={() => startEdit(policy)}>
                    编辑策略
                  </UiButton>
                </div>
              ) : null}
            </PanelCard>
          </Col>
        ))}
      </Row>

      <RuntimeGovernanceTab
        authContext={governance.authContext}
        policySettings={governance.policySettings}
        metrics={governance.observabilityMetrics}
        memoryGovernance={governance.memoryGovernance}
        savingSettings={governance.savingSettings}
        refreshingGovernance={governance.refreshingGovernance}
        notice={governance.governanceNotice}
        error={governance.governanceError}
        busyMemoryId={governance.busyMemoryId}
        onSettingsChange={governance.setPolicySettings}
        onSaveSettings={governance.handleSavePolicySettings}
        onRefreshGovernance={governance.handleRefreshGovernance}
        onMemoryStatus={governance.handleMemoryStatus}
        onRollbackMemory={governance.handleRollbackMemory}
      />
    </div>
  );
}
