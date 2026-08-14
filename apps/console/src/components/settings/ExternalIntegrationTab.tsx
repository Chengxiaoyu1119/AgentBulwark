import { Col, Collapse, Flex, Row, Space, Typography } from 'antd';
import { LabelTag, PanelCard, UiButton } from '../ui';
import { OpenClawPluginPanel } from './OpenClawPluginPanel';
import type {
  AgentIntegrationBundle,
  OpenClawIntegrationBundle,
  OpenClawPluginPackageResult,
  OpenClawPluginValidationWriteResult
} from '@/types';

type ExternalIntegrationTabProps = {
  integrationBundle: OpenClawIntegrationBundle | null;
  agentIntegrationBundle: AgentIntegrationBundle | null;
  openClawPluginPackage: OpenClawPluginPackageResult | null;
  openClawPluginValidation: OpenClawPluginValidationWriteResult | null;
  writingOpenClawPlugin: boolean;
  validatingOpenClawPlugin: boolean;
  handleWriteOpenClawPlugin: () => void | Promise<void>;
  handleValidateOpenClawPlugin: () => void | Promise<void>;
  ensureOpenClawIntegration: () => void | Promise<unknown>;
};

export function ExternalIntegrationTab({
  integrationBundle,
  agentIntegrationBundle,
  openClawPluginPackage,
  openClawPluginValidation,
  writingOpenClawPlugin,
  validatingOpenClawPlugin,
  handleWriteOpenClawPlugin,
  handleValidateOpenClawPlugin,
  ensureOpenClawIntegration
}: ExternalIntegrationTabProps) {
  const integrationChecks = [
    {
      label: '通用 Agent 监督',
      value: agentIntegrationBundle ? '接口可用' : '读取中',
      ready: Boolean(agentIntegrationBundle)
    },
    {
      label: '接入适配状态',
      value: agentIntegrationBundle ? 'HTTP + 执行回执已实现' : '读取中',
      ready: Boolean(agentIntegrationBundle)
    },
    {
      label: '执行前强制闸门',
      value: 'AgentToolGuard 已实现',
      ready: Boolean(agentIntegrationBundle)
    },
    {
      label: '接入协议',
      value: '判定 + 执行回执',
      ready: Boolean(agentIntegrationBundle)
    }
  ];

  return (
    <Space orientation="vertical" size="large" className="zh-tab-stack">
      <PanelCard title="Agent运行时安全接入" type="inner">
        <Row gutter={[16, 16]} className="zh-settings-status-grid">
          {integrationChecks.map((item) => (
            <Col xs={24} sm={12} lg={6} key={item.label}>
              <div className="zh-settings-status-card">
                <Typography.Text type="secondary" className="zh-meta-block">
                  {item.label}
                </Typography.Text>
                <Flex justify="space-between" align="center" gap={8}>
                  <Typography.Text strong>{item.value}</Typography.Text>
                  <LabelTag
                    variant="filled"
                    color={item.ready ? 'success' : 'warning'}
                    className="zh-settings-tag-flush"
                  >
                    {item.ready ? '已准备' : '待操作'}
                  </LabelTag>
                </Flex>
              </div>
            </Col>
          ))}
        </Row>

        <Row gutter={[16, 16]} className="zh-mb-24">
          <Col xs={24} sm={12} lg={6}>
            <PanelCard size="small" type="inner" className="zh-full-height">
              <Typography.Text type="secondary" className="zh-settings-info-label">
                HTTP 接口
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                POST /api/runtime/evaluate
              </Typography.Text>
            </PanelCard>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <PanelCard size="small" type="inner" className="zh-full-height">
              <Typography.Text type="secondary" className="zh-settings-info-label">
                OpenClaw 兼容
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                POST /api/integrations/openclaw/events
              </Typography.Text>
            </PanelCard>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <PanelCard size="small" type="inner" className="zh-full-height">
              <Typography.Text type="secondary" className="zh-settings-info-label">
                适配器代码
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                GET /api/integrations/openclaw/adapter.py
              </Typography.Text>
            </PanelCard>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <PanelCard size="small" type="inner" className="zh-full-height">
              <Typography.Text type="secondary" className="zh-settings-info-label">
                执行回执
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                POST /api/runtime/executions/&#123;audit_id&#125;/complete
              </Typography.Text>
            </PanelCard>
          </Col>
        </Row>

        {agentIntegrationBundle && (
          <PanelCard
            title={
              <Space>
                通用 Agent Runtime 接入包
                <LabelTag variant="filled" color="green">
                  {agentIntegrationBundle.version}
                </LabelTag>
              </Space>
            }
            className="zh-mb-24 zh-settings-muted-body"
            type="inner"
            variant="borderless"
          >
            <Typography.Paragraph>{agentIntegrationBundle.purpose}</Typography.Paragraph>
            <Row gutter={[16, 16]} className="zh-mb-24">
              {agentIntegrationBundle.examples.map((example) => (
                <Col xs={24} md={12} xl={6} key={example.id}>
                  <PanelCard size="small" bodyPadding={12} className="zh-full-height">
                    <Typography.Text strong className="zh-text-block">
                      {example.name}
                    </Typography.Text>
                    <Typography.Text type="secondary" className="zh-meta-block">
                      {example.framework}
                    </Typography.Text>
                    <LabelTag variant="filled" color={example.status === 'ready' ? 'success' : 'blue'}>
                      {example.status}
                    </LabelTag>
                  </PanelCard>
                </Col>
              ))}
            </Row>
            <Flex justify="space-between" align="center" wrap="wrap" gap={16}>
              <Typography.Text code className="zh-settings-code-wrap zh-settings-code-md">
                POST /api/integrations/agents/model_driven_demo
              </Typography.Text>
              <Space wrap>
                <UiButton size="small" href="/api/integrations/agents/bundle" target="_blank">
                  查看通用接入包
                </UiButton>
                <UiButton size="small" href="/api/integrations/agents/bundle.md" target="_blank">
                  查看 Markdown
                </UiButton>
              </Space>
            </Flex>
          </PanelCard>
        )}

        <Collapse
          ghost
          onChange={(keys) => {
            const nextKeys = Array.isArray(keys) ? keys.map(String) : [String(keys)];
            if (nextKeys.includes('optional-adapters')) {
              void ensureOpenClawIntegration();
            }
          }}
          items={[
            {
              key: 'optional-adapters',
              label: '可选框架适配器',
              children: (
                <>
                  {integrationBundle && (
                    <PanelCard
                      title={
                        <Space>
                          OpenClaw 可选兼容接入包{' '}
                          <LabelTag variant="filled" color="blue">
                            {integrationBundle.version}
                          </LabelTag>
                        </Space>
                      }
                      className="zh-mb-24 zh-settings-muted-body"
                      type="inner"
                      variant="borderless"
                    >
                      <Typography.Paragraph>{integrationBundle.purpose}</Typography.Paragraph>
                      <Row gutter={[16, 16]} className="zh-mb-24">
                        <Col xs={12} md={6}>
                          <PanelCard size="small" variant="borderless">
                            <Typography.Text type="secondary" className="zh-meta-block">
                              接口数量
                            </Typography.Text>
                            <Typography.Text strong className="zh-settings-stat-value">
                              {integrationBundle.endpoints.length}
                            </Typography.Text>
                          </PanelCard>
                        </Col>
                        <Col xs={12} md={6}>
                          <PanelCard size="small" variant="borderless">
                            <Typography.Text type="secondary" className="zh-meta-block">
                              样例事件
                            </Typography.Text>
                            <Typography.Text strong className="zh-settings-stat-value">
                              {integrationBundle.sample_events.length}
                            </Typography.Text>
                          </PanelCard>
                        </Col>
                        <Col xs={12} md={6}>
                          <PanelCard size="small" variant="borderless">
                            <Typography.Text type="secondary" className="zh-meta-block">
                              最低控制
                            </Typography.Text>
                            <Typography.Text strong className="zh-settings-stat-value">
                              {integrationBundle.validation.expected.controlled_min}
                            </Typography.Text>
                          </PanelCard>
                        </Col>
                        <Col xs={12} md={6}>
                          <PanelCard size="small" variant="borderless">
                            <Typography.Text type="secondary" className="zh-meta-block">
                              安全默认
                            </Typography.Text>
                            <Typography.Text strong className="zh-settings-stat-value">
                              {integrationBundle.event_contract.safe_default.includes('false') ? '只审计' : '需确认'}
                            </Typography.Text>
                          </PanelCard>
                        </Col>
                      </Row>

                      <PanelCard size="small" className="zh-settings-soft-panel" variant="borderless">
                        <Flex justify="space-between" align="center" wrap="wrap" gap={16}>
                          <Typography.Text code className="zh-settings-code-wrap zh-settings-code-md">
                            {integrationBundle.validation.cli}
                          </Typography.Text>
                          <Space wrap>
                            <UiButton size="small" href="/api/integrations/openclaw/bundle" target="_blank">
                              查看接入包 JSON
                            </UiButton>
                            <UiButton size="small" href="/api/integrations/openclaw/schema" target="_blank">
                              查看事件结构
                            </UiButton>
                            <UiButton size="small" href="/api/integrations/openclaw/adapter.py" target="_blank">
                              查看适配器代码
                            </UiButton>
                          </Space>
                        </Flex>
                      </PanelCard>
                    </PanelCard>
                  )}

                  <OpenClawPluginPanel
                    integrationBundle={integrationBundle}
                    openClawPluginPackage={openClawPluginPackage}
                    openClawPluginValidation={openClawPluginValidation}
                    writingOpenClawPlugin={writingOpenClawPlugin}
                    validatingOpenClawPlugin={validatingOpenClawPlugin}
                    handleWriteOpenClawPlugin={handleWriteOpenClawPlugin}
                    handleValidateOpenClawPlugin={handleValidateOpenClawPlugin}
                  />
                </>
              )
            }
          ]}
        />
      </PanelCard>
    </Space>
  );
}
