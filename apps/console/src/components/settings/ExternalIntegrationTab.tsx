import { Col, Collapse, Flex, Row, Space, Typography } from 'antd';
import { LabelTag, PanelCard, UiButton, UiFieldLabel } from '../ui';
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
      value: agentIntegrationBundle ? 'LLM API + HTTP + 回执已实现' : '读取中',
      ready: Boolean(agentIntegrationBundle)
    },
    {
      label: '服务端强制执行',
      value: '监督 + 隔离执行器已实现',
      ready: Boolean(agentIntegrationBundle)
    },
    {
      label: '安全阶段',
      value: '输入预检 / 输出拦截 / 执行回执',
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
                <UiFieldLabel>{item.label}</UiFieldLabel>
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
                强制执行接口
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                POST /api/runtime/execute
              </Typography.Text>
              <UiFieldLabel>`/api/runtime/evaluate` 仅返回判定</UiFieldLabel>
            </PanelCard>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <PanelCard size="small" type="inner" className="zh-full-height">
              <Typography.Text type="secondary" className="zh-settings-info-label">
                LLM API / MCP 网关
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                POST /v1/chat/completions
              </Typography.Text>
              <UiFieldLabel>透明转发 + tool call 阻断</UiFieldLabel>
            </PanelCard>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <PanelCard size="small" type="inner" className="zh-full-height">
              <Typography.Text type="secondary" className="zh-settings-info-label">
                MCP Gateway
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                POST /api/mcp
              </Typography.Text>
              <UiFieldLabel>强制代理 + 工具定义投毒扫描</UiFieldLabel>
            </PanelCard>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <PanelCard size="small" type="inner" className="zh-full-height">
              <Typography.Text type="secondary" className="zh-settings-info-label">
                通用 Agent 接入包
              </Typography.Text>
              <Typography.Text code className="zh-settings-code-wrap">
                GET /api/integrations/agents/bundle
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
                    <UiFieldLabel>{example.framework}</UiFieldLabel>
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
                <UiButton size="small" authenticatedHref="/api/integrations/agents/bundle">
                  查看通用接入包
                </UiButton>
                <UiButton size="small" authenticatedHref="/api/integrations/agents/bundle.md">
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
                            <UiFieldLabel>接口数量</UiFieldLabel>
                            <Typography.Text strong className="zh-settings-stat-value">
                              {integrationBundle.endpoints.length}
                            </Typography.Text>
                          </PanelCard>
                        </Col>
                        <Col xs={12} md={6}>
                          <PanelCard size="small" variant="borderless">
                            <UiFieldLabel>样例事件</UiFieldLabel>
                            <Typography.Text strong className="zh-settings-stat-value">
                              {integrationBundle.sample_events.length}
                            </Typography.Text>
                          </PanelCard>
                        </Col>
                        <Col xs={12} md={6}>
                          <PanelCard size="small" variant="borderless">
                            <UiFieldLabel>最低控制</UiFieldLabel>
                            <Typography.Text strong className="zh-settings-stat-value">
                              {integrationBundle.validation.expected.controlled_min}
                            </Typography.Text>
                          </PanelCard>
                        </Col>
                        <Col xs={12} md={6}>
                          <PanelCard size="small" variant="borderless">
                            <UiFieldLabel>安全默认</UiFieldLabel>
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
                            <UiButton size="small" authenticatedHref="/api/integrations/openclaw/bundle">
                              查看接入包 JSON
                            </UiButton>
                            <UiButton size="small" authenticatedHref="/api/integrations/openclaw/schema">
                              查看事件结构
                            </UiButton>
                            <UiButton size="small" authenticatedHref="/api/integrations/openclaw/adapter.py">
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
