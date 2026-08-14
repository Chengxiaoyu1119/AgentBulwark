import { Col, Descriptions, Row, Space, Typography } from 'antd';
import { TerminalSquare } from 'lucide-react';
import { LabelTag, PanelCard, UiAlert, UiButton } from '../ui';
import type {
  OpenClawIntegrationBundle,
  OpenClawPluginPackageResult,
  OpenClawPluginValidationWriteResult
} from '@/types';

type OpenClawPluginPanelProps = {
  integrationBundle: OpenClawIntegrationBundle | null;
  openClawPluginPackage: OpenClawPluginPackageResult | null;
  openClawPluginValidation: OpenClawPluginValidationWriteResult | null;
  writingOpenClawPlugin: boolean;
  validatingOpenClawPlugin: boolean;
  handleWriteOpenClawPlugin: () => void | Promise<void>;
  handleValidateOpenClawPlugin: () => void | Promise<void>;
};

export function OpenClawPluginPanel({
  integrationBundle,
  openClawPluginPackage,
  openClawPluginValidation,
  writingOpenClawPlugin,
  validatingOpenClawPlugin,
  handleWriteOpenClawPlugin,
  handleValidateOpenClawPlugin
}: OpenClawPluginPanelProps) {
  return (
    <PanelCard
      title="可选兼容：OpenClaw 源码级插件包"
      className="zh-mb-24"
      type="inner"
      extra={
        <Space>
          <UiButton
            type="primary"
            onClick={handleWriteOpenClawPlugin}
            loading={writingOpenClawPlugin}
            icon={<TerminalSquare size={16} />}
          >
            生成插件包
          </UiButton>
          <UiButton onClick={handleValidateOpenClawPlugin} loading={validatingOpenClawPlugin}>
            运行验收
          </UiButton>
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        这是通用 Agent 接入之外的可选适配，生成 native plugin 并在 before_tool_call 阶段接入智安哨监督器。
      </Typography.Paragraph>
      <Space className="zh-settings-action-row" wrap>
        <UiButton href="/api/integrations/openclaw/plugin_package" target="_blank">
          查看插件摘要
        </UiButton>
        <UiButton href="/api/integrations/openclaw/plugin_package.md" target="_blank">
          查看插件说明
        </UiButton>
        <UiButton href="/api/integrations/openclaw/plugin_package/validation" target="_blank">
          查看验收 JSON
        </UiButton>
        <UiButton href="/api/integrations/openclaw/plugin_package/validation.md" target="_blank">
          查看验收报告
        </UiButton>
      </Space>

      {openClawPluginPackage ? (
        <>
          <Row gutter={[16, 16]} className="zh-settings-row-mb-16">
            <Col xs={12} sm={6}>
              <Typography.Text type="secondary" className="zh-settings-text-block">
                插件类型
              </Typography.Text>
              <Typography.Text strong>{openClawPluginPackage.summary.package_type}</Typography.Text>
            </Col>
            <Col xs={12} sm={6}>
              <Typography.Text type="secondary" className="zh-settings-text-block">
                核心 Hook
              </Typography.Text>
              <Typography.Text strong>{openClawPluginPackage.summary.core_hooks.length}</Typography.Text>
            </Col>
            <Col xs={12} sm={6}>
              <Typography.Text type="secondary" className="zh-settings-text-block">
                文件数
              </Typography.Text>
              <Typography.Text strong>{openClawPluginPackage.file_count}</Typography.Text>
            </Col>
            <Col xs={12} sm={6}>
              <Typography.Text type="secondary" className="zh-settings-text-block">
                检查通过
              </Typography.Text>
              <Typography.Text strong>
                {
                  Object.entries(openClawPluginPackage.summary.runtime_checks).filter(
                    ([key, value]) => key !== 'file_count' && value === true
                  ).length
                }
              </Typography.Text>
            </Col>
          </Row>
          <Space orientation="vertical" className="zh-settings-stack zh-settings-stack--mb-16">
            <Space wrap>
              <UiButton size="small" href="/api/integrations/openclaw/plugin_package.md" target="_blank">
                打开插件说明
              </UiButton>
              <UiButton size="small" href="/api/integrations/openclaw/plugin_package" target="_blank">
                打开插件摘要
              </UiButton>
            </Space>
            <Typography.Text code className="zh-settings-code-wrap">
              {openClawPluginPackage.package_dir}
            </Typography.Text>
            <Typography.Text code className="zh-settings-code-wrap">
              {openClawPluginPackage.zip_path}
            </Typography.Text>
            <Typography.Text code className="zh-settings-code-wrap">
              {openClawPluginPackage.markdown_path}
            </Typography.Text>
          </Space>
          <Space wrap className="zh-settings-stack--mb-16">
            {Object.entries(openClawPluginPackage.summary.runtime_checks).map(([key, value]) => (
              <LabelTag variant="filled" key={key} color={value ? 'success' : 'error'}>
                {key}: {String(value)}
              </LabelTag>
            ))}
          </Space>
          <Space orientation="vertical" className="zh-settings-stack">
            {openClawPluginPackage.summary.install_commands.map((command) => (
              <Typography.Text key={command} code>
                {command}
              </Typography.Text>
            ))}
            {integrationBundle?.validation.plugin_validation_cli && (
              <Typography.Text code>{integrationBundle.validation.plugin_validation_cli}</Typography.Text>
            )}
          </Space>
        </>
      ) : (
        <UiAlert
          title="还没有生成 OpenClaw 插件包。生成后会在本地输出 `agent-supervisor-openclaw-guard` 目录、zip 和说明文档。"
          type="info"
          showIcon
        />
      )}

      {openClawPluginValidation && (
        <PanelCard size="small" type="inner" className="zh-settings-result-panel">
          <Descriptions size="small" column={{ xs: 1, md: 2 }} className="zh-settings-description">
            <Descriptions.Item label="验收状态">
              <LabelTag
                variant="filled"
                color={
                  openClawPluginValidation.validation.overall_status === 'runtime-validated' ||
                  openClawPluginValidation.validation.overall_status === 'static-validated'
                    ? 'success'
                    : 'warning'
                }
              >
                {openClawPluginValidation.validation.overall_status === 'runtime-validated'
                  ? '真实 runtime 通过'
                  : openClawPluginValidation.validation.overall_status === 'static-validated'
                    ? '静态通过'
                    : openClawPluginValidation.validation.overall_status}
              </LabelTag>
            </Descriptions.Item>
            <Descriptions.Item label="文件完整">
              <LabelTag variant="filled" color={openClawPluginValidation.validation.files_passed ? 'success' : 'error'}>
                {openClawPluginValidation.validation.files_passed ? '通过' : '未通过'}
              </LabelTag>
            </Descriptions.Item>
            <Descriptions.Item label="Hook 结构">
              <LabelTag
                variant="filled"
                color={openClawPluginValidation.validation.static_passed ? 'success' : 'error'}
              >
                {openClawPluginValidation.validation.static_passed ? '通过' : '未通过'}
              </LabelTag>
            </Descriptions.Item>
            <Descriptions.Item label="JS 语法">
              <LabelTag
                variant="filled"
                color={openClawPluginValidation.validation.node_syntax_passed ? 'success' : 'error'}
              >
                {openClawPluginValidation.validation.node_syntax_passed ? '通过' : '未通过'}
              </LabelTag>
            </Descriptions.Item>
            <Descriptions.Item label="OpenClaw runtime">
              <LabelTag
                variant="filled"
                color={openClawPluginValidation.validation.runtime_inspect_passed ? 'success' : 'processing'}
              >
                {openClawPluginValidation.validation.runtime_inspect_passed ? '通过' : '待真实环境'}
              </LabelTag>
            </Descriptions.Item>
          </Descriptions>
          <Space orientation="vertical" className="zh-settings-stack zh-settings-stack--mb-16">
            <Space wrap>
              <UiButton size="small" href="/api/integrations/openclaw/plugin_package/validation.md" target="_blank">
                打开验收报告
              </UiButton>
              <UiButton size="small" href="/api/integrations/openclaw/plugin_package/validation" target="_blank">
                打开验收 JSON
              </UiButton>
            </Space>
            <Typography.Text code className="zh-settings-code-wrap">
              {openClawPluginValidation.markdown_path}
            </Typography.Text>
            <Typography.Text code className="zh-settings-code-wrap">
              {openClawPluginValidation.json_path}
            </Typography.Text>
          </Space>
          <Space wrap className="zh-settings-stack--mb-16">
            {Object.entries(openClawPluginValidation.validation.file_checks).map(([key, value]) => (
              <LabelTag variant="filled" key={key} color={value ? 'success' : 'error'}>
                {key}: {value ? '存在' : '缺失'}
              </LabelTag>
            ))}
          </Space>
          {openClawPluginValidation.validation.remaining_gap.length > 0 && (
            <div className="zh-settings-error-text">
              {openClawPluginValidation.validation.remaining_gap.map((gap) => (
                <div key={gap}>{gap}</div>
              ))}
            </div>
          )}
        </PanelCard>
      )}
    </PanelCard>
  );
}
