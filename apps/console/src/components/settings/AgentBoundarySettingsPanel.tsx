import { Col, Collapse, Flex, Row, Switch, Typography } from 'antd';
import type { PolicySettings } from '@/types';
import { PanelCard, UiButton, UiSelect } from '../ui';
import { AgentApiAllowlistEditor } from './AgentApiAllowlistEditor';
import { AgentContextAllowlistEditor } from './AgentContextAllowlistEditor';
import { AgentModelAllowlistEditor } from './AgentModelAllowlistEditor';
import { AgentToolAllowlistEditor } from './AgentToolAllowlistEditor';
import { AgentToolMappingEditor } from './AgentToolMappingEditor';

type Props = {
  policySettings: PolicySettings | null;
  canEdit: boolean;
  saving: boolean;
  onPatch: (patch: Partial<PolicySettings>) => void;
  onSave: () => void | Promise<void>;
};

export function AgentBoundarySettingsPanel({ policySettings, canEdit, saving, onPatch, onSave }: Props) {
  const mappingCount = Object.values(policySettings?.agent_tool_mappings ?? {}).reduce(
    (total, mappings) => total + Object.keys(mappings).length,
    0
  );
  return (
    <PanelCard title="业务安全边界" subtitle="先关闭未登记能力，再按 Agent 精确放行。">
      <Typography.Paragraph type="secondary">
        配置内部邮箱域、敏感路径和高敏 API 边界。生产 Agent 应先登记能力，再发放绑定 Token。
      </Typography.Paragraph>
      <Row gutter={[16, 16]} className="zh-mb-16">
        <Col xs={24} md={12}>
          <RegistrationSwitch
            checked={Boolean(policySettings?.require_agent_capability_registration)}
            disabled={!canEdit}
            onChange={(checked) => onPatch({ require_agent_capability_registration: checked })}
            title="未登记 Agent 工具默认拒绝"
            description="开启后，Agent 必须命中工具白名单；未登记身份不会继承默认放行。"
          />
        </Col>
        <Col xs={24} md={12}>
          <RegistrationSwitch
            checked={Boolean(policySettings?.require_agent_context_registration)}
            disabled={!canEdit}
            onChange={(checked) => onPatch({ require_agent_context_registration: checked })}
            title="未登记 Agent MCP 上下文默认拒绝"
            description="开启后，resources/prompts 只能读取当前 Agent 的上下文白名单。"
          />
        </Col>
        <Col xs={24} md={12}>
          <RegistrationSwitch
            checked={Boolean(policySettings?.require_agent_model_registration)}
            disabled={!canEdit}
            onChange={(checked) => onPatch({ require_agent_model_registration: checked })}
            title="未登记 Agent 模型默认拒绝"
            description="开启后，透明代理只能选择该 Agent 的模型白名单。"
          />
        </Col>
      </Row>
      <Row gutter={[16, 16]}>
        <BoundarySelect
          label="内部邮箱域"
          value={policySettings?.internal_email_domains ?? []}
          placeholder="例如 company.example"
          disabled={!canEdit}
          onChange={(value) => onPatch({ internal_email_domains: value.map(String) })}
        />
        <BoundarySelect
          label="敏感路径标记"
          value={policySettings?.sensitive_path_markers ?? []}
          placeholder="例如 vault、credentials"
          disabled={!canEdit}
          onChange={(value) => onPatch({ sensitive_path_markers: value.map(String) })}
        />
        <BoundarySelect
          label="高敏 API 标记"
          value={policySettings?.sensitive_api_markers ?? []}
          placeholder="例如 payroll、admin"
          disabled={!canEdit}
          onChange={(value) => onPatch({ sensitive_api_markers: value.map(String) })}
        />
      </Row>
      <Collapse
        className="zh-permission-collapse"
        items={[
          {
            key: 'allowlists',
            label: 'Agent 工具最小权限',
            children: (
              <div className="zh-settings-column">
                <AgentToolAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentApiAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentModelAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentContextAllowlistEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
                <AgentToolMappingEditor policySettings={policySettings} canEdit={canEdit} onPatch={onPatch} />
              </div>
            )
          }
        ]}
      />
      <Flex justify="space-between" align="center" wrap="wrap" gap={12} className="zh-mt-16">
        <Typography.Text type="secondary">
          已登记 {Object.keys(policySettings?.agent_tool_allowlists ?? {}).length} 个 Agent，{mappingCount} 条工具映射。
        </Typography.Text>
        <UiButton type="primary" loading={saving} disabled={!canEdit} onClick={() => void onSave()}>
          保存业务边界
        </UiButton>
      </Flex>
    </PanelCard>
  );
}

function RegistrationSwitch({
  checked,
  disabled,
  onChange,
  title,
  description
}: {
  checked: boolean;
  disabled: boolean;
  onChange: (checked: boolean) => void;
  title: string;
  description: string;
}) {
  return (
    <div className="zh-settings-switch-row">
      <Switch checked={checked} disabled={disabled} onChange={onChange} />
      <div>
        <Typography.Text strong>{title}</Typography.Text>
        <Typography.Paragraph type="secondary" className="zh-mb-0">
          {description}
        </Typography.Paragraph>
      </div>
    </div>
  );
}

function BoundarySelect({
  label,
  value,
  placeholder,
  disabled,
  onChange
}: {
  label: string;
  value: string[];
  placeholder: string;
  disabled: boolean;
  onChange: (value: unknown[]) => void;
}) {
  return (
    <Col xs={24} lg={8}>
      <Typography.Text type="secondary" className="zh-meta-block">
        {label}
      </Typography.Text>
      <UiSelect
        mode="tags"
        value={value}
        onChange={onChange}
        className="zh-full-width"
        placeholder={placeholder}
        disabled={disabled}
      />
    </Col>
  );
}
