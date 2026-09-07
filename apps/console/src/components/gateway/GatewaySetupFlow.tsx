import type { ReactNode } from 'react';
import { UiFlex, UiSpace, UiSteps, UiTypography } from '../ui';
import { ArrowLeft, ArrowRight, CircleCheck, CircleDashed, PlugZap, Send, ShieldCheck } from 'lucide-react';
import { CopyButton, PanelCard, UiAlert, UiButton } from '../ui';

export type GatewaySetupReadiness = {
  provider: boolean;
  gateway: boolean;
  toolBoundary: boolean;
};

export function GatewaySetupFlow({
  step,
  onStepChange,
  readiness,
  onOpenSettings,
  onVerify
}: {
  step: number;
  onStepChange: (step: number) => void;
  readiness: GatewaySetupReadiness;
  onOpenSettings: () => void;
  onVerify: () => void;
}) {
  const baseUrl = `${window.location.origin}/v1`;
  const steps = [{ title: '连接模型' }, { title: '修改地址' }, { title: '发送请求' }, { title: '保护工具' }];

  return (
    <div className="zh-setup-flow">
      <UiSteps current={step} items={steps} responsive={false} size="small" />
      <div className="zh-setup-flow__content">
        {step === 0 ? (
          <SetupStep
            icon={readiness.provider ? <CircleCheck size={22} /> : <CircleDashed size={22} />}
            title="先连接真实模型"
            description="智垒把检查通过的请求转发给你的模型服务。密钥只保存在后端，不进入浏览器。"
          >
            <UiAlert
              type={readiness.provider ? 'success' : 'warning'}
              showIcon
              title={readiness.provider ? 'Provider 凭证已配置' : 'Provider 待配置'}
            />
            <UiButton type={readiness.provider ? 'default' : 'primary'} onClick={onOpenSettings}>
              {readiness.provider ? '查看模型设置' : '配置模型连接'}
            </UiButton>
          </SetupStep>
        ) : null}

        {step === 1 ? (
          <SetupStep
            icon={<PlugZap size={22} />}
            title="把应用的模型地址指向智垒"
            description="Base URL 是模型客户端发送请求的入口。模型名和其余代码保持不变。"
          >
            <div className="zh-copy-field">
              <div>
                <UiTypography.Text type="secondary">OpenAI 兼容 Base URL</UiTypography.Text>
                <UiTypography.Text code>{baseUrl}</UiTypography.Text>
              </div>
              <CopyButton text={baseUrl}>复制地址</CopyButton>
            </div>
            <UiAlert
              type="info"
              showIcon
              title="为每个 Agent 使用独立 Token"
              description="操作员登录 Token 只用于控制台，不应写进业务应用。Agent Token 由后端按最小权限单独发放。"
            />
          </SetupStep>
        ) : null}

        {step === 2 ? (
          <SetupStep
            icon={<Send size={22} />}
            title="发送第一条请求"
            description="先发送一个正常请求，再发送一个注入请求。两条请求会立即出现在实时列表中。"
          >
            <UiButton type="primary" onClick={onVerify}>
              打开验证请求
            </UiButton>
          </SetupStep>
        ) : null}

        {step === 3 ? (
          <SetupStep
            icon={<ShieldCheck size={22} />}
            title="最后开启工具执行保护"
            description="模型提出 Tool Call 后，网关会再次检查权限与参数；只有服务端观察到的执行回执才作为事实。"
          >
            <UiAlert
              type={readiness.toolBoundary ? 'success' : 'warning'}
              showIcon
              title={readiness.toolBoundary ? '工具执行边界已闭合' : '工具回执边界待完善'}
            />
            <UiButton onClick={onOpenSettings}>配置工具与数据权限</UiButton>
          </SetupStep>
        ) : null}
      </div>

      <UiFlex justify="space-between" className="zh-setup-flow__footer">
        <UiButton
          icon={<ArrowLeft size={16} />}
          disabled={step === 0}
          onClick={() => onStepChange(Math.max(0, step - 1))}
        >
          上一步
        </UiButton>
        <UiButton
          type="primary"
          icon={step < steps.length - 1 ? <ArrowRight size={16} /> : <CircleCheck size={16} />}
          onClick={() => (step < steps.length - 1 ? onStepChange(step + 1) : onVerify())}
        >
          {step < steps.length - 1 ? '下一步' : '完成并验证'}
        </UiButton>
      </UiFlex>
    </div>
  );
}

function SetupStep({
  icon,
  title,
  description,
  children
}: {
  icon: ReactNode;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <PanelCard variant="borderless" className="zh-setup-step">
      <UiSpace orientation="vertical" size={18} className="zh-full-width">
        <span className="zh-setup-step__icon" aria-hidden="true">
          {icon}
        </span>
        <div>
          <UiTypography.Title level={3}>{title}</UiTypography.Title>
          <UiTypography.Paragraph type="secondary">{description}</UiTypography.Paragraph>
        </div>
        {children}
      </UiSpace>
    </PanelCard>
  );
}
