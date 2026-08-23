import { useMemo, useState } from 'react';
import { Drawer, Flex, Space, Steps, Typography } from 'antd';
import { ArrowLeft, ArrowRight, CircleCheck, CircleDashed, PlugZap, Send, ShieldCheck } from 'lucide-react';
import { CopyButton, LabelTag, PanelCard, UiAlert, UiButton } from '../components/ui';
import { GatewayEvidencePanel } from '../components/settings/GatewayEvidencePanel';
import { GatewayRequestPanel, GatewayRequestPresets } from '../components/settings/GatewayRequestPanel';
import { GatewayTracePanel } from '../components/settings/GatewayTracePanel';
import { useGatewayPanelController } from '../app/useGatewayPanelController';

type DrawerMode = 'setup' | 'verify' | null;

export function GatewayPanel({ onOpenSettings }: { onOpenSettings?: () => void }) {
  const [drawerMode, setDrawerMode] = useState<DrawerMode>(null);
  const [setupStep, setSetupStep] = useState(0);
  const controller = useGatewayPanelController();
  const {
    payload,
    setPayload,
    result,
    error,
    loading,
    executingTool,
    executionResult,
    executionError,
    followupResult,
    followingUp,
    runtimeStatus,
    sessionId,
    setSessionId,
    managedMode,
    setManagedMode,
    metadata,
    canExecuteManagedTools,
    decision,
    blocked,
    toolDecisions,
    toolDefinitionFindings,
    toolArgumentFindings,
    toolResultFindings,
    executableToolDecision,
    responsePreview,
    sendRequest,
    executeToolCall,
    followupToolResult
  } = controller;

  const readiness = useMemo(() => {
    const provider = Boolean(
      runtimeStatus?.models?.target?.some((item) => item.configured && item.mode === 'real-api')
    );
    const gateway = runtimeStatus?.proxy?.enabled === true && Boolean(runtimeStatus?.gateway_evidence?.fingerprint);
    const toolBoundary =
      runtimeStatus?.proxy?.tool_receipts_required === true &&
      runtimeStatus.proxy.server_observed_receipts_required === true;
    return { provider, gateway, toolBoundary };
  }, [runtimeStatus]);

  const protectionReady = readiness.provider && readiness.gateway;

  return (
    <div className="zh-product-page">
      <header className="zh-product-heading">
        <div>
          <Flex align="center" gap={10} wrap="wrap">
            <Typography.Title level={1}>请求防护</Typography.Title>
            <LabelTag color={protectionReady ? 'green' : 'warning'}>
              {protectionReady ? '防护运行中' : '等待接入'}
            </LabelTag>
          </Flex>
          <Typography.Text type="secondary">实时查看请求如何被放行、阻断或隔离。</Typography.Text>
        </div>
        <Flex gap={10} wrap="wrap">
          <UiButton icon={<Send size={16} />} onClick={() => setDrawerMode('verify')}>
            验证防护
          </UiButton>
          <UiButton type="primary" icon={<PlugZap size={16} />} onClick={() => setDrawerMode('setup')}>
            接入应用
          </UiButton>
        </Flex>
      </header>

      <GatewayTracePanel
        refreshSignal={String(metadata.request_id || metadata.gateway_evidence_fingerprint || '')}
        onCreateRequest={() => setDrawerMode('verify')}
      />

      <Drawer
        title={drawerMode === 'setup' ? '接入应用' : '验证一条真实请求'}
        size="large"
        open={drawerMode !== null}
        onClose={() => setDrawerMode(null)}
        destroyOnHidden
        className="zh-workflow-drawer"
      >
        {drawerMode === 'setup' ? (
          <SetupFlow
            step={setupStep}
            onStepChange={setSetupStep}
            readiness={readiness}
            onOpenSettings={() => {
              setDrawerMode(null);
              onOpenSettings?.();
            }}
            onVerify={() => setDrawerMode('verify')}
          />
        ) : (
          <div className="zh-verify-workflow">
            <Flex justify="space-between" align="center" gap={12} wrap="wrap">
              <Typography.Text type="secondary">选择一个请求，也可以直接编辑 JSON。</Typography.Text>
              <GatewayRequestPresets onSelect={setPayload} />
            </Flex>
            <GatewayRequestPanel
              payload={payload}
              onPayloadChange={setPayload}
              sessionId={sessionId}
              onSessionIdChange={setSessionId}
              managedMode={managedMode}
              onManagedModeChange={setManagedMode}
              canGenerate={runtimeStatus?.security_context?.can_generate}
              canExecuteManagedTools={canExecuteManagedTools}
              identityText={
                runtimeStatus?.security_context
                  ? `当前身份：${runtimeStatus.security_context.role || 'unknown'} / ${
                      runtimeStatus.security_context.agent_id || '未绑定 Agent'
                    }`
                  : undefined
              }
              loading={loading}
              error={error}
              onSubmit={() => void sendRequest()}
            />
            {result ? (
              <GatewayEvidencePanel
                result={result}
                metadata={metadata}
                blocked={blocked}
                decision={decision}
                toolDecisions={toolDecisions}
                toolDefinitionFindings={toolDefinitionFindings}
                toolArgumentFindings={toolArgumentFindings}
                toolResultFindings={toolResultFindings}
                responsePreview={responsePreview}
                executableToolDecision={executableToolDecision}
                executionResult={executionResult}
                executionError={executionError}
                executingTool={executingTool}
                onExecuteTool={() => void executeToolCall()}
                followupResult={followupResult}
                followingUp={followingUp}
                onFollowupToolResult={() => void followupToolResult()}
              />
            ) : null}
          </div>
        )}
      </Drawer>
    </div>
  );
}

function SetupFlow({
  step,
  onStepChange,
  readiness,
  onOpenSettings,
  onVerify
}: {
  step: number;
  onStepChange: (step: number) => void;
  readiness: { provider: boolean; gateway: boolean; toolBoundary: boolean };
  onOpenSettings: () => void;
  onVerify: () => void;
}) {
  const baseUrl = `${window.location.origin}/v1`;
  const steps = [{ title: '连接模型' }, { title: '修改地址' }, { title: '发送请求' }, { title: '保护工具' }];

  return (
    <div className="zh-setup-flow">
      <Steps current={step} items={steps} responsive={false} size="small" />
      <div className="zh-setup-flow__content">
        {step === 0 ? (
          <SetupStep
            icon={readiness.provider ? <CircleCheck size={22} /> : <CircleDashed size={22} />}
            title="先连接真实模型"
            description="智安哨把检查通过的请求转发给你的模型服务。密钥只保存在后端，不进入浏览器。"
          >
            <UiAlert
              type={readiness.provider ? 'success' : 'warning'}
              showIcon
              title={readiness.provider ? 'Provider 已连接' : '还没有可用的 Provider'}
            />
            <UiButton type={readiness.provider ? 'default' : 'primary'} onClick={onOpenSettings}>
              {readiness.provider ? '查看模型设置' : '去连接模型'}
            </UiButton>
          </SetupStep>
        ) : null}

        {step === 1 ? (
          <SetupStep
            icon={<PlugZap size={22} />}
            title="把应用的模型地址指向智安哨"
            description="Base URL 是模型客户端发送请求的入口。模型名和其余代码保持不变。"
          >
            <div className="zh-copy-field">
              <div>
                <Typography.Text type="secondary">OpenAI 兼容 Base URL</Typography.Text>
                <Typography.Text code>{baseUrl}</Typography.Text>
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
              title={readiness.toolBoundary ? '工具执行边界已闭合' : '工具回执仍处于兼容或未配置状态'}
            />
            <UiButton onClick={onOpenSettings}>配置工具与数据权限</UiButton>
          </SetupStep>
        ) : null}
      </div>

      <Flex justify="space-between" className="zh-setup-flow__footer">
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
      </Flex>
    </div>
  );
}

function SetupStep({
  icon,
  title,
  description,
  children
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <PanelCard variant="borderless" className="zh-setup-step">
      <Space orientation="vertical" size={18} className="zh-full-width">
        <span className="zh-setup-step__icon" aria-hidden="true">
          {icon}
        </span>
        <div>
          <Typography.Title level={3}>{title}</Typography.Title>
          <Typography.Paragraph type="secondary">{description}</Typography.Paragraph>
        </div>
        {children}
      </Space>
    </PanelCard>
  );
}
