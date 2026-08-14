import { useEffect, useMemo, useRef, useState } from 'react';
import { Play } from 'lucide-react';
import { Col, Descriptions, Divider, Row, Space, Typography } from 'antd';
import { fetchAttackLabModules, runAttackLabModule } from '../../api';
import type { AttackLabModule, AttackLabRunResult } from '../../types';
import { DecisionPill, LabelTag, MetricCard, PanelCard, UiAlert, UiButton, UiInput, UiSelect, UiSwitch } from '../ui';
import { DEFAULT_ATTACK_LAB_MODULES } from './attackFunctionModules';
import { AttackComparisonHero } from './AttackComparisonHero';
import { AttackEvidenceTimeline } from './AttackEvidenceTimeline';
import { AttackModuleOptionsPanel } from './AttackModuleOptionsPanel';
import { AuditDeepLinkButton } from '../audit/AuditDeepLinkButton';
import { defaultAttackModuleOptions, type AttackModuleOptions } from './attackModuleOptions';
import { attackFunctionIcons, fallbackAttackFunctionIcon } from './attackFunctionIcons';
import { attackFunctionFlowSteps } from './labRuntimeFlowPresets';
import { LabModulePicker } from './LabModulePicker';
import { LabRuntimeFlow } from './LabRuntimeFlow';
import { ResultRunButton, RunResultEmptyState } from './RunResultActions';
import { CustomAttackWorkspace } from './CustomAttackWorkspace';

type AttackFunctionLabProps = {
  refresh?: () => Promise<unknown>;
  onOpenAgentChain?: () => void;
};

export function AttackFunctionLab({ refresh, onOpenAgentChain }: AttackFunctionLabProps) {
  const [modules, setModules] = useState<AttackLabModule[]>(DEFAULT_ATTACK_LAB_MODULES);
  const [selectedSurface, setSelectedSurface] = useState(DEFAULT_ATTACK_LAB_MODULES[0].surface_id);
  const [attackInput, setAttackInput] = useState(DEFAULT_ATTACK_LAB_MODULES[0].default_input);
  const [moduleOptions, setModuleOptions] = useState<AttackModuleOptions>(
    defaultAttackModuleOptions(DEFAULT_ATTACK_LAB_MODULES[0].surface_id)
  );
  const [executeInSandbox, setExecuteInSandbox] = useState(true);
  const [plannerMode, setPlannerMode] = useState<'fixed' | 'model'>('fixed');
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState('');
  const [result, setResult] = useState<AttackLabRunResult | null>(null);
  const comparisonRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let mounted = true;
    fetchAttackLabModules()
      .then((response) => {
        if (!mounted) return;
        if (response.modules.length) setModules(response.modules);
        const first = response.modules[0];
        if (first) {
          setSelectedSurface(first.surface_id);
          setAttackInput(first.default_input);
          setModuleOptions(defaultAttackModuleOptions(first.surface_id));
        }
      })
      .catch(() => {
        if (mounted) setNotice('后端未连接时只能查看模块说明，运行实验需要启动智安哨后端。');
      });
    return () => {
      mounted = false;
    };
  }, []);

  const activeModule = useMemo(
    () => modules.find((module) => module.surface_id === selectedSurface) ?? modules[0],
    [modules, selectedSurface]
  );

  function selectModule(module: AttackLabModule) {
    setSelectedSurface(module.surface_id);
    setAttackInput(module.default_input);
    setModuleOptions(defaultAttackModuleOptions(module.surface_id));
    setResult(null);
    setNotice('');
  }

  function selectModuleById(surfaceId: string) {
    const module = modules.find((item) => item.surface_id === surfaceId);
    if (module) selectModule(module);
  }

  async function runModule() {
    if (!activeModule) return;
    setRunning(true);
    setNotice('');
    try {
      const nextResult = await runAttackLabModule({
        surface_id: activeModule.surface_id,
        attack_input: attackInput,
        execute_in_sandbox: executeInSandbox,
        planner_mode: plannerMode,
        force_real_model: plannerMode === 'model',
        options: moduleOptions
      });
      setResult(nextResult);
      await refresh?.();
      window.requestAnimationFrame(() => comparisonRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
    } catch (error) {
      setNotice(`攻击实验运行失败：${error instanceof Error ? error.message : '未知错误'}`);
    } finally {
      setRunning(false);
    }
  }

  if (!activeModule) {
    return <UiAlert type="warning" showIcon title="暂无攻击功能模块。" />;
  }

  return (
    <div className="zh-attack-lab">
      {notice && <UiAlert type="warning" showIcon title={notice} className="zh-mb-24" />}
      <CustomAttackWorkspace refresh={refresh} onOpenAgentChain={onOpenAgentChain} onNotice={setNotice} />
      {result ? (
        <div ref={comparisonRef} className="zh-comparison-anchor">
          <AttackComparisonHero result={result} />
        </div>
      ) : null}
      <div className="zh-custom-attack-regression-heading">
        <div>
          <Typography.Title level={4}>预置回归样本</Typography.Title>
          <Typography.Paragraph type="secondary">
            以下 7 类固定场景用于版本回归和稳定复现；上方自定义入口才是用户直接提交 Payload、工具与命令的主功能。
          </Typography.Paragraph>
        </div>
        <LabelTag color="default">辅助验证</LabelTag>
      </div>
      <Row gutter={[20, 20]} align="stretch">
        <Col xs={24} xl={7}>
          <LabModulePicker
            title="攻击功能"
            subtitle={`${modules.length} 类可运行攻击面`}
            items={modules.map((module) => ({
              id: module.surface_id,
              title: module.name,
              subtitle: module.tool,
              icon: attackFunctionIcons[module.surface_id] ?? fallbackAttackFunctionIcon
            }))}
            activeId={activeModule.surface_id}
            onSelect={selectModuleById}
          />
        </Col>

        <Col xs={24} xl={9}>
          <PanelCard
            title={`${activeModule.name}攻防验证`}
            subtitle={`${activeModule.target} · ${activeModule.tool}`}
            className="zh-attack-lab__input-panel"
          >
            <Space orientation="vertical" size={16} className="zh-full-width">
              <div className="zh-attack-lab__field">
                <Typography.Text strong>工具调用生成方式</Typography.Text>
                <UiSelect
                  value={plannerMode}
                  onChange={(value) => setPlannerMode(value)}
                  options={[
                    { label: '固定规划（稳定复现攻防因果）', value: 'fixed' },
                    { label: '真实模型规划（验证模型自主调用）', value: 'model' }
                  ]}
                />
              </div>
              {plannerMode === 'model' && (
                <UiAlert
                  type="info"
                  showIcon
                  message="运行时优先调用后端配置的大模型生成工具调用；结果会明确标记模型来源，固定规划结果不作为真实模型证据。真实模型请求最长等待 180 秒，运行期间不要重复点击。"
                />
              )}
              <LabRuntimeFlow compact steps={attackFunctionFlowSteps(plannerMode, executeInSandbox)} />
              <div className="zh-attack-lab__field">
                <Typography.Text strong>攻击输入</Typography.Text>
                <UiInput.TextArea
                  value={attackInput}
                  onChange={(event) => setAttackInput(event.target.value)}
                  rows={8}
                  showCount
                  maxLength={12000}
                />
              </div>
              <PanelCard title="可编辑工具参数" subtitle={activeModule.tool} type="inner">
                <AttackModuleOptionsPanel
                  surfaceId={activeModule.surface_id}
                  value={moduleOptions}
                  onChange={setModuleOptions}
                />
              </PanelCard>
              <div className="zh-attack-lab__switch-row">
                <div>
                  <Typography.Text strong>受控业务环境执行</Typography.Text>
                  <Typography.Paragraph type="secondary" className="zh-attack-lab__hint">
                    两组运行使用独立环境副本，邮件、文件、API、命令和记忆变化会分别记录并生成状态Hash。
                  </Typography.Paragraph>
                </div>
                <UiSwitch checked={executeInSandbox} onChange={setExecuteInSandbox} />
              </div>
              <UiButton type="primary" icon={<Play size={16} />} loading={running} onClick={runModule}>
                运行攻防验证
              </UiButton>
            </Space>
          </PanelCard>
        </Col>

        <Col xs={24} xl={8}>
          <PanelCard
            title="本次运行结论"
            subtitle={result ? `证据编号 ${result.comparison_id.slice(0, 8)}` : '等待运行'}
            className="zh-full-height"
            extra={
              <ResultRunButton
                hasResult={Boolean(result)}
                idleLabel="运行"
                rerunLabel="重新运行"
                loading={running}
                onClick={runModule}
              />
            }
          >
            {result ? (
              <Space orientation="vertical" size={14} className="zh-full-width">
                <Row gutter={[12, 12]} align="stretch">
                  <Col xs={12} sm={12}>
                    <MetricCard
                      label="关闭防护"
                      value={result.summary.exposed_without_guard ? '攻击成功' : '攻击未成功'}
                      tone={result.summary.exposed_without_guard ? 'red' : 'green'}
                    />
                  </Col>
                  <Col xs={12} sm={12}>
                    <MetricCard
                      label="启用防护"
                      value={result.summary.controlled_with_guard ? '风险已控制' : '仍有风险'}
                      tone={result.summary.controlled_with_guard ? 'green' : 'red'}
                    />
                  </Col>
                </Row>
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="生成方式">{result.module.planner_mode}</Descriptions.Item>
                  <Descriptions.Item label="规划器">
                    {result.model_plan.provider} {result.model_plan.model}
                  </Descriptions.Item>
                  <Descriptions.Item label="模型证据">
                    <LabelTag color={result.model_evidence?.valid ? 'success' : 'warning'}>
                      {result.model_evidence?.status ??
                        (result.module.planner_mode === 'model' ? '历史结果未记录' : 'fixed')}
                    </LabelTag>
                  </Descriptions.Item>
                  <Descriptions.Item label="无防护决策">
                    <DecisionPill decision={result.without_guard.decision} />
                  </Descriptions.Item>
                  <Descriptions.Item label="监督器决策">
                    <DecisionPill decision={result.with_guard.decision} />
                  </Descriptions.Item>
                  <Descriptions.Item label="命中策略">{result.summary.policy_id}</Descriptions.Item>
                  <Descriptions.Item label="风险分">{result.summary.risk_score}</Descriptions.Item>
                </Descriptions>
                <Divider className="zh-attack-lab__divider" />
                <div className="zh-attack-lab__explain-list">
                  {result.explanation.map((item) => (
                    <div key={item.title} className="zh-attack-lab__explain-item">
                      <LabelTag color="blue">{item.title}</LabelTag>
                      <Typography.Text>{item.text}</Typography.Text>
                    </div>
                  ))}
                </div>
              </Space>
            ) : (
              <RunResultEmptyState
                icon={<Play size={28} />}
                title="等待运行攻防验证"
                description="系统会复制同一个初始环境，分别执行关闭防护和启用防护两条链路，展示攻击副作用与阻断证据。"
                actionLabel="运行攻防验证"
                loading={running}
                onAction={runModule}
              />
            )}
          </PanelCard>
        </Col>
      </Row>

      {result && (
        <Row gutter={[20, 20]} className="zh-attack-lab__evidence-row">
          <Col xs={24} lg={14}>
            <AttackEvidenceTimeline result={result} />
          </Col>
          <Col xs={24} lg={10}>
            <PanelCard
              title="监督证据"
              subtitle={result.with_guard.audit_id}
              extra={<AuditDeepLinkButton auditId={result.with_guard.audit_id} size="small" />}
            >
              <Descriptions column={1} size="small">
                <Descriptions.Item label="处置方式">{result.summary.execution_mode}</Descriptions.Item>
                <Descriptions.Item label="判定原因">{result.with_guard.reason}</Descriptions.Item>
                <Descriptions.Item label="防御建议">{result.with_guard.recommendation}</Descriptions.Item>
                <Descriptions.Item label="上下文来源">{result.context_sources.join(', ')}</Descriptions.Item>
              </Descriptions>
            </PanelCard>
          </Col>
        </Row>
      )}
    </div>
  );
}
