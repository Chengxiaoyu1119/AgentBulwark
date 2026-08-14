import { Col, Row, Typography } from 'antd';
import { Network } from 'lucide-react';
import { AttackFunctionLab } from './AttackFunctionLab';
import { AttackTestsetLab } from './AttackTestsetLab';
import { AuthorizedTargetLab } from './AuthorizedTargetLab';
import { CapabilityReplayLab } from './CapabilityReplayLab';
import { DualModelJailbreakLab } from './DualModelJailbreakLab';
import { ExperimentControlPanel } from './ExperimentControlPanel';
import type { ExperimentLabProps } from './ExperimentLab.types';
import { ExperimentResultPanel } from './ExperimentResultPanel';
import { JailbreakRedteamLab } from './JailbreakRedteamLab';
import { ModelDrivenAgentLab } from './ModelDrivenAgentLab';
import { PenetrationLearningLab } from './PenetrationLearningLab';
import { RefusalRewriteEvasionLab } from './RefusalRewriteEvasionLab';
import { ScenarioSamplePanel } from './ScenarioSamplePanel';
import { PanelCard, UiButton, UiTabs } from '../ui';

export function ExperimentLab(props: ExperimentLabProps) {
  const auditReplayPanel = (
    <Row gutter={[24, 24]} align="stretch">
      <Col xs={24} lg={8}>
        <div className="zh-lab-side-stack">
          <ExperimentControlPanel
            scenario={props.scenario}
            scenarios={props.scenarios}
            selected={props.selected}
            setSelected={props.setSelected}
            guardEnabled={props.guardEnabled}
            setGuardEnabled={props.setGuardEnabled}
            running={props.running}
            run={props.run}
            compare={props.compare}
            batchCompare={props.batchCompare}
          />
          <ScenarioSamplePanel scenario={props.scenario} />
        </div>
      </Col>

      <Col xs={24} lg={16}>
        <ExperimentResultPanel
          result={props.result}
          compareResult={props.compareResult}
          batchResult={props.batchResult}
        />
      </Col>
    </Row>
  );

  return (
    <UiTabs
      defaultActiveKey="attack-compare"
      className="zh-lab-category-tabs"
      items={[
        {
          key: 'attack-compare',
          label: '单次攻防对照',
          children: (
            <UiTabs
              defaultActiveKey="causal-compare"
              className="zh-lab-sub-tabs"
              items={[
                {
                  key: 'causal-compare',
                  label: '工具调用因果对照',
                  children: <AttackFunctionLab refresh={props.refresh} onOpenAgentChain={props.onOpenAgentChain} />
                },
                {
                  key: 'local-controlled',
                  label: '本地受控环境',
                  children: <PenetrationLearningLab refresh={props.refresh} />
                }
              ]}
            />
          )
        },
        {
          key: 'external-agent-validation',
          label: '真实 Agent 验证',
          children: (
            <UiTabs
              defaultActiveKey="model-driven-agent"
              className="zh-lab-sub-tabs"
              items={[
                {
                  key: 'model-driven-agent',
                  label: '模型驱动完整闭环',
                  children: <ModelDrivenAgentLab refresh={props.refresh} />
                },
                {
                  key: 'authorized-target',
                  label: '外部模型 / Agent 接口',
                  children: <AuthorizedTargetLab refresh={props.refresh} />
                },
                {
                  key: 'capability-replay',
                  label: '核心能力实跑',
                  children: <CapabilityReplayLab refresh={props.refresh} />
                }
              ]}
            />
          )
        },
        {
          key: 'attack-testsets',
          label: '批量回归',
          children: <AttackTestsetLab />
        },
        {
          key: 'advanced-research',
          label: '高级攻击研究',
          children: (
            <div className="zh-lab-research-stack">
              <PanelCard variant="borderless" className="zh-lab-chain-entry">
                <div>
                  <Typography.Text strong>多 Agent 攻击链</Typography.Text>
                  <Typography.Paragraph type="secondary">
                    验证攻击指令在规划、生成、执行等多个 Agent 之间传播时，监督器能否逐阶段阻断并留下证据。
                  </Typography.Paragraph>
                </div>
                <UiButton icon={<Network size={16} />} onClick={props.onOpenAgentChain}>
                  打开攻击链验证
                </UiButton>
              </PanelCard>
              <UiTabs
                defaultActiveKey="jailbreak-redteam"
                className="zh-lab-sub-tabs"
                items={[
                  {
                    key: 'jailbreak-redteam',
                    label: '多技术越狱对测',
                    children: <JailbreakRedteamLab refresh={props.refresh} />
                  },
                  {
                    key: 'dual-model-jailbreak',
                    label: '双模型对抗迭代',
                    children: <DualModelJailbreakLab refresh={props.refresh} />
                  },
                  {
                    key: 'refusal-rewrite-evasion',
                    label: '拒答改写评测',
                    children: <RefusalRewriteEvasionLab refresh={props.refresh} />
                  },
                  {
                    key: 'script-evidence',
                    label: '脚本回放',
                    children: auditReplayPanel
                  }
                ]}
              />
            </div>
          )
        }
      ]}
    />
  );
}
