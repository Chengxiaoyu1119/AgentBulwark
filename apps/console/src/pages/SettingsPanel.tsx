import { Collapse, Typography } from 'antd';
import { useState } from 'react';
import {
  DemoReadinessTab,
  ExternalIntegrationTab,
  SettingsBasicsTab,
  SupervisorDebugTab
} from '../components/settings';
import { useSettingsPanelController } from '../components/settings/useSettingsPanelController';
import { UiTabs } from '../components/ui';
import type { Overview } from '../types';

export function SettingsPanel({ overview, refresh }: { overview: Overview; refresh: () => Promise<unknown> }) {
  const { state, actions } = useSettingsPanelController(refresh);
  const [advancedKeys, setAdvancedKeys] = useState<string[]>([]);

  return (
    <div className="zh-page-stack">
      <Typography.Title level={2}>Agent接入与系统设置</Typography.Title>
      <UiTabs
        className="zh-settings-tabs"
        defaultActiveKey="integration"
        size="large"
        items={[
          {
            key: 'integration',
            label: 'Agent 运行时接入',
            children: (
              <ExternalIntegrationTab
                integrationBundle={state.integrationBundle}
                agentIntegrationBundle={state.agentIntegrationBundle}
                openClawPluginPackage={state.openClawPluginPackage}
                openClawPluginValidation={state.openClawPluginValidation}
                writingOpenClawPlugin={state.writingOpenClawPlugin}
                validatingOpenClawPlugin={state.validatingOpenClawPlugin}
                handleWriteOpenClawPlugin={actions.handleWriteOpenClawPlugin}
                handleValidateOpenClawPlugin={actions.handleValidateOpenClawPlugin}
                ensureOpenClawIntegration={actions.ensureOpenClawIntegration}
              />
            )
          },
          {
            key: 'models',
            label: '模型连接',
            children: (
              <SettingsBasicsTab
                overview={overview}
                modelConfig={state.modelConfig}
                savingModelConfig={state.savingModelConfig}
                onModelConfigChange={actions.setModelConfig}
                onSaveModelConfig={actions.handleSaveModelConfig}
              />
            )
          },
          {
            key: 'advanced',
            label: '高级工具',
            children: (
              <Collapse
                activeKey={advancedKeys}
                onChange={(keys) => {
                  const nextKeys = Array.isArray(keys) ? keys.map(String) : [String(keys)];
                  setAdvancedKeys(nextKeys);
                  if (nextKeys.includes('delivery')) {
                    void actions.ensureDeliveryData();
                  }
                }}
                items={[
                  {
                    key: 'debug',
                    label: '接口调试',
                    children: (
                      <SupervisorDebugTab
                        externalAgentDemo={state.externalAgentDemo}
                        runningExternalAgentDemo={state.runningExternalAgentDemo}
                        handleRunExternalAgentDemo={actions.handleRunExternalAgentDemo}
                        eventJson={state.eventJson}
                        setEventJson={actions.setEventJson}
                        batchJson={state.batchJson}
                        setBatchJson={actions.setBatchJson}
                        evaluation={state.evaluation}
                        batchEvaluation={state.batchEvaluation}
                        evaluating={state.evaluating}
                        batchEvaluating={state.batchEvaluating}
                        evaluateError={state.evaluateError}
                        handleEvaluateEvent={actions.handleEvaluateEvent}
                        handleBatchEvaluate={actions.handleBatchEvaluate}
                        loadSingleExternalSample={actions.loadSingleExternalSample}
                        loadBatchExternalSample={actions.loadBatchExternalSample}
                        clearExternalResults={actions.clearExternalResults}
                      />
                    )
                  },
                  {
                    key: 'delivery',
                    label: '可复现验证与交付核验',
                    children: (
                      <DemoReadinessTab
                        overview={overview}
                        attackDataset={state.attackDataset}
                        demoDrill={state.demoDrill}
                        runningDemoDrill={state.runningDemoDrill}
                        handleRunDemoDrill={actions.handleRunDemoDrill}
                        competitionReadiness={state.competitionReadiness}
                        competitionReadinessOutput={state.competitionReadinessOutput}
                        checkingReadiness={state.checkingReadiness}
                        handleRunReadiness={actions.handleRunReadiness}
                      />
                    )
                  }
                ]}
              />
            )
          }
        ]}
      />
    </div>
  );
}
