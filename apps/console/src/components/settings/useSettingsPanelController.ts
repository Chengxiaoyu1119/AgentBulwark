import { useEffect, useState } from 'react';
import {
  evaluateSupervisorBatch,
  evaluateSupervisorEvent,
  fetchAgentIntegrationBundle,
  fetchAttackCaseDataset,
  fetchCompetitionReadiness,
  fetchDemoDrill,
  fetchModelConfig,
  fetchOpenClawIntegrationBundle,
  runDemoDrill,
  runExternalAgentDemo,
  writeCompetitionReadiness,
  updateModelConfig,
  writeOpenClawPluginPackage,
  writeOpenClawPluginValidation
} from '@/api';
import type {
  AgentIntegrationBundle,
  AttackCaseDataset,
  CompetitionReadiness,
  CompetitionReadinessWriteResult,
  DemoDrillResult,
  ExternalAgentDemoResult,
  ModelRuntimeConfig,
  OpenClawIntegrationBundle,
  OpenClawPluginPackageResult,
  OpenClawPluginValidationWriteResult,
  SupervisorBatchEvaluation,
  SupervisorEvaluation
} from '@/types';
import { externalBatchEventSample, externalEventSample } from '@/utils';
import { safeUiErrorSummary } from '@/app/apiRequestSupport';

export function useSettingsPanelController(refresh: () => Promise<unknown>) {
  const [eventJson, setEventJson] = useState(JSON.stringify(externalEventSample, null, 2));
  const [batchJson, setBatchJson] = useState(JSON.stringify(externalBatchEventSample, null, 2));
  const [evaluation, setEvaluation] = useState<SupervisorEvaluation | null>(null);
  const [batchEvaluation, setBatchEvaluation] = useState<SupervisorBatchEvaluation | null>(null);
  const [externalAgentDemo, setExternalAgentDemo] = useState<ExternalAgentDemoResult | null>(null);
  const [attackDataset, setAttackDataset] = useState<AttackCaseDataset | null>(null);
  const [integrationBundle, setIntegrationBundle] = useState<OpenClawIntegrationBundle | null>(null);
  const [agentIntegrationBundle, setAgentIntegrationBundle] = useState<AgentIntegrationBundle | null>(null);
  const [demoDrill, setDemoDrill] = useState<DemoDrillResult | null>(null);
  const [openClawPluginPackage, setOpenClawPluginPackage] = useState<OpenClawPluginPackageResult | null>(null);
  const [openClawPluginValidation, setOpenClawPluginValidation] = useState<OpenClawPluginValidationWriteResult | null>(
    null
  );
  const [competitionReadiness, setCompetitionReadiness] = useState<CompetitionReadiness | null>(null);
  const [competitionReadinessOutput, setCompetitionReadinessOutput] = useState<CompetitionReadinessWriteResult | null>(
    null
  );
  const [modelConfig, setModelConfig] = useState<ModelRuntimeConfig | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [batchEvaluating, setBatchEvaluating] = useState(false);
  const [runningExternalAgentDemo, setRunningExternalAgentDemo] = useState(false);
  const [runningDemoDrill, setRunningDemoDrill] = useState(false);
  const [writingOpenClawPlugin, setWritingOpenClawPlugin] = useState(false);
  const [validatingOpenClawPlugin, setValidatingOpenClawPlugin] = useState(false);
  const [checkingReadiness, setCheckingReadiness] = useState(false);
  const [savingModelConfig, setSavingModelConfig] = useState(false);
  const [evaluateError, setEvaluateError] = useState('');

  useEffect(() => {
    Promise.all([
      fetchAgentIntegrationBundle().then(setAgentIntegrationBundle).catch(ignore),
      fetchModelConfig().then(setModelConfig).catch(ignore)
    ]);
  }, []);

  async function ensureOpenClawIntegration() {
    if (integrationBundle) return integrationBundle;
    const bundle = await fetchOpenClawIntegrationBundle();
    setIntegrationBundle(bundle);
    return bundle;
  }

  async function ensureDeliveryData() {
    const [dataset, drill, readiness] = await Promise.all([
      attackDataset ? Promise.resolve(attackDataset) : fetchAttackCaseDataset(),
      demoDrill ? Promise.resolve(demoDrill) : fetchDemoDrill(),
      competitionReadiness ? Promise.resolve(competitionReadiness) : fetchCompetitionReadiness()
    ]);
    setAttackDataset(dataset);
    setDemoDrill(drill);
    setCompetitionReadiness(readiness);
  }

  async function handleEvaluateEvent() {
    setEvaluating(true);
    setEvaluateError('');
    try {
      const result = await evaluateSupervisorEvent(JSON.parse(eventJson) as Record<string, unknown>);
      setEvaluation(result);
      await refresh();
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, '事件 JSON 解析或监督接口调用失败'));
    } finally {
      setEvaluating(false);
    }
  }

  async function handleBatchEvaluate() {
    setBatchEvaluating(true);
    setEvaluateError('');
    try {
      const events = parseBatchEvents(batchJson);
      const result = await evaluateSupervisorBatch(events);
      setBatchEvaluation(result);
      await refresh();
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, '批量事件 JSON 解析或监督接口调用失败'));
    } finally {
      setBatchEvaluating(false);
    }
  }

  async function handleRunExternalAgentDemo() {
    setRunningExternalAgentDemo(true);
    setEvaluateError('');
    try {
      setExternalAgentDemo(await runExternalAgentDemo());
      await refresh();
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, '外部 Agent 验证运行失败'));
    } finally {
      setRunningExternalAgentDemo(false);
    }
  }

  async function handleRunDemoDrill() {
    setRunningDemoDrill(true);
    setEvaluateError('');
    try {
      const demoResult = await runDemoDrill();
      setDemoDrill(demoResult);
      const readinessResult = await writeCompetitionReadiness();
      setCompetitionReadinessOutput(readinessResult);
      setCompetitionReadiness(readinessResult.readiness);
      await refresh();
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, '闭环复现实验运行失败'));
    } finally {
      setRunningDemoDrill(false);
    }
  }

  async function handleWriteOpenClawPlugin() {
    setWritingOpenClawPlugin(true);
    setEvaluateError('');
    try {
      setOpenClawPluginPackage(await writeOpenClawPluginPackage());
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, 'OpenClaw 插件包生成失败'));
    } finally {
      setWritingOpenClawPlugin(false);
    }
  }

  async function handleValidateOpenClawPlugin() {
    setValidatingOpenClawPlugin(true);
    setEvaluateError('');
    try {
      const result = await writeOpenClawPluginValidation();
      setOpenClawPluginValidation(result);
      setOpenClawPluginPackage(result.validation.package);
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, 'OpenClaw 插件包验收失败'));
    } finally {
      setValidatingOpenClawPlugin(false);
    }
  }

  async function handleRunReadiness() {
    setCheckingReadiness(true);
    setEvaluateError('');
    try {
      const result = await writeCompetitionReadiness();
      setCompetitionReadinessOutput(result);
      setCompetitionReadiness(result.readiness);
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, 'AI Agent 安全就绪检查运行失败'));
    } finally {
      setCheckingReadiness(false);
    }
  }

  async function handleSaveModelConfig() {
    if (!modelConfig) {
      return;
    }
    setSavingModelConfig(true);
    setEvaluateError('');
    try {
      const result = await updateModelConfig({
        real_api_enabled: modelConfig.real_api_enabled,
        profiles: modelConfig.profiles
      });
      setModelConfig(result);
      await refresh();
    } catch (error) {
      setEvaluateError(safeUiErrorSummary(error, '模型运行配置保存失败'));
    } finally {
      setSavingModelConfig(false);
    }
  }

  function loadSingleExternalSample() {
    setEventJson(JSON.stringify(externalEventSample, null, 2));
    setEvaluation(null);
    setEvaluateError('');
  }

  function loadBatchExternalSample() {
    setBatchJson(JSON.stringify(externalBatchEventSample, null, 2));
    setBatchEvaluation(null);
    setEvaluateError('');
  }

  function clearExternalResults() {
    setEvaluation(null);
    setBatchEvaluation(null);
    setExternalAgentDemo(null);
    setOpenClawPluginPackage(null);
    setOpenClawPluginValidation(null);
    setCompetitionReadinessOutput(null);
    setEvaluateError('');
  }

  return {
    state: {
      agentIntegrationBundle,
      attackDataset,
      batchEvaluation,
      batchEvaluating,
      batchJson,
      checkingReadiness,
      competitionReadiness,
      competitionReadinessOutput,
      demoDrill,
      evaluateError,
      evaluating,
      evaluation,
      eventJson,
      externalAgentDemo,
      integrationBundle,
      modelConfig,
      openClawPluginPackage,
      openClawPluginValidation,
      runningDemoDrill,
      runningExternalAgentDemo,
      savingModelConfig,
      validatingOpenClawPlugin,
      writingOpenClawPlugin
    },
    actions: {
      clearExternalResults,
      handleBatchEvaluate,
      handleEvaluateEvent,
      ensureDeliveryData,
      ensureOpenClawIntegration,
      handleRunDemoDrill,
      handleRunExternalAgentDemo,
      handleRunReadiness,
      handleSaveModelConfig,
      handleValidateOpenClawPlugin,
      handleWriteOpenClawPlugin,
      loadBatchExternalSample,
      loadSingleExternalSample,
      setBatchJson,
      setEventJson,
      setEvaluateError,
      setModelConfig
    }
  };
}

function parseBatchEvents(rawJson: string): Record<string, unknown>[] {
  const parsed = JSON.parse(rawJson) as unknown;
  const events = Array.isArray(parsed)
    ? parsed
    : typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as { events?: unknown }).events)
      ? (parsed as { events: unknown[] }).events
      : null;
  if (!events) {
    throw new Error('批量事件必须是 JSON 数组，或形如 { "events": [...] } 的对象。');
  }
  return events as Record<string, unknown>[];
}

function ignore() {
  return undefined;
}
