import type { Dispatch, SetStateAction } from 'react';
import { useCallback } from 'react';
import { batchCompareScenarios, compareAttackChain, compareScenario, runAttackChain, runScenario } from '../api';
import type {
  AttackChain,
  AttackChainCompareResult,
  AttackChainRunResult,
  BatchCompareResult,
  CompareResult,
  RunResult,
  Scenario
} from '../types';
import type { PageKey } from './navigation';
import { safeUiErrorSummary } from './apiRequestSupport';

type UseAppActionsOptions = {
  setPage: (page: PageKey) => void;
  scenarios: Scenario[];
  activeScenario: Scenario | undefined;
  guardEnabled: boolean;
  setGuardEnabled: Dispatch<SetStateAction<boolean>>;
  attackChains: AttackChain[];
  selectedAttackChain: string;
  setSelectedScenario: Dispatch<SetStateAction<string>>;
  setLastResult: Dispatch<SetStateAction<RunResult | null>>;
  setCompareResult: Dispatch<SetStateAction<CompareResult | null>>;
  setBatchResult: Dispatch<SetStateAction<BatchCompareResult | null>>;
  setAttackChainResult: Dispatch<SetStateAction<AttackChainRunResult | null>>;
  setAttackChainCompareResult: Dispatch<SetStateAction<AttackChainCompareResult | null>>;
  setRunning: Dispatch<SetStateAction<boolean>>;
  setApiNotice: Dispatch<SetStateAction<string>>;
  refresh: () => Promise<unknown>;
};

export function useAppActions({
  setPage,
  scenarios,
  activeScenario,
  guardEnabled,
  setGuardEnabled,
  attackChains,
  selectedAttackChain,
  setSelectedScenario,
  setLastResult,
  setCompareResult,
  setBatchResult,
  setAttackChainResult,
  setAttackChainCompareResult,
  setRunning,
  setApiNotice,
  refresh
}: UseAppActionsOptions) {
  const handleRunScenario = useCallback(
    async (scenarioId: string, compare = false) => {
      if (!scenarioId) return;
      setRunning(true);
      setApiNotice('');
      setSelectedScenario(scenarioId);
      try {
        if (compare) {
          const comparison = await compareScenario(scenarioId);
          setCompareResult(comparison);
          setBatchResult(null);
          setLastResult(comparison.with_guard);
          setGuardEnabled(true);
          setApiNotice(
            `对比完成：无防护攻击${comparison.without_guard.attack_success ? '成功' : '未成功'}，有防护结果为${
              comparison.with_guard.attack_success ? '仍成功' : '已控制'
            }。`
          );
        } else {
          const result = await runScenario(scenarioId, guardEnabled);
          setCompareResult(null);
          setBatchResult(null);
          setLastResult(result);
        }
        await refresh();
        setPage('lab');
      } catch (error) {
        setApiNotice(`后端未启动或运行失败：${safeUiErrorSummary(error, '未知错误')}`);
      } finally {
        setRunning(false);
      }
    },
    [
      guardEnabled,
      refresh,
      setApiNotice,
      setBatchResult,
      setCompareResult,
      setGuardEnabled,
      setLastResult,
      setPage,
      setRunning,
      setSelectedScenario
    ]
  );

  const handleRun = useCallback(
    async (compare = false) => {
      if (!activeScenario) return;
      await handleRunScenario(activeScenario.id, compare);
    },
    [activeScenario, handleRunScenario]
  );

  const handleBatchCompare = useCallback(
    async (scenarioIds?: string[], label = '全部脚本') => {
      setRunning(true);
      setApiNotice('');
      try {
        const ids = scenarioIds?.length ? scenarioIds : scenarios.map((scenario) => scenario.id);
        const result = await batchCompareScenarios(ids);
        setBatchResult(result);
        const lastComparison = result.comparisons[result.comparisons.length - 1];
        setCompareResult(lastComparison ?? null);
        setLastResult(lastComparison?.with_guard ?? null);
        if (ids[0]) {
          setSelectedScenario(ids[0]);
        }
        setGuardEnabled(true);
        setApiNotice(
          `批量对比完成：${label} ${result.summary.total} 个脚本，无防护暴露 ${result.summary.exposed_without_guard} 个，有防护控制 ${result.summary.controlled_with_guard} 个。`
        );
        await refresh();
        setPage('lab');
      } catch (error) {
        setApiNotice(`批量运行失败：${safeUiErrorSummary(error, '未知错误')}`);
      } finally {
        setRunning(false);
      }
    },
    [
      refresh,
      scenarios,
      setApiNotice,
      setBatchResult,
      setCompareResult,
      setGuardEnabled,
      setLastResult,
      setPage,
      setRunning,
      setSelectedScenario
    ]
  );

  const handleAttackChain = useCallback(
    async (compare = false) => {
      const chainId = selectedAttackChain || attackChains[0]?.id;
      if (!chainId) return;
      setRunning(true);
      setApiNotice('');
      try {
        if (compare) {
          const result = await compareAttackChain(chainId);
          const lastComparison = result.comparisons[result.comparisons.length - 1];
          setAttackChainCompareResult(result);
          setAttackChainResult(null);
          setLastResult(lastComparison?.with_guard.run ?? null);
          setApiNotice(
            `组合链对比完成：无防护暴露 ${result.summary.without_guard_attack_success_count} 步，有防护控制率 ${result.summary.control_rate}%。`
          );
        } else {
          const result = await runAttackChain(chainId, true);
          const lastStage = result.stages[result.stages.length - 1];
          setAttackChainResult(result);
          setAttackChainCompareResult(null);
          setLastResult(lastStage?.run ?? null);
          setApiNotice(
            `组合链运行完成：${result.summary.stage_count} 步，控制率 ${result.summary.control_rate}%，平均延迟 ${result.summary.avg_latency_ms}ms。`
          );
        }
        await refresh();
        setPage('chain');
      } catch (error) {
        setApiNotice(`组合攻击链运行失败：${safeUiErrorSummary(error, '未知错误')}`);
      } finally {
        setRunning(false);
      }
    },
    [
      attackChains,
      refresh,
      selectedAttackChain,
      setApiNotice,
      setAttackChainCompareResult,
      setAttackChainResult,
      setLastResult,
      setPage,
      setRunning
    ]
  );

  return {
    handleRun,
    handleRunScenario,
    handleBatchCompare,
    handleAttackChain
  };
}
