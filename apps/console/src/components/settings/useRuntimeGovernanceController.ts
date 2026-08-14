import { useEffect, useState } from 'react';
import {
  fetchAuthContext,
  fetchMemoryGovernance,
  fetchObservabilityMetrics,
  fetchPolicyConfig,
  rollbackLatestMemory,
  updateMemoryStatus,
  updatePolicySettings
} from '@/api';
import type { AuthContext, MemoryGovernance, ObservabilityMetrics, PolicySettings } from '@/types';

export function useRuntimeGovernanceController(setSharedError: (message: string) => void) {
  const [authContext, setAuthContext] = useState<AuthContext | null>(null);
  const [policySettings, setPolicySettings] = useState<PolicySettings | null>(null);
  const [observabilityMetrics, setObservabilityMetrics] = useState<ObservabilityMetrics | null>(null);
  const [memoryGovernance, setMemoryGovernance] = useState<MemoryGovernance | null>(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [refreshingGovernance, setRefreshingGovernance] = useState(false);
  const [governanceNotice, setGovernanceNotice] = useState('');
  const [governanceError, setGovernanceError] = useState('');
  const [busyMemoryId, setBusyMemoryId] = useState('');

  useEffect(() => {
    void loadGovernanceData()
      .then(({ auth, config, metrics, memory }) => {
        setAuthContext(auth);
        setPolicySettings(config.settings);
        setObservabilityMetrics(metrics);
        setMemoryGovernance(memory);
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : '运行治理状态刷新失败';
        setGovernanceError(message);
        setSharedError(message);
      });
  }, [setSharedError]);

  async function handleRefreshGovernance() {
    setRefreshingGovernance(true);
    setSharedError('');
    setGovernanceError('');
    setGovernanceNotice('');
    try {
      const { auth, config, metrics, memory } = await loadGovernanceData();
      setAuthContext(auth);
      setPolicySettings(config.settings);
      setObservabilityMetrics(metrics);
      setMemoryGovernance(memory);
      setGovernanceNotice('治理状态已刷新。');
    } catch (error) {
      const message = error instanceof Error ? error.message : '运行治理状态刷新失败';
      setGovernanceError(message);
      setSharedError(message);
    } finally {
      setRefreshingGovernance(false);
    }
  }

  async function handleSavePolicySettings() {
    if (!policySettings) return;
    setSavingSettings(true);
    setSharedError('');
    setGovernanceError('');
    setGovernanceNotice('');
    try {
      setPolicySettings(
        await updatePolicySettings({
          ...policySettings,
          operator: 'security-admin',
          comment: '通过防护策略中心更新策略阈值、业务边界与 Agent 工具白名单'
        })
      );
      await handleRefreshGovernance();
      setGovernanceNotice('策略阈值、业务边界、Agent 白名单和工具映射已保存，并生成新策略版本。');
    } catch (error) {
      const message = error instanceof Error ? error.message : '策略阈值保存失败';
      setGovernanceError(message);
      setSharedError(message);
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleMemoryStatus(memoryId: string, status: string) {
    setSharedError('');
    setGovernanceError('');
    setGovernanceNotice('');
    setBusyMemoryId(memoryId);
    try {
      const result = await updateMemoryStatus(memoryId, status);
      setMemoryGovernance(await fetchMemoryGovernance());
      setGovernanceNotice(`记忆 ${memoryId} 已更新为 ${status}；治理证据事件 #${result.event_id ?? '-'} 已写入。`);
    } catch (error) {
      const message = error instanceof Error ? error.message : '记忆状态更新失败';
      setGovernanceError(message);
      setSharedError(message);
    } finally {
      setBusyMemoryId('');
    }
  }

  async function handleRollbackMemory() {
    setSharedError('');
    setGovernanceError('');
    setGovernanceNotice('');
    setBusyMemoryId('__rollback__');
    try {
      const result = await rollbackLatestMemory();
      setMemoryGovernance(await fetchMemoryGovernance());
      setGovernanceNotice(`最新非种子记忆已回滚；治理证据事件 #${result.event_id ?? '-'} 已写入。`);
    } catch (error) {
      const message = error instanceof Error ? error.message : '记忆回滚失败';
      setGovernanceError(message);
      setSharedError(message);
    } finally {
      setBusyMemoryId('');
    }
  }

  return {
    authContext,
    busyMemoryId,
    governanceError,
    governanceNotice,
    handleMemoryStatus,
    handleRefreshGovernance,
    handleRollbackMemory,
    handleSavePolicySettings,
    memoryGovernance,
    observabilityMetrics,
    policySettings,
    refreshingGovernance,
    savingSettings,
    setPolicySettings
  };
}

async function loadGovernanceData() {
  const [auth, config, metrics, memory] = await Promise.all([
    fetchAuthContext(),
    fetchPolicyConfig(),
    fetchObservabilityMetrics(),
    fetchMemoryGovernance()
  ]);
  return { auth, config, metrics, memory };
}
