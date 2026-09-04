import { useEffect, useState } from 'react';
import { safeUiErrorSummary } from '../../app/apiRequestSupport';
import { fetchModelStatuses, probeModelProvider } from '../../app/operationalApi';
import type { ModelProfileId, ModelProviderProbeResult, ModelStatusByProfile } from '../../types';

const MODEL_PROFILE_IDS: ModelProfileId[] = ['target', 'optimizer', 'global'];

export function useProviderProbe(canProbe: boolean, reportError: (message: string) => void) {
  const [probingProviderKey, setProbingProviderKey] = useState('');
  const [probeResult, setProbeResult] = useState<ModelProviderProbeResult | null>(null);

  async function probeProvider(profile: string, providerId: string) {
    if (!canProbe || probingProviderKey) return;
    setProbingProviderKey(`${profile}:${providerId}`);
    setProbeResult(null);
    reportError('');
    try {
      setProbeResult(await probeModelProvider({ profile, provider_id: providerId }));
    } catch (error) {
      reportError(safeUiErrorSummary(error, 'Provider 连接探针请求失败。'));
    } finally {
      setProbingProviderKey('');
    }
  }

  return { probingProviderKey, probeResult, probeProvider };
}

export function useProviderStatuses(enabled: boolean) {
  const [profileStatuses, setProfileStatuses] = useState<ModelStatusByProfile>({});
  const [profileStatusError, setProfileStatusError] = useState('');
  const [profileStatusLoading, setProfileStatusLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!enabled) {
      return () => {
        cancelled = true;
      };
    }
    queueMicrotask(() => {
      if (cancelled) return;
      setProfileStatuses({});
      setProfileStatusError('');
      setProfileStatusLoading(true);
    });
    void Promise.allSettled(MODEL_PROFILE_IDS.map((profile) => fetchModelStatuses(profile))).then((results) => {
      if (cancelled) return;
      const nextStatuses: ModelStatusByProfile = {};
      const failures: string[] = [];
      results.forEach((result, index) => {
        const profile = MODEL_PROFILE_IDS[index];
        if (result.status === 'fulfilled') nextStatuses[profile] = result.value;
        else failures.push(`${profile}：${safeUiErrorSummary(result.reason, '模型状态读取失败。')}`);
      });
      setProfileStatuses(nextStatuses);
      setProfileStatusError(failures.join('；'));
      setProfileStatusLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  return {
    profileStatuses: enabled ? profileStatuses : {},
    profileStatusError: enabled ? profileStatusError : '',
    profileStatusLoading: enabled && profileStatusLoading
  };
}
