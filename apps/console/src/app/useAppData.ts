import { useCallback, useEffect, useState } from 'react';
import { fetchHealth, fetchOverview } from '../api';
import type { Overview } from '../types';
import { offlineOverview } from '../fallback';
import type { ProductPageKey } from './navigation';

export function useAppData(_page: ProductPageKey) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [apiNotice, setApiNotice] = useState('');
  const [apiAvailable, setApiAvailable] = useState<boolean | null>(null);

  const refresh = useCallback(async () => {
    const backendHealthy = await fetchHealth();
    setApiAvailable(backendHealthy);
    if (!backendHealthy) {
      setOverview(offlineOverview);
      setApiNotice('后端连接中断，当前页面不会用样本或历史报告冒充实时数据。');
      return false;
    }

    try {
      setOverview(await fetchOverview());
      setApiNotice('');
      return true;
    } catch (error) {
      setOverview(offlineOverview);
      setApiNotice(error instanceof Error ? error.message : '实时运行状态读取失败。');
      return false;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(async () => {
      if (!cancelled) await refresh();
    });
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  return { overview, apiNotice, apiAvailable, refresh };
}
