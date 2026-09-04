import { useCallback, useEffect, useRef, useState } from 'react';
import type { Overview } from '../types';
import type { ProductPageKey } from './navigation';
import { ApiError, safeUiDiagnostic } from './apiRequest';
import { fetchHealth, fetchOverview } from './operationalApi';

export type OperationalConnectionStatus = 'checking' | 'online' | 'offline' | 'auth-expired' | 'forbidden' | 'degraded';

export type OperationalConnection = {
  status: OperationalConnectionStatus;
  message: string;
  stale?: boolean;
  snapshotUpdatedAt?: number;
};

const initialConnection: OperationalConnection = {
  status: 'checking',
  message: '正在检测后端与实时数据连接。',
  stale: false
};

function connectionForError(error: unknown, healthChecked: boolean, snapshotUpdatedAt?: number): OperationalConnection {
  const stale = snapshotUpdatedAt !== undefined;
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return { status: 'auth-expired', message: '当前会话已失效，请重新验证身份。', stale, snapshotUpdatedAt };
    }
    if (error.status === 403) {
      return { status: 'forbidden', message: '当前身份没有读取实时运行数据的权限。', stale, snapshotUpdatedAt };
    }
    if (error.code === 'network_error' || error.code === 'timeout') {
      return healthChecked
        ? {
            status: 'degraded',
            message: `后端在线，但实时总览读取失败：${safeUiDiagnostic(error)}`,
            stale,
            snapshotUpdatedAt
          }
        : { status: 'offline', message: '后端连接中断，未将空数据表示为实时结果。', stale, snapshotUpdatedAt };
    }
  }
  return healthChecked
    ? {
        status: 'degraded',
        message: `后端在线，但实时总览读取失败：${safeUiDiagnostic(error)}`,
        stale,
        snapshotUpdatedAt
      }
    : { status: 'offline', message: '后端连接中断，未将空数据表示为实时结果。', stale, snapshotUpdatedAt };
}

export function useAppData(_page: ProductPageKey) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [apiNotice, setApiNotice] = useState('');
  const [apiAvailable, setApiAvailable] = useState<boolean | null>(null);
  const [connection, setConnection] = useState<OperationalConnection>(initialConnection);
  const [refreshing, setRefreshing] = useState(false);
  const refreshSequence = useRef(0);
  const overviewRef = useRef<Overview | null>(null);
  const snapshotUpdatedAt = useRef<number | undefined>(undefined);

  const setOperationalConnection = useCallback((nextConnection: OperationalConnection) => {
    setConnection(nextConnection);
    setApiNotice(
      nextConnection.status === 'online' || nextConnection.status === 'checking'
        ? ''
        : `${nextConnection.message}${nextConnection.stale ? ' 当前显示的是最后一次成功读取的陈旧快照。' : ''}`
    );
  }, []);

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    setRefreshing(true);
    if (!overviewRef.current) {
      setOperationalConnection({ status: 'checking', message: '正在检测后端与实时数据连接。', stale: false });
    }
    let healthChecked = false;
    try {
      const backendHealthy = await fetchHealth();
      if (sequence !== refreshSequence.current) return false;
      healthChecked = true;
      setApiAvailable(backendHealthy);
      if (!backendHealthy) {
        setOperationalConnection({
          status: 'offline',
          message: '后端连接中断，未将空数据表示为实时结果。',
          stale: Boolean(overviewRef.current),
          snapshotUpdatedAt: snapshotUpdatedAt.current
        });
        return false;
      }
      const nextOverview = await fetchOverview();
      if (sequence !== refreshSequence.current) return false;
      const updatedAt = Date.now();
      overviewRef.current = nextOverview;
      snapshotUpdatedAt.current = updatedAt;
      setOverview(nextOverview);
      setOperationalConnection({
        status: 'online',
        message: '后端在线，实时总览已更新。',
        stale: false,
        snapshotUpdatedAt: updatedAt
      });
      return true;
    } catch (error) {
      if (sequence !== refreshSequence.current) return false;
      const nextConnection = connectionForError(error, healthChecked, snapshotUpdatedAt.current);
      setApiAvailable(nextConnection.status === 'offline' ? false : true);
      setOperationalConnection(nextConnection);
      return false;
    } finally {
      if (sequence === refreshSequence.current) setRefreshing(false);
    }
  }, [setOperationalConnection]);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(async () => {
      if (!cancelled) await refresh();
    });
    return () => {
      cancelled = true;
      refreshSequence.current += 1;
    };
  }, [refresh]);

  return { overview, apiNotice, apiAvailable, connection, refreshing, refresh };
}
