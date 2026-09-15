import { lazy, useCallback, useEffect, useState } from 'react';
import { AuthGate } from './app/AuthGate';
import { AppErrorBoundary } from './app/AppErrorBoundary';
import { AppLoading, AppShell } from './app/AppShell';
import { useRuntimeEventRefresh } from './app/useRuntimeEventRefresh';
import { type OperationalConnection, useAppData } from './app/useAppData';
import { isPageKey, pageFromHash, pageToHash, type ProductPageKey } from './app/navigation';
import { readThemePreference, saveThemePreference, type AppTheme } from './app/themePreference';
import { PanelCard, UiAlert, UiButton } from './components/ui';
import type { AuthContext } from './types';
import { SituationPanel } from './pages/SituationPanel';

const GatewayPanel = lazy(() => import('./pages/GatewayPanel').then((module) => ({ default: module.GatewayPanel })));
const SecurityEventsPanel = lazy(() =>
  import('./pages/SecurityEventsPanel').then((module) => ({ default: module.SecurityEventsPanel }))
);
const SettingsPanel = lazy(() => import('./pages/SettingsPanel').then((module) => ({ default: module.SettingsPanel })));

export default function App() {
  return (
    <AuthGate>
      {({ context, signOut }) => (
        <AppErrorBoundary>
          <Workspace authContext={context} onSignOut={signOut} />
        </AppErrorBoundary>
      )}
    </AuthGate>
  );
}

function Workspace({ authContext, onSignOut }: { authContext: AuthContext; onSignOut: () => void }) {
  const [page, setPageState] = useState<ProductPageKey>(() => pageFromHash(window.location.hash));
  const [situation, setSituation] = useState(() => isSituationLocation());
  const [theme, setTheme] = useState<AppTheme>(() => readThemePreference());
  const [drawerVisible, setDrawerVisible] = useState(false);
  const { overview, apiNotice, connection, refreshing, refresh } = useAppData(page);
  const [runtimeRevision, setRuntimeRevision] = useState(0);
  const refreshLiveData = useCallback(async () => {
    await refresh();
    setRuntimeRevision((value) => value + 1);
  }, [refresh]);
  const liveConnection = useRuntimeEventRefresh(refreshLiveData, { debounceMs: 400 });

  const setPage = useCallback((nextPage: ProductPageKey) => {
    setPageState(nextPage);
    setSituation(false);
    const nextHash = pageToHash(nextPage);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

  const openEvents = useCallback((requestId = '') => {
    const query = requestId ? `?request_id=${encodeURIComponent(requestId)}` : '';
    setSituation(false);
    setPageState('events');
    window.history.pushState(null, '', `#/events${query}`);
  }, []);

  const openSituation = useCallback(() => {
    setPageState('protection');
    setSituation(true);
    window.history.pushState(null, '', '#/protection?view=situation');
  }, []);

  const exitSituation = useCallback(() => {
    setSituation(false);
    window.history.pushState(null, '', '#/protection');
  }, []);

  useEffect(() => {
    const syncPageFromHash = () => {
      setPageState(pageFromHash(window.location.hash));
      setSituation(isSituationLocation());
    };
    window.addEventListener('hashchange', syncPageFromHash);
    window.addEventListener('popstate', syncPageFromHash);

    const rawPage = window.location.hash.replace(/^#\/?/, '').split(/[?#]/)[0].trim();
    if (!isPageKey(rawPage)) {
      window.history.replaceState(null, '', pageToHash(pageFromHash(window.location.hash)));
    }

    return () => {
      window.removeEventListener('hashchange', syncPageFromHash);
      window.removeEventListener('popstate', syncPageFromHash);
    };
  }, []);

  useEffect(() => {
    saveThemePreference(theme);
  }, [theme]);

  if (!overview && connection.status === 'checking') return <AppLoading />;

  return (
    <AppShell
      page={page}
      immersive={situation}
      theme={theme}
      drawerVisible={drawerVisible}
      apiNotice={apiNotice}
      connection={connection}
      authContext={authContext}
      onPageChange={setPage}
      onThemeChange={setTheme}
      refreshing={refreshing}
      onRefresh={() => void refresh()}
      onOpenDrawer={() => setDrawerVisible(true)}
      onCloseDrawer={() => setDrawerVisible(false)}
      onSignOut={onSignOut}
    >
      {!overview ? (
        <WorkspaceDataUnavailable connection={connection} onRefresh={() => void refresh()} />
      ) : (
        <>
          {page === 'protection' && situation ? (
            <SituationPanel
              overview={overview}
              connection={connection}
              theme={theme}
              onThemeChange={setTheme}
              onExit={exitSituation}
              onOpenEvents={openEvents}
              onOpenSettings={() => setPage('settings')}
              liveConnection={liveConnection}
            />
          ) : null}
          {page === 'protection' && !situation ? (
            <GatewayPanel
              overview={overview}
              connection={connection}
              onOpenSettings={() => setPage('settings')}
              onOpenEvents={openEvents}
              onOpenSituation={openSituation}
              onRefresh={refresh}
              liveConnection={liveConnection}
            />
          ) : null}
          {page === 'events' && (
            <SecurityEventsPanel
              authContext={authContext}
              liveConnection={liveConnection}
              refreshSignal={String(runtimeRevision)}
            />
          )}
          {page === 'settings' && <SettingsPanel overview={overview} refresh={refresh} />}
        </>
      )}
    </AppShell>
  );
}

function isSituationLocation() {
  const hashQuery = window.location.hash.includes('?') ? window.location.hash.split('?').slice(1).join('?') : '';
  const query = new URLSearchParams(`${window.location.search.replace(/^\?/, '')}&${hashQuery}`);
  return query.get('view') === 'situation';
}

function WorkspaceDataUnavailable({
  connection,
  onRefresh
}: {
  connection: OperationalConnection;
  onRefresh: () => void;
}) {
  const title =
    connection.status === 'auth-expired'
      ? '操作员会话已失效'
      : connection.status === 'forbidden'
        ? '当前身份不能读取运行数据'
        : connection.status === 'offline'
          ? '后端暂时不可达'
          : '实时总览暂时不可用';

  return (
    <section className="zh-page-stack" aria-labelledby="workspace-data-unavailable-title">
      <PanelCard title={title} variant="borderless">
        <UiAlert
          type={connection.status === 'degraded' ? 'warning' : 'error'}
          showIcon
          title={connection.message}
          description="控制台没有将空白或零指标显示为实时运行结果。恢复连接后可重新读取数据。"
        />
        <UiButton type="primary" onClick={onRefresh} className="zh-mt-16">
          重新读取实时数据
        </UiButton>
      </PanelCard>
    </section>
  );
}
