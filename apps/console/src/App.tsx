import { lazy, useCallback, useEffect, useState } from 'react';
import { AuthGate } from './app/AuthGate';
import { AppLoading, AppShell, type AppTheme } from './app/AppShell';
import { useAppData } from './app/useAppData';
import { isPageKey, pageFromHash, pageToHash, type ProductPageKey } from './app/navigation';
import type { AuthContext } from './types';

const GatewayPanel = lazy(() => import('./pages/GatewayPanel').then((module) => ({ default: module.GatewayPanel })));
const SecurityEventsPanel = lazy(() =>
  import('./pages/SecurityEventsPanel').then((module) => ({ default: module.SecurityEventsPanel }))
);
const SettingsPanel = lazy(() => import('./pages/SettingsPanel').then((module) => ({ default: module.SettingsPanel })));

export default function App() {
  return <AuthGate>{({ context, signOut }) => <Workspace authContext={context} onSignOut={signOut} />}</AuthGate>;
}

function Workspace({ authContext, onSignOut }: { authContext: AuthContext; onSignOut: () => void }) {
  const [page, setPageState] = useState<ProductPageKey>(() => pageFromHash(window.location.hash));
  const [theme, setTheme] = useState<AppTheme>('light');
  const [drawerVisible, setDrawerVisible] = useState(false);
  const { overview, apiNotice, refresh } = useAppData(page);

  const setPage = useCallback((nextPage: ProductPageKey) => {
    setPageState(nextPage);
    const nextHash = pageToHash(nextPage);
    if (window.location.hash !== nextHash) window.history.pushState(null, '', nextHash);
  }, []);

  useEffect(() => {
    const syncPageFromHash = () => setPageState(pageFromHash(window.location.hash));
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

  if (!overview) return <AppLoading />;

  return (
    <AppShell
      page={page}
      theme={theme}
      drawerVisible={drawerVisible}
      apiNotice={apiNotice}
      authContext={authContext}
      onPageChange={setPage}
      onThemeChange={setTheme}
      onRefresh={() => void refresh()}
      onOpenDrawer={() => setDrawerVisible(true)}
      onCloseDrawer={() => setDrawerVisible(false)}
      onSignOut={onSignOut}
    >
      {page === 'protection' && <GatewayPanel onOpenSettings={() => setPage('settings')} />}
      {page === 'events' && <SecurityEventsPanel />}
      {page === 'settings' && <SettingsPanel overview={overview} refresh={refresh} />}
    </AppShell>
  );
}
