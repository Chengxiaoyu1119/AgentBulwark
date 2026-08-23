import { lazy, useCallback, useEffect, useState } from 'react';
import { AppLoading, AppShell, type AppTheme } from './app/AppShell';
import { useAppActions } from './app/useAppActions';
import { useAppData } from './app/useAppData';
import { isPageKey, pageFromHash, pageToHash, type PageKey } from './app/navigation';

const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })));
const GatewayPanel = lazy(() => import('./pages/GatewayPanel').then((module) => ({ default: module.GatewayPanel })));
const ScenarioLibrary = lazy(() =>
  import('./components/scenarios/ScenarioLibrary').then((module) => ({ default: module.ScenarioLibrary }))
);
const ExperimentLab = lazy(() =>
  import('./components/lab/ExperimentLab').then((module) => ({ default: module.ExperimentLab }))
);
const AgentChain = lazy(() =>
  import('./components/agent/AgentChain').then((module) => ({ default: module.AgentChain }))
);
const PolicyCenter = lazy(() =>
  import('./components/policy/PolicyCenter').then((module) => ({ default: module.PolicyCenter }))
);
const AuditLogPanel = lazy(() => import('./pages/AuditLogPanel').then((module) => ({ default: module.AuditLogPanel })));
const AlertsPanel = lazy(() => import('./pages/AlertsPanel').then((module) => ({ default: module.AlertsPanel })));
const ReportPanel = lazy(() => import('./pages/ReportPanel').then((module) => ({ default: module.ReportPanel })));
const SettingsPanel = lazy(() => import('./pages/SettingsPanel').then((module) => ({ default: module.SettingsPanel })));

export default function App() {
  const [page, setPageState] = useState<PageKey>(() => pageFromHash(window.location.hash));
  const [theme, setTheme] = useState<AppTheme>('light');
  const [drawerVisible, setDrawerVisible] = useState(false);
  const setPage = useCallback((nextPage: PageKey) => {
    setPageState(nextPage);
    const nextHash = pageToHash(nextPage);
    if (window.location.hash !== nextHash) {
      window.history.pushState(null, '', nextHash);
    }
  }, []);
  const appData = useAppData(page);
  const {
    overview,
    scenarios,
    selectedScenario,
    setSelectedScenario,
    policies,
    setPolicies,
    auditLogs,
    alerts,
    lastResult,
    setLastResult,
    compareResult,
    setCompareResult,
    batchResult,
    setBatchResult,
    attackChains,
    selectedAttackChain,
    setSelectedAttackChain,
    attackChainResult,
    setAttackChainResult,
    attackChainCompareResult,
    setAttackChainCompareResult,
    running,
    setRunning,
    guardEnabled,
    setGuardEnabled,
    report,
    reportSource,
    reportLoading,
    apiNotice,
    apiAvailable,
    setApiNotice,
    refresh,
    loadReport,
    loadAuditLogs,
    loadAlerts,
    activeScenario
  } = appData;
  const { handleRun, handleRunScenario, handleBatchCompare, handleAttackChain } = useAppActions({
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
  });

  useEffect(() => {
    const syncPageFromHash = () => {
      setPageState(pageFromHash(window.location.hash));
    };
    window.addEventListener('hashchange', syncPageFromHash);
    window.addEventListener('popstate', syncPageFromHash);

    const hashPage = window.location.hash.replace(/^#\/?/, '').split(/[?#]/)[0].trim();
    if (!isPageKey(hashPage)) {
      window.history.replaceState(null, '', pageToHash(pageFromHash(window.location.hash)));
    }

    return () => {
      window.removeEventListener('hashchange', syncPageFromHash);
      window.removeEventListener('popstate', syncPageFromHash);
    };
  }, []);

  if (!overview) {
    return <AppLoading />;
  }

  return (
    <AppShell
      page={page}
      theme={theme}
      drawerVisible={drawerVisible}
      apiNotice={apiNotice}
      onPageChange={setPage}
      onThemeChange={setTheme}
      onRefresh={() => {
        void refresh();
      }}
      onOpenDrawer={() => setDrawerVisible(true)}
      onCloseDrawer={() => setDrawerVisible(false)}
      onOpenLab={() => setPage('lab')}
      onOpenGateway={() => setPage('gateway')}
    >
      {page === 'dashboard' && <Dashboard overview={overview} apiAvailable={apiAvailable} onOpenPage={setPage} />}
      {page === 'gateway' && <GatewayPanel />}
      {page === 'scenarios' && (
        <ScenarioLibrary
          scenarios={scenarios}
          selected={selectedScenario}
          recentRuns={overview.recent_runs}
          running={running}
          onSelect={setSelectedScenario}
          onOpenLab={(id) => {
            setSelectedScenario(id);
            setPage('lab');
          }}
          onRunScenario={(id) => {
            void handleRunScenario(id, false);
          }}
          onCompareScenario={(id) => {
            void handleRunScenario(id, true);
          }}
          onOpenAudit={() => setPage('audit')}
        />
      )}
      {page === 'lab' && activeScenario && (
        <ExperimentLab
          scenario={activeScenario}
          scenarios={scenarios}
          selected={selectedScenario}
          setSelected={setSelectedScenario}
          guardEnabled={guardEnabled}
          setGuardEnabled={setGuardEnabled}
          running={running}
          run={() => {
            void handleRun(false);
          }}
          compare={() => {
            void handleRun(true);
          }}
          batchCompare={() => {
            void handleBatchCompare();
          }}
          result={lastResult}
          compareResult={compareResult}
          batchResult={batchResult}
          refresh={refresh}
          onOpenAgentChain={() => setPage('chain')}
        />
      )}
      {page === 'chain' && (
        <AgentChain
          result={lastResult}
          runs={overview.recent_runs}
          chains={attackChains}
          selectedChainId={selectedAttackChain}
          onSelectChain={setSelectedAttackChain}
          chainResult={attackChainResult}
          chainCompareResult={attackChainCompareResult}
          chainRunning={running}
          onRunChain={() => {
            void handleAttackChain(false);
          }}
          onCompareChain={() => {
            void handleAttackChain(true);
          }}
        />
      )}
      {page === 'audit' && (
        <AuditLogPanel
          logs={
            auditLogs.length ? auditLogs : lastResult?.audit_logs?.length ? lastResult.audit_logs : overview.audit_logs
          }
          alerts={lastResult?.alerts?.length ? lastResult.alerts : alerts.length ? alerts : overview.alerts}
          refresh={loadAuditLogs}
          refreshAlerts={loadAlerts}
        />
      )}
      {page === 'policy' && <PolicyCenter policies={policies} setPolicies={setPolicies} />}
      {page === 'alerts' && (
        <AlertsPanel
          alerts={lastResult?.alerts?.length ? lastResult.alerts : alerts.length ? alerts : overview.alerts}
          refresh={loadAlerts}
        />
      )}
      {page === 'report' && (
        <ReportPanel
          report={report}
          reportSource={reportSource}
          reportLoading={reportLoading}
          onRefreshReport={loadReport}
          onRefreshRuntime={refresh}
          onOpenScenario={(id) => {
            setSelectedScenario(id);
            setPage('lab');
          }}
          onOpenPage={setPage}
        />
      )}
      {page === 'settings' && <SettingsPanel overview={overview} refresh={refresh} />}
    </AppShell>
  );
}
