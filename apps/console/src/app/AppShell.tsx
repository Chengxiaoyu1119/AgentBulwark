import { type ReactNode, Suspense, useEffect, useMemo } from 'react';
import { LogOut, Menu as MenuIcon, Moon, RefreshCw, Sun, UserRound } from 'lucide-react';
import {
  LabelTag,
  UiAlert,
  UiButton,
  UiConfigProvider,
  UiDrawer,
  UiLayout,
  UiMenu,
  UiSpace,
  UiSpin,
  UiTheme,
  UiTypography
} from '../components/ui';
import type { AuthContext } from '../types';
import { navItems, pageLabel, type ProductPageKey } from './navigation';
import type { OperationalConnection } from './useAppData';
import type { AppTheme } from './themePreference';

const { Sider, Header, Content } = UiLayout;
const { darkAlgorithm, defaultAlgorithm } = UiTheme;

export type { AppTheme } from './themePreference';

type AppShellProps = {
  page: ProductPageKey;
  immersive?: boolean;
  theme: AppTheme;
  drawerVisible: boolean;
  apiNotice: string;
  connection: OperationalConnection;
  authContext: AuthContext;
  children: ReactNode;
  onPageChange: (page: ProductPageKey) => void;
  onThemeChange: (theme: AppTheme) => void;
  refreshing: boolean;
  onRefresh: () => void;
  onOpenDrawer: () => void;
  onCloseDrawer: () => void;
  onSignOut: () => void;
};

function PageFallback() {
  return (
    <div className="zh-page-loading">
      <UiSpin size="small" />
    </div>
  );
}

export function AppLoading() {
  return (
    <div className="zh-app-loading">
      <div className="zh-app-loading__panel">
        <img src="/favicon.png" alt="logo" className="zh-app-logo" />
        <div>
          <div className="zh-app-loading__title">智垒</div>
          <div className="zh-app-loading__text">正在加载工作台...</div>
        </div>
        <div className="zh-app-loading__spin">
          <UiSpin size="small" />
        </div>
      </div>
    </div>
  );
}

export function AppShell({
  page,
  immersive = false,
  theme,
  drawerVisible,
  apiNotice,
  connection,
  authContext,
  children,
  onPageChange,
  onThemeChange,
  refreshing,
  onRefresh,
  onOpenDrawer,
  onCloseDrawer,
  onSignOut
}: AppShellProps) {
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const menuItems = useMemo(
    () =>
      navItems.map((item) => ({
        key: item.key,
        icon: item.icon,
        label: item.label,
        onClick: () => {
          onPageChange(item.key);
          onCloseDrawer();
        }
      })),
    [onCloseDrawer, onPageChange]
  );

  return (
    <UiConfigProvider
      theme={{
        cssVar: { key: 'agentSupervisor' },
        hashed: false,
        algorithm: theme === 'dark' ? darkAlgorithm : defaultAlgorithm
      }}
    >
      <UiLayout className={`zh-app-root${immersive ? ' zh-app-root--immersive' : ''}`}>
        {!immersive ? (
          <Sider
            breakpoint="lg"
            collapsedWidth="0"
            width={236}
            theme={theme}
            className={`desktop-sider zh-app-sider zh-app-sider--${theme}`}
          >
            <div className={`zh-app-brand zh-app-brand--${theme}`}>
              <img src="/favicon.png" alt="logo" className="zh-app-logo" />
              <div>
                <UiTypography.Title level={4} className="zh-title-flush">
                  智垒
                </UiTypography.Title>
                <UiTypography.Text type="secondary" className="zh-text-meta">
                  AI Agent 防火墙
                </UiTypography.Text>
              </div>
            </div>
            <UiMenu mode="inline" theme={theme} selectedKeys={[page]} className="zh-app-menu" items={menuItems} />
          </Sider>
        ) : null}

        {!immersive ? (
          <UiDrawer
            title={
              <div className="zh-app-drawer-title">
                <img src="/favicon.png" alt="logo" className="zh-app-logo zh-app-logo--small" />
                <UiTypography.Title level={5} className="zh-title-flush">
                  智垒
                </UiTypography.Title>
              </div>
            }
            placement="left"
            onClose={onCloseDrawer}
            open={drawerVisible}
            classNames={{ body: 'zh-drawer-body-flush' }}
            size="default"
          >
            <UiMenu mode="inline" theme={theme} selectedKeys={[page]} className="zh-app-menu" items={menuItems} />
          </UiDrawer>
        ) : null}

        <UiLayout className="zh-app-layout">
          {!immersive ? (
            <Header className={`zh-app-header zh-app-header--${theme}`}>
              <UiSpace>
                <UiButton
                  type="text"
                  icon={<MenuIcon size={20} />}
                  onClick={onOpenDrawer}
                  className="mobile-menu-btn"
                  aria-label="打开导航菜单"
                />
                <UiTypography.Title level={3} className="zh-app-header-title">
                  {pageLabel(page)}
                </UiTypography.Title>
              </UiSpace>
              <UiSpace>
                <div className="zh-app-identity" aria-label={`当前身份 ${authContext.role}`}>
                  <UserRound size={16} aria-hidden="true" />
                  <span className="hide-on-mobile">{authContext.agent_id || '控制台操作员'}</span>
                  <LabelTag color={authContext.role === 'admin' ? 'blue' : 'default'}>{authContext.role}</LabelTag>
                </div>
                <UiButton
                  type="text"
                  icon={theme === 'light' ? <Moon size={17} /> : <Sun size={17} />}
                  onClick={() => onThemeChange(theme === 'light' ? 'dark' : 'light')}
                  aria-label={theme === 'light' ? '切换深色模式' : '切换浅色模式'}
                  title={theme === 'light' ? '切换深色模式' : '切换浅色模式'}
                />
                <UiButton
                  type="text"
                  icon={<RefreshCw size={17} />}
                  onClick={onRefresh}
                  loading={refreshing}
                  aria-label="刷新数据"
                  aria-busy={refreshing}
                />
                <UiButton type="text" icon={<LogOut size={16} />} onClick={onSignOut} aria-label="退出控制台">
                  <span className="hide-on-mobile">退出</span>
                </UiButton>
              </UiSpace>
            </Header>
          ) : null}

          <Content className={`main-content zh-main-content${immersive ? ' zh-main-content--immersive' : ''}`}>
            {apiNotice && (
              <UiAlert
                title={apiNotice}
                type={
                  connection.status === 'offline' ||
                  connection.status === 'auth-expired' ||
                  connection.status === 'forbidden'
                    ? 'error'
                    : 'warning'
                }
                showIcon
                action={
                  <UiButton size="small" onClick={onRefresh} loading={refreshing}>
                    重新读取
                  </UiButton>
                }
                className="zh-mb-24"
              />
            )}

            <Suspense fallback={<PageFallback />}>{children}</Suspense>
          </Content>
        </UiLayout>
      </UiLayout>
    </UiConfigProvider>
  );
}
