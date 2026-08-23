import { type ReactNode, Suspense, useEffect, useMemo } from 'react';
import { ConfigProvider, Drawer, Layout, Menu, Space, Spin, Typography, theme as antdTheme } from 'antd';
import { Activity, LogOut, Menu as MenuIcon, Moon, ShieldCheck, Sun, UserRound } from 'lucide-react';
import { LabelTag, UiAlert, UiButton } from '../components/ui';
import type { AuthContext } from '../types';
import { navGroups, pageLabel, type PageKey } from './navigation';

const { Sider, Header, Content } = Layout;
const { darkAlgorithm, defaultAlgorithm } = antdTheme;

export type AppTheme = 'light' | 'dark';

type AppShellProps = {
  page: PageKey;
  theme: AppTheme;
  drawerVisible: boolean;
  apiNotice: string;
  authContext: AuthContext;
  children: ReactNode;
  onPageChange: (page: PageKey) => void;
  onThemeChange: (theme: AppTheme) => void;
  onRefresh: () => void;
  onOpenDrawer: () => void;
  onCloseDrawer: () => void;
  onOpenLab: () => void;
  onOpenGateway?: () => void;
  onSignOut: () => void;
};

function PageFallback() {
  return (
    <div className="zh-page-loading">
      <Spin size="small" />
    </div>
  );
}

export function AppLoading() {
  return (
    <div className="zh-app-loading">
      <div className="zh-app-loading__panel">
        <img src="/favicon.svg" alt="logo" className="zh-app-logo" />
        <div>
          <div className="zh-app-loading__title">智安哨</div>
          <div className="zh-app-loading__text">正在加载工作台...</div>
        </div>
        <div className="zh-app-loading__spin">
          <Spin size="small" />
        </div>
      </div>
    </div>
  );
}

export function AppShell({
  page,
  theme,
  drawerVisible,
  apiNotice,
  authContext,
  children,
  onPageChange,
  onThemeChange,
  onRefresh,
  onOpenDrawer,
  onCloseDrawer,
  onOpenLab,
  onOpenGateway,
  onSignOut
}: AppShellProps) {
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const menuItems = useMemo(
    () =>
      navGroups.map((group) => ({
        type: 'group' as const,
        key: group.key,
        label: group.label,
        children: group.items.map((item) => ({
          key: item.key,
          icon: item.icon,
          label: item.label,
          onClick: () => {
            onPageChange(item.key);
            onCloseDrawer();
          }
        }))
      })),
    [onCloseDrawer, onPageChange]
  );

  return (
    <ConfigProvider
      theme={{
        cssVar: { key: 'agentSupervisor' },
        hashed: false,
        algorithm: theme === 'dark' ? darkAlgorithm : defaultAlgorithm
      }}
    >
      <Layout className="zh-app-root">
        <Sider
          breakpoint="lg"
          collapsedWidth="0"
          width={280}
          theme={theme}
          className={`desktop-sider zh-app-sider zh-app-sider--${theme}`}
        >
          <div className={`zh-app-brand zh-app-brand--${theme}`}>
            <img src="/favicon.svg" alt="logo" className="zh-app-logo" />
            <div>
              <Typography.Title level={4} className="zh-title-flush">
                智安哨
              </Typography.Title>
              <Typography.Text type="secondary" className="zh-text-meta">
                AI Agent Runtime Security
              </Typography.Text>
            </div>
          </div>
          <Menu mode="inline" theme={theme} selectedKeys={[page]} className="zh-app-menu" items={menuItems} />
        </Sider>

        <Drawer
          title={
            <div className="zh-app-drawer-title">
              <img src="/favicon.svg" alt="logo" className="zh-app-logo zh-app-logo--small" />
              <Typography.Title level={5} className="zh-title-flush">
                智安哨
              </Typography.Title>
            </div>
          }
          placement="left"
          onClose={onCloseDrawer}
          open={drawerVisible}
          classNames={{ body: 'zh-drawer-body-flush' }}
          size="default"
        >
          <Menu mode="inline" theme={theme} selectedKeys={[page]} className="zh-app-menu" items={menuItems} />
        </Drawer>

        <Layout className="zh-app-layout">
          <Header className={`zh-app-header zh-app-header--${theme}`}>
            <Space>
              <UiButton
                type="text"
                icon={<MenuIcon size={20} />}
                onClick={onOpenDrawer}
                className="mobile-menu-btn"
                aria-label="打开导航菜单"
              />
              <Typography.Title level={3} className="zh-app-header-title">
                {pageLabel(page)}
              </Typography.Title>
            </Space>
            <Space>
              <div className="zh-app-identity" aria-label={`当前身份 ${authContext.role}`}>
                <UserRound size={16} aria-hidden="true" />
                <span className="hide-on-mobile">{authContext.agent_id || '控制台操作员'}</span>
                <LabelTag color={authContext.role === 'admin' ? 'blue' : 'default'}>{authContext.role}</LabelTag>
              </div>
              <UiButton
                type="text"
                icon={theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
                onClick={() => onThemeChange(theme === 'light' ? 'dark' : 'light')}
              >
                <span className="hide-on-mobile">{theme === 'light' ? '深色模式' : '浅色模式'}</span>
              </UiButton>
              <UiButton icon={<Activity size={16} />} onClick={onRefresh}>
                <span className="hide-on-mobile">刷新数据</span>
              </UiButton>
              <UiButton type="text" icon={<LogOut size={16} />} onClick={onSignOut} aria-label="退出控制台">
                <span className="hide-on-mobile">退出</span>
              </UiButton>
              {page !== 'gateway' ? (
                <UiButton type="primary" icon={<ShieldCheck size={16} />} onClick={onOpenGateway ?? onOpenLab}>
                  <span className="hide-on-mobile">打开 LLM API / MCP 网关</span>
                </UiButton>
              ) : null}
            </Space>
          </Header>

          <Content className="main-content zh-main-content">
            {apiNotice && <UiAlert title={apiNotice} type="warning" showIcon className="zh-mb-24" />}

            <Suspense fallback={<PageFallback />}>{children}</Suspense>
          </Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
