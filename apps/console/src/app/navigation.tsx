import type { JSX } from 'react';
import { Activity, ScrollText, Settings2, ShieldCheck } from 'lucide-react';

export type PageKey =
  | 'dashboard'
  | 'gateway'
  | 'scenarios'
  | 'lab'
  | 'chain'
  | 'audit'
  | 'policy'
  | 'alerts'
  | 'report'
  | 'settings';

export type NavItem = {
  key: PageKey;
  label: string;
  icon: JSX.Element;
};

export type NavGroup = {
  key: string;
  label: string;
  items: NavItem[];
};

export const defaultPage: PageKey = 'gateway';

export const navGroups: NavGroup[] = [
  {
    key: 'operations',
    label: '网关运行',
    items: [
      { key: 'gateway', label: 'LLM API / MCP 网关', icon: <ShieldCheck size={18} /> },
      { key: 'dashboard', label: '运行总览', icon: <Activity size={18} /> },
      { key: 'audit', label: '事件与复核', icon: <ScrollText size={18} /> }
    ]
  },
  {
    key: 'protection',
    label: '配置',
    items: [{ key: 'policy', label: '防护策略', icon: <ShieldCheck size={18} /> }]
  },
  {
    key: 'integration',
    label: '接入',
    items: [{ key: 'settings', label: 'Agent 接入', icon: <Settings2 size={18} /> }]
  }
];

export const navItems: NavItem[] = navGroups.flatMap((group) => group.items);
const allPageKeys: PageKey[] = [
  'dashboard',
  'gateway',
  'scenarios',
  'lab',
  'chain',
  'audit',
  'policy',
  'alerts',
  'report',
  'settings'
];

export function isPageKey(value: string): value is PageKey {
  return allPageKeys.includes(value as PageKey);
}

export function pageFromHash(hash: string): PageKey {
  const page = hash.replace(/^#\/?/, '').split(/[?#]/)[0].trim();
  return isPageKey(page) ? page : defaultPage;
}

export function pageToHash(page: PageKey) {
  return `#/${page}`;
}

export function pageLabel(page: PageKey) {
  if (page === 'gateway') return 'LLM API / MCP 网关';
  if (page === 'dashboard') return '安全运行总览';
  if (page === 'lab') return '现场验证';
  if (page === 'report') return '证据导出（按需）';
  if (page === 'scenarios') return '攻击场景与样本';
  if (page === 'chain') return '多 Agent 攻击链';
  if (page === 'alerts') return '安全事件与阻断';
  return navItems.find((item) => item.key === page)?.label ?? '安全工作台';
}
