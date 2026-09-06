import type { JSX } from 'react';
import { ListChecks, Settings2, ShieldCheck } from 'lucide-react';

export type ProductPageKey = 'protection' | 'events' | 'settings';
export type PageKey = ProductPageKey;

export type NavItem = {
  key: ProductPageKey;
  label: string;
  icon: JSX.Element;
};

export const defaultPage: ProductPageKey = 'protection';

export const navItems: NavItem[] = [
  { key: 'protection', label: '防护', icon: <ShieldCheck size={18} /> },
  { key: 'events', label: '事件', icon: <ListChecks size={18} /> },
  { key: 'settings', label: '设置', icon: <Settings2 size={18} /> }
];

export function isPageKey(value: string): value is ProductPageKey {
  return value === 'protection' || value === 'events' || value === 'settings';
}

export function pageFromHash(hash: string): ProductPageKey {
  const page = hash.replace(/^#\/?/, '').split(/[?#]/)[0].trim();
  return isPageKey(page) ? page : defaultPage;
}

export function pageToHash(page: ProductPageKey) {
  return `#/${page}`;
}

export function pageLabel(page: PageKey) {
  return navItems.find((item) => item.key === page)?.label ?? '防护';
}
