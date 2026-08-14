import { describe, expect, it } from 'vitest';
import { navItems, pageFromHash, pageLabel } from './navigation';

describe('primary navigation', () => {
  it('keeps the product surface focused on five daily tasks', () => {
    expect(navItems.map((item) => item.key)).toEqual(['dashboard', 'audit', 'lab', 'policy', 'settings']);
  });

  it('preserves old deep links for secondary tools', () => {
    expect(pageFromHash('#/scenarios')).toBe('scenarios');
    expect(pageFromHash('#/chain')).toBe('chain');
    expect(pageFromHash('#/alerts')).toBe('alerts');
    expect(pageFromHash('#/report')).toBe('report');
    expect(pageLabel('report')).toBe('证据导出（按需）');
  });
});
