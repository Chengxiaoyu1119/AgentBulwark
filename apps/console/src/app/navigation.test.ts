import { describe, expect, it } from 'vitest';
import { navItems, pageFromHash, pageLabel, pageToHash } from './navigation';

describe('primary navigation', () => {
  it('keeps only the three daily product surfaces', () => {
    expect(navItems.map((item) => item.key)).toEqual(['protection', 'events', 'settings']);
  });

  it('folds legacy deep links into the nearest product task', () => {
    expect(pageFromHash('#/gateway')).toBe('protection');
    expect(pageFromHash('#/dashboard')).toBe('protection');
    expect(pageFromHash('#/audit')).toBe('events');
    expect(pageFromHash('#/alerts')).toBe('events');
    expect(pageFromHash('#/lab')).toBe('protection');
    expect(pageToHash(pageFromHash('#/lab'))).toBe('#/protection');
    expect(pageLabel('events')).toBe('事件');
  });
});
