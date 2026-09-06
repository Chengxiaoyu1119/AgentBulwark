import { describe, expect, it } from 'vitest';
import { navItems, pageFromHash, pageLabel, pageToHash } from './navigation';

describe('primary navigation', () => {
  it('keeps only the three daily product surfaces', () => {
    expect(navItems.map((item) => item.key)).toEqual(['protection', 'events', 'settings']);
  });

  it('accepts only canonical product deep links', () => {
    expect(pageFromHash('#/protection')).toBe('protection');
    expect(pageFromHash('#/events')).toBe('events');
    expect(pageFromHash('#/settings')).toBe('settings');
    expect(pageFromHash('#/legacy')).toBe('protection');
    expect(pageToHash(pageFromHash('#/legacy'))).toBe('#/protection');
    expect(pageLabel('events')).toBe('事件');
  });
});
