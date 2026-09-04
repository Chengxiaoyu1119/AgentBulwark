import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { UiStack } from './Stack';

describe('UiStack', () => {
  it('maps layout intent to shared classes without inline styles', () => {
    render(
      <UiStack direction="horizontal" gap="lg" align="center" justify="between" wrap aria-label="操作区">
        <span>左侧</span>
        <span>右侧</span>
      </UiStack>
    );

    const stack = screen.getByLabelText('操作区');
    expect(stack).toHaveClass(
      'zh-ui-stack',
      'zh-ui-stack--horizontal',
      'zh-ui-stack--gap-lg',
      'zh-ui-stack--align-center',
      'zh-ui-stack--justify-between',
      'zh-ui-stack--wrap'
    );
    expect(stack).not.toHaveAttribute('style');
  });
});
