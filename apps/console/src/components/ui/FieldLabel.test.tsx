import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { UiFieldLabel } from './FieldLabel';

describe('UiFieldLabel', () => {
  it('associates a field label with its control', () => {
    render(
      <>
        <UiFieldLabel htmlFor="policy-threshold">策略阈值</UiFieldLabel>
        <input id="policy-threshold" />
      </>
    );

    const label = screen.getByText('策略阈值').closest('label');
    const control = screen.getByLabelText('策略阈值');
    expect(label).toHaveAttribute('for', 'policy-threshold');
    expect(control).toHaveAttribute('id', 'policy-threshold');
  });

  it('renders a secondary label with stable shared classes', () => {
    render(<UiFieldLabel className="custom-label">策略阈值</UiFieldLabel>);

    const label = screen.getByText('策略阈值');
    expect(label).toHaveClass('zh-field-label', 'custom-label');
    expect(label).toHaveClass('ant-typography-secondary');
  });
});
