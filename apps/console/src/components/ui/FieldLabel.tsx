import type { ReactNode } from 'react';
import { Typography } from 'antd';

export type UiFieldLabelProps = {
  children: ReactNode;
  className?: string;
  htmlFor?: string;
};

/**
 * A consistent secondary label for controls and compact metric fields.
 * Keep the visual treatment in the shared design system instead of repeating
 * Typography.Text props in every business component.
 */
export function UiFieldLabel({ children, className = '', htmlFor }: UiFieldLabelProps) {
  const classes = ['zh-field-label', className].filter(Boolean).join(' ');
  if (htmlFor) {
    return (
      <label htmlFor={htmlFor} className={classes}>
        <Typography.Text type="secondary">{children}</Typography.Text>
      </label>
    );
  }
  return (
    <Typography.Text type="secondary" className={classes}>
      {children}
    </Typography.Text>
  );
}
