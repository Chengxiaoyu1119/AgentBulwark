import type { HTMLAttributes } from 'react';

export type UiStackDirection = 'horizontal' | 'vertical';
export type UiStackGap = 'none' | 'xs' | 'sm' | 'md' | 'lg' | 'xl';
export type UiStackAlign = 'start' | 'center' | 'end' | 'stretch';
export type UiStackJustify = 'start' | 'center' | 'end' | 'between';

export type UiStackProps = HTMLAttributes<HTMLDivElement> & {
  direction?: UiStackDirection;
  gap?: UiStackGap;
  align?: UiStackAlign;
  justify?: UiStackJustify;
  wrap?: boolean;
};

export function UiStack({
  direction = 'vertical',
  gap = 'md',
  align = 'stretch',
  justify = 'start',
  wrap = false,
  className = '',
  ...props
}: UiStackProps) {
  const classes = [
    'zh-ui-stack',
    `zh-ui-stack--${direction}`,
    `zh-ui-stack--gap-${gap}`,
    `zh-ui-stack--align-${align}`,
    `zh-ui-stack--justify-${justify}`,
    wrap ? 'zh-ui-stack--wrap' : '',
    className
  ]
    .filter(Boolean)
    .join(' ');

  return <div {...props} className={classes} />;
}
