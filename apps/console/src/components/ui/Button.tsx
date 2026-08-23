import React, { useState } from 'react';
import { Button as AntButton, ButtonProps, message } from 'antd';
import { openAuthenticatedResource } from '../../app/apiRequest';

export type UiButtonProps = {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'default';
  icon?: React.ReactNode;
  authenticatedHref?: string;
} & Omit<ButtonProps, 'variant'>;

export function UiButton({
  variant = 'default',
  className = '',
  icon,
  children,
  authenticatedHref,
  onClick,
  loading,
  href,
  target,
  ...props
}: UiButtonProps) {
  const [resourceLoading, setResourceLoading] = useState(false);
  let type: ButtonProps['type'] = undefined;
  let danger = false;
  if (variant === 'primary') type = 'primary';
  if (variant === 'ghost') type = 'text';
  if (variant === 'danger') {
    type = 'primary';
    danger = true;
  }

  async function handleClick(event: React.MouseEvent<HTMLButtonElement>) {
    onClick?.(event);
    if (event.defaultPrevented || !authenticatedHref) {
      return;
    }
    setResourceLoading(true);
    try {
      await openAuthenticatedResource(authenticatedHref);
    } catch (error) {
      message.error(error instanceof Error ? error.message : '受保护资源打开失败。');
    } finally {
      setResourceLoading(false);
    }
  }

  return (
    <AntButton
      type={type}
      danger={danger}
      icon={icon}
      className={className}
      {...props}
      href={authenticatedHref ? undefined : href}
      target={authenticatedHref ? undefined : target}
      onClick={authenticatedHref ? handleClick : onClick}
      loading={authenticatedHref ? resourceLoading || loading : loading}
    >
      {children}
    </AntButton>
  );
}
