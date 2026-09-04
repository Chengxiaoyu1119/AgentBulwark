import type { ReactNode } from 'react';
import { Popconfirm } from 'antd';
import { UiButton, type UiButtonProps } from './Button';

export type UiConfirmButtonProps = Omit<UiButtonProps, 'onClick'> & {
  confirmTitle: ReactNode;
  confirmDescription?: ReactNode;
  onConfirm: () => void;
  confirmOkText?: string;
  confirmCancelText?: string;
};

export function UiConfirmButton({
  confirmTitle,
  confirmDescription,
  onConfirm,
  confirmOkText = '确认',
  confirmCancelText = '取消',
  danger,
  ...buttonProps
}: UiConfirmButtonProps) {
  return (
    <Popconfirm
      title={confirmTitle}
      description={confirmDescription}
      okText={confirmOkText}
      cancelText={confirmCancelText}
      okButtonProps={{ danger }}
      onConfirm={onConfirm}
      disabled={buttonProps.disabled}
    >
      <UiButton {...buttonProps} danger={danger} />
    </Popconfirm>
  );
}
