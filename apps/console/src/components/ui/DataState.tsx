import type { ReactNode } from 'react';
import { Spin } from 'antd';
import { EmptyState } from './EmptyState';
import { UiAlert } from './AntdControls';

export type UiDataStateStatus = 'loading' | 'error' | 'empty' | 'ready';

export type UiDataStateProps = {
  status: UiDataStateStatus;
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  children?: ReactNode;
  className?: string;
};

/**
 * One rendering contract for asynchronous data surfaces. A page must make
 * loading, failed, empty and ready states distinct instead of silently
 * replacing a failed live read with an empty or sample snapshot.
 */
export function UiDataState({ status, title, description, action, children, className = '' }: UiDataStateProps) {
  if (status === 'ready') return <>{children}</>;

  const classes = ['zh-data-state', `zh-data-state--${status}`, className].filter(Boolean).join(' ');
  if (status === 'loading') {
    return (
      <div className={classes} role="status" aria-live="polite">
        <Spin size="small" />
        <span>{title ?? '正在读取实时数据…'}</span>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className={classes}>
        <UiAlert type="error" showIcon title={title ?? '实时数据读取失败'} description={description} action={action} />
      </div>
    );
  }

  return (
    <div className={classes} role="status" aria-live="polite">
      <EmptyState description={title ?? '暂无实时数据'} />
      {description ? <div className="zh-data-state__description">{description}</div> : null}
      {action ? <div className="zh-data-state__action">{action}</div> : null}
    </div>
  );
}
