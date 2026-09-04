import type { ReactNode } from 'react';
import { Space, Typography } from 'antd';

export type PageHeaderProps = {
  title: ReactNode;
  description?: ReactNode;
  badge?: ReactNode;
  actions?: ReactNode;
  className?: string;
};

export function PageHeader({ title, description, badge, actions, className }: PageHeaderProps) {
  const classes = ['zh-product-heading', className].filter(Boolean).join(' ');
  return (
    <header className={classes}>
      <div>
        <Space align="center" size={10} wrap>
          <Typography.Title level={1}>{title}</Typography.Title>
          {badge}
        </Space>
        {description ? <Typography.Text type="secondary">{description}</Typography.Text> : null}
      </div>
      {actions ? <div className="zh-product-heading__actions">{actions}</div> : null}
    </header>
  );
}
