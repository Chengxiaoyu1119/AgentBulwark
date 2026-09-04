import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { PageHeader } from './PageHeader';

describe('PageHeader', () => {
  it('keeps the title, status, description, and actions in one semantic header', () => {
    render(
      <PageHeader
        title="请求防护"
        badge={<span>防护运行中</span>}
        description="查看实时请求"
        actions={<button type="button">验证防护</button>}
      />
    );

    expect(screen.getByRole('heading', { level: 1, name: '请求防护' })).toBeInTheDocument();
    expect(screen.getByText('防护运行中')).toBeInTheDocument();
    expect(screen.getByText('查看实时请求')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '验证防护' }).closest('header')).not.toBeNull();
  });
});
