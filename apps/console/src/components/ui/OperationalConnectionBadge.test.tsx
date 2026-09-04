import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { OperationalConnectionBadge } from './OperationalConnectionBadge';

describe('OperationalConnectionBadge', () => {
  it('makes a degraded data connection visible to the operator', () => {
    render(
      <OperationalConnectionBadge
        connection={{ status: 'degraded', message: '后端在线，但实时总览读取失败：数据库读取失败' }}
      />
    );

    expect(screen.getByLabelText('运行数据状态：数据读取降级')).toBeInTheDocument();
    expect(screen.getByText('数据读取降级')).toBeInTheDocument();
  });
});
