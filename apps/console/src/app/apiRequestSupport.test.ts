import { describe, expect, it } from 'vitest';
import { ApiError, safeUiErrorSummary } from './apiRequest';

describe('safeUiErrorSummary', () => {
  it('keeps bounded stream protocol diagnostics after HTTP headers are committed', () => {
    const error = new ApiError('Provider流式响应失败或在完成前中断。', {
      code: 'http_error',
      path: '/v1/chat/completions',
      status: 200
    });

    expect(safeUiErrorSummary(error)).toBe('Provider流式响应失败或在完成前中断。');
  });
});
