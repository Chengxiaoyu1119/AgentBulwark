import { describe, expect, it } from 'vitest';
import { validateRuntimeResponse } from './runtimeResponseValidation';

const status = {
  ok: true,
  service: 'agent-security-supervisor',
  console_auth: { required: true, transport: 'bearer', profile: 'local' }
};

describe('public console status validation', () => {
  it('accepts only a healthy response from the expected backend', () => {
    expect(validateRuntimeResponse('/api/public/status', status)).toBe(true);
    expect(validateRuntimeResponse('/api/public/status', { ...status, ok: false })).toBe(false);
    expect(validateRuntimeResponse('/api/public/status', { ...status, service: 'unexpected-service' })).toBe(false);
  });
});
