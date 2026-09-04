import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { GatewayRequestPanel } from './GatewayRequestPanel';

describe('GatewayRequestPanel', () => {
  it('associates the visible session label with the session input', () => {
    render(
      <GatewayRequestPanel
        payload="{}"
        onPayloadChange={vi.fn()}
        sessionId="session-1"
        onSessionIdChange={vi.fn()}
        managedMode={false}
        onManagedModeChange={vi.fn()}
        loading={false}
        streamProgress={null}
        error=""
        onSubmit={vi.fn()}
        onCancelStream={vi.fn()}
      />
    );

    expect(screen.getByLabelText(/Agent 会话 ID/)).toHaveAttribute('id', 'gateway-agent-session-id');
  });
});
