import { act, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from './apiRequest';
import { useGatewayMcpController } from './useGatewayMcpController';

vi.mock('./apiRequest', () => ({ request: vi.fn() }));
vi.mock('./useGatewayMcpSubscription', () => ({
  useGatewayMcpSubscription: () => ({ stopSubscription: vi.fn() })
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function Probe({ sessionId = 'session-a' }: { sessionId?: string }) {
  const controller = useGatewayMcpController({ sessionId });
  return (
    <div>
      <button type="button" onClick={() => void controller.send('tools/list')}>
        send
      </button>
      <button type="button" onClick={() => void controller.loadContextEvidence()}>
        evidence
      </button>
      <span data-testid="result">{String(controller.result?.response?.marker ?? '')}</span>
      <span data-testid="loading">{controller.loadingMethod}</span>
      <span data-testid="input-required">{controller.inputRequired?.requestState ?? ''}</span>
      <span data-testid="context">{String(controller.contextEvidence?.marker ?? '')}</span>
      <span data-testid="error">{controller.error}</span>
      <span data-testid="stream-events">{controller.streamEvents.length}</span>
    </div>
  );
}

describe('useGatewayMcpController request lifecycle', () => {
  beforeEach(() => {
    vi.mocked(request).mockReset();
  });

  it('cancels the superseded request and ignores its late response', async () => {
    const first = deferred<Record<string, unknown>>();
    const second = deferred<Record<string, unknown>>();
    vi.mocked(request).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    render(<Probe />);

    screen.getByRole('button', { name: 'send' }).click();
    screen.getByRole('button', { name: 'send' }).click();
    expect(vi.mocked(request).mock.calls[0]?.[1]?.signal?.aborted).toBe(true);

    await act(async () => second.resolve({ marker: 'newest' }));
    expect(screen.getByTestId('result')).toHaveTextContent('newest');
    expect(screen.getByTestId('loading')).toHaveTextContent('');

    await act(async () => first.resolve({ marker: 'stale' }));
    expect(screen.getByTestId('result')).toHaveTextContent('newest');
  });

  it('clears response state when the operator changes MCP sessions', async () => {
    vi.mocked(request).mockResolvedValue({ marker: 'session-a-result' });
    const { rerender } = render(<Probe sessionId="session-a" />);

    screen.getByRole('button', { name: 'send' }).click();
    expect(await screen.findByTestId('result')).toHaveTextContent('session-a-result');

    rerender(<Probe sessionId="session-b" />);

    expect(screen.getByTestId('result')).toBeEmptyDOMElement();
    expect(screen.getByTestId('input-required')).toBeEmptyDOMElement();
    expect(screen.getByTestId('context')).toBeEmptyDOMElement();
    expect(screen.getByTestId('error')).toBeEmptyDOMElement();
    expect(screen.getByTestId('stream-events')).toHaveTextContent('0');
  });

  it('aborts an in-flight request when the operator changes MCP sessions', async () => {
    const pending = deferred<Record<string, unknown>>();
    vi.mocked(request).mockReturnValue(pending.promise);
    const { rerender } = render(<Probe sessionId="session-a" />);

    screen.getByRole('button', { name: 'send' }).click();
    const signal = vi.mocked(request).mock.calls[0]?.[1]?.signal;
    expect(signal?.aborted).toBe(false);

    rerender(<Probe sessionId="session-b" />);
    expect(signal?.aborted).toBe(true);

    await act(async () => pending.resolve({ marker: 'stale-session-a-result' }));
    expect(screen.getByTestId('result')).toBeEmptyDOMElement();
  });

  it('keeps the pending MRTR recovery state while blocking unrelated requests', async () => {
    vi.mocked(request).mockResolvedValueOnce({
      result: {
        resultType: 'input_required',
        inputRequests: { approval: { mode: 'form' } },
        requestState: 'signed-session-a-state'
      }
    });
    render(<Probe />);

    screen.getByRole('button', { name: 'send' }).click();
    expect(await screen.findByTestId('input-required')).toHaveTextContent('signed-session-a-state');

    await act(async () => screen.getByRole('button', { name: 'evidence' }).click());

    expect(request).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('input-required')).toHaveTextContent('signed-session-a-state');
    expect(screen.getByTestId('error')).toHaveTextContent('请先完成当前输入请求');
  });
});
