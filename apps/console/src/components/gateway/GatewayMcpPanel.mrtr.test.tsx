import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from '../../app/apiRequest';
import { GatewayMcpPanel } from './GatewayMcpPanel';

vi.mock('../../app/apiRequest', () => ({ request: vi.fn() }));

const configuredStatus = {
  mcp: { configured: true, enabled: true, guard_enabled: true, resource_limits: { os_enforced: true } }
};

describe('GatewayMcpPanel MRTR', () => {
  beforeEach(() => vi.mocked(request).mockReset());

  it('resumes an input_required round with the original request and protected state', async () => {
    vi.mocked(request)
      .mockResolvedValueOnce({
        jsonrpc: '2.0',
        id: 'round-1',
        result: {
          resultType: 'input_required',
          inputRequests: { 'srv-req-1': { method: 'sampling/createMessage', params: {} } },
          requestState: 'v1.signed-state.signature'
        }
      })
      .mockResolvedValueOnce({
        jsonrpc: '2.0',
        id: 'round-2',
        result: { resultType: 'complete', isError: false }
      });
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: 'tools/call' }));
    expect(await screen.findByText('MCP 需要操作员输入')).toBeInTheDocument();
    const responseEditor = screen.getByRole('textbox', { name: 'MCP inputResponses' }) as HTMLTextAreaElement;
    expect(responseEditor.value).toContain('srv-req-1');
    await userEvent.click(screen.getByRole('button', { name: '提交输入并恢复' }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    const resumedCall = vi.mocked(request).mock.calls[1];
    expect(resumedCall?.[1]?.headers).toMatchObject({ 'Mcp-Method': 'tools/call', 'Mcp-Name': 'file.read' });
    expect(JSON.parse(String(resumedCall?.[1]?.body))).toMatchObject({
      method: 'tools/call',
      params: {
        name: 'file.read',
        arguments: { path: 'public/项目说明.md' },
        inputResponses: {
          'srv-req-1': {
            role: 'assistant',
            content: { type: 'text', text: '已由操作员确认。' },
            model: 'operator-input'
          }
        },
        requestState: 'v1.signed-state.signature'
      }
    });
    await waitFor(() => expect(screen.queryByText('MCP 需要操作员输入')).not.toBeInTheDocument());
  });

  it('keeps malformed responses in the browser without consuming requestState', async () => {
    vi.mocked(request).mockResolvedValue({
      jsonrpc: '2.0',
      id: 'round-1',
      result: {
        resultType: 'input_required',
        inputRequests: { 'srv-req-1': { method: 'sampling/createMessage', params: {} } },
        requestState: 'v1.signed-state.signature'
      }
    });
    render(<GatewayMcpPanel runtimeStatus={configuredStatus} sessionId="mcp-session-1" onSessionIdChange={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: 'tools/call' }));
    const responseEditor = await screen.findByRole('textbox', { name: 'MCP inputResponses' });
    fireEvent.change(responseEditor, { target: { value: '[]' } });
    await userEvent.click(screen.getByRole('button', { name: '提交输入并恢复' }));

    expect(await screen.findByText('inputResponses 必须是 JSON 对象。')).toBeInTheDocument();
    expect(request).toHaveBeenCalledTimes(1);
  });
});
