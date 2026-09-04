import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  fetchAlerts,
  fetchAuditLogs,
  fetchApprovalReviews,
  fetchHealth,
  fetchOverview,
  fetchPolicies,
  fetchReport,
  fetchScenarios,
  setAuthTokenProvider,
  subscribeRuntimeEvents,
  writeOpenClawPluginValidation
} from './api';
import { authInvalidEvent, openAuthenticatedResource } from './app/apiRequest';
import type { Overview, ReportData } from './types';

afterEach(() => {
  setAuthTokenProvider(null);
  vi.unstubAllGlobals();
});

describe('api client', () => {
  it('keeps the production approval queue scoped to operational records', async () => {
    const response = { reviews: [], summary: {} };
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: true,
      json: async () => response
    } as Response);
    vi.stubGlobal('fetch', fetchMock);

    await fetchApprovalReviews('待复核', 20);

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/approvals?status=%E5%BE%85%E5%A4%8D%E6%A0%B8&scope=operational&limit=20',
      expect.any(Object)
    );
  });

  it('fetches JSON with the shared request wrapper', async () => {
    const overview = {
      attack_surfaces: [],
      scenarios: [],
      models: [],
      recent_runs: [],
      alerts: [],
      audit_logs: [],
      summary: {
        surface_count: 0,
        scenario_count: 0,
        recent_run_count: 0,
        block_rate: 0,
        attack_success_rate: 0,
        avg_latency_ms: 0
      }
    } satisfies Overview;
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: true,
      json: async () => overview
    } as Response);

    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchOverview()).resolves.toEqual(overview);
    expect(fetchMock).toHaveBeenCalledWith('/api/overview', expect.objectContaining({ headers: expect.any(Headers) }));
    const init = fetchMock.mock.calls[0]?.[1];
    expect((init?.headers as Headers).get('Content-Type')).toBeNull();
  });

  it('surfaces an offline overview failure instead of fabricating runtime evidence', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockRejectedValue(new Error('offline')));

    await expect(fetchOverview()).rejects.toMatchObject({ code: 'network_error', path: '/api/overview' });
  });

  it('does not hide authorization failures behind fallback data', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: false,
      status: 403,
      text: async () => 'forbidden'
    } as Response);

    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchOverview()).rejects.toMatchObject({
      code: 'http_error',
      path: '/api/overview',
      status: 403,
      body: 'forbidden'
    });
  });

  it('turns FastAPI error envelopes into readable operator messages', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ detail: 'Invalid or missing API token' })
    } as Response);

    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchHealth()).rejects.toMatchObject({
      code: 'http_error',
      status: 401,
      message: 'Invalid or missing API token',
      body: JSON.stringify({ detail: 'Invalid or missing API token' })
    });
  });

  it('keeps validation details readable without exposing a synthetic fallback result', async () => {
    const body = JSON.stringify({ detail: [{ loc: ['body', 'model'], msg: 'Field required' }] });
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({ ok: false, status: 422, text: async () => body } as Response)
    );

    await expect(fetchAuditLogs()).rejects.toMatchObject({ message: 'body.model: Field required', body });
  });

  it('does not replace audit or alert read failures with empty live evidence', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockRejectedValue(new Error('offline')));

    await expect(fetchAuditLogs()).rejects.toMatchObject({ code: 'network_error', path: '/api/audit_logs?limit=100' });
    await expect(fetchAlerts()).rejects.toMatchObject({ code: 'network_error', path: '/api/alerts?limit=100' });
  });

  it('fails closed when historical policy or scenario catalogs are unavailable', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(new Error('offline'));
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchScenarios()).rejects.toMatchObject({ code: 'network_error', path: '/api/scenarios' });
    await expect(fetchPolicies()).rejects.toMatchObject({ code: 'network_error', path: '/api/policies' });
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('uses an abort signal for report loading', async () => {
    const report = { markdown: '# report' } as ReportData;
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: true,
      json: async () => report
    } as Response);

    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchReport()).resolves.toEqual(report);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(init?.cache).toBe('no-store');
  });

  it('does not repeat the expensive report request after a network failure', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(new Error('offline'));
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchReport()).rejects.toMatchObject({ code: 'network_error', path: '/api/report' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('adds an authorization header when a token provider is configured', async () => {
    const report = { markdown: '# report' } as ReportData;
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: true,
      json: async () => report
    } as Response);

    vi.stubGlobal('fetch', fetchMock);
    setAuthTokenProvider(() => 'local-token');

    await expect(fetchReport()).resolves.toEqual(report);
    const init = fetchMock.mock.calls[0]?.[1];
    const headers = init?.headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer local-token');
  });

  it('opens protected artifacts with the configured authorization header', async () => {
    vi.useFakeTimers();
    const popup = { close: vi.fn(), location: { href: '' } } as unknown as Window;
    const openMock = vi.spyOn(window, 'open').mockReturnValue(popup);
    const createUrlMock = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:readiness');
    const revokeUrlMock = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: true,
      blob: async () => new Blob(['{}'], { type: 'application/json' })
    } as Response);

    vi.stubGlobal('fetch', fetchMock);
    setAuthTokenProvider(() => 'operator-token');

    try {
      await openAuthenticatedResource('/api/readiness');
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/readiness',
        expect.objectContaining({
          headers: expect.any(Headers),
          cache: 'no-store',
          signal: expect.any(AbortSignal)
        })
      );
      const init = fetchMock.mock.calls[0]?.[1];
      expect((init?.headers as Headers).get('Authorization')).toBe('Bearer operator-token');
      expect(openMock).toHaveBeenCalledWith('', '_blank');
      expect(popup.location.href).toBe('blob:readiness');
      expect(createUrlMock).toHaveBeenCalledOnce();
      vi.advanceTimersByTime(60_000);
      expect(revokeUrlMock).toHaveBeenCalledWith('blob:readiness');
    } finally {
      openMock.mockRestore();
      createUrlMock.mockRestore();
      revokeUrlMock.mockRestore();
      vi.useRealTimers();
    }
  });

  it('invalidates the operator session when a protected artifact returns 401', async () => {
    const popup = { close: vi.fn(), location: { href: '' } } as unknown as Window;
    const openMock = vi.spyOn(window, 'open').mockReturnValue(popup);
    const invalidation = vi.fn();
    window.addEventListener(authInvalidEvent, invalidation);
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => JSON.stringify({ detail: 'Invalid or missing API token' })
      } as Response)
    );

    try {
      await expect(openAuthenticatedResource('/api/readiness')).rejects.toMatchObject({ status: 401 });
      expect(invalidation).toHaveBeenCalledOnce();
      expect(popup.close).toHaveBeenCalledOnce();
    } finally {
      window.removeEventListener(authInvalidEvent, invalidation);
      openMock.mockRestore();
    }
  });

  it('throws a structured ApiError for non-fallback API failures', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: false,
      status: 403,
      text: async () => 'forbidden'
    } as Response);

    vi.stubGlobal('fetch', fetchMock);

    try {
      await fetchReport();
      throw new Error('Expected fetchReport to reject');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({
        code: 'http_error',
        path: '/api/report',
        status: 403,
        body: 'forbidden'
      });
    }
  });

  it('invalidates the operator session when the live event stream returns 401', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => 'expired'
    } as Response);
    const invalidation = vi.fn();
    window.addEventListener(authInvalidEvent, invalidation);
    vi.stubGlobal('fetch', fetchMock);

    try {
      await expect(subscribeRuntimeEvents(vi.fn(), new AbortController().signal)).rejects.toMatchObject({
        status: 401,
        path: '/api/events/stream'
      });
      expect(invalidation).toHaveBeenCalledOnce();
    } finally {
      window.removeEventListener(authInvalidEvent, invalidation);
    }
  });

  it('requests OpenClaw runtime validation when writing plugin validation evidence', async () => {
    const validation = { validation: { overall_status: 'runtime-validated' } };
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: true,
      json: async () => validation
    } as Response);

    vi.stubGlobal('fetch', fetchMock);

    await expect(writeOpenClawPluginValidation()).resolves.toEqual(validation);
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/integrations/openclaw/plugin_package/validation/write?inspect_runtime=true',
      expect.objectContaining({ method: 'POST' })
    );
  });
});
