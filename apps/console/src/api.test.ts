import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, fetchOverview, fetchReport, setAuthTokenProvider, writeOpenClawPluginValidation } from './api';
import { openAuthenticatedResource } from './app/apiRequest';
import type { Overview, ReportData } from './types';

afterEach(() => {
  setAuthTokenProvider(null);
  vi.unstubAllGlobals();
});

describe('api client', () => {
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

  it('returns an empty offline overview instead of fabricated runtime evidence', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockRejectedValue(new Error('offline')));

    const overview = await fetchOverview();

    expect(overview.summary.surface_count).toBe(0);
    expect(overview.models).toEqual([]);
    expect(overview.recent_runs).toEqual([]);
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

  it('requests OpenClaw runtime validation when writing plugin validation evidence', async () => {
    const validation = {
      validation: {
        overall_status: 'runtime-validated'
      }
    };
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
