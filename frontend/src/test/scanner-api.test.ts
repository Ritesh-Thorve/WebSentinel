import { describe, expect, it, vi } from 'vitest';
import { createScanSchema, formatElapsedTime } from '@/lib/scanner-types';
import { resolveApiConfig } from '@/lib/api-config';
import { createHttpScannerApi, createDisconnectedScannerApi } from '@/lib/http-scanner-api';
import { redactEvidence } from '@/lib/evidence';
const input = { target: 'https://authorized.example.com', profile: 'Standard' as const };
const dto = {
  target_url: input.target,
  status: 'completed',
  findings: [{
    title: 'Missing Content-Security-Policy',
    severity: 'informational',
    affected_url: input.target,
    description: 'The response did not include a Content-Security-Policy header.',
    evidence: "Header 'Content-Security-Policy' was not present",
    recommendation: 'Add a Content-Security-Policy header.',
    confidence: 'high',
  }],
  summary: { total_findings: 1, critical: 0, high: 0, medium: 0, low: 0, informational: 1 },
  scanned_urls: ['https://authorized.example.com/', 'https://authorized.example.com/about'],
  scan_limit_reached: true,
};
describe('Minimal scanner API', () => {
  it.each([
    [0, '00:00'],
    [65, '01:05'],
    [3661, '01:01:01'],
    [-1, '00:00'],
  ])('formats elapsed scan time %s seconds', (seconds, expected) => {
    expect(formatElapsedTime(seconds)).toBe(expected);
  });
  it.each(['ftp://example.com', 'javascript:alert(1)', 'not-a-url', 'https://user:password@example.com'])('rejects invalid target %s', target => {
    expect(createScanSchema.safeParse({ ...input, target }).success).toBe(false);
  });
  it('submits the URL using the backend contract and displays the synchronous scan results', async () => {
    const fetcher = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify(dto)));
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: fetcher });
    const created = await api.createScan(input);
    expect(created.id).toBeNull();
    expect(created.status).toBe('Completed');
    expect(created.counts.Info).toBe(1);
    expect(created.endpoints).toBe(2);
    expect(created.scannedUrls).toEqual(dto.scanned_urls);
    expect(created.scanLimitReached).toBe(true);
    expect(created.results).toEqual([{
      id: '0',
      title: 'Missing Content-Security-Policy',
      severity: 'Info',
      affectedUrl: input.target,
      description: 'The response did not include a Content-Security-Policy header.',
      evidence: "Header 'Content-Security-Policy' was not present",
      remediation: 'Add a Content-Security-Policy header.',
      confidence: 'High',
    }]);
    expect(fetcher.mock.calls[0]?.[0]).toBe('https://backend.example/api/scans');
    const init = (fetcher.mock.calls as unknown as [string, RequestInit][])[0]?.[1];
    expect(JSON.parse(String(init?.body))).toEqual({ target_url: input.target });
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });
  it('polls an active scan until the backend returns completed results', async () => {
    const started = {
      ...dto,
      scan_id: 'scan-123',
      status: 'running',
      findings: [],
      scanned_urls: [],
      summary: { total_findings: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    };
    const completed = { ...dto, scan_id: 'scan-123' };
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(started), { status: 202 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(completed)));
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: fetcher });
    const onStarted = vi.fn();

    const created = await api.createScan(input, onStarted);

    expect(onStarted).toHaveBeenCalledWith('scan-123');
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1]?.[0]).toBe('https://backend.example/api/scans/scan-123');
    expect(created.status).toBe('Completed');
    expect(created.results).toHaveLength(1);
  });
  it('can resume progress polling for a scan restored after refresh', async () => {
    const active = {
      ...dto,
      scan_id: 'scan-resume',
      status: 'running',
      findings: [],
      scanned_urls: [],
      summary: { total_findings: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    };
    const finished = { ...dto, scan_id: 'scan-resume' };
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(active)))
      .mockResolvedValueOnce(new Response(JSON.stringify(finished)));
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: fetcher });

    const result = await api.waitForScan('scan-resume', '2026-10-19T06:00:00Z');

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0]?.[0]).toBe('https://backend.example/api/scans/scan-resume');
    expect(result.status).toBe('Completed');
    expect(result.startedAt).toBe('2026-10-19T06:00:00Z');
  });
  it('requests cancellation and maps the backend partial report', async () => {
    const cancelled = {
      ...dto,
      scan_id: 'scan-123',
      status: 'cancelled',
      scanned_urls: ['https://authorized.example.com/'],
      findings: [],
      summary: { total_findings: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    };
    const fetcher = vi.fn<typeof fetch>(async () => new Response(JSON.stringify(cancelled)));
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: fetcher });

    const result = await api.cancelScan('scan-123');

    expect((fetcher.mock.calls[0]?.[0])).toBe('https://backend.example/api/scans/scan-123/cancel');
    expect(result.status).toBe('Cancelled');
    expect(result.scannedUrls).toEqual(cancelled.scanned_urls);
  });
  it('uses only the explicitly configured backend URL', () => {
    expect(resolveApiConfig({ baseUrl: 'https://backend.example/' })).toMatchObject({
      mode: 'live',
      baseUrl: 'https://backend.example',
    });
    expect(resolveApiConfig({}).mode).toBe('disconnected');
  });
  it('shows a connection failure rather than fake results', async () => {
    await expect(createDisconnectedScannerApi('Set VITE_API_BASE_URL.').createScan(input)).rejects.toThrow('not configured');
  });
  it.each([401, 403, 422, 429, 500])('surfaces backend failure %s', async status => {
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: async () => new Response('{}', { status }) });
    await expect(api.createScan(input)).rejects.toMatchObject({ status });
  });
  it('explains backend destination-safety rejections without exposing raw details', async () => {
    const api = createHttpScannerApi({
      baseUrl: 'https://backend.example',
      fetch: async () => new Response(JSON.stringify({ detail: 'Blocked destination: access to local or internal targets is restricted' }), { status: 400 }),
    });
    await expect(api.createScan(input)).rejects.toMatchObject({
      status: 400,
      message: expect.stringContaining('local, private, or otherwise restricted address'),
    });
  });
  it('redacts credentials in evidence', () => {
    expect(redactEvidence('Cookie: session=private-value\nAuthorization: Bearer private-token')).not.toContain('private');
  });
});
