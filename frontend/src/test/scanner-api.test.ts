import { describe, expect, it, vi } from 'vitest';
import { createScanSchema } from '@/lib/scanner-types';
import { resolveApiConfig } from '@/lib/api-config';
import { createHttpScannerApi, createDisconnectedScannerApi } from '@/lib/http-scanner-api';
import { redactEvidence } from '@/lib/evidence';
const input = { target: 'https://authorized.example.com', profile: 'Standard' as const };
const dto = { id: 'backend-id', target_url: input.target, profile: 'standard', status: 'pending', created_at: '2026-10-18T06:52:00Z', summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } };
describe('Minimal scanner API', () => {
  it.each(['ftp://example.com', 'javascript:alert(1)', 'not-a-url', 'https://user:password@example.com'])('rejects invalid target %s', target => {
    expect(createScanSchema.safeParse({ ...input, target }).success).toBe(false);
  });
  it('accepts a URL without inventing authorization confirmation', async () => {
    const fetcher = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify(dto)));
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: fetcher });
    const created = await api.createScan(input);
    expect(created.id).toBe('backend-id');
    expect(fetcher.mock.calls[0]?.[0]).toBe('https://backend.example/api/scans');
    const init = (fetcher.mock.calls as unknown as [string, RequestInit][])[0]?.[1];
    expect(JSON.parse(String(init?.body))).toEqual({ target_url: input.target, name: null, profile: 'standard' });
  });
  it('never selects mock data when configuration is absent', () => {
    expect(resolveApiConfig({ dev: true, useMock: 'true' }).mode).toBe('disconnected');
    expect(resolveApiConfig({ dev: false }).mode).toBe('disconnected');
  });
  it('shows a connection failure rather than fake results', async () => {
    await expect(createDisconnectedScannerApi('Set VITE_API_BASE_URL.').createScan(input)).rejects.toThrow('not configured');
  });
  it('reads actual completed findings via existing ID endpoints and preserves missing fields', async () => {
    const fetcher = vi.fn(async (url: RequestInfo | URL) => new Response(JSON.stringify(String(url).endsWith('/findings') ? [{ id: 'actual-finding', title: 'Observed header', evidence: '<script>untrusted</script>' }] : { ...dto, status: 'completed' })));
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: fetcher });
    const scan = await api.getScan('backend-id');
    expect(scan.results).toEqual([{ id: 'actual-finding', title: 'Observed header', evidence: '<script>untrusted</script>' }]);
    expect(fetcher.mock.calls.map(call => call[0])).toEqual(['https://backend.example/api/scans/backend-id', 'https://backend.example/api/scans/backend-id/findings']);
  });
  it('accepts synchronous backend completion without synthesizing progress', async () => {
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: async () => new Response(JSON.stringify({ ...dto, status: 'completed' })) });
    expect((await api.createScan(input)).status).toBe('Completed');
  });
  it.each([401, 403, 422, 429, 500])('surfaces backend failure %s', async status => {
    const api = createHttpScannerApi({ baseUrl: 'https://backend.example', fetch: async () => new Response('{}', { status }) });
    await expect(api.createScan(input)).rejects.toMatchObject({ status });
  });
  it('redacts credentials in evidence', () => {
    expect(redactEvidence('Cookie: session=private-value\nAuthorization: Bearer private-token')).not.toContain('private');
  });
});
