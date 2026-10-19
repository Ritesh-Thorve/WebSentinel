import { z } from 'zod';
import { ApiError, ScanNotFoundError, statusToError } from './api-errors';
import { createScanSchema, emptyCounts, formatDuration, type Finding, type HealthStatus, type ReportFormat, type ScannerApi, type ScanRecord, type Severity } from './scanner-types';

// ---- Wire contract (FastAPI, snake_case). See README "API contract". ----
const severityDto = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const statusDto = z.enum(['pending', 'running', 'completed', 'failed', 'cancelled']);
const isoDate = z.string().refine(v => !Number.isNaN(Date.parse(v)), 'Invalid timestamp');
const summaryDto = z.object({ critical: z.number().int().nonnegative(), high: z.number().int().nonnegative(), medium: z.number().int().nonnegative(), low: z.number().int().nonnegative(), info: z.number().int().nonnegative() });
export const scanDto = z.object({
  id: z.string().min(1).max(128),
  target_url: z.string().url(),
  name: z.string().max(200).nullish(),
  profile: z.string().max(40),
  status: statusDto,
  created_at: isoDate,
  started_at: isoDate.nullish(),
  completed_at: isoDate.nullish(),
  endpoints_discovered: z.number().int().nonnegative().nullish(),
  scope: z.string().max(2000).nullish(),
  summary: summaryDto,
  error_message: z.string().max(1000).nullish(),
  reports_available: z.array(z.enum(['json', 'html'])).nullish(),
  can_cancel: z.boolean().nullish(),
});
export const findingDto = z.object({
  id: z.string().min(1).max(128),
  title: z.string().max(300).nullish(),
  severity: severityDto.nullish(),
  confidence: z.enum(['low', 'medium', 'high']).nullish(),
  verification_status: z.enum(['potential', 'confirmed', 'false_positive']).nullish(),
  category: z.string().max(120).nullish(),
  affected_url: z.string().max(4096).nullish(),
  description: z.string().max(10000).nullish(),
  evidence: z.string().max(50000).nullish(),
  why_it_matters: z.string().max(10000).nullish(),
  remediation: z.string().max(10000).nullish(),
  first_detected_at: isoDate.nullish(),
  related_endpoints: z.array(z.string().max(4096)).max(200).nullish(),
});
const listDto = z.union([z.array(scanDto), z.object({ items: z.array(scanDto) })]);
const findingsDto = z.union([z.array(findingDto), z.object({ items: z.array(findingDto) })]);
const healthDto = z.object({ status: z.string(), version: z.string().optional() });
export type ScanDto = z.infer<typeof scanDto>;
export type FindingDto = z.infer<typeof findingDto>;

const cap = (s: string) => (s.charAt(0).toUpperCase() + s.slice(1)) as Severity;
const statusMap = { pending: 'Pending', running: 'Running', completed: 'Completed', failed: 'Failed', cancelled: 'Cancelled' } as const;
export function normalizeFinding(f: FindingDto): Finding {
  return { id: f.id, ...(f.title != null ? { title: f.title } : {}), ...(f.severity ? { severity: cap(f.severity) } : {}), ...(f.confidence ? { confidence: cap(f.confidence) as Exclude<Finding['confidence'], undefined> } : {}), ...(f.verification_status ? { verification: f.verification_status === 'false_positive' ? 'False positive' as const : f.verification_status === 'confirmed' ? 'Confirmed' as const : 'Potential' as const } : {}), ...(f.category != null ? { category: f.category } : {}), ...(f.affected_url != null ? { affectedUrl: f.affected_url } : {}), ...(f.description != null ? { description: f.description } : {}), ...(f.evidence != null ? { evidence: f.evidence } : {}), ...(f.why_it_matters != null ? { whyItMatters: f.why_it_matters } : {}), ...(f.remediation != null ? { remediation: f.remediation } : {}), ...(f.first_detected_at ? { firstDetectedAt: f.first_detected_at } : {}), ...(f.related_endpoints ? { relatedEndpoints: f.related_endpoints } : {}) };
}
export function normalizeScan(dto: ScanDto, results: Finding[] = []): ScanRecord {
  const status = statusMap[dto.status];
  const counts = emptyCounts();
  counts.Critical = dto.summary.critical; counts.High = dto.summary.high; counts.Medium = dto.summary.medium; counts.Low = dto.summary.low; counts.Info = dto.summary.info;
  const findings = Object.values(counts).reduce((a, b) => a + b, 0);
  // Reports are only offered for completed scans that the backend says have reports.
  const reportFormats = status === 'Completed' ? [...new Set(dto.reports_available ?? [])] : [];
  return {
    id: dto.id, target: dto.target_url, name: dto.name || new URL(dto.target_url).hostname, profile: dto.profile.charAt(0).toUpperCase() + dto.profile.slice(1), status,
    date: new Date(dto.created_at).toLocaleString('en-GB', { timeZone: 'UTC' }) + ' UTC',
    duration: formatDuration(dto.started_at ?? null, dto.completed_at ?? null), findings, high: counts.Critical + counts.High, demo: false,
    createdAt: dto.created_at, startedAt: dto.started_at ?? null, completedAt: dto.completed_at ?? null, endpoints: dto.endpoints_discovered ?? 0, counts, results,
    ...(dto.scope ? { scope: dto.scope } : {}), ...(status === 'Failed' ? { error: dto.error_message || 'The scan failed on the backend.' } : {}),
    reportFormats, canCancel: Boolean(dto.can_cancel) && (status === 'Pending' || status === 'Running'),
  };
}
function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new ApiError('invalid_response');
  return result.data;
}

export type HttpAdapterOptions = { baseUrl: string; fetch?: typeof fetch; timeoutMs?: number; reportTimeoutMs?: number; getAccessToken?: () => string | null | Promise<string | null> };

export function createHttpScannerApi(options: HttpAdapterOptions): ScannerApi {
  const base = options.baseUrl.replace(/\/+$/, '');
  const doFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  async function request(path: string, init: { method?: string; body?: unknown; timeoutMs?: number; notFound?: () => Error } = {}): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), init.timeoutMs ?? options.timeoutMs ?? 15000);
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (init.body !== undefined) headers['Content-Type'] = 'application/json';
    const token = await options.getAccessToken?.();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    let response: Response;
    try {
      response = await doFetch(`${base}${path}`, { method: init.method ?? 'GET', headers, credentials: 'include', signal: controller.signal, redirect: 'error', ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}) });
    } catch (error) {
      if (controller.signal.aborted) throw new ApiError('timeout');
      void error; throw new ApiError('disconnected');
    } finally { clearTimeout(timer); }
    if (!response.ok) {
      if (response.status === 404 && init.notFound) throw init.notFound();
      let body: unknown = null; try { body = await response.json(); } catch { /* non-JSON error body */ }
      throw statusToError(response.status, body, response.headers.get('Retry-After'));
    }
    return response;
  }
  const json = async (res: Response) => { try { return await res.json(); } catch { throw new ApiError('invalid_response'); } };
  const scanPath = (id: string) => `/api/scans/${encodeURIComponent(id)}`;
  const notFound = () => new ScanNotFoundError();
  const api: ScannerApi = {
    mode: 'live',
    capabilities: { settings: false, authorizedTargets: false },
    async health(): Promise<HealthStatus> {
      const data = parse(healthDto, await json(await request('/health', { timeoutMs: 5000 })));
      return { ok: data.status === 'ok', mode: 'live', ...(data.version ? { version: data.version } : {}) };
    },
    async listScans() {
      const data = parse(listDto, await json(await request('/api/scans')));
      return (Array.isArray(data) ? data : data.items).map(dto => normalizeScan(dto));
    },
    async getScan(id) {
      const [scanRes, findingsRes] = await Promise.all([request(scanPath(id), { notFound }), request(`${scanPath(id)}/findings`, { notFound })]);
      const dto = parse(scanDto, await json(scanRes));
      if (dto.id !== id) throw new ApiError('invalid_response');
      const f = parse(findingsDto, await json(findingsRes));
      return normalizeScan(dto, (Array.isArray(f) ? f : f.items).map(normalizeFinding));
    },
    async createScan(input) {
      const valid = createScanSchema.parse(input);
      const res = await request('/api/scans', { method: 'POST', body: { target_url: valid.target, name: valid.name || null, profile: valid.profile.toLowerCase(), ...(valid.authorized === true ? { authorization_confirmed: true } : {}) } });
      const dto = parse(scanDto, await json(res));
      // Preserve the backend's actual lifecycle, including synchronous completion or failure.
      return normalizeScan(dto);
    },
    async exportReport(id, format: ReportFormat) {
      const res = await request(`${scanPath(id)}/report?format=${format}`, { timeoutMs: options.reportTimeoutMs ?? 60000, notFound: () => new ApiError('not_found', { status: 404, message: 'This report is not available. The scan may not be finished, or the backend has not generated it.' }) });
      const type = res.headers.get('Content-Type') ?? '';
      const content = await res.text();
      if (format === 'json') {
        if (!type.includes('json')) throw new ApiError('invalid_response');
        try { JSON.parse(content); } catch { throw new ApiError('invalid_response'); }
      } else {
        if (!type.includes('text/html')) throw new ApiError('invalid_response');
        // Defense in depth: the backend must escape target content. Refuse active content rather than save it.
        if (/<script\b|\son[a-z]+\s*=|javascript:/i.test(content)) throw new ApiError('invalid_response', { message: 'The HTML report contained active content and was blocked. The backend must escape all target-derived content.' });
      }
      const disposition = res.headers.get('Content-Disposition') ?? '';
      const match = /filename="?([A-Za-z0-9._-]{1,120})"?/.exec(disposition);
      return { filename: match?.[1] ?? `websentinel-${id}.${format}`, content, mime: format === 'json' ? 'application/json' : 'text/html' };
    },
    async cancelScan(id) {
      const res = await request(`${scanPath(id)}/cancel`, { method: 'POST' });
      return normalizeScan(parse(scanDto, await json(res)));
    },
  };
  return api;
}

export function createDisconnectedScannerApi(reason: string): ScannerApi {
  const fail = async (): Promise<never> => { throw new ApiError('disconnected', { message: `The WebSentinel backend is not configured. ${reason}` }); };
  return { mode: 'disconnected', capabilities: { settings: false, authorizedTargets: false }, health: fail, listScans: fail, getScan: fail, createScan: fail, exportReport: fail, cancelScan: fail };
}
