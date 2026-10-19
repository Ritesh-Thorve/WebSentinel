export type ApiErrorKind =
  | 'disconnected'
  | 'timeout'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'validation'
  | 'rate_limited'
  | 'server'
  | 'invalid_response'
  | 'not_implemented'
  | 'unknown';

const defaults: Record<ApiErrorKind, string> = {
  disconnected: 'The WebSentinel backend is not reachable. Check that the API is running and that the frontend is configured with its URL.',
  timeout: 'The backend did not respond in time. Please try again in a moment.',
  unauthorized: 'The backend requires an authenticated session before scanning. No scan results are available.',
  forbidden: 'You do not have permission to access this resource. Scans are only visible to their owner.',
  not_found: 'The requested record was not found or is not available to your account.',
  validation: 'The backend rejected the request. Review the highlighted fields and try again.',
  rate_limited: 'Too many requests were sent. Wait a moment before trying again.',
  server: 'The backend encountered an error. Please try again later.',
  invalid_response: 'The backend returned data in an unexpected format, so it was not displayed.',
  not_implemented: 'This action is not supported by the connected backend yet.',
  unknown: 'Something went wrong. Please try again.',
};

/** Normalized, user-presentable API error. Raw backend messages are never shown verbatim. */
export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;
  readonly fieldErrors: Record<string, string>;
  readonly retryAfterSeconds: number | undefined;
  constructor(kind: ApiErrorKind, options: { message?: string; status?: number; fieldErrors?: Record<string, string>; retryAfterSeconds?: number } = {}) {
    super(options.message ?? defaults[kind]);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = options.status;
    this.fieldErrors = options.fieldErrors ?? {};
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
  get retryable() { return ['disconnected', 'timeout', 'rate_limited', 'server', 'unknown'].includes(this.kind); }
}

export class ScanNotFoundError extends ApiError {
  constructor(message = 'This scan does not exist or is not available to your account.') { super('not_found', { message, status: 404 }); this.name = 'ScanNotFoundError'; }
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError('unknown');
}

/** Maps a FastAPI 422 `detail` array to form field messages without echoing raw input. */
export function parseValidationDetail(body: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  const detail = body && typeof body === 'object' ? (body as { detail?: unknown }).detail : undefined;
  if (!Array.isArray(detail)) return out;
  const fieldMap: Record<string, string> = { target_url: 'target', target: 'target', name: 'name', profile: 'profile', authorization_confirmed: 'authorized' };
  for (const item of detail) {
    if (!item || typeof item !== 'object') continue;
    const loc = (item as { loc?: unknown }).loc;
    const msg = (item as { msg?: unknown }).msg;
    const last = Array.isArray(loc) ? String(loc[loc.length - 1]) : '';
    const key = fieldMap[last] ?? 'submit';
    if (!out[key] && typeof msg === 'string') out[key] = msg.slice(0, 200);
  }
  return out;
}

export function statusToError(status: number, body: unknown, retryAfter: string | null): ApiError {
  if (status === 401) return new ApiError('unauthorized', { status });
  if (status === 403) return new ApiError('forbidden', { status });
  if (status === 404) return new ApiError('not_found', { status });
  if (status === 405 || status === 501) return new ApiError('not_implemented', { status });
  if (status === 422 || status === 400) return new ApiError('validation', { status, fieldErrors: parseValidationDetail(body) });
  if (status === 429) { const seconds = retryAfter ? Number(retryAfter) : NaN; return new ApiError('rate_limited', { status, ...(Number.isFinite(seconds) ? { retryAfterSeconds: seconds, message: `Too many requests. Try again in about ${Math.ceil(seconds)} seconds.` } : {}) }); }
  if (status >= 500) return new ApiError('server', { status });
  return new ApiError('unknown', { status });
}
