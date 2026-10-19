export type ApiMode = 'mock' | 'live' | 'disconnected';
export type ApiConfig = { mode: ApiMode; baseUrl: string | null; reason: string };

/**
 * Resolves which scanner adapter to use from Vite env values:
 * - VITE_API_BASE_URL set (http/https) -> live FastAPI adapter.
 * - Missing or invalid URL -> disconnected in every environment. Never use demo data.
 */
export function resolveApiConfig(env: { baseUrl?: string | undefined; useMock?: string | undefined; dev: boolean }): ApiConfig {
  const raw = env.baseUrl?.trim();
  if (raw) {
    try {
      const url = new URL(raw);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('bad');
      return { mode: 'live', baseUrl: url.toString().replace(/\/+$/, ''), reason: 'Connected to the configured FastAPI backend.' };
    } catch {
      return { mode: 'disconnected', baseUrl: null, reason: 'VITE_API_BASE_URL is not a valid http(s) URL without credentials.' };
    }
  }
  return { mode: 'disconnected', baseUrl: null, reason: 'Set VITE_API_BASE_URL to the existing scanner backend URL.' };
}

export const apiConfig: ApiConfig = resolveApiConfig({
  baseUrl: import.meta.env['VITE_API_BASE_URL'] as string | undefined,
  useMock: import.meta.env['VITE_USE_MOCK_API'] as string | undefined,
  dev: Boolean(import.meta.env.DEV),
});
