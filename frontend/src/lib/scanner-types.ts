import { z } from 'zod';
export type ScanStatus = 'Pending' | 'Running' | 'Completed' | 'Failed' | 'Cancelled';
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export const createScanSchema = z.object({
  target: z.string().trim().min(1, 'Enter a target base URL.').max(2048, 'The URL is too long.').url('Enter a valid URL, for example https://app.example.com.').refine(value => { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && Boolean(url.hostname) && !url.username && !url.password; } catch { return false; } }, 'Use an http:// or https:// URL without embedded credentials.'),
  name: z.string().trim().max(100, 'Use 100 characters or fewer.').optional(),
  profile: z.enum(['Basic', 'Standard']),
  authorized: z.literal(true).optional(),
});
export type CreateScanInput = z.infer<typeof createScanSchema>;
export type Confidence = 'High' | 'Medium' | 'Low';
export type Verification = 'Potential' | 'Confirmed' | 'False positive';
export type Finding = { id: string; title?: string; severity?: Severity; category?: string; path?: string; description?: string; evidence?: string; remediation?: string; confidence?: Confidence; verification?: Verification; affectedUrl?: string; whyItMatters?: string; firstDetectedAt?: string; relatedEndpoints?: string[] };
export type SeverityCounts = Record<Severity, number>;
export type ReportFormat = 'json' | 'html';
export type ScanRecord = {
  id: string | null; target: string; name: string; profile: string; status: ScanStatus;
  date: string; duration: string; findings: number; high: number;
  /** true only for mock-adapter records; live records come from the backend database. */
  demo: boolean;
  createdAt: string; startedAt: string | null; completedAt: string | null;
  endpoints: number; counts: SeverityCounts; results: Finding[]; scannedUrls?: string[]; scanLimitReached?: boolean; scope?: string; error?: string;
  /** Formats the backend reports as downloadable for this scan. Empty means unavailable. */
  reportFormats: ReportFormat[];
  /** Backend-declared: cancel endpoint exists and this scan can be cancelled. */
  canCancel: boolean;
};
export type Report = { filename: string; content: string; mime: string };
export type HealthStatus = { ok: boolean; mode: 'mock' | 'live' | 'disconnected'; version?: string };
export interface ScannerApi {
  readonly mode: 'mock' | 'live' | 'disconnected';
  readonly capabilities: { settings: boolean; authorizedTargets: boolean };
  health(): Promise<HealthStatus>;
  listScans(): Promise<ScanRecord[]>;
  getScan(id: string): Promise<ScanRecord>;
  createScan(input: CreateScanInput, onStarted?: (scanId: string) => void): Promise<ScanRecord>;
  waitForScan(scanId: string, startedAt?: string): Promise<ScanRecord>;
  exportReport(id: string, format: ReportFormat): Promise<Report>;
  cancelScan(id: string): Promise<ScanRecord>;
}
export const emptyCounts = (): SeverityCounts => ({ Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 });
export const activeStatuses: ScanStatus[] = ['Pending', 'Running'];
export function formatDuration(start: string | null, end: string | null): string {
  if (!start || !end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const s = Math.round(ms / 1000);
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}
export function formatElapsedTime(elapsedSeconds: number): string {
  const totalSeconds = Math.max(0, Math.floor(elapsedSeconds));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor(totalSeconds / 60) % 60;
  const seconds = totalSeconds % 60;
  const pad = (value: number) => String(value).padStart(2, '0');
  return hours > 0 ? `${pad(hours)}:${pad(minutes)}:${pad(seconds)}` : `${pad(Math.floor(totalSeconds / 60))}:${pad(seconds)}`;
}
