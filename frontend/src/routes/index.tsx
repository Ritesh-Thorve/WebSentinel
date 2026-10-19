import { useEffect, useRef, useState, type FormEvent } from 'react';
import { createFileRoute } from '@tanstack/react-router';
import { useMutation } from '@tanstack/react-query';
import { ScanSearch, Shield, Square } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { scannerApi, createScanSchema, formatElapsedTime } from '@/lib/scanner-api';
import { toApiError } from '@/lib/api-errors';
import { redactEvidence } from '@/lib/evidence';
import type { ScanRecord } from '@/lib/scanner-types';
import { CategoryBreakdown, FindingsList, ScanSummary, ScannedPaths, SeverityDistribution, TechnicalDetails } from '@/components/scan-report';

const SCAN_SESSION_KEY = 'websentinel.current-scan.v1';

type StoredScanSession = {
  target: string;
  startedAt: number;
  scanId: string | null;
  scan: ScanRecord | null;
};

function isScanRecord(value: unknown): value is ScanRecord {
  if (typeof value !== 'object' || value === null) return false;
  const scan = value as Partial<ScanRecord>;
  return typeof scan.target === 'string'
    && ['Pending', 'Running', 'Completed', 'Failed', 'Cancelled'].includes(String(scan.status))
    && typeof scan.counts === 'object'
    && scan.counts !== null
    && Array.isArray(scan.results)
    && typeof scan.findings === 'number';
}

function readScanSession(): StoredScanSession | null {
  try {
    const stored = sessionStorage.getItem(SCAN_SESSION_KEY);
    if (!stored) return null;
    const value: unknown = JSON.parse(stored);
    if (typeof value !== 'object' || value === null) return null;
    const session = value as Partial<StoredScanSession>;
    if (
      typeof session.target !== 'string'
      || typeof session.startedAt !== 'number'
      || !Number.isFinite(session.startedAt)
      || !(session.scanId === null || typeof session.scanId === 'string')
      || !(session.scan === null || isScanRecord(session.scan))
    ) return null;
    return session as StoredScanSession;
  } catch {
    return null;
  }
}

function saveScanSession(session: StoredScanSession): boolean {
  try {
    sessionStorage.setItem(SCAN_SESSION_KEY, JSON.stringify(session));
    return true;
  } catch {
    return false;
  }
}

export const Route = createFileRoute('/')({
  head: () => ({ meta: [
    { title: 'WebSentinel · Web Application Security Scanner' },
    { name: 'description', content: 'Analyze security headers, cookies, CORS policies, exposed resources, and input-reflection issues of an authorized target with a single scan.' },
    { property: 'og:title', content: 'WebSentinel · Web Application Security Scanner' },
    { property: 'og:description', content: 'Discover your web application\'s security posture with a single authorized scan.' },
    { property: 'og:type', content: 'website' }, { name: 'twitter:card', content: 'summary' },
  ] }),
  component: Scanner,
});

export function Scanner() {
  const [target, setTarget] = useState('');
  const [validationError, setValidationError] = useState('');
  const [scanStartedAt, setScanStartedAt] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [stopping, setStopping] = useState(false);
  const [controlError, setControlError] = useState('');
  const [restoredScan, setRestoredScan] = useState<ScanRecord | null>(null);
  const [resumePending, setResumePending] = useState(false);
  const scanStartedAtRef = useRef<number | null>(null);
  const lock = useRef(false);
  const activeScanId = useRef<string | null>(null);
  const stopRequested = useRef(false);
  const mutation = useMutation({
    mutationFn: (input: Parameters<typeof scannerApi.createScan>[0]) =>
      scannerApi.createScan(input, scanId => {
        activeScanId.current = scanId;
        const startedAt = scanStartedAtRef.current;
        if (
          startedAt !== null
          && !saveScanSession({ target: input.target, startedAt, scanId, scan: null })
        ) {
          setControlError('The scan is running, but browser storage is unavailable; it may not survive a page refresh.');
        }
        if (stopRequested.current) void cancelActiveScan(scanId);
      }),
    retry: false,
  });
  const scan = mutation.data ?? restoredScan;
  const scanning = mutation.isPending || resumePending;
  const completed = scan?.status === 'Completed' || scan?.status === 'Cancelled';
  const error = validationError
    || (mutation.error ? toApiError(mutation.error).message : '')
    || (scan?.status === 'Failed' ? redactEvidence(scan.error || 'The scanner failed. No results are available.') : '')
    || controlError;

  useEffect(() => {
    if (!scanning || scanStartedAt === null) return;
    const updateElapsedTime = () => setElapsedSeconds(Math.floor((Date.now() - scanStartedAt) / 1000));
    updateElapsedTime();
    const interval = window.setInterval(updateElapsedTime, 1000);
    return () => window.clearInterval(interval);
  }, [scanning, scanStartedAt]);

  useEffect(() => {
    const session = readScanSession();
    if (!session) return;
    setTarget(session.target);
    scanStartedAtRef.current = session.startedAt;
    setScanStartedAt(session.startedAt);
    setElapsedSeconds(Math.floor((Date.now() - session.startedAt) / 1000));
    if (session.scan) {
      setRestoredScan(session.scan);
      return;
    }
    if (!session.scanId) return;

    activeScanId.current = session.scanId;
    setResumePending(true);
    scannerApi.waitForScan(session.scanId, new Date(session.startedAt).toISOString())
      .then(result => {
        setRestoredScan(result);
        if (!saveScanSession({
          target: session.target,
          startedAt: session.startedAt,
          scanId: session.scanId,
          scan: result,
        })) {
          setControlError('The scan finished, but browser storage is unavailable; its result may not survive a page refresh.');
        }
      })
      .catch(scanError => setControlError(toApiError(scanError).message))
      .finally(() => {
        activeScanId.current = null;
        setResumePending(false);
      });
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (lock.current || scanning) return;
    setValidationError('');
    const input = createScanSchema.safeParse({ target, profile: 'Standard' });
    if (!input.success) { setValidationError(input.error.issues[0]?.message || 'Enter a valid HTTP or HTTPS URL.'); return; }
    lock.current = true;
    activeScanId.current = null;
    stopRequested.current = false;
    setStopping(false);
    setControlError('');
    setRestoredScan(null);
    mutation.reset();
    const startedAt = Date.now();
    scanStartedAtRef.current = startedAt;
    setScanStartedAt(startedAt);
    setElapsedSeconds(0);
    if (!saveScanSession({
      target: input.data.target,
      startedAt,
      scanId: null,
      scan: null,
    })) {
      setControlError('Browser storage is unavailable; this scan result may not survive a page refresh.');
    }
    try {
      const result = await mutation.mutateAsync(input.data);
      if (!saveScanSession({
        target: input.data.target,
        startedAt,
        scanId: result.id,
        scan: result,
      })) {
        setControlError('The scan finished, but browser storage is unavailable; its result may not survive a page refresh.');
      }
    } catch { /* API errors are displayed below the form. */ }
    finally {
      lock.current = false;
      activeScanId.current = null;
      stopRequested.current = false;
      setStopping(false);
    }
  }

  async function cancelActiveScan(scanId: string) {
    try {
      await scannerApi.cancelScan(scanId);
      setControlError('');
    } catch (cancelError) {
      setControlError(toApiError(cancelError).message);
      setStopping(false);
      stopRequested.current = false;
    }
  }

  function stopScan() {
    if (!scanning || stopping) return;
    stopRequested.current = true;
    setStopping(true);
    const scanId = activeScanId.current;
    if (scanId) void cancelActiveScan(scanId);
  }

  const form = (
    <form onSubmit={submit} noValidate className="scanner-form">
      <div className="scanner-field">
        <label htmlFor="target-url">Target URL</label>
        <input id="target-url" type="url" placeholder="https://example.com" value={target} onChange={event => setTarget(event.target.value)} maxLength={2048} disabled={scanning} aria-invalid={Boolean(validationError)} aria-describedby={error ? 'scan-error' : undefined} required />
      </div>
      {!scanning
        ? <Button type="submit"><ScanSearch aria-hidden="true" size={16} />{scan ? 'Scan Again' : 'Scan Target'}</Button>
        : <Button type="button" onClick={stopScan} disabled={stopping}><Square aria-hidden="true" size={16} />{stopping ? 'Stopping…' : 'Stop Scan'}</Button>}
    </form>
  );

  if (!scan && !scanning) {
    return (
      <main className="scanner-hero">
        <div className="scanner-hero-inner">
          <p className="scanner-brand"><Shield aria-hidden="true" size={30} /><span>WebSentinel</span></p>
          <p className="scanner-tagline">Web Application Security Scanner</p>
          <h1>Discover Your Web Application's Security Posture</h1>
          <p className="scanner-description">Analyze security headers, cookies, CORS policies, exposed resources, and potential input-reflection issues with a single scan.</p>
          {form}
          <p className="scanner-auth-notice">Scan only websites you own or have permission to test.</p>
          {error && <p id="scan-error" role="alert" className="scanner-error">{error}</p>}
        </div>
      </main>
    );
  }

  return (
    <main className="minimal-scanner">
      <header className="scanner-header">
        <p className="scanner-brand"><Shield aria-hidden="true" size={22} /><span>WebSentinel</span></p>
      </header>
      {form}
      <p className="scanner-auth-notice">Scan only websites you own or have permission to test.</p>
      <div aria-live="polite" className="scanner-state">
        {scanning && <p role="status" className="scanner-scanning"><span className="scanner-spinner" aria-hidden="true" />{stopping ? 'Stopping scan and collecting partial results…' : 'Analyzing target…'} <span aria-live="off">Elapsed: {formatElapsedTime(elapsedSeconds)}</span></p>}
        {error && <p id="scan-error" role="alert" className="scanner-error">{error}</p>}
      </div>
      {completed && scan && (
        <div className="scan-report">
          {scan.status === 'Cancelled' && <p role="status" className="limitations-notice">Scan stopped early. These are partial results collected before the scan was stopped.</p>}
          <ScanSummary scan={scan} />
          <SeverityDistribution scan={scan} />
          {scan.scanLimitReached && <p role="note" className="limitations-notice">The crawler reached its 500-request limit; some discovered paths may not have been scanned.</p>}
          <FindingsList scan={scan} />
          <CategoryBreakdown scan={scan} />
          <ScannedPaths scan={scan} />
          <TechnicalDetails scan={scan} />
        </div>
      )}
    </main>
  );
}
