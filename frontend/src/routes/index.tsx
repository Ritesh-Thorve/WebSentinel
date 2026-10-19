import { useRef, useState, type FormEvent } from 'react';
import { createFileRoute } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ScanSearch, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { scannerApi, scanOptions, createScanSchema, activeStatuses } from '@/lib/scanner-api';
import { toApiError } from '@/lib/api-errors';
import { redactEvidence } from '@/lib/evidence';
import { CategoryBreakdown, FindingsList, ScanSummary, SeverityDistribution, TechnicalDetails } from '@/components/scan-report';

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

function Scanner() {
  const [target, setTarget] = useState('');
  const [scanId, setScanId] = useState('');
  const [validationError, setValidationError] = useState('');
  const lock = useRef(false);
  const client = useQueryClient();
  const mutation = useMutation({ mutationFn: scannerApi.createScan, retry: false });
  const scanQuery = useQuery({ ...scanOptions(scanId), enabled: Boolean(scanId) });
  const scan = scanQuery.data;
  const scanning = mutation.isPending || Boolean(scan && activeStatuses.includes(scan.status) && !scanQuery.isError);
  const completed = scan?.status === 'Completed' && !scanQuery.isError;
  const error = validationError
    || (mutation.error ? toApiError(mutation.error).message : '')
    || (scanQuery.error ? toApiError(scanQuery.error).message : '')
    || (scan?.status === 'Failed' ? redactEvidence(scan.error || 'The scanner failed. No completed results are available.') : scan?.status === 'Cancelled' ? 'The scan was cancelled by the backend.' : '');

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (lock.current || scanning) return;
    setValidationError('');
    const input = createScanSchema.safeParse({ target, profile: 'Standard' });
    if (!input.success) { setValidationError(input.error.issues[0]?.message || 'Enter a valid HTTP or HTTPS URL.'); return; }
    lock.current = true;
    setScanId('');
    mutation.reset();
    try {
      const created = await mutation.mutateAsync(input.data);
      client.setQueryData(['scans', created.id], created);
      setScanId(created.id);
    } catch { /* API errors are displayed below the form. */ }
    finally { lock.current = false; }
  }

  const form = (
    <form onSubmit={submit} noValidate className="scanner-form">
      <div className="scanner-field">
        <label htmlFor="target-url">Target URL</label>
        <input id="target-url" type="url" placeholder="https://example.com" value={target} onChange={event => setTarget(event.target.value)} maxLength={2048} disabled={scanning} aria-invalid={Boolean(validationError)} aria-describedby={error ? 'scan-error' : undefined} required />
      </div>
      <Button type="submit" disabled={scanning}><ScanSearch aria-hidden="true" size={16} />{scanId ? 'Scan Again' : 'Scan Target'}</Button>
    </form>
  );

  if (!scanId && !mutation.isPending) {
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
        {scanning && <p role="status" className="scanner-scanning"><span className="scanner-spinner" aria-hidden="true" />Analyzing target…</p>}
        {error && <p id="scan-error" role="alert" className="scanner-error">{error}</p>}
      </div>
      {completed && scan && (
        <div className="scan-report">
          <ScanSummary scan={scan} />
          <SeverityDistribution scan={scan} />
          <FindingsList scan={scan} />
          <CategoryBreakdown scan={scan} />
          <TechnicalDetails scan={scan} />
        </div>
      )}
    </main>
  );
}
