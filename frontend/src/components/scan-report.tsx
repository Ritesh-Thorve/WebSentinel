import { useMemo, useState } from 'react';
import { AlertTriangle, Clock, Globe, ListChecks, Shield, ShieldCheck } from 'lucide-react';
import { redactEvidence, limitationsNotice } from '@/lib/evidence';
import type { Finding, ScanRecord, Severity } from '@/lib/scanner-api';

const severities: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`scanner-severity severity-${severity.toLowerCase()}`}>{severity === 'Info' ? 'Informational' : severity}</span>;
}

function SummaryCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <div className="summary-card">
      <span className="summary-card-icon" aria-hidden="true">{icon}</span>
      <span className="summary-card-value">{value}</span>
      <span className="summary-card-label">{label}</span>
    </div>
  );
}

export function ScanSummary({ scan }: { scan: ScanRecord }) {
  const hostname = useMemo(() => { try { return new URL(scan.target).hostname; } catch { return scan.target; } }, [scan.target]);
  return (
    <section className="scan-summary" aria-label="Scan summary">
      <div className="scan-summary-head">
        <h2><Globe aria-hidden="true" size={16} />{hostname}</h2>
        <p className="scan-target-url">{redactEvidence(scan.target)}</p>
        <p className="scan-meta">
          <span className={`scan-status scan-status-${scan.status.toLowerCase()}`}>{scan.status}</span>
          <span><Clock aria-hidden="true" size={13} />{scan.date}</span>
          {scan.duration !== '—' && <span>Duration {scan.duration}</span>}
          {scan.endpoints > 0 && <span>{scan.endpoints} URLs scanned</span>}
        </p>
      </div>
      <div className="summary-grid">
        <SummaryCard icon={<ListChecks size={18} />} label="Total findings" value={scan.findings} />
        {severities.map(sev => <SummaryCard key={sev} icon={<Shield size={18} className={`severity-${sev.toLowerCase()}`} />} label={sev === 'Info' ? 'Informational' : sev} value={scan.counts[sev]} />)}
      </div>
    </section>
  );
}

export function ScannedPaths({ scan }: { scan: ScanRecord }) {
  if (!scan.scannedUrls?.length) return null;
  return (
    <details className="technical-details">
      <summary>Scanned paths ({scan.scannedUrls.length})</summary>
      <ul className="related-endpoints">
        {scan.scannedUrls.map(url => (
          <li key={url} className="scanner-endpoint">{redactEvidence(url)}</li>
        ))}
      </ul>
    </details>
  );
}

export function SeverityDistribution({ scan }: { scan: ScanRecord }) {
  if (scan.findings === 0) return null;
  return (
    <section className="severity-distribution" aria-label="Severity distribution">
      <h3>Severity distribution</h3>
      <div className="severity-bar" role="img" aria-label={severities.map(s => `${s}: ${scan.counts[s]}`).join(', ')}>
        {severities.map(sev => scan.counts[sev] > 0 && (
          <span key={sev} className={`severity-bar-segment severity-bg-${sev.toLowerCase()}`} style={{ width: `${(scan.counts[sev] / scan.findings) * 100}%` }} />
        ))}
      </div>
      <ul className="severity-legend">
        {severities.map(sev => <li key={sev}><span className={`severity-dot severity-bg-${sev.toLowerCase()}`} aria-hidden="true" />{sev === 'Info' ? 'Informational' : sev} · {scan.counts[sev]}</li>)}
      </ul>
    </section>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <details className="scanner-finding">
      <summary>
        <span className="finding-summary-title">{finding.title != null ? redactEvidence(finding.title) : 'Untitled finding'}</span>
        <span className="finding-summary-badges">
          {finding.severity && <SeverityBadge severity={finding.severity} />}
          {finding.confidence && <span className="finding-badge">Confidence: {finding.confidence}</span>}
          {finding.verification && <span className="finding-badge">{finding.verification}</span>}
        </span>
      </summary>
      <div className="finding-body">
        {finding.category != null && <div className="scanner-finding-field"><h3>Category</h3><p>{redactEvidence(finding.category)}</p></div>}
        {finding.affectedUrl != null && <div className="scanner-finding-field"><h3>Affected URL</h3><p className="scanner-endpoint">{redactEvidence(finding.affectedUrl)}</p></div>}
        {finding.description != null && <div className="scanner-finding-field"><h3>Description</h3><p>{redactEvidence(finding.description)}</p></div>}
        {finding.evidence != null && <div className="scanner-finding-field"><h3>Evidence</h3><pre>{redactEvidence(finding.evidence)}</pre></div>}
        {finding.whyItMatters != null && <div className="scanner-finding-field"><h3>Why it matters</h3><p>{redactEvidence(finding.whyItMatters)}</p></div>}
        {finding.remediation != null && <div className="scanner-finding-field"><h3>Remediation</h3><p>{redactEvidence(finding.remediation)}</p></div>}
        {finding.firstDetectedAt != null && <div className="scanner-finding-field"><h3>First detected</h3><p>{finding.firstDetectedAt}</p></div>}
        {finding.relatedEndpoints && finding.relatedEndpoints.length > 0 && (
          <div className="scanner-finding-field"><h3>Related endpoints</h3>
            <ul className="related-endpoints">{finding.relatedEndpoints.map(ep => <li key={ep} className="scanner-endpoint">{redactEvidence(ep)}</li>)}</ul>
          </div>
        )}
      </div>
    </details>
  );
}

export function FindingsList({ scan }: { scan: ScanRecord }) {
  const [filter, setFilter] = useState<Severity | null>(null);
  const visible = filter ? scan.results.filter(f => f.severity === filter) : scan.results;
  const present = severities.filter(s => scan.results.some(f => f.severity === s));
  return (
    <section className="scanner-results" aria-label="Scan findings">
      <div className="findings-head">
        <h3>Findings</h3>
        {present.length > 1 && (
          <div className="severity-filter" role="group" aria-label="Filter findings by severity">
            <button type="button" className={filter === null ? 'active' : ''} onClick={() => setFilter(null)}>All ({scan.results.length})</button>
            {present.map(sev => (
              <button key={sev} type="button" className={filter === sev ? 'active' : ''} onClick={() => setFilter(filter === sev ? null : sev)}>
                {sev === 'Info' ? 'Informational' : sev} ({scan.results.filter(f => f.severity === sev).length})
              </button>
            ))}
          </div>
        )}
      </div>
      {visible.length === 0 ? (
        <p className="scanner-empty">The scanner returned no findings{filter ? ` at ${filter} severity` : ''}. This does not prove the application is secure.</p>
      ) : visible.map(finding => <FindingCard key={finding.id} finding={finding} />)}
      <p className="limitations-notice"><AlertTriangle aria-hidden="true" size={14} />{limitationsNotice}</p>
    </section>
  );
}

export function CategoryBreakdown({ scan }: { scan: ScanRecord }) {
  const categories = useMemo(() => {
    const map = new Map<string, number>();
    for (const f of scan.results) { if (f.category) map.set(f.category, (map.get(f.category) ?? 0) + 1); }
    return [...map.entries()];
  }, [scan.results]);
  if (categories.length === 0) return null;
  return (
    <section className="category-breakdown" aria-label="Scanner categories">
      <h3>Analysis categories</h3>
      <ul>
        {categories.map(([category, count]) => (
          <li key={category}><ShieldCheck aria-hidden="true" size={15} /><span className="category-name">{redactEvidence(category)}</span><span className="category-count">{count} finding{count === 1 ? '' : 's'}</span></li>
        ))}
      </ul>
      <p className="category-note">Categories without findings are not listed; absence of findings does not confirm a category is secure.</p>
    </section>
  );
}

export function TechnicalDetails({ scan }: { scan: ScanRecord }) {
  return (
    <details className="technical-details">
      <summary>Technical details</summary>
      <dl>
        {scan.id && <div><dt>Scan ID</dt><dd className="scanner-endpoint">{scan.id}</dd></div>}
        <div><dt>Profile</dt><dd>{scan.profile}</dd></div>
        <div><dt>Created</dt><dd>{scan.createdAt}</dd></div>
        {scan.startedAt && <div><dt>Started</dt><dd>{scan.startedAt}</dd></div>}
        {scan.completedAt && <div><dt>Completed</dt><dd>{scan.completedAt}</dd></div>}
        {scan.scope && <div><dt>Scope</dt><dd>{redactEvidence(scan.scope)}</dd></div>}
        {scan.error && <div><dt>Backend error</dt><dd>{redactEvidence(scan.error)}</dd></div>}
      </dl>
    </details>
  );
}
