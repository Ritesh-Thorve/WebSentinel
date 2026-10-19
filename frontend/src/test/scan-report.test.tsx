import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { CategoryBreakdown, FindingsList, ScanSummary, SeverityDistribution, TechnicalDetails } from '@/components/scan-report';
import { emptyCounts, type ScanRecord } from '@/lib/scanner-api';

const counts = { ...emptyCounts(), Critical: 1, High: 1, Medium: 1 };
const scan: ScanRecord = {
  id: 'scan-123', target: 'https://app.example.com', name: 'app.example.com', profile: 'Standard',
  status: 'Completed', date: '19/10/2026, 06:00:00 UTC', duration: '1m 05s', findings: 3, high: 2, demo: false,
  createdAt: '2026-10-19T06:00:00Z', startedAt: '2026-10-19T06:00:00Z', completedAt: '2026-10-19T06:01:05Z',
  endpoints: 12, counts, scope: 'https://app.example.com/*', reportFormats: [], canCancel: false,
  results: [
    { id: 'f1', title: 'Missing Content-Security-Policy header', severity: 'Medium', confidence: 'High', verification: 'Potential', category: 'Security Headers', affectedUrl: 'https://app.example.com/', description: 'The response did not include a CSP header.', evidence: 'GET / HTTP/1.1\nauthorization: Bearer secret-token-123', remediation: 'Add a Content-Security-Policy header.' },
    { id: 'f2', title: 'Reflected marker observed', severity: 'High', confidence: 'Low', verification: 'Potential', category: 'Input Reflection', affectedUrl: 'https://app.example.com/search?q=ws7', description: 'A marker was reflected in the response body.' },
    { id: 'f3', title: 'Session cookie without SameSite', severity: 'Critical', confidence: 'Medium', verification: 'Confirmed', category: 'Cookie Security', affectedUrl: 'https://app.example.com/login' },
  ],
};

describe('ScanSummary', () => {
  it('derives all counts from the scan record', () => {
    render(<ScanSummary scan={scan} />);
    expect(screen.getByText('app.example.com')).toBeTruthy();
    expect(screen.getByText('Completed')).toBeTruthy();
    expect(screen.getByText('Total findings')).toBeTruthy();
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.getByText('12 endpoints discovered')).toBeTruthy();
  });
});

describe('SeverityDistribution', () => {
  it('labels the distribution with actual counts', () => {
    render(<SeverityDistribution scan={scan} />);
    expect(screen.getByRole('img', { name: /Critical: 1, High: 1, Medium: 1/ })).toBeTruthy();
  });
  it('renders nothing when there are no findings', () => {
    const { container } = render(<SeverityDistribution scan={{ ...scan, findings: 0, counts: emptyCounts() }} />);
    expect(container.firstChild).toBeNull();
  });
});

describe('FindingsList', () => {
  it('renders only backend-provided fields and redacts evidence secrets', () => {
    render(<FindingsList scan={scan} />);
    expect(screen.getByText('Missing Content-Security-Policy header')).toBeTruthy();
    expect(screen.getByText('Confidence: High')).toBeTruthy();
    expect(screen.getAllByText('Potential').length).toBe(2);
    expect(screen.getByText(/authorization: \[REDACTED\]/)).toBeTruthy();
    expect(screen.queryByText(/secret-token-123/)).toBeNull();
  });
  it('shows the limitations notice and never claims the target is secure', () => {
    render(<FindingsList scan={{ ...scan, results: [], findings: 0, counts: emptyCounts() }} />);
    expect(screen.getByText(/does not prove the application is secure/)).toBeTruthy();
    expect(screen.getByText(/Automated scans have limitations/)).toBeTruthy();
  });
  it('shows no invented security score', () => {
    const { container } = render(<FindingsList scan={scan} />);
    expect(container.textContent).not.toMatch(/score|rating/i);
  });
});

describe('CategoryBreakdown', () => {
  it('groups findings by backend category without marking anything secure', () => {
    render(<CategoryBreakdown scan={scan} />);
    expect(screen.getByText('Security Headers')).toBeTruthy();
    expect(screen.getByText('Input Reflection')).toBeTruthy();
    expect(screen.getByText(/does not confirm a category is secure/)).toBeTruthy();
  });
});

describe('TechnicalDetails', () => {
  it('exposes scan metadata inside an expandable section', () => {
    render(<TechnicalDetails scan={scan} />);
    expect(screen.getByText('scan-123')).toBeTruthy();
    expect(screen.getByText('https://app.example.com/*')).toBeTruthy();
  });
});
