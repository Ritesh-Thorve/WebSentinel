import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Scanner } from '@/routes/index';
import { emptyCounts, scannerApi, type ScanRecord } from '@/lib/scanner-api';

const completedScan: ScanRecord = {
  id: null,
  target: 'https://example.com',
  name: 'example.com',
  profile: 'Backend default',
  status: 'Completed',
  date: '19/10/2026, 06:00:00 UTC',
  duration: '0m 02s',
  findings: 0,
  high: 0,
  demo: false,
  createdAt: '2026-10-19T06:00:00Z',
  startedAt: '2026-10-19T06:00:00Z',
  completedAt: '2026-10-19T06:00:02Z',
  endpoints: 0,
  counts: emptyCounts(),
  results: [],
  reportFormats: [],
  canCancel: false,
};

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe('scan progress', () => {
  it('shows a live elapsed timer and waits for the completed scan before rendering results', async () => {
    let resolveScan!: (scan: ScanRecord) => void;
    vi.spyOn(scannerApi, 'createScan').mockImplementation(
      () => new Promise(resolve => {
        resolveScan = resolve;
      }),
    );

    const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <Scanner />
      </QueryClientProvider>,
    );

    fireEvent.change(screen.getByLabelText('Target URL'), {
      target: { value: 'https://example.com' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Scan Target' }));
      await Promise.resolve();
    });

    expect(screen.getByRole('status').textContent).toContain('Elapsed: 00:00');
    expect(screen.queryByRole('heading', { name: 'Findings' })).toBeNull();

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 1100));
    });
    expect(screen.getByRole('status').textContent).toContain('Elapsed: 00:01');
    expect(screen.queryByRole('heading', { name: 'Findings' })).toBeNull();

    await act(async () => {
      resolveScan(completedScan);
    });

    await waitFor(() => expect(screen.queryByRole('status')).toBeNull());
    expect(screen.getByRole('heading', { name: 'Findings' })).toBeTruthy();
    expect(screen.getByText('Duration 0m 02s')).toBeTruthy();
  });

  it('stops the active scan and displays the returned partial report', async () => {
    let resolveScan!: (scan: ScanRecord) => void;
    const createScan = vi.spyOn(scannerApi, 'createScan').mockImplementation(
      (_input, onStarted) => new Promise(resolve => {
        resolveScan = resolve;
        onStarted?.('scan-123');
      }),
    );
    const cancelScan = vi.spyOn(scannerApi, 'cancelScan').mockResolvedValue({
      ...completedScan,
      id: 'scan-123',
      status: 'Cancelled',
      scannedUrls: ['https://example.com/'],
      endpoints: 1,
    });

    const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <Scanner />
      </QueryClientProvider>,
    );

    fireEvent.change(screen.getByLabelText('Target URL'), {
      target: { value: 'https://example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan Target' }));

    await waitFor(() => expect(createScan).toHaveBeenCalled());
    fireEvent.click(await screen.findByRole('button', { name: 'Stop Scan' }));
    await waitFor(() => expect(cancelScan).toHaveBeenCalledWith('scan-123'));

    await act(async () => {
      resolveScan({
        ...completedScan,
        id: 'scan-123',
        status: 'Cancelled',
        scannedUrls: ['https://example.com/'],
        endpoints: 1,
      });
    });

    expect(await screen.findByText(/Scan stopped early/i)).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Findings' })).toBeTruthy();
  });

  it('restores a completed report from this tab after a page refresh', async () => {
    let resolveScan!: (scan: ScanRecord) => void;
    const createScan = vi.spyOn(scannerApi, 'createScan').mockImplementation(
      () => new Promise(resolve => {
        resolveScan = resolve;
      }),
    );
    const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
    const firstPage = render(
      <QueryClientProvider client={client}>
        <Scanner />
      </QueryClientProvider>,
    );

    fireEvent.change(screen.getByLabelText('Target URL'), {
      target: { value: 'https://example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan Target' }));
    await waitFor(() => expect(createScan).toHaveBeenCalled());
    await act(async () => resolveScan(completedScan));
    expect(await screen.findByRole('heading', { name: 'Findings' })).toBeTruthy();
    firstPage.unmount();

    render(
      <QueryClientProvider client={new QueryClient()}>
        <Scanner />
      </QueryClientProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'Findings' })).toBeTruthy();
    expect(screen.getByText('Duration 0m 02s')).toBeTruthy();
    expect(createScan).toHaveBeenCalledTimes(1);
  });

  it('resumes polling and keeps the stop control after refreshing an active scan', async () => {
    let resolveResumedScan!: (scan: ScanRecord) => void;
    const waitForScan = vi.spyOn(scannerApi, 'waitForScan').mockImplementation(
      () => new Promise(resolve => {
        resolveResumedScan = resolve;
      }),
    );
    sessionStorage.setItem('websentinel.current-scan.v1', JSON.stringify({
      target: 'https://example.com',
      startedAt: Date.now() - 1500,
      scanId: 'scan-active',
      scan: null,
    }));

    render(
      <QueryClientProvider client={new QueryClient()}>
        <Scanner />
      </QueryClientProvider>,
    );

    expect(await screen.findByRole('button', { name: 'Stop Scan' })).toBeTruthy();
    expect(waitForScan).toHaveBeenCalledWith('scan-active', expect.any(String));
    expect(screen.getByRole('status').textContent).toContain('Elapsed: 00:01');

    await act(async () => resolveResumedScan(completedScan));
    expect(await screen.findByRole('heading', { name: 'Findings' })).toBeTruthy();
  });
});
