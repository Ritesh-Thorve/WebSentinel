import { queryOptions } from '@tanstack/react-query';
import { apiConfig } from './api-config';
import { ApiError } from './api-errors';
import { createDisconnectedScannerApi, createHttpScannerApi } from './http-scanner-api';
import { activeStatuses, type ScannerApi } from './scanner-types';
export * from './scanner-types';
export { ApiError, ScanNotFoundError } from './api-errors';
export const scannerApi: ScannerApi = apiConfig.mode === 'live' && apiConfig.baseUrl
  ? createHttpScannerApi({ baseUrl: apiConfig.baseUrl })
  : createDisconnectedScannerApi(apiConfig.reason);
export const POLL_INTERVAL_MS = 5000;
export const scanOptions = (id: string) => queryOptions({
  queryKey: ['scans', id], queryFn: () => scannerApi.getScan(id),
  retry: false,
  refetchInterval: q => !q.state.error && q.state.data && activeStatuses.includes(q.state.data.status) ? POLL_INTERVAL_MS : false,
  refetchOnWindowFocus: false,
});
