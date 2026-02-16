// Network API endpoints
import { fetchApi } from './client';
import type {
  PoolStatus,
  PeersResponse,
  TreasuryStatus,
  ElderStatus,
  NetworkPayoutHistoryResponse,
  PayoutHistoryTimeFilter,
} from '@/types/api';

export async function getPoolStatus(): Promise<PoolStatus> {
  return fetchApi<PoolStatus>('/api/v1/network/pool');
}

export async function getPeers(): Promise<PeersResponse> {
  return fetchApi<PeersResponse>('/api/v1/network/peers');
}

export async function getTreasury(): Promise<TreasuryStatus> {
  return fetchApi<TreasuryStatus>('/api/v1/network/treasury');
}

export async function getElderStatus(): Promise<ElderStatus> {
  return fetchApi<ElderStatus>('/api/v1/network/elder');
}

export async function getNetworkPayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d'
): Promise<NetworkPayoutHistoryResponse> {
  return fetchApi<NetworkPayoutHistoryResponse>(
    `/api/v1/network/payout-history?time_filter=${timeFilter}`
  );
}
