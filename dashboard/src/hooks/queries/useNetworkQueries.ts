import { useQuery } from '@tanstack/react-query';
import { getPoolStatus, getPeers, getTreasury, getElderStatus, getNetworkPayoutHistory } from '@/lib/api/network';
import type { PayoutHistoryTimeFilter } from '@/types/api';

export const networkKeys = {
  all: ['network'] as const,
  pool: () => [...networkKeys.all, 'pool'] as const,
  peers: () => [...networkKeys.all, 'peers'] as const,
  treasury: () => [...networkKeys.all, 'treasury'] as const,
  elder: () => [...networkKeys.all, 'elder'] as const,
  payoutHistory: (timeFilter: PayoutHistoryTimeFilter) => [...networkKeys.all, 'payout-history', timeFilter] as const,
};

export function usePoolStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: networkKeys.pool(),
    queryFn: getPoolStatus,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function usePeers(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: networkKeys.peers(),
    queryFn: getPeers,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function useTreasury(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: networkKeys.treasury(),
    queryFn: getTreasury,
    refetchInterval: options?.refetchInterval ?? 60_000, // 1 minute
  });
}

export function useElderStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: networkKeys.elder(),
    queryFn: getElderStatus,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

export function useNetworkPayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d',
  options?: { refetchInterval?: number }
) {
  return useQuery({
    queryKey: networkKeys.payoutHistory(timeFilter),
    queryFn: () => getNetworkPayoutHistory(timeFilter),
    refetchInterval: options?.refetchInterval ?? 60_000, // 1 minute
  });
}
