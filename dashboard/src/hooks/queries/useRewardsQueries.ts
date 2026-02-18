import { useQuery } from '@tanstack/react-query';
import { getRewardsCurrent, getRewardsHistory, getRewardsFull, getNodePayoutHistory, getNodeBalances } from '@/lib/api/rewards';
import type { PayoutHistoryTimeFilter } from '@/types/api';

export const rewardsKeys = {
  all: ['rewards'] as const,
  current: () => [...rewardsKeys.all, 'current'] as const,
  history: () => [...rewardsKeys.all, 'history'] as const,
  full: () => [...rewardsKeys.all, 'full'] as const,
  nodeHistory: (timeFilter: PayoutHistoryTimeFilter, payoutType?: string) =>
    [...rewardsKeys.all, 'node-history', timeFilter, payoutType] as const,
  nodeBalances: () => [...rewardsKeys.all, 'node-balances'] as const,
};

export function useRewardsCurrent(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.current(),
    queryFn: getRewardsCurrent,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

export function useRewardsHistory(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.history(),
    queryFn: getRewardsHistory,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

export function useRewardsFull(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.full(),
    queryFn: getRewardsFull,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

// Alias for convenience
export const useRewards = useRewardsFull;

export function useNodePayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d',
  payoutType?: string,
  options?: { refetchInterval?: number }
) {
  return useQuery({
    queryKey: rewardsKeys.nodeHistory(timeFilter, payoutType),
    queryFn: () => getNodePayoutHistory(timeFilter, payoutType),
    refetchInterval: options?.refetchInterval ?? 60_000, // 1 minute
  });
}

export function useNodeBalances(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.nodeBalances(),
    queryFn: getNodeBalances,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}
