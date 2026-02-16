import { useQuery } from '@tanstack/react-query';
import { getBudsMempool, getBudsCapabilities } from '@/lib/api/buds';

export const budsKeys = {
  all: ['buds'] as const,
  mempool: () => [...budsKeys.all, 'mempool'] as const,
  capabilities: () => [...budsKeys.all, 'capabilities'] as const,
};

export function useBudsMempool(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: budsKeys.mempool(),
    queryFn: getBudsMempool,
    refetchInterval: options?.refetchInterval ?? 10_000, // Poll every 10 seconds
  });
}

export function useBudsCapabilities() {
  return useQuery({
    queryKey: budsKeys.capabilities(),
    queryFn: getBudsCapabilities,
    staleTime: 60_000, // Capabilities don't change often
  });
}
