import { useQuery } from '@tanstack/react-query';
import { getShroudStatus } from '@/lib/api/shroud';

export const shroudKeys = {
  all: ['shroud'] as const,
  status: () => [...shroudKeys.all, 'status'] as const,
};

export function useShroudStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: shroudKeys.status(),
    queryFn: getShroudStatus,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}
