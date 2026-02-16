import { useQuery } from '@tanstack/react-query';
import { getResourceStatus } from '@/lib/api/resources';

export const resourceKeys = {
  all: ['resources'] as const,
  status: () => [...resourceKeys.all, 'status'] as const,
};

export function useResourceStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: resourceKeys.status(),
    queryFn: getResourceStatus,
    refetchInterval: options?.refetchInterval ?? 10_000, // Poll every 10 seconds
  });
}
