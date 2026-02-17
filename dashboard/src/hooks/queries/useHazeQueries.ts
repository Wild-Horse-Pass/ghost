import { useQuery } from '@tanstack/react-query';
import { getHazeStatus } from '@/lib/api/haze';

export const hazeKeys = {
  all: ['haze'] as const,
  status: () => [...hazeKeys.all, 'status'] as const,
};

export function useHazeStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: hazeKeys.status(),
    queryFn: getHazeStatus,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}
