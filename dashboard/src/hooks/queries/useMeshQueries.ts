import { useQuery } from '@tanstack/react-query';
import { getMeshStatus, type MeshResponse } from '@/lib/api/mesh';

export const meshKeys = {
  all: ['mesh'] as const,
  status: () => [...meshKeys.all, 'status'] as const,
};

export function useMeshStatus() {
  return useQuery<MeshResponse>({
    queryKey: meshKeys.status(),
    queryFn: getMeshStatus,
    refetchInterval: 30000, // Refresh every 30 seconds
    staleTime: 10000,
  });
}
