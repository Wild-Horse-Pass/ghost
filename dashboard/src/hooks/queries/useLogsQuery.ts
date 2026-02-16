import { useQuery } from '@tanstack/react-query';
import { getLogs } from '@/lib/api/logs';

export const logsKeys = {
  all: ['logs'] as const,
  list: (params?: { limit?: number; level?: string }) => [...logsKeys.all, 'list', params] as const,
};

export function useLogs(params?: { limit?: number; level?: string }) {
  return useQuery({
    queryKey: logsKeys.list(params),
    queryFn: () => getLogs(params?.limit, params?.level),
    refetchInterval: false, // Manual refresh or WebSocket
  });
}
