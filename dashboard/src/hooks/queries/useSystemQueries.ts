import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getVersion,
  checkForUpdates,
  startUpdate,
  getUpdateStatus,
  rollbackUpdate,
} from '@/lib/api/system';

export const systemKeys = {
  all: ['system'] as const,
  version: () => [...systemKeys.all, 'version'] as const,
  updates: () => [...systemKeys.all, 'updates'] as const,
  updateStatus: () => [...systemKeys.all, 'updateStatus'] as const,
};

export function useSystemVersion() {
  return useQuery({
    queryKey: systemKeys.version(),
    queryFn: getVersion,
    staleTime: 60_000, // Cache for 1 minute
  });
}

export function useCheckForUpdates(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: systemKeys.updates(),
    queryFn: checkForUpdates,
    staleTime: 300_000, // Cache for 5 minutes
    enabled: options?.enabled ?? true,
  });
}

export function useUpdateStatus(options?: { refetchInterval?: number | false; enabled?: boolean }) {
  return useQuery({
    queryKey: systemKeys.updateStatus(),
    queryFn: getUpdateStatus,
    refetchInterval: options?.refetchInterval ?? false,
    enabled: options?.enabled ?? true,
  });
}

export function useStartUpdate() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: startUpdate,
    onSuccess: () => {
      // Start polling update status
      queryClient.invalidateQueries({ queryKey: systemKeys.updateStatus() });
    },
  });
}

export function useRollbackUpdate() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: rollbackUpdate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: systemKeys.all });
    },
  });
}
