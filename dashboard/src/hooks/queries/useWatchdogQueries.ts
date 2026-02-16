import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getWatchdogStatus,
  getWatchdogEvents,
  startService,
  stopService,
  restartService,
} from '@/lib/api/watchdog';

export const watchdogKeys = {
  all: ['watchdog'] as const,
  status: () => [...watchdogKeys.all, 'status'] as const,
  events: (limit?: number) => [...watchdogKeys.all, 'events', limit] as const,
};

export function useWatchdogStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: watchdogKeys.status(),
    queryFn: getWatchdogStatus,
    refetchInterval: options?.refetchInterval ?? 5_000, // Poll every 5 seconds for health monitoring
  });
}

export function useWatchdogEvents(limit = 50, options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: watchdogKeys.events(limit),
    queryFn: () => getWatchdogEvents(limit),
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function useStartService() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (service: string) => startService(service),
    onSuccess: () => {
      // Invalidate watchdog status after starting a service
      queryClient.invalidateQueries({ queryKey: watchdogKeys.all });
    },
  });
}

export function useStopService() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (service: string) => stopService(service),
    onSuccess: () => {
      // Invalidate watchdog status after stopping a service
      queryClient.invalidateQueries({ queryKey: watchdogKeys.all });
    },
  });
}

export function useRestartService() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (service: string) => restartService(service),
    onSuccess: () => {
      // Invalidate watchdog status after restarting a service
      queryClient.invalidateQueries({ queryKey: watchdogKeys.all });
    },
  });
}
