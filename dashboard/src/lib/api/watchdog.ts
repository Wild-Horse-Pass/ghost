// Watchdog API endpoints
import { fetchApi } from './client';
import type {
  WatchdogStatus,
  WatchdogEvent,
} from '@/types/api';

export interface ServiceControlResponse {
  success: boolean;
  message: string;
  service: string;
  action: string;
}

export interface ClearCacheResponse {
  success: boolean;
  message: string;
  memory_freed_mb?: number;
}

export async function getWatchdogStatus(): Promise<WatchdogStatus> {
  return fetchApi<WatchdogStatus>('/api/v1/watchdog/status');
}

export async function getWatchdogEvents(limit?: number): Promise<{ events: WatchdogEvent[] }> {
  const params = new URLSearchParams();
  if (limit) params.set('limit', limit.toString());
  const query = params.toString();
  return fetchApi<{ events: WatchdogEvent[] }>(`/api/v1/watchdog/events${query ? `?${query}` : ''}`);
}

export async function startService(service: string): Promise<ServiceControlResponse> {
  return fetchApi<ServiceControlResponse>(`/api/v1/watchdog/start/${service}`, {
    method: 'POST',
  });
}

export async function stopService(service: string): Promise<ServiceControlResponse> {
  return fetchApi<ServiceControlResponse>(`/api/v1/watchdog/stop/${service}`, {
    method: 'POST',
  });
}

export async function restartService(service: string): Promise<ServiceControlResponse> {
  return fetchApi<ServiceControlResponse>(`/api/v1/watchdog/restart/${service}`, {
    method: 'POST',
  });
}

export async function clearSystemCache(): Promise<ClearCacheResponse> {
  return fetchApi<ClearCacheResponse>('/api/v1/watchdog/clear-cache', {
    method: 'POST',
  });
}
