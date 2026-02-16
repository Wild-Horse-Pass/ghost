// Logs API endpoints
import { fetchApi } from './client';
import type { LogsResponse } from '@/types/api';

export async function getLogs(limit?: number, level?: string): Promise<LogsResponse> {
  const params = new URLSearchParams();
  if (limit) params.set('limit', limit.toString());
  if (level) params.set('level', level);
  const query = params.toString();
  return fetchApi<LogsResponse>(`/api/v1/logs${query ? `?${query}` : ''}`);
}
