// Shroud API endpoints
import { fetchApi } from './client';
import type { ShroudStatus } from '@/types/api';

export async function getShroudStatus(): Promise<ShroudStatus> {
  return fetchApi<ShroudStatus>('/api/v1/shroud/status');
}
