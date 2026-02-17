// Haze API endpoints
import { fetchApi } from './client';
import type { HazeStatus } from '@/types/api';

export async function getHazeStatus(): Promise<HazeStatus> {
  return fetchApi<HazeStatus>('/api/v1/haze/status');
}
