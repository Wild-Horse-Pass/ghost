// Resources API endpoints
import { fetchApi } from './client';

export interface ResourceStatus {
  cpu_percent: number;
  memory_percent: number;
  memory_used_mb: number;
  memory_total_mb: number;
  disk_percent: number;
  disk_used_gb: number;
  disk_total_gb: number;
  connected_miners: number;
  estimated_capacity: number;
  status: 'healthy' | 'warning' | 'critical';
  last_redirect_secs_ago?: number;
  last_redirect_count: number;
  warning_threshold_cpu: number;
  warning_threshold_memory: number;
  critical_threshold_cpu: number;
  critical_threshold_memory: number;
}

export async function getResourceStatus(): Promise<ResourceStatus> {
  return fetchApi<ResourceStatus>('/api/v1/resources/status');
}
