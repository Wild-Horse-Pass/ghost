// Node API endpoints
import { fetchApi } from './client';
import type { NodeInfo, NodeStatus, SharesInfo, HealthStatus } from '@/types/api';

export async function getNodeInfo(): Promise<NodeInfo> {
  return fetchApi<NodeInfo>('/api/v1/node/info');
}

export async function getNodeStatus(): Promise<NodeStatus> {
  return fetchApi<NodeStatus>('/api/v1/node/status');
}

export async function getShares(): Promise<SharesInfo> {
  return fetchApi<SharesInfo>('/api/v1/node/shares');
}

export async function getHealth(): Promise<HealthStatus> {
  return fetchApi<HealthStatus>('/health');
}

// Nickname (new)
export async function getNickname(): Promise<{ nickname: string }> {
  return fetchApi<{ nickname: string }>('/api/v1/node/nickname');
}

export async function setNickname(nickname: string): Promise<{ nickname: string }> {
  return fetchApi<{ nickname: string }>('/api/v1/node/nickname', {
    method: 'POST',
    body: JSON.stringify({ nickname }),
  });
}
