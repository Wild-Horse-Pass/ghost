// Swarm API endpoints
import { fetchApi } from './client';
import type { SwarmResponse, SwarmNode } from '@/types/api';

export async function getSwarm(): Promise<SwarmResponse> {
  return fetchApi<SwarmResponse>('/api/v1/swarm');
}

export async function getSwarmNodes(): Promise<{ nodes: SwarmNode[] }> {
  return fetchApi<{ nodes: SwarmNode[] }>('/api/v1/swarm/nodes');
}

export async function addSwarmNode(name: string, address: string): Promise<SwarmNode> {
  return fetchApi<SwarmNode>('/api/v1/swarm/nodes', {
    method: 'POST',
    body: JSON.stringify({ name, address }),
  });
}

export async function removeSwarmNode(nodeId: string): Promise<void> {
  return fetchApi<void>(`/api/v1/swarm/nodes/${nodeId}`, {
    method: 'DELETE',
  });
}

export async function updateSwarmNode(nodeId: string, updates: { name?: string; address?: string }): Promise<void> {
  return fetchApi<void>(`/api/v1/swarm/nodes/${nodeId}`, {
    method: 'PUT',
    body: JSON.stringify(updates),
  });
}

export async function refreshSwarmNode(nodeId: string): Promise<SwarmNode> {
  return fetchApi<SwarmNode>(`/api/v1/swarm/nodes/${nodeId}/refresh`, {
    method: 'POST',
  });
}

export async function configureSwarmNode(nodeId: string, config: Record<string, unknown>): Promise<SwarmNode> {
  return fetchApi<SwarmNode>(`/api/v1/swarm/nodes/${nodeId}/config`, {
    method: 'PUT',
    body: JSON.stringify(config),
  });
}

export interface SyncSwarmResponse {
  discovered_peers: number;
  removed_stale: number;
  total_peers: number;
}

export async function syncSwarm(): Promise<SyncSwarmResponse> {
  return fetchApi<SyncSwarmResponse>('/api/v1/swarm/sync', {
    method: 'POST',
  });
}

export interface RestartSwarmNodeResponse {
  success: boolean;
  message: string;
}

export async function restartSwarmNode(nodeId: string): Promise<RestartSwarmNodeResponse> {
  return fetchApi<RestartSwarmNodeResponse>(`/api/v1/swarm/nodes/${nodeId}/restart`, {
    method: 'POST',
  });
}

export interface UpdateSwarmNodeResponse {
  success: boolean;
  message: string;
}

export async function updateSwarmNodeVersion(nodeId: string, version: string): Promise<UpdateSwarmNodeResponse> {
  return fetchApi<UpdateSwarmNodeResponse>(`/api/v1/swarm/nodes/${nodeId}/update`, {
    method: 'POST',
    body: JSON.stringify({ version }),
  });
}

export interface UpdateAllSwarmNodesResponse {
  success: boolean;
  message: string;
  version: string;
  results: Array<{
    node_id: string;
    name: string;
    success: boolean;
    message: string;
  }>;
}

export async function updateAllSwarmNodes(version: string): Promise<UpdateAllSwarmNodesResponse> {
  return fetchApi<UpdateAllSwarmNodesResponse>('/api/v1/swarm/update-all', {
    method: 'POST',
    body: JSON.stringify({ version }),
  });
}
