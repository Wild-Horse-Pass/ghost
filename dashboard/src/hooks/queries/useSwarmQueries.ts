import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getSwarm,
  getSwarmNodes,
  addSwarmNode,
  removeSwarmNode,
  updateSwarmNode,
  refreshSwarmNode,
  configureSwarmNode,
} from '@/lib/api/swarm';

export const swarmKeys = {
  all: ['swarm'] as const,
  summary: () => [...swarmKeys.all, 'summary'] as const,
  nodes: () => [...swarmKeys.all, 'nodes'] as const,
};

export function useSwarm(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: swarmKeys.summary(),
    queryFn: getSwarm,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function useSwarmNodes(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: swarmKeys.nodes(),
    queryFn: getSwarmNodes,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function useAddSwarmNode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ name, address }: { name: string; address: string }) =>
      addSwarmNode(name, address),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: swarmKeys.all });
    },
  });
}

export function useRemoveSwarmNode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (nodeId: string) => removeSwarmNode(nodeId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: swarmKeys.all });
    },
  });
}

export function useUpdateSwarmNode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ nodeId, updates }: { nodeId: string; updates: { name?: string; address?: string } }) =>
      updateSwarmNode(nodeId, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: swarmKeys.all });
    },
  });
}

export function useRefreshSwarmNode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (nodeId: string) => refreshSwarmNode(nodeId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: swarmKeys.all });
    },
  });
}

export function useConfigureSwarmNode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ nodeId, config }: { nodeId: string; config: Record<string, unknown> }) =>
      configureSwarmNode(nodeId, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: swarmKeys.all });
    },
  });
}
