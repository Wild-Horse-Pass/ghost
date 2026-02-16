import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getConfig,
  getFullConfig,
  setGhostMode,
  setArchiveMode,
  setBitcoinPure,
  setMempoolProfile,
  setTemplateProfile,
  getMempoolProfiles,
  saveMempoolProfile,
  deleteMempoolProfile,
  activateMempoolProfile,
  getTemplateProfiles,
  saveTemplateProfile,
  deleteTemplateProfile,
  activateTemplateProfile,
  setPruneProfile,
  setOperatorWindow,
  getL2PruningStatus,
  setGhostPayPayoutAddress,
  type CustomMempoolProfile,
  type CustomTemplateProfile,
} from '@/lib/api/config';
import type { MempoolProfile, TemplateProfile, PruneProfile } from '@/types/api';

export const configKeys = {
  all: ['config'] as const,
  basic: () => [...configKeys.all, 'basic'] as const,
  full: () => [...configKeys.all, 'full'] as const,
  mempoolProfiles: () => [...configKeys.all, 'mempool-profiles'] as const,
  templateProfiles: () => [...configKeys.all, 'template-profiles'] as const,
};

export function useConfig() {
  return useQuery({
    queryKey: configKeys.basic(),
    queryFn: getConfig,
    staleTime: 30_000,
  });
}

export function useFullConfig() {
  return useQuery({
    queryKey: configKeys.full(),
    queryFn: getFullConfig,
    staleTime: 30_000,
  });
}

export function useSetGhostMode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setGhostMode(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useSetArchiveMode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setArchiveMode(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useSetBitcoinPure() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setBitcoinPure(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useSetMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: MempoolProfile) => setMempoolProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useSetTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: TemplateProfile) => setTemplateProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Custom Mempool Profiles
export function useMempoolProfiles() {
  return useQuery({
    queryKey: configKeys.mempoolProfiles(),
    queryFn: getMempoolProfiles,
    staleTime: 60_000,
  });
}

export function useSaveMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: CustomMempoolProfile) => saveMempoolProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.mempoolProfiles() });
    },
  });
}

export function useDeleteMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => deleteMempoolProfile(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.mempoolProfiles() });
    },
  });
}

export function useActivateMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => activateMempoolProfile(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Custom Template Profiles
export function useTemplateProfiles() {
  return useQuery({
    queryKey: configKeys.templateProfiles(),
    queryFn: getTemplateProfiles,
    staleTime: 60_000,
  });
}

export function useSaveTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: CustomTemplateProfile) => saveTemplateProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.templateProfiles() });
    },
  });
}

export function useDeleteTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => deleteTemplateProfile(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.templateProfiles() });
    },
  });
}

export function useActivateTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => activateTemplateProfile(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Pruning configuration
export const pruningKeys = {
  all: ['pruning'] as const,
  l2: () => [...pruningKeys.all, 'l2'] as const,
};

export function useL2PruningStatus() {
  return useQuery({
    queryKey: pruningKeys.l2(),
    queryFn: getL2PruningStatus,
    staleTime: 60_000,
  });
}

export function useSetPruneProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: PruneProfile) => setPruneProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useSetOperatorWindow() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (blocks: number) => setOperatorWindow(blocks),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Payout Address Settings
export function useSetGhostPayPayoutAddress() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (address: string | null) => setGhostPayPayoutAddress(address),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      // Also invalidate mining status which may include payout info
      queryClient.invalidateQueries({ queryKey: ['mining', 'status'] });
    },
  });
}

// Re-export types for convenience
export type { CustomMempoolProfile, CustomTemplateProfile };
