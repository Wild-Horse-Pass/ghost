import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  createBackup,
  verifyBackup,
  importBackup,
  getBackupHistory,
  deleteBackup,
} from '@/lib/api/backup';
import type { BackupOptions } from '@/types/api';

export const backupKeys = {
  all: ['backup'] as const,
  history: () => [...backupKeys.all, 'history'] as const,
};

export function useBackupHistory() {
  return useQuery({
    queryKey: backupKeys.history(),
    queryFn: getBackupHistory,
    refetchInterval: false,
  });
}

export function useCreateBackup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ options, password }: { options: BackupOptions; password: string }) =>
      createBackup(options, password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: backupKeys.history() });
    },
  });
}

export function useVerifyBackup() {
  return useMutation({
    mutationFn: ({ file, password }: { file: File; password: string }) =>
      verifyBackup(file, password),
  });
}

export function useImportBackup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ file, password }: { file: File; password: string }) =>
      importBackup(file, password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: backupKeys.all });
    },
  });
}

export function useDeleteBackup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (filename: string) => deleteBackup(filename),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: backupKeys.history() });
    },
  });
}
