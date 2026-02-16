// Backup/Migration API endpoints
import { fetchApi, fetchWithTimeout, getApiBase } from './client';
import type { BackupOptions, BackupResponse, BackupHistoryResponse, VerifyBackupResponse } from '@/types/api';

export async function createBackup(options: BackupOptions, password: string): Promise<BackupResponse> {
  return fetchApi<BackupResponse>('/api/v1/backup/export', {
    method: 'POST',
    body: JSON.stringify({ options, password }),
  });
}

export async function verifyBackup(file: File, password: string): Promise<VerifyBackupResponse> {
  // Read file and convert to base64
  const fileContent = await fileToBase64(file);

  return fetchApi<VerifyBackupResponse>('/api/v1/backup/verify', {
    method: 'POST',
    body: JSON.stringify({ file_content: fileContent, password }),
  });
}

export async function importBackup(file: File, password: string): Promise<void> {
  // Read file and convert to base64
  const fileContent = await fileToBase64(file);

  const response = await fetchWithTimeout(
    `${getApiBase()}/api/proxy/api/v1/backup/import`,
    {
      method: 'POST',
      body: JSON.stringify({ file_content: fileContent, password }),
      headers: {
        'Content-Type': 'application/json',
      },
    },
    60000 // 60 second timeout for import
  );

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `API error: ${response.status}`);
  }
}

// Helper to convert File to base64
async function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      // Remove the data URL prefix (e.g., "data:application/json;base64,")
      const base64 = result.includes(',') ? result.split(',')[1] : result;
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

export async function getBackupHistory(): Promise<BackupHistoryResponse> {
  return fetchApi<BackupHistoryResponse>('/api/v1/backup/history');
}

export async function deleteBackup(filename: string): Promise<{ success: boolean; error?: string }> {
  return fetchApi<{ success: boolean; error?: string }>(`/api/v1/backup/delete/${encodeURIComponent(filename)}`, {
    method: 'DELETE',
  });
}

export function getBackupDownloadUrl(filename: string): string {
  return `${getApiBase()}/api/v1/backup/download/${encodeURIComponent(filename)}`;
}
