// System API endpoints (updates)
import { fetchApi } from './client';

export interface VersionInfo {
  // Backend fields
  version?: string;
  build?: string;
  ghost_core_version?: string | null;
  rust_version?: string;
  target?: string;
  os?: string;
  update_available?: boolean;
  // Dashboard aliases
  node_version?: string;
  build_time?: string;
  git_hash?: string;
}

export interface UpdateInfo {
  version: string;
  release_date?: string;
  changelog?: string;
  download_url?: string;
  sha256?: string;
  size_bytes?: number;
}

export interface UpdateCheckResponse {
  current_version?: string;
  latest_version?: string;
  update_available?: boolean;
  update_info?: UpdateInfo;
}

export interface UpdateProgress {
  step?: string;
  progress_percent?: number;
  message?: string;
}

export type UpdateStatus =
  | { status: "idle" }
  | { status: "checking" }
  | { status: "downloading"; progress: UpdateProgress }
  | { status: "verifying" }
  | { status: "installing"; progress: UpdateProgress }
  | { status: "complete"; message: string }
  | { status: "failed"; error: string };

export interface UpdateStatusResponse {
  update_status?: UpdateStatus;
}

export interface RollbackResponse {
  success?: boolean;
  message?: string;
}

export interface StartUpdateResponse {
  success?: boolean;
  message?: string;
}

export async function getVersion(): Promise<VersionInfo> {
  return fetchApi<VersionInfo>('/api/v1/system/version');
}

export async function checkForUpdates(): Promise<UpdateCheckResponse> {
  return fetchApi<UpdateCheckResponse>('/api/v1/system/updates');
}

export async function startUpdate(): Promise<StartUpdateResponse> {
  return fetchApi<StartUpdateResponse>('/api/v1/system/update', {
    method: 'POST',
  });
}

export async function getUpdateStatus(): Promise<UpdateStatusResponse> {
  return fetchApi<UpdateStatusResponse>('/api/v1/system/update/status');
}

export async function rollbackUpdate(): Promise<RollbackResponse> {
  return fetchApi<RollbackResponse>('/api/v1/system/rollback', {
    method: 'POST',
  });
}
