// Typed wrappers around the Tauri commands defined in
// `src-tauri/src/lib.rs`. Every function here is a thin shim that
// forwards to `invoke()` and gives the frontend a typed return shape.
//
// The Rust side returns `serde_json::Value` for most commands; we
// narrow at this boundary using the response variants from
// `wraith_wallet_ipc::Response`. Shapes drift if the IPC enum
// changes, so when something here looks wrong the first place to
// look is `apps/wraith-wallet/ipc/src/lib.rs`.

import { invoke } from "@tauri-apps/api/core";

// ----- Response shape helpers --------------------------------------------

/**
 * Daemon Response is an externally-tagged enum like `{ "Health": {...} }`.
 * Most callers just want the inner payload; this unwraps the first
 * variant key and returns the value beneath, leaving the variant tag
 * accessible separately when callers need to discriminate.
 */
function unwrap<T = unknown>(resp: unknown): { variant: string; payload: T } {
  if (resp == null || typeof resp !== "object") {
    throw new Error(`unexpected response shape: ${JSON.stringify(resp)}`);
  }
  const entries = Object.entries(resp as Record<string, unknown>);
  if (entries.length === 0) {
    return { variant: "(empty)", payload: undefined as T };
  }
  const [variant, payload] = entries[0];
  return { variant, payload: payload as T };
}

// ----- Daemon ------------------------------------------------------------

export interface HealthResponse {
  status: string;
  version: string;
  uptime_secs: number;
}

export async function daemonHealth(): Promise<HealthResponse> {
  const resp = await invoke("daemon_health");
  return unwrap<HealthResponse>(resp).payload;
}

export async function daemonDoctor(): Promise<unknown> {
  return await invoke("daemon_doctor");
}

export interface DaemonEnvResponse {
  network: string;
  ghost_pay_urls: string[];
  gsp_urls: string[];
  socket_path: string;
  wallets_dir: string;
}

export async function daemonEnv(): Promise<DaemonEnvResponse> {
  const resp = await invoke("daemon_env");
  return unwrap<DaemonEnvResponse>(resp).payload;
}

// ----- Wallet ------------------------------------------------------------

export interface WalletEntry {
  name: string;
  ghost_id?: string;
  is_active: boolean;
  is_unlocked: boolean;
}

export interface WalletListResponse {
  wallets: WalletEntry[];
  active: string | null;
}

export async function walletList(): Promise<WalletListResponse> {
  const resp = await invoke("wallet_list");
  return unwrap<WalletListResponse>(resp).payload;
}

export interface WalletStatusResponse {
  active: string | null;
  unlocked: boolean;
  ghost_id?: string;
  network: string;
}

export async function walletStatus(): Promise<WalletStatusResponse> {
  const resp = await invoke("wallet_status");
  return unwrap<WalletStatusResponse>(resp).payload;
}

export async function walletCreate(
  name: string,
  passphrase: string,
): Promise<unknown> {
  return await invoke("wallet_create", { name, passphrase });
}

export async function walletUnlock(
  name: string,
  passphrase: string,
): Promise<unknown> {
  return await invoke("wallet_unlock", { name, passphrase });
}

export async function walletLock(name: string | null): Promise<unknown> {
  return await invoke("wallet_lock", { name });
}

export async function walletSelect(name: string): Promise<unknown> {
  return await invoke("wallet_select", { name });
}

export async function walletGhostId(): Promise<{
  ghost_id: string;
  network: string;
  scan_public_key_hex: string;
  spend_public_key_hex: string;
}> {
  const resp = await invoke("wallet_ghost_id");
  return unwrap<{
    ghost_id: string;
    network: string;
    scan_public_key_hex: string;
    spend_public_key_hex: string;
  }>(resp).payload;
}

// ----- Light wallet (L2) -------------------------------------------------

export interface LightBalanceResponse {
  spendable_sats: number;
  pending_sats: number;
  total_sats: number;
}

export async function lightBalance(): Promise<LightBalanceResponse> {
  const resp = await invoke("light_balance");
  return unwrap<LightBalanceResponse>(resp).payload;
}

export interface LightHistoryEntry {
  txid: string;
  block_height: number | null;
  timestamp: number;
  amount_sats: number;
  fee_sats: number | null;
  tx_type: string;
  confirmations: number;
  memo: string | null;
}

export interface LightHistoryResponse {
  transactions: LightHistoryEntry[];
  total_count: number;
}

export async function lightHistory(
  limit = 50,
  offset = 0,
): Promise<LightHistoryResponse> {
  const resp = await invoke("light_history", { limit, offset });
  return unwrap<LightHistoryResponse>(resp).payload;
}

export interface LightReceiveResponse {
  address: string;
  index: number;
  network: string;
}

export async function lightReceive(index = 0): Promise<LightReceiveResponse> {
  const resp = await invoke("light_receive", { index });
  return unwrap<LightReceiveResponse>(resp).payload;
}

export async function lightSend(
  recipient: string,
  amount_sats: number,
  memo?: string,
): Promise<unknown> {
  return await invoke("light_send", { recipient, amountSats: amount_sats, memo });
}

// ----- GSP ---------------------------------------------------------------

export async function gspAuth(): Promise<unknown> {
  return await invoke("gsp_auth");
}

export async function gspSessionStatus(): Promise<unknown> {
  return await invoke("gsp_session_status");
}

// ----- Locks -------------------------------------------------------------

export interface LockEntry {
  lock_id: string;
  capacity_sats: number;
  state: string;
  created_at: number;
  funding_address?: string;
  funding_txid?: string;
  recovery_height?: number;
}

export interface LocksListResponse {
  locks: LockEntry[];
}

export async function locksList(): Promise<LocksListResponse> {
  const resp = await invoke("locks_list");
  return unwrap<LocksListResponse>(resp).payload;
}

export interface LocksPreparedResponse {
  lock_id: string;
  funding_address: string;
  required_sats: number;
}

export async function locksPrepare(
  capacity_sats: number,
): Promise<LocksPreparedResponse> {
  const resp = await invoke("locks_prepare", { capacitySats: capacity_sats });
  return unwrap<LocksPreparedResponse>(resp).payload;
}

export async function locksConfirm(
  lock_id: string,
  funding_txid: string,
): Promise<unknown> {
  return await invoke("locks_confirm", { lockId: lock_id, fundingTxid: funding_txid });
}
