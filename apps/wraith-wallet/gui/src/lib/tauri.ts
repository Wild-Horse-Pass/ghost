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
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

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

export interface LightUtxoEntry {
  txid: string;
  vout: number;
  amount_sats: number;
  confirmations: number;
  script_type: string;
  spendable: boolean;
}

export interface LightUtxosResponse {
  utxos: LightUtxoEntry[];
  total_sats: number;
}

export async function lightUtxos(
  min_confirmations = 0,
): Promise<LightUtxosResponse> {
  const resp = await invoke("light_utxos", { minConfirmations: min_confirmations });
  return unwrap<LightUtxosResponse>(resp).payload;
}

export interface LightL1UtxoEntry {
  txid: string;
  vout: number;
  amount_sats: number;
  scriptpubkey_hex: string;
  /// BIP86 derivation index that produced the address holding this
  /// UTXO. Drop into a Wraith mix request's `bip86_index` to skip
  /// the daemon-side scan.
  bip86_index: number;
  address: string;
  confirmations: number;
  height: number;
}

export interface LightL1UtxosResponse {
  utxos: LightL1UtxoEntry[];
  total_sats: number;
  chain_height: number;
  scanned_max_index: number;
}

/// Scan ghost-pay's bitcoind for unspent L1 outputs at the active
/// wallet's BIP86 receive addresses 0..`scan_max_index`. Mainnet
/// scantxoutset takes 5-15s; signet/regtest sub-second. Surface
/// the latency in any UI.
export async function lightL1Utxos(
  scan_max_index = 32,
  min_confirmations = 0,
): Promise<LightL1UtxosResponse> {
  const resp = await invoke("light_l1_utxos", {
    scanMaxIndex: scan_max_index,
    minConfirmations: min_confirmations,
  });
  return unwrap<LightL1UtxosResponse>(resp).payload;
}

// ----- Wraith Lite (CoinJoin mix) ----------------------------------------

export interface WraithDiscoverTier {
  id: string;
  denomination_sats: number;
  min_participants: number;
  max_participants: number;
  bond_sats: number;
  service_fee_sats: number;
}

export interface WraithDiscoverResult {
  /// Coordinator URL that actually answered (may differ from the
  /// requested `coordinator_url` if the call rotated through
  /// `coordinator_peers`).
  answered_by: string;
  network: string;
  pool_id: string;
  service_fee_bps: number;
  bond_bps: number;
  fill_window_secs: number;
  tiers: WraithDiscoverTier[];
}

/// Fetch a coordinator's `/api/v1/pool/discover` payload. Same
/// failover semantics as the mix calls — connect errors rotate to
/// the next peer; HTTP errors propagate.
export async function wraithCoordinatorDiscover(
  coordinator_url: string,
  coordinator_peers?: string[],
): Promise<WraithDiscoverResult> {
  const resp = await invoke("wraith_coordinator_discover", {
    coordinatorUrl: coordinator_url,
    coordinatorPeers: coordinator_peers ?? [],
  });
  return unwrap<WraithDiscoverResult>(resp).payload;
}

export interface WraithMixCompleted {
  session_id: string;
  broadcast_txid: string;
  mixed_output_tx_index: number;
}

export interface WraithMixRunArgs {
  coordinator_url: string;
  coordinator_peers?: string[];
  socks5_proxy?: string;
  tier_id: string;
  ghost_id: string;
  bond_id_placeholder?: string;
  utxo_txid: string;
  utxo_vout: number;
  utxo_value_sats: number;
  utxo_scriptpubkey_hex: string;
  change_address?: string;
  mix_output_address: string;
  bip86_index?: number;
  bip86_scan_max?: number;
}

/// One-shot Wraith Lite CoinJoin. Daemon enrols, signs the
/// taproot key-path witness using the active wallet's BIP86
/// keystore, and drives the round to broadcast.
export async function wraithMixRun(
  args: WraithMixRunArgs,
): Promise<WraithMixCompleted> {
  const resp = await invoke("wraith_mix_run", {
    coordinatorUrl: args.coordinator_url,
    coordinatorPeers: args.coordinator_peers ?? [],
    socks5Proxy: args.socks5_proxy,
    tierId: args.tier_id,
    ghostId: args.ghost_id,
    bondIdPlaceholder: args.bond_id_placeholder,
    utxoTxid: args.utxo_txid,
    utxoVout: args.utxo_vout,
    utxoValueSats: args.utxo_value_sats,
    utxoScriptpubkeyHex: args.utxo_scriptpubkey_hex,
    changeAddress: args.change_address,
    mixOutputAddress: args.mix_output_address,
    bip86Index: args.bip86_index,
    bip86ScanMax: args.bip86_scan_max,
  });
  return unwrap<WraithMixCompleted>(resp).payload;
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

export interface LocksRecoveredResult {
  lock_id: string;
  broadcast_txid: string;
  destination: string;
  recovered_sats: number;
  fee_sats: number;
}

export async function locksRecover(
  lock_id: string,
  destination_address: string,
  fee_sats: number,
): Promise<LocksRecoveredResult> {
  const resp = await invoke("locks_recover", {
    lockId: lock_id,
    destinationAddress: destination_address,
    feeSats: fee_sats,
  });
  return unwrap<LocksRecoveredResult>(resp).payload;
}

// ----- Live BIP-352 receive notifications --------------------------------

/// Start the daemon push-watch subscription. The Tauri side keeps a
/// long-lived IPC connection and forwards each `PaymentDetected`
/// frame to the frontend as a `wraith://payment-detected` event.
/// Idempotent — the Rust side's atomic guard makes repeat calls a
/// no-op, so the safest pattern is to call it once on app mount and
/// once more on any reconnect.
export async function startWatch(): Promise<void> {
  await invoke("start_watch");
}

export interface DetectedPayment {
  txid: string;
  block_height: number | null;
  vout: number;
  amount_sats: number;
  k: number;
  received_at: number;
}

/// Subscribe to live payment detections. Returns an unlisten fn —
/// call it from the effect's cleanup. Pair with `startWatch()` once
/// at app boot.
export async function onPaymentDetected(
  cb: (p: DetectedPayment) => void,
): Promise<UnlistenFn> {
  return listen<DetectedPayment>("wraith://payment-detected", (event) => {
    cb(event.payload);
  });
}

export interface WatchError {
  message: string;
}

/// Subscribe to watch-loop terminal errors (daemon socket closed,
/// IPC parse failure, etc.). The Tauri side restarts the loop on
/// `startWatch()` next time the GUI calls it.
export async function onWatchError(
  cb: (e: WatchError) => void,
): Promise<UnlistenFn> {
  return listen<WatchError>("wraith://watch-error", (event) => {
    cb(event.payload);
  });
}
