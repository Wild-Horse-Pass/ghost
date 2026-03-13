import { invoke } from "@tauri-apps/api/core";

// --- Types ---

export interface BalanceResponse {
  confirmed: number;
  pending: number;
}

export interface HistoryEntry {
  txid: string;
  direction: string;
  amount: number;
  fee: number | null;
  address: string;
  status: string;
  timestamp: number;
  memo: string | null;
}

export interface ConnectionStatus {
  mode: string;
  connected: boolean;
}

export interface NodeInfo {
  connection_mode: "light" | "fullnode";
  ghostd_connected: boolean;
  ghost_pay_connected: boolean;
  block_height: number;
  header_count: number;
  sync_progress: number;
  initial_block_download: boolean;
  network: string;
  peer_count: number;
  node_version: string;
}

export interface ConnectionTestResult {
  ghostd_ok: boolean;
  ghostd_error: string | null;
  ghost_pay_ok: boolean;
  ghost_pay_error: string | null;
}

export interface UnsignedTxResponse {
  inputs_count: number;
  outputs_count: number;
  fee: number;
  tx_json: string;
}

export interface BroadcastResponse {
  txid: string;
  size: number;
  fee: number;
}

export interface PaymentRequestResponse {
  address: string;
  amount: number | null;
  memo: string | null;
  label: string | null;
  exp: number | null;
  net: string | null;
}

export interface CheckedPaymentResponse {
  request: PaymentRequestResponse;
  warnings: string[];
}

export interface DashboardSummary {
  total_received: number;
  total_sent: number;
  total_fees: number;
  tx_count: number;
}

export interface InvoiceResponse {
  invoice_id: string;
  business_name: string;
  amount: number;
  ghost_address: string;
  due_date: number;
  status: string;
  amount_paid: number;
  payment_uri: string;
  memo: string | null;
}

export interface ReceiptResponse {
  receipt_id: string;
  html: string;
}

export interface LineItemInput {
  description: string;
  amount: number;
}

export interface WashRequestResponse {
  txid: string;
  amount: number;
  status: string;
  wraith_in_txid: string | null;
  wraith_out_txid: string | null;
  created_at: number;
  updated_at: number;
  retry_count: number;
}

export interface WashStatsResponse {
  queued_count: number;
  queued_amount: number;
  in_progress_count: number;
  in_progress_amount: number;
  completed_count: number;
  completed_amount: number;
  failed_count: number;
  failed_amount: number;
  total_count: number;
}

// --- Wallet ---

export async function createWallet(wordCount: number): Promise<string> {
  return invoke("create_wallet", { wordCount });
}

export async function restoreWallet(mnemonic: string): Promise<void> {
  return invoke("restore_wallet", { mnemonic });
}

export async function getMnemonic(): Promise<string> {
  return invoke("get_mnemonic");
}

export async function getBalance(): Promise<BalanceResponse> {
  return invoke("get_balance");
}

export async function newReceiveAddress(): Promise<string> {
  return invoke("new_receive_address");
}

export async function getAllAddresses(): Promise<string[]> {
  return invoke("get_all_addresses");
}

export async function getHistory(offset: number, limit: number): Promise<HistoryEntry[]> {
  return invoke("get_history", { offset, limit });
}

export async function lockWallet(): Promise<void> {
  return invoke("lock_wallet");
}

export async function unlockWallet(): Promise<void> {
  return invoke("unlock_wallet");
}

export async function isLocked(): Promise<boolean> {
  return invoke("is_locked");
}

export async function hasWallet(): Promise<boolean> {
  return invoke("has_wallet");
}

export async function setPin(pin: string): Promise<void> {
  return invoke("set_pin", { pin });
}

export async function verifyPin(pin: string): Promise<boolean> {
  return invoke("verify_pin", { pin });
}

export async function hasPin(): Promise<boolean> {
  return invoke("has_pin");
}

export async function loadWallet(pin: string): Promise<void> {
  return invoke("load_wallet", { pin });
}

// --- Transaction ---

export async function buildTransaction(
  to: string,
  amount: number,
  feePriority: number,
): Promise<UnsignedTxResponse> {
  return invoke("build_transaction", { to, amount, feePriority });
}

export async function signAndBroadcast(unsignedTxJson: string): Promise<BroadcastResponse> {
  return invoke("sign_and_broadcast", { unsignedTxJson });
}

export async function estimateFee(confTarget: number): Promise<number | null> {
  return invoke("estimate_fee", { confTarget });
}

// --- Payment ---

export async function parsePaymentUri(uri: string): Promise<PaymentRequestResponse> {
  return invoke("parse_payment_uri", { uri });
}

export async function parsePaymentUriChecked(
  uri: string,
  now: number,
  network?: string,
): Promise<CheckedPaymentResponse> {
  return invoke("parse_payment_uri_checked", { uri, now, network });
}

export async function createPaymentUri(
  address: string,
  amount?: number,
  memo?: string,
  label?: string,
  exp?: number,
  network?: string,
): Promise<string> {
  return invoke("create_payment_uri", { address, amount, memo, label, exp, network });
}

// --- Connection ---

export async function setConnectionMode(mode: string): Promise<void> {
  return invoke("set_connection_mode", { mode });
}

export async function setRpcConfig(
  host: string,
  port: number,
  user?: string,
  pass?: string,
): Promise<void> {
  return invoke("set_rpc_config", { host, port, user, pass });
}

export async function setGhostPayConfig(
  host: string,
  port: number,
  apiSecret?: string,
): Promise<void> {
  return invoke("set_ghost_pay_config", { host, port, apiSecret });
}

export async function getConnectionStatus(): Promise<ConnectionStatus> {
  return invoke("get_connection_status");
}

export async function getNodeInfo(): Promise<NodeInfo> {
  return invoke("get_node_info");
}

export async function testConnection(): Promise<ConnectionTestResult> {
  return invoke("test_connection");
}

export async function syncConnection(): Promise<void> {
  return invoke("sync");
}

// --- Merchant ---

export async function computeDashboard(since: number, until: number): Promise<DashboardSummary> {
  return invoke("compute_dashboard", { since, until });
}

export async function createInvoice(
  address: string,
  amount: number,
  businessName?: string,
  memo?: string,
  dueDate?: number,
  items?: LineItemInput[],
): Promise<InvoiceResponse> {
  return invoke("create_invoice", { address, amount, businessName, memo, dueDate, items });
}

export async function listInvoices(): Promise<InvoiceResponse[]> {
  return invoke("list_invoices");
}

export async function deleteInvoice(invoiceId: string): Promise<void> {
  return invoke("delete_invoice", { invoiceId });
}

export async function generateReceipt(
  txid: string,
  amount: number,
  items: LineItemInput[],
  merchantName?: string,
  memo?: string,
): Promise<ReceiptResponse> {
  return invoke("generate_receipt", { txid, amount, items, merchantName, memo });
}

export async function exportCsv(since: number, until: number): Promise<string> {
  return invoke("export_csv", { since, until });
}

export async function exportHtml(
  since: number,
  until: number,
  businessName?: string,
): Promise<string> {
  return invoke("export_html", { since, until, businessName });
}

// --- Wraith ---

export async function washPayment(txid: string, amount: number): Promise<void> {
  return invoke("wash_payment", { txid, amount });
}

export async function getWashQueue(): Promise<WashRequestResponse[]> {
  return invoke("get_wash_queue");
}

export async function getWashStats(): Promise<WashStatsResponse> {
  return invoke("get_wash_stats");
}

export async function startWashProcessor(): Promise<void> {
  return invoke("start_wash_processor");
}

export async function stopWashProcessor(): Promise<void> {
  return invoke("stop_wash_processor");
}

export async function retryWash(txid: string): Promise<boolean> {
  return invoke("retry_wash", { txid });
}

// --- GhostGlyph ---

export interface GlyphClaimResult {
  commitment: string;
  bitmap_hash: string;
  status: string;
}

export interface GlyphInfoResult {
  ghost_id: string;
  pixels: number[];
  bitmap_hash: string;
  commitment: string;
  funding_txid: string | null;
  registered_at: number | null;
  status: string;
}

export interface PaletteColor {
  index: number;
  r: number;
  g: number;
  b: number;
}

export async function claimGlyph(
  ghostId: string,
  pixels: number[],
  payUrl: string,
): Promise<GlyphClaimResult> {
  return invoke("claim_glyph", { ghostId, pixels, payUrl });
}

export async function getGlyph(
  ghostId: string,
  payUrl: string,
): Promise<GlyphInfoResult | null> {
  return invoke("get_glyph", { ghostId, payUrl });
}

export async function checkGlyphAvailability(
  pixels: number[],
  payUrl: string,
): Promise<boolean> {
  return invoke("check_glyph_availability", { pixels, payUrl });
}

export async function renderGlyph(
  pixels: number[],
  ghostId: string,
  scale: number,
): Promise<number[]> {
  return invoke("render_glyph", { pixels, ghostId, scale });
}

export function getGlyphPalette(): Promise<PaletteColor[]> {
  return invoke("get_glyph_palette");
}

export async function validateGlyphPixels(pixels: number[]): Promise<boolean> {
  return invoke("validate_glyph_pixels", { pixels });
}

// --- Address Book ---

export interface AddressEntry {
  address: string;
  label: string;
  amount: number;
  confirmations: number;
}

export async function listAddressLabels(): Promise<string[]> {
  return invoke("list_address_labels");
}

export async function getAddressesForLabel(label: string): Promise<string[]> {
  return invoke("get_addresses_for_label", { label });
}

export async function setAddressLabel(address: string, label: string): Promise<void> {
  return invoke("set_address_label", { address, label });
}

export async function validateAddressInfo(address: string): Promise<any> {
  return invoke("validate_address_info", { address });
}

export async function listReceivedAddresses(): Promise<AddressEntry[]> {
  return invoke("list_received_addresses");
}

// --- Sign/Verify ---

export async function signMessage(address: string, message: string): Promise<string> {
  return invoke("sign_message", { address, message });
}

export async function verifyMessage(address: string, signature: string, message: string): Promise<boolean> {
  return invoke("verify_message", { address, signature, message });
}

// --- PSBT ---

export async function decodePsbt(psbt: string): Promise<any> {
  return invoke("decode_psbt", { psbt });
}

export async function analyzePsbt(psbt: string): Promise<any> {
  return invoke("analyze_psbt", { psbt });
}

export async function signPsbt(psbt: string): Promise<any> {
  return invoke("sign_psbt", { psbt });
}

export async function combinePsbts(psbts: string[]): Promise<string> {
  return invoke("combine_psbts", { psbts });
}

export async function finalizePsbt(psbt: string): Promise<any> {
  return invoke("finalize_psbt", { psbt });
}

export async function broadcastPsbt(psbt: string): Promise<string> {
  return invoke("broadcast_psbt", { psbt });
}

// --- Coin Control ---

export async function listUnspent(): Promise<any[]> {
  return invoke("list_unspent");
}

export async function lockUnspentOutput(txid: string, vout: number, lock: boolean): Promise<boolean> {
  return invoke("lock_unspent_output", { txid, vout, lock });
}

export async function listLockedOutputs(): Promise<any[]> {
  return invoke("list_locked_outputs");
}

export async function sendWithInputs(
  inputs: any[],
  address: string,
  amount: number,
  feeRate?: number,
): Promise<string> {
  return invoke("send_with_inputs", { inputs, address, amount, feeRate });
}

// --- Node Wallet ---

export async function nodeEncryptWallet(passphrase: string): Promise<void> {
  return invoke("node_encrypt_wallet", { passphrase });
}

export async function nodeUnlockWallet(passphrase: string, timeout: number): Promise<void> {
  return invoke("node_unlock_wallet", { passphrase, timeout });
}

export async function nodeLockWallet(): Promise<void> {
  return invoke("node_lock_wallet");
}

export async function nodeChangePassphrase(oldPassphrase: string, newPassphrase: string): Promise<void> {
  return invoke("node_change_passphrase", { oldPassphrase, newPassphrase });
}

export async function getNodeWalletInfo(): Promise<any> {
  return invoke("get_node_wallet_info");
}

// --- RPC Console ---

export async function executeRpc(method: string, paramsJson: string): Promise<any> {
  return invoke("execute_rpc", { method, paramsJson });
}

// --- L2 Balance ---

export async function l2Balance(): Promise<{ confirmed: number; pending: number }> {
  return invoke("l2_balance");
}

// --- Ghost Locks ---

export interface LockInfo {
  id: string;
  denomination: string;
  amount_sats: number;
  state: string;
  created_at: number;
  timelock_tier: string;
  jump_risk: string;
  needs_jump: boolean;
  address: string;
  output_pubkey: string;
  recovery_height: number;
  blocks_until_jump: number;
}

export interface WraithSessionInfo {
  id: string;
  tier: string;
  denomination: string;
  state: string;
  participants: number;
  fill_percentage: number;
}

export interface GhostIdInfo {
  ghost_id: string;
  scan_pubkey: string;
  spend_pubkey: string;
}

export async function listLocks(): Promise<LockInfo[]> {
  return invoke("list_locks");
}
export async function getLock(lockId: string): Promise<LockInfo> {
  return invoke("get_lock", { lockId });
}
export async function createLock(amountSats: number, timelockTier?: string): Promise<any> {
  return invoke("create_lock", { amountSats, timelockTier });
}
export async function jumpLock(lockId: string): Promise<any> {
  return invoke("jump_lock", { lockId });
}
export async function reconcileLock(lockId: string, destination: string, settlementClass?: string): Promise<any> {
  return invoke("reconcile_lock", { lockId, destination, settlementClass });
}
export async function listWraithSessions(): Promise<WraithSessionInfo[]> {
  return invoke("list_wraith_sessions");
}
export async function getWraithSession(sessionId: string): Promise<WraithSessionInfo> {
  return invoke("get_wraith_session", { sessionId });
}
export async function joinWraithSession(tier: string, denomination: string, lockId?: string): Promise<any> {
  return invoke("join_wraith_session", { tier, denomination, lockId });
}
export async function submitWraithInput(sessionId: string, ghostId: string, txid: string, vout: number, amount: number, scriptPubkey: string): Promise<any> {
  return invoke("submit_wraith_input", { sessionId, ghostId, txid, vout, amount, scriptPubkey });
}
export async function getGhostId(): Promise<GhostIdInfo> {
  return invoke("get_ghost_id");
}
export async function generateGhostId(): Promise<any> {
  return invoke("generate_ghost_id");
}
export async function sendL2Payment(recipient: string, amountSats: number, memo?: string): Promise<any> {
  return invoke("send_l2_payment", { recipient, amountSats, memo });
}
export async function listWithdrawals(): Promise<any[]> {
  return invoke("list_withdrawals");
}

// --- Helpers ---

export function formatGhost(sats: number): string {
  return (sats / 100_000_000).toFixed(8);
}

export function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}
