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

export async function getConnectionStatus(): Promise<ConnectionStatus> {
  return invoke("get_connection_status");
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

// --- Helpers ---

export function formatGhost(sats: number): string {
  return (sats / 100_000_000).toFixed(8);
}

export function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}
