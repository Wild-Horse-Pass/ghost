# Merchant Mode Specification

**Version:** 0.2.0
**Last Updated:** 2026-03-01

---

## 1. Overview

Merchant mode transforms GhostTap from a consumer wallet into a point-of-sale payment terminal. It adds:

- Payment terminal with numeric keypad
- Receipt generation (PDF via HTML rendering)
- Invoice creation and sharing
- Transaction export (CSV and PDF)
- Wraith washing for payment privacy
- Business profile management

Merchant mode is toggled in Settings. When enabled, the app adds "Terminal" and "Business" tabs to the navigation.

## 2. Payment Terminal

### 2.1 Flow

```
┌─────────────────────┐
│    Enter Amount      │
│                      │
│    [$125.00]         │
│                      │
│  [1] [2] [3]        │
│  [4] [5] [6]        │
│  [7] [8] [9]        │
│  [.] [0] [⌫]       │
│                      │
│  [ Charge $125.00 ]  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Waiting for        │
│   Payment            │
│                      │
│   [QR Code]          │
│                      │
│   NFC Ready ✓        │
│                      │
│   ghost:Gaddr...     │
│   ?amount=12500000   │
│                      │
│   [ Cancel ]         │
└──────────┬──────────┘
           │ (payment received)
           ▼
┌─────────────────────┐
│   Payment Received   │
│                      │
│   ✓ $125.00 Ghost    │
│   TxID: abc123...    │
│                      │
│ [Wash via Wraith]    │
│ [View Receipt]       │
│ [New Transaction]    │
└─────────────────────┘
```

### 2.2 Payment Detection

When the terminal is active:
1. Display QR code with `ghost:<merchant_address>?amount=<sats>`
2. Activate NFC reader (Android) or show QR only (iOS)
3. Poll for incoming transactions every 2 seconds (RPC) or listen for push events (GSP)
4. On detection: show confirmation with txid
5. Auto-generate receipt if enabled in settings

### 2.3 Amount Entry

- Numeric keypad with decimal point
- Maximum 8 decimal places (Ghost satoshi precision)
- Amount displayed in both Ghost and configurable fiat currency (with live exchange rate)
- Backspace to delete last digit
- "Charge" button disabled until amount > 0

## 3. Receipts

### 3.1 Receipt Data

```rust
pub struct Receipt {
    pub receipt_id: String,       // UUID
    pub business_name: String,    // From merchant profile
    pub business_address: String, // From merchant profile
    pub amount: u64,              // In satoshis
    pub txid: String,             // Transaction ID
    pub timestamp: u64,           // Unix timestamp
    pub memo: Option<String>,     // Optional note
    pub items: Vec<LineItem>,     // Optional line items
}

pub struct LineItem {
    pub description: String,
    pub amount: u64,
}
```

### 3.2 Receipt HTML Template

Receipts are generated as self-contained HTML with inline CSS (no external dependencies). The Rust core's `Receipt::to_html()` produces the HTML, which is rendered to PDF by the platform:

- **Android:** `WebView` → `PrintDocumentAdapter` → temp PDF → share via `FileProvider` + `Intent.ACTION_SEND`
- **iOS:** `WKWebView.createPDF(configuration:)` → share via `UIActivityViewController`

### 3.3 Receipt Numbering

Receipts use sequential numbering per merchant: `R-0001`, `R-0002`, etc. The sequence counter is stored in local SQLite and persists across app restarts.

### 3.4 Receipt Content

```
┌─────────────────────────────┐
│       Bob's Coffee Shop      │
│   123 Main St, Anytown      │
│                              │
│   Receipt #R-0001            │
│   Date: 2026-02-28 14:30    │
│                              │
│   ─────────────────────────  │
│   Latte             5.00     │
│   Muffin            3.50     │
│   ─────────────────────────  │
│   Total:            8.50 GHOST│
│                              │
│   TxID: abc123def456...      │
│                              │
│   Powered by GhostTap        │
└─────────────────────────────┘
```

### 3.4 Receipt Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Auto-generate receipt | On | Create receipt for every terminal payment |
| Show logo on receipts | Off | Include merchant logo (if set in profile) |
| Receipt memo default | Empty | Pre-fill memo field |

## 4. Invoices

### 4.1 Invoice Data

```rust
pub struct Invoice {
    pub invoice_id: String,        // UUID
    pub business_name: String,
    pub business_address: String,
    pub amount: u64,               // Total in satoshis
    pub ghost_address: String,     // Payment address
    pub due_date: Option<u64>,     // Unix timestamp
    pub line_items: Vec<LineItem>,
    pub memo: Option<String>,
    pub status: InvoiceStatus,
}

pub enum InvoiceStatus {
    Draft,
    Sent,
    Paid,
    Overdue,
    Cancelled,
}
```

### 4.2 Invoice Creation Flow

1. Merchant enters amount, optional line items, due date, memo
2. System generates `Invoice` with fresh Ghost address
3. Preview rendered as HTML (styled, with payment QR code)
4. Share via OS share sheet (PDF) or copy payment URI

### 4.3 Invoice Payment URI

Invoices include a `ghost:` payment URI that can be shared as text or QR:

```
ghost:GXj2k8...?amount=850000&label=Bob%27s%20Coffee&memo=Invoice%20INV-2026-0001
```

### 4.4 Partial Payments

Invoices support partial payments:
- Track total paid vs. total due
- Status remains "Sent" until fully paid
- Each partial payment recorded with its txid
- UI shows remaining balance due
- Payment URI updates to reflect remaining amount

### 4.5 Invoice Status Tracking

- **Draft:** Created but not shared
- **Sent:** Shared with customer (may have partial payments)
- **Paid:** Full payment detected on-chain (auto-detected via sync)
- **Overdue:** Past due date, not fully paid
- **Cancelled:** Manually cancelled by merchant

Auto-detection of invoice payment requires monitoring the invoice's address for incoming transactions. This is handled during wallet sync.

## 5. Transaction Export

### 5.1 Export Formats

**CSV:**
```
Date,TxID,Direction,Amount (GHOST),Fee (GHOST),Address,Status,Memo
2026-02-28 14:30,abc123...,Received,8.50000000,0.00000000,GXj2k8...,Confirmed,Coffee sale
2026-02-28 15:00,def456...,Sent,2.00000000,0.00010000,GYm3n9...,Confirmed,Supplier payment
```

**PDF (HTML report):**
Summary cards (total received, total sent, total fees, transaction count) followed by a detailed transaction table. Generated from HTML via the same WebView → PDF pipeline as receipts.

### 5.2 Export Parameters

| Parameter | Description |
|-----------|-------------|
| Date range | Start and end date (inclusive) |
| Format | CSV or PDF |
| Direction filter | All, Received only, Sent only |
| Network filter | Ghost, Bitcoin, All (future) |

### 5.3 Export Flow

1. Merchant selects date range and format
2. System queries transaction history from local storage
3. Generates CSV string or HTML report via Rust core
4. Platform renders PDF (if HTML) and presents share sheet

## 6. Wraith Protocol Washing

### 6.1 What is Wraith Washing?

Ghost's Wraith protocol allows toggling between public and private ledger modes. "Washing" a payment means:

1. Move received funds from public balance to private (anon) balance
2. Move funds back from private to a new public address

This breaks the on-chain link between the merchant's receive address and their spending address, providing privacy.

### 6.2 Manual Washing

After each terminal payment, the confirmation screen shows a "Wash via Wraith" button. Tapping it:

1. Calls `createwraithtx(amount, 10)` — Phase 1: split into intermediate UTXOs
2. Waits for confirmation (1 block)
3. Calls `createwraithfinaltx(intermediates, new_address)` — Phase 2: merge into final outputs
4. Updates wash status in the queue

This uses the Ghost two-phase CoinJoin approach (OP_RETURN markers `GPW1` / `GPW2`) rather than simple anon send/receive.

### 6.3 Auto-Washing

In merchant settings, enable "Auto-wash incoming payments":

1. Every terminal payment is automatically queued for washing
2. Background queue processes washes with concurrency limit (default: 2)
3. Configurable ring size for private transactions (3-32, default: 8)
4. Queue status visible on merchant dashboard

### 6.4 Wash Queue

```rust
pub struct WashRequest {
    pub id: String,
    pub txid: String,
    pub amount: u64,
    pub status: WashStatus,
    pub created_at: u64,
    pub completed_at: Option<u64>,
    pub error: Option<String>,
    pub retry_count: u32,
}

pub enum WashStatus {
    Queued,
    InProgress,
    Completed,
    Failed,
}
```

Queue behavior:
- **Persists across app restarts** — wash queue stored in SQLite, not in-memory
- Maximum concurrent washes: configurable (default 2)
- Failed washes: auto-retry up to 3 times with exponential backoff
- Pruning: completed washes removed after 30 days
- Dashboard shows: queued count, active count, completed count, failed count

### 6.5 Wash Fee Consideration

Washing involves two on-chain transactions (public→private, private→public), each with a fee. The total wash cost is approximately 2x the normal transaction fee. The UI should display the estimated wash fee before the merchant confirms.

## 7. Merchant Profile

### 7.1 Profile Fields

| Field | Required | Description |
|-------|----------|-------------|
| Business name | Yes | Displayed on receipts and invoices |
| Business address | No | Physical address for receipts |
| Tax ID | No | Tax identification number |
| Ghost address | Yes | Default receive address for payments |
| Logo | No | Business logo (local file path) |
| Auto-wash | No | Enable automatic Wraith washing |
| Ring size | No | Ring size for Wraith washes (3-32) |

### 7.2 Profile Storage

Stored in local SQLite database (`merchant_profile` table), encrypted fields for sensitive data (tax ID). Profile data is included in generated receipts and invoices.

## 8. Merchant Dashboard

The dashboard provides a quick overview of business activity:

### 8.1 Sales Summary Cards

| Card | Description |
|------|-------------|
| Today | Total received today, transaction count |
| This Week | Total received this week |
| This Month | Total received this month |

### 8.2 Wraith Status

Visual indicator of wash queue status:
- Queued: number of pending washes
- Active: number of in-progress washes
- Done: completed washes (last 24h)
- Failed: failed washes requiring attention

### 8.3 Quick Actions

- **Charge:** Open payment terminal
- **Invoice:** Create new invoice
- **Export:** Export transactions

### 8.4 Recent Transactions

Scrollable list of recent merchant transactions with amount, time, and status.

## 9. Resolved Design Decisions

- **Partial payments:** Yes — invoices support partial payments with remaining balance tracking.
- **Fiat display:** Yes — configurable fiat currency with live exchange rate for amount display.
- **Receipt numbering:** Sequential per-merchant (`R-0001`, `R-0002`, ...).
- **Wash queue persistence:** Yes — stored in SQLite, survives app restarts.
- **Tax calculation:** Out of scope for GhostTap. Merchants handle tax externally.

## 10. Open Questions

- [ ] Multi-currency receipts when Bitcoin/Lightning are added — separate or combined?
