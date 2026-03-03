```
//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: GHOST_TAP.md                                                                                                   |
//|======================================================================================================================|
```

# GhostTap

Cross-platform mobile wallet and merchant payment terminal for Bitcoin Ghost.

## Overview

GhostTap is a mobile wallet and contactless merchant terminal built on a shared Rust core library (`ghost-tap-core`) with thin native wrappers for iOS (Swift/SwiftUI), Android (Kotlin/Compose), and desktop (Tauri v2 + React). The core library handles all wallet logic, cryptography, payment protocols, and network communication, exposed to native platforms via UniFFI and JNI bindings.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Native UI Layer                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │   iOS    │ │ Android  │ │    Tauri     │ │
│  │  Swift   │ │  Kotlin  │ │   Desktop    │ │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
│       │             │              │          │
│  ┌────┴─────────────┴──────────────┴───────┐ │
│  │         ghost-tap-core (Rust)           │ │
│  │  ┌────────┐ ┌─────────┐ ┌────────────┐  │ │
│  │  │ Wallet │ │ Payment │ │  Merchant  │  │ │
│  │  └────────┘ └─────────┘ └────────────┘  │ │
│  │  ┌────────┐ ┌─────────┐ ┌────────────┐  │ │
│  │  │Network │ │ Storage │ │   Crypto   │  │ │
│  │  └────────┘ └─────────┘ └────────────┘  │ │
│  └─────────────────────────────────────────┘ │
│       │                                      │
│  ┌────┴────────────────────────┐             │
│  │   UniFFI / JNI Bindings    │             │
│  └─────────────────────────────┘             │
└─────────────────────────────────────────────┘
        │
        ▼
┌───────────────┐     ┌──────────────┐
│  Ghost Pool   │     │  Ghost GSP   │
│  (L2 Relay)   │     │ (SP Scanner) │
└───────────────┘     └──────────────┘
```

## Wallet

### Key Derivation

- BIP-39 mnemonic generation (12 or 24 words)
- BIP-44 hierarchical deterministic key derivation
- Coin type: 0 (Bitcoin mainnet compatible)
- Path: `m/44'/0'/account'/change/index`
- Address format: Hash160 (RIPEMD160(SHA256(pubkey))) with Base58Check encoding, version byte `0x00`
- Seed encrypted at rest via AES-256-GCM, key material zeroized on drop

### Balance Management

- UTXO set tracking with confirmed, pending incoming, and pending outgoing balances
- Largest-first UTXO selection for spending (excludes pending-spend and unconfirmed UTXOs)
- Pending spend tracking: UTXOs marked as pending-spend remain in the set but are excluded from available balance and coin selection
- Transaction history with direction (incoming/outgoing), confirmation count, and memo support

### Authentication

- PIN-based wallet lock/unlock via Argon2id key derivation
- All operations that access private keys require an unlocked wallet
- Encrypted mnemonic backup export: `salt(16) || nonce(12) || AES-256-GCM ciphertext` with Argon2id KDF

## Payments

### QR Code Payments

Standard flow for in-person payments using the `ghost:` URI scheme:

1. Merchant generates a `PaymentRequest` (address + amount + memo + label + optional expiry)
2. Encoded as URI: `ghost:<address>?amount=<sats>&memo=<text>&label=<text>&exp=<unix_ts>&net=<network>`
3. URI rendered as QR code for customer to scan
4. Customer wallet parses URI, validates expiry and network, constructs and signs transaction
5. Submitted to Ghost Pay L2 or broadcast on-chain

URI features:
- Percent-encoded query parameters (RFC 3986)
- Optional `exp` field for time-limited payment requests (rejected if expired)
- Optional `net` field for network identification (warns on mismatch)
- Unknown parameters silently ignored for forward compatibility

### NFC Contactless

Binary APDU protocol for tap-to-pay at merchant terminals:

**Request wire format (merchant to customer):**
```
[version: 1 byte] [msg_type: 1 byte] [amount: 8 bytes BE u64]
[addr_len: 2 bytes BE u16] [address: UTF-8] [memo_len: 2 bytes BE u16] [memo: UTF-8]
```

**Response wire format (customer to merchant):**
```
[status: 1 byte] [txid_len: 2 bytes BE u16] [txid: UTF-8]
```

- Protocol version: 1
- Message types: `0x01` (payment request), `0x02` (payment response)
- Status: `0x00` = success, non-zero = error

### NFC Payment Limits

NFC tap-to-pay enforces a configurable satoshi cap anchored to a fiat ceiling of 250 GBP:

- **Default cap (no exchange rate):** 500,000 sats (conservative fallback)
- **With exchange rate:** `(250 GBP / rate) * 100,000,000 sats`, hard-capped at 10,000,000,000 sats (100 GHOST)
- Amounts exceeding the NFC limit are rejected with a suggestion to use QR code payment instead
- Exchange rate updates silently ignored if non-finite, zero, or negative

## Merchant Mode

### Profile

Merchant business identity stored encrypted in the local database:
- Business name, address, tax ID, logo path
- Ghost address for receiving payments
- Auto-wash toggle (automatic Wraith mixing of received funds)

### Invoices

Full invoice lifecycle with state machine transitions:

```
Draft --> Sent --> Paid
  |         |
  v         v
Cancelled  Overdue / Cancelled
```

- Line items with individual amounts
- Partial payment tracking (multiple payments against one invoice)
- Automatic `Paid` status transition when `amount_paid >= amount`
- Duplicate txid rejection
- Generates `ghost:` payment URIs encoding remaining balance
- HTML rendering with inline CSS (suitable for WebView or PDF conversion)

### Receipts

- Styled HTML receipt generation with business branding
- Line items, total, transaction ID, timestamp, optional memo
- HTML-escaped output safe for WebView rendering

### Export

Transaction reporting for accounting:
- **CSV export:** Date, TxID, Direction, Amount, Fee, Address, Status, Memo columns with date-range filtering
- **HTML report:** Styled document with summary cards (transaction count, total received, total sent, total fees) and full transaction table

### WraithWash

Queue-based system for washing received merchant payments through Wraith Protocol:

```
Queued --> InProgress --> Completed
              |
              v
           Failed --> (retry) --> Queued
```

- Configurable concurrency limit (default: 3 concurrent washes)
- Persistent queue backed by encrypted SQLite storage
- Automatic pruning of completed/failed requests by age
- Queue statistics: counts and amounts per status

## Network

### GhostClient (JSON-RPC)

Full RPC client for interacting with the Ghost daemon:
- Blockchain queries: block height, block hash, blockchain info
- Wallet operations: address balance, UTXOs, transaction history, address generation
- Transaction operations: raw transaction creation, signing, broadcast, fee estimation
- Wraith Protocol: mode switching, stealth addresses, private/public transfers
- Ghost Locks: staking info, lock creation/listing/unlocking, reward estimation
- Jump Locks: HTLC creation, claim with preimage, refund on expiry
- Multi-endpoint support with automatic failover and retry
- TLS certificate pinning support

### GSP WebSocket

Real-time sync with Ghost GSP server via `MobileGspClient`:
- Persistent WebSocket connection with background read/write task
- Authentication with wallet ID and session token
- RPC-style request/response with serialization lock (atomic send/recv)
- Push event subscriptions: balance changes, payment confirmations
- Event channel (mpsc) for delivering push notifications to the application layer
- Message types: Authenticate, GetBalance, PreparePayment, SubmitSignedPayment, SubscribeBalance, SubscribePayments

### Ghost Pay Client (HTTP REST)

HTTP client for Ghost Pay L2 API with retry and exponential backoff:
- Glyph operations: claim, lookup by ghost ID, availability check by bitmap hash
- Retry with exponential backoff (200ms, 400ms, 800ms) for transient failures (5xx, 429)
- Path segment percent-encoding for injection prevention
- Shared `reqwest::Client` support for connection pooling in long-lived applications

## Storage

- **SQLite** (rusqlite): Local database with WAL mode, schema version 2
  - Encrypted blob storage for UTXOs, transaction history, wash queue, and merchant profile (AES-256-GCM)
  - Plaintext indexes on txid/timestamp for ordering and lookup
  - Key-value store with optional per-key encryption
  - Wallet metadata (account index, address counters)
- **Keychain**: Platform-native secure storage abstraction for private keys
- **AES-256-GCM**: All sensitive data encrypted at rest with 12-byte random nonce prepended to ciphertext
- **Argon2id**: Password-based key derivation for encrypted backups (16-byte random salt)

## Build

```bash
# Rust core library
cargo build -p ghost-tap-core
cargo test -p ghost-tap-core

# Integration tests
cargo test -p ghost-tap-integration

# Lint
cargo clippy -p ghost-tap-core -- -D warnings

# iOS XCFramework
./apps/ghost-tap/scripts/build-ios.sh

# Android JNI
./apps/ghost-tap/scripts/build-android.sh

# Desktop (Tauri)
cd apps/ghost-tap/desktop && cargo tauri build
```

## Source Files

| Path | Purpose |
|------|---------|
| `apps/ghost-tap/core/src/lib.rs` | Crate root, error types, UniFFI scaffolding |
| `apps/ghost-tap/core/src/wallet/` | Wallet, BIP-39/BIP-44 derivation, balance, UTXO set, auth, history |
| `apps/ghost-tap/core/src/transaction/` | Transaction builder and signer |
| `apps/ghost-tap/core/src/network/client.rs` | GhostClient JSON-RPC (blockchain, wraith, locks) |
| `apps/ghost-tap/core/src/network/gsp.rs` | MobileGspClient WebSocket (real-time sync) |
| `apps/ghost-tap/core/src/network/ghost_pay.rs` | GhostPayClient HTTP REST (L2, glyph operations) |
| `apps/ghost-tap/core/src/network/gsp_auth.rs` | GSP authentication |
| `apps/ghost-tap/core/src/network/gsp_failover.rs` | GSP endpoint failover |
| `apps/ghost-tap/core/src/network/connection.rs` | Connection management |
| `apps/ghost-tap/core/src/network/sync.rs` | Blockchain sync logic |
| `apps/ghost-tap/core/src/network/peer.rs` | Peer discovery and management |
| `apps/ghost-tap/core/src/payment/qr.rs` | `ghost:` URI scheme (PaymentRequest encode/decode) |
| `apps/ghost-tap/core/src/payment/nfc.rs` | NFC binary APDU protocol (request/response codec) |
| `apps/ghost-tap/core/src/payment/limits.rs` | NFC payment limits (fiat-anchored cap) |
| `apps/ghost-tap/core/src/merchant/profile.rs` | MerchantProfile (business identity) |
| `apps/ghost-tap/core/src/merchant/invoice.rs` | Invoice lifecycle, HTML rendering, payment tracking |
| `apps/ghost-tap/core/src/merchant/receipt.rs` | Receipt HTML generation |
| `apps/ghost-tap/core/src/merchant/export.rs` | CSV and HTML transaction export |
| `apps/ghost-tap/core/src/merchant/wraith.rs` | WraithWasher queue (privacy mixing) |
| `apps/ghost-tap/core/src/merchant/wash_task.rs` | Background wash task driver |
| `apps/ghost-tap/core/src/storage/mod.rs` | WalletStorage (encrypted SQLite) |
| `apps/ghost-tap/core/src/storage/keychain.rs` | Platform keychain abstraction |
| `apps/ghost-tap/core/src/ffi/mod.rs` | FFI bindings root |
| `apps/ghost-tap/core/src/ffi/ios.rs` | UniFFI bindings for iOS |
| `apps/ghost-tap/core/src/ffi/android.rs` | JNI bindings for Android |
| `apps/ghost-tap/core/src/crypto/mod.rs` | AES-256-GCM encrypt/decrypt, secure random |
| `apps/ghost-tap/core/src/crypto/secure_mem.rs` | Secure memory utilities |
| `apps/ghost-tap/core/src/glyph.rs` | GhostGlyph visual identity integration |
| `apps/ghost-tap/desktop/` | Tauri v2 merchant terminal (wallet, payment, merchant, glyph, wraith commands) |
| `apps/ghost-tap/tests/integration/` | Integration test suite |

## Related Documentation

- [Ghost Pay](GHOST_PAY.md) - L2 payment network
- [Ghost Keys](GHOST_KEYS.md) - Silent Payment addresses
- [GhostGlyph](GHOST_GLYPHS.md) - Visual identity avatars
- [Wraith Protocol](WRAITH_PROTOCOL.md) - Private entry via mixing
- [Ghost Locks](GHOST_LOCKS.md) - Timelocked staking
- [Jump Locks](JUMP_LOCKS.md) - Hash time-locked contracts
