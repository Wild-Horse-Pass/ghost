# GhostTap Product Specification

**Version:** 0.2.0
**Last Updated:** 2026-03-01

---

## 1. Overview

GhostTap is a non-custodial mobile wallet and merchant payment terminal. It supports three payment networks:

| Network | Priority | Status |
|---------|----------|--------|
| Ghost (on-chain + Wraith privacy) | Primary | In development |
| Bitcoin (on-chain) | Secondary | Planned |
| Lightning Network (via LDK) | Secondary | Planned |

All three networks share a single BIP39 mnemonic seed with separate BIP44 derivation paths.

## 2. Target Users

**Consumer:** Wants a mobile wallet to hold, send, and receive Ghost and Bitcoin. Values privacy (Wraith protocol). May pay merchants via QR or NFC tap.

**Merchant:** Runs a small business. Wants to accept Ghost/Bitcoin payments at point-of-sale via NFC terminal or QR codes. Needs receipts, invoices, transaction export for bookkeeping, and optional Wraith washing for privacy.

**Desktop User (Future):** Wants the same wallet experience on a laptop/desktop. Tauri-based app sharing the Rust core. Deferred until mobile is production-ready.

## 3. Core Features

### 3.1 Wallet Management

- Generate new wallet (12 or 24 word mnemonic)
- Import existing wallet from mnemonic
- Deterministic key derivation (BIP44)
  - Ghost: `m/44'/531'/0'`
  - Bitcoin: `m/44'/0'/0'` (legacy), `m/84'/0'/0'` (native segwit)
  - Lightning: Managed by LDK from same seed
- Encrypted local storage (SQLite + AES-256-GCM)
- Platform keychain integration (iOS Keychain, Android Keystore)
- Biometric unlock (Face ID, Touch ID, Android BiometricPrompt)
- 6-digit PIN as alternative/fallback to biometrics
- Auto-lock after configurable inactivity timeout
- Root/jailbreak detection with user warning
- Lock/unlock state management

### 3.2 Ghost Payments

- Send Ghost to an address with configurable fee priority
- Receive Ghost with generated QR code
- View transaction history with status tracking
- Balance display (confirmed, pending incoming, pending outgoing)
- Sync with Ghost node via JSON-RPC or GSP WebSocket
- Wraith protocol: toggle between public and private ledger
- Stealth addresses for private receiving

### 3.3 Bitcoin Payments (Planned)

- Send/receive Bitcoin on-chain
- Native SegWit addresses (bech32, `bc1...`)
- UTXO management and coin selection
- Fee estimation from mempool data
- Connect to Bitcoin Core node (own) or public Electrum server
- Testnet/signet support for development

### 3.4 Lightning Payments (Planned)

- Send/receive via Lightning Network using LDK (Rust-native)
- Connect to LSP (Lightning Service Provider) for channel management
- Bolt11 invoice creation and scanning
- Bolt12 offers support (when stable)
- Automatic channel management (open/close/rebalance via LSP)
- No requirement to run a full Lightning node

### 3.5 QR Code Payments

- Ghost URI: `ghost:<address>?amount=<sats>&memo=<text>&label=<text>`
- Bitcoin URI: `bitcoin:<address>?amount=<btc>&message=<text>&label=<text>` (BIP21)
- Lightning: `lightning:<bolt11_invoice>` or LNURL
- Camera-based QR scanning (CameraX + MLKit on Android, AVCaptureSession on iOS)
- QR code generation for receiving

### 3.6 NFC Payments (Android)

- Android HCE (Host Card Emulation) for tap-to-pay
- Custom AID: `F0474854415000`
- ISO 7816-4 APDU protocol for payment data exchange
- Merchant reads customer's NFC tag to initiate payment
- iOS can read Android HCE tags via Core NFC
- Fallback to QR when NFC is unavailable
- Biometric or PIN required for ALL NFC payments (no auto-sign threshold)
- Maximum NFC payment: equivalent of 250 GBP fiat value

**NFC Payment Matrix:**

| Customer | Merchant | Method |
|----------|----------|--------|
| Android | Android | NFC tap |
| Android | iOS | NFC tap (Core NFC reads HCE) |
| iOS | Android | QR code |
| iOS | iOS | QR code |

### 3.7 Merchant Mode

- Toggle merchant mode in settings (adds Terminal and Business tabs)
- **Payment Terminal:** Numeric keypad to enter amount, generates QR + activates NFC reader, shows confirmation on payment receipt
- **Receipts:** Auto-generated HTML receipt per transaction, rendered as PDF via platform WebView, shared via OS share sheet
- **Invoices:** Create invoice with line items, due date, memo. Generates shareable payment URI and PDF.
- **Transaction Export:** Date range filter, CSV and PDF output, shared via OS share sheet
- **Wraith Washing:** Per-transaction "Wash via Wraith" button. Auto-wash toggle in merchant settings. Two-phase CoinJoin via `createwraithtx` (split) + `createwraithfinaltx` (merge). Background wash queue persists across app restarts.
- **Merchant Profile:** Business name, address, tax ID, Ghost address, logo. Printed on receipts and invoices.
- **Invoices:** Support partial payments.
- **Fiat Display:** Configurable fiat currency with live exchange rate for display purposes.

No product catalog. Merchant types the amount for each transaction. Tax calculation is out of scope.

## 4. Non-Goals

- Full node on mobile (light wallet only — connects to remote nodes)
- Staking/mining from the wallet
- Multi-signature wallets (single-sig only for v1)
- Token/asset support beyond Ghost and Bitcoin
- Fiat on/off ramps
- Exchange/swap functionality (v1)
- Desktop app (deferred to post-mobile-launch)

## 5. Platform Support

| Platform | Min Version | UI Framework |
|----------|-------------|--------------|
| Android | API 26 (Android 8.0) | Jetpack Compose + Material 3 |
| iOS | iOS 15 | SwiftUI |
| Desktop | Deferred | Tauri (planned) |

## 6. Network Connectivity

### Primary: Ghost Nodes (JSON-RPC)

Direct connection to user's own Ghost node or a trusted node. Requires:
- RPC endpoint (host:port) — Mainnet: 8332, Signet: 38332
- Authentication: cookie-based (local) or HTTP Basic Auth (remote, TLS required)
- Supports multiple nodes for failover (4 signet nodes available)
- ZMQ notifications available for real-time tx/block detection

### Secondary: GSP WebSocket

Built into every ghostd node on port 8900. Provides:
- Push notifications for balance changes and incoming payments
- BIP-157 compact block filters for privacy (server can't see wallet addresses)
- Lower latency than polling RPC
- No need to expose own node's RPC port separately

### Bitcoin: Electrum Protocol or Bitcoin Core RPC

- Connect to own Bitcoin Core node
- Or use public Electrum servers (with privacy tradeoff)
- Compact block filters (BIP157/158) as future option

### Lightning: LDK + LSP

- LDK manages channels and routing locally
- LSP provides liquidity and channel management
- No direct node operation required

## 7. Security Model

See [security.md](security.md) for full threat model.

Summary:
- Mnemonic never leaves the device
- Private keys derived on-demand, zeroized after use
- Local database encrypted with AES-256-GCM
- Encryption key stored in platform keychain (hardware-backed where available)
- Biometric gate before signing transactions
- NFC HCE responds with "locked" status when wallet is locked
- No sensitive data in logs

## 8. Development Phases

### Phase 1: Ghost Wallet (Current)
Core wallet operations, storage, keychain, FFI, mobile UI scaffolds. **Status: Code complete, needs testing on hardware.**

### Phase 2: Signet Integration
Connect to live Ghost signet nodes, test full wallet flows end-to-end, wire up biometric auth, harden error handling.

### Phase 3: QR + NFC Payments
Test QR scanning/generation on devices, test NFC HCE on Android hardware, test Core NFC reading on iOS.

### Phase 4: Merchant Mode
Test receipt/invoice generation, PDF rendering, CSV export, Wraith washing against live node.

### Phase 5: Bitcoin On-Chain
Add Bitcoin derivation paths, transaction building, Electrum/RPC connectivity. Test on Bitcoin testnet/signet.

### Phase 6: Lightning Network
Integrate LDK, connect to LSP, test invoice creation/payment, channel management.

### Phase 7: Production Hardening
Security audit, performance optimization, crash reporting, analytics, app store preparation.

### Phase 8: Desktop App (Optional)
Tauri-based desktop app reusing Rust core. QR-only payments (no NFC).

## 9. Phase Boundaries

**Current scope (Phases 1-4):** Ghost-only wallet with HD key derivation,
QR/NFC payments, merchant mode (receipts, invoices, export), Wraith
washing, and GSP/RPC sync. This is the scope of the initial audit
remediation.

**Phase 5 (Bitcoin on-chain):** Adds Bitcoin derivation paths
(`m/84'/0'/0'`), Bitcoin transaction building, and Electrum/Bitcoin Core
RPC connectivity. Not implemented in the current codebase. The Rust core
has no Bitcoin-specific transaction builder or address types.

**Phase 6 (Lightning Network):** Adds LDK-based Lightning payments via
LSP. Not implemented. Requires separate channel management and routing
logic.

Bitcoin and Lightning support are explicitly out of scope for the current
release. The architecture (modular network layer, trait-based connection
manager) is designed to support them when the time comes.

## 10. Success Criteria (v1.0)

- [ ] Create wallet, back up mnemonic, verify backup
- [ ] Receive Ghost payment (QR code)
- [ ] Send Ghost payment with fee selection
- [ ] NFC tap-to-pay between two Android devices
- [ ] iOS reads Android NFC payment
- [ ] Merchant mode: charge, receipt, invoice, export
- [ ] Wraith wash a payment
- [ ] Sync with Ghost signet node reliably
- [ ] Biometric auth gates all signing operations
- [ ] No crashes on 10 consecutive payment cycles
