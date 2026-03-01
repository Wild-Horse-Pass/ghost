# GhostTap Architecture

**Version:** 0.2.0
**Last Updated:** 2026-03-01

---

## 1. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Mobile / Desktop                        │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  iOS (Swift)  │  │Android (Kt)  │  │Desktop (Tauri)│      │
│  │  SwiftUI      │  │Compose       │  │Web UI (future)│      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
│         │                  │                  │               │
│         └──────────┬───────┘──────────────────┘               │
│                    │ UniFFI (Swift/Kotlin bindings)           │
│         ┌──────────▼──────────┐                              │
│         │   ghost-tap-core    │                              │
│         │      (Rust)         │                              │
│         │                     │                              │
│         │ ┌─────────────────┐ │                              │
│         │ │ wallet/         │ │  Key derivation, UTXO mgmt  │
│         │ │ transaction/    │ │  Tx building, signing        │
│         │ │ crypto/         │ │  AES, secp256k1, zeroize     │
│         │ │ storage/        │ │  SQLite, keychain            │
│         │ │ payment/        │ │  QR URIs, NFC APDU           │
│         │ │ merchant/       │ │  Receipts, invoices, export  │
│         │ │ network/        │ │  RPC, GSP, connection mgr    │
│         │ │ ffi/            │ │  UniFFI exports              │
│         │ └─────────────────┘ │                              │
│         └──────────┬──────────┘                              │
└────────────────────┼─────────────────────────────────────────┘
                     │
        ┌────────────┼────────────────┐
        │            │                │
        ▼            ▼                ▼
  ┌──────────┐ ┌──────────┐   ┌──────────┐
  │Ghost Node│ │Bitcoin   │   │Lightning │
  │(RPC/GSP) │ │Core/Elec.│   │(LDK+LSP)│
  └──────────┘ └──────────┘   └──────────┘
```

## 2. Rust Core (`ghost-tap-core`)

All business logic lives in Rust. The mobile and desktop apps are thin UI shells that call into the core via FFI. This ensures:

- Single implementation of all crypto, wallet, and network logic
- Consistent behavior across platforms
- Easier security auditing (one codebase to review)
- ~90% code sharing

### Module Map

```
core/src/
├── lib.rs              Entry point, GhostTapError, init()
├── wallet/
│   ├── mod.rs          Wallet struct, create/import/lock/unlock
│   ├── keys.rs         BIP39 mnemonic, BIP44 derivation, key management
│   ├── balance.rs      UTXO tracking, balance calculation, coin selection
│   └── history.rs      Transaction history, HistoryEntry, TxDirection/TxStatus
├── transaction/
│   ├── mod.rs          TransactionError
│   ├── builder.rs      UTXO selection, transaction construction
│   └── signer.rs       Transaction signing, message signing
├── crypto/
│   ├── mod.rs          AES-256-GCM encrypt/decrypt, random bytes
│   └── secure_mem.rs   Secure buffer, constant-time comparison
├── storage/
│   ├── mod.rs          SQLite storage (kv, utxos, history, wallet_meta, merchant)
│   └── keychain.rs     PlatformKeychain trait, register_keychain(), fallback
├── payment/
│   ├── mod.rs          Module declarations
│   ├── qr.rs           PaymentRequest, ghost:/bitcoin:/lightning: URI format
│   └── nfc.rs          NfcPaymentRequest/Response, binary APDU encoding
├── merchant/
│   ├── mod.rs          Module declarations
│   ├── profile.rs      MerchantProfile CRUD
│   ├── receipt.rs       Receipt + LineItem, to_html()
│   ├── invoice.rs      Invoice + InvoiceStatus, to_html(), to_payment_uri()
│   ├── export.rs       TransactionExporter: to_csv(), to_html_report()
│   └── wraith.rs       WraithWasher, wash queue, concurrency limits
├── network/
│   ├── mod.rs          NetworkError
│   ├── client.rs       Ghost JSON-RPC client
│   ├── sync.rs         Wallet sync logic
│   ├── peer.rs         Peer management
│   ├── gsp.rs          GSP WebSocket client (tokio-tungstenite)
│   ├── gsp_auth.rs     GSP registration, session creation, BIP-340 proofs
│   ├── gsp_failover.rs Endpoint failover with retry logic
│   └── connection.rs   ConnectionManager (GSP vs DirectRPC abstraction)
└── ffi/
    ├── mod.rs          UniFFI exports (~30 functions), WalletHandle
    └── android.rs      JNI bridge for Android-specific calls
```

### Key Design Decisions

**UniFFI for FFI bindings.** Mozilla's UniFFI generates Swift and Kotlin bindings from Rust type definitions using proc macros. This avoids hand-written C headers and manual memory management. The `WalletHandle` is exposed as a UniFFI `Object` (ref-counted, opaque pointer) with methods callable from Swift/Kotlin.

**Mutex-wrapped wallet state.** `WalletHandle` holds `Arc<Mutex<Wallet>>`. All FFI methods acquire the lock, operate, and release. This is safe for concurrent UI access (e.g., background sync while user views balance).

**PlatformKeychain callback trait.** The Rust core defines `PlatformKeychain` as a trait. Native code (Swift/Kotlin) implements it and registers via `register_keychain()`. This avoids Rust needing to know about iOS Keychain Services or Android Keystore APIs directly. A `DesktopFallbackKeychain` (in-memory HashMap) is used for testing and desktop.

**ConnectionManager abstraction.** `ConnectionManager` provides a single API surface (`get_balance()`, `send_payment()`, `sync()`) that delegates to either GSP WebSocket or direct JSON-RPC. The mobile UI doesn't need to know which transport is active.

**Encrypted SQLite.** Sensitive values in the KV store are encrypted with AES-256-GCM before writing to SQLite. The encryption key is stored in the platform keychain. Non-sensitive data (tx history, UTXOs) is stored in plaintext for query performance.

## 3. Mobile App Architecture

### Android (Kotlin / Jetpack Compose)

```
android/app/src/main/kotlin/com/ghost/tap/
├── MainActivity.kt              Single-activity entry point
├── Navigation.kt                NavHost with sealed Screen routes
├── RustBridge.kt                System.loadLibrary("ghost_tap_core")
├── viewmodel/
│   ├── WalletViewModel.kt       Main wallet state (StateFlow<WalletUiState>)
│   └── MerchantViewModel.kt     Merchant state and operations
├── ui/
│   ├── theme/Theme.kt           GhostTapTheme (Material 3)
│   ├── screens/                  Consumer screens (12)
│   ├── screens/merchant/         Merchant screens (7)
│   └── components/               Reusable composables (QR code view)
└── nfc/
    ├── GhostTapHceService.kt    HostApduService (customer mode)
    └── NfcPaymentReader.kt      NfcAdapter.ReaderCallback (merchant mode)
```

**State management:** Single `WalletViewModel` per activity, exposed via Compose's `viewModel()`. Uses `StateFlow<WalletUiState>` for reactive UI updates. All Rust calls happen on `Dispatchers.IO`.

**Navigation:** Single-activity with `NavHost`. Sealed `Screen` class defines all routes. Navigation events flow up from screens to the NavHost via callbacks.

### iOS (Swift / SwiftUI)

```
ios/GhostTap/
├── GhostTapApp.swift            @main App entry, RootView, OnboardingView
├── ViewModels/
│   ├── WalletViewModel.swift    @MainActor ObservableObject
│   └── MerchantViewModel.swift  Merchant state
└── Views/
    ├── WalletCreateView.swift
    ├── MnemonicBackupView.swift
    ├── MnemonicVerifyView.swift
    ├── WalletImportView.swift
    ├── HomeView.swift
    ├── SendView.swift
    ├── ReceiveView.swift
    ├── TransactionDetailView.swift
    ├── SettingsView.swift
    ├── QrScannerView.swift
    ├── NfcReaderView.swift
    ├── Components/
    │   └── QrCodeImageView.swift
    └── Merchant/
        ├── MerchantDashboardView.swift
        ├── PaymentTerminalView.swift
        ├── MerchantProfileView.swift
        ├── ReceiptView.swift
        ├── InvoiceCreateView.swift
        ├── TransactionExportView.swift
        └── MerchantSettingsView.swift
```

**State management:** `WalletViewModel` as `@StateObject` at the app root, passed down via `.environmentObject()`. All Rust calls dispatched to background via `Task {}`.

**Navigation:** `NavigationStack` with programmatic navigation via `@State` booleans and `.navigationDestination()`.

## 4. Data Flow

### Wallet Creation

```
User taps "Create" → ViewModel calls FFI generate_24()
  → Rust: bip39::Mnemonic::generate(24)
  → Rust: derive seed → derive master key → derive account key
  → Rust: Wallet { keys, utxos: [], history: [] }
  → FFI returns WalletHandle (opaque pointer)
  → ViewModel stores handle, navigates to mnemonic backup
```

### Sending a Payment

```
User enters address + amount → ViewModel calls build_transaction()
  → Rust: UTXO selection (largest-first)
  → Rust: build unsigned transaction
  → FFI returns FfiUnsignedTx { hex, fee, change_amount }
  → UI shows review screen with fee
  → User confirms (biometric or 6-digit PIN) → ViewModel calls sign_and_broadcast()
  → Rust: sign with private key (derived on demand, zeroized after)
  → Rust: broadcast via ConnectionManager (GSP or RPC)
  → FFI returns txid
  → ViewModel updates history, navigates to confirmation
```

### Receiving a Payment (Merchant NFC)

```
Merchant enters amount → Terminal screen activates
  → NFC: encode NfcPaymentRequest (amount, address, memo)
  → Android: NfcPaymentReader waits for tag
  → Customer taps phone (Android HCE responds with payment data)
  → Merchant reads NfcPaymentResponse (txid)
  → ViewModel verifies transaction on-chain
  → Terminal shows confirmation + "Wash via Wraith" button
```

### Wallet Sync

```
App foreground / pull-to-refresh → ViewModel calls sync()
  → Rust: ConnectionManager.sync()
  → If GSP: subscribe to balance/payment events
  → If RPC: poll for new UTXOs, check pending tx confirmations
  → Update local UTXO set and history
  → FFI returns FfiSyncResult { new_txs, updated_balance }
  → ViewModel updates UI state
```

## 5. Build Pipeline

### Rust Core

```bash
# Native (development/testing)
cargo build -p ghost-tap-core
cargo test -p ghost-tap-core

# Android cross-compilation (4 architectures)
./scripts/build-android.sh
# Produces: target/{aarch64,armv7,x86_64,i686}-linux-android/release/libghost_tap_core.so

# iOS cross-compilation (XCFramework)
./scripts/build-ios.sh
# Produces: target/GhostTapCore.xcframework (arm64 device + arm64/x86_64 simulator)
```

### UniFFI Binding Generation

UniFFI generates bindings at build time via `build.rs`:
- **Kotlin:** `ghost_tap.kt` — placed in Android project's generated sources
- **Swift:** `ghost_tap.swift` + `ghost_tapFFI.h` — included in Xcode project

### Mobile Apps

```bash
# Android
cd android && ./gradlew assembleDebug

# iOS
cd ios && xcodebuild -scheme GhostTap -sdk iphoneos build
```

## 6. Dependency Summary

### Rust Core

| Crate | Purpose | Version |
|-------|---------|---------|
| bip39 | Mnemonic generation/validation | 2.0 |
| bip32 | HD key derivation | 0.5 |
| secp256k1 | Elliptic curve crypto | 0.29 |
| k256 | ECDSA signing | 0.13 |
| sha2 | SHA-256 hashing | 0.10 |
| aes-gcm | AES-256-GCM encryption | 0.10 |
| rusqlite | SQLite (bundled) | 0.31 |
| reqwest | HTTP client (RPC) | 0.12 |
| tokio | Async runtime | 1 |
| tokio-tungstenite | WebSocket (GSP) | 0.21 |
| uniffi | FFI binding generation | 0.27 |
| serde / serde_json | Serialization | 1 |
| zeroize | Memory zeroization | 1 |
| secrecy | Secret wrapper types | 0.8 |
| tracing | Structured logging | 0.1 |
| chrono | Date/time formatting | 0.4 |
| parking_lot | Fast mutexes | 0.12 |

### Planned Additions

| Crate | Purpose | Phase |
|-------|---------|-------|
| bitcoin | Bitcoin transaction types, script, address encoding | Phase 5 |
| ldk-node or lightning | Lightning Dev Kit | Phase 6 |
| bdk | Bitcoin Dev Kit (wallet, coin selection, Electrum) | Phase 5 |
| electrum-client | Electrum server connectivity | Phase 5 |

### Android

| Dependency | Purpose |
|-----------|---------|
| Jetpack Compose + Material 3 | UI framework |
| CameraX + MLKit Barcode | QR scanning |
| ZXing Core | QR generation |
| Biometric library | Fingerprint/face auth |
| Navigation Compose | Screen routing |

### iOS

All native frameworks — no external dependencies:
- SwiftUI, CoreImage (QR generation), AVFoundation (QR scanning), CoreNFC, LocalAuthentication, WebKit (PDF rendering)
