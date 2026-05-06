# Wallets

*Multiple ways to send and receive Ghost payments — from command line to mobile NFC.*

## Overview

Ghost offers several wallet options for different use cases:

| Wallet | Platform | Best For | Status |
| --- | --- | --- | --- |
| [Light Wallet CLI](#wallet-light-cli) | Linux, macOS, Windows | Users without full node, GSP-connected | Available |
| Desktop GUI | Linux, macOS, Windows | Everyday use | Available |
| Ghost Tap | iOS, Android | Mobile payments, NFC | Available |
| Hardware | Coldcard, Ledger, etc. | Cold storage | Planned |

:::info All Wallets Share
BIP-39 seed phrases, Ghost Pay integration, silent payments support, and the ability to settle to regular Bitcoin addresses at any time.
:::

## TUI CLI Wallet

### ghost-light-wallet

A terminal-based wallet with a beautiful TUI (Text User Interface). Full keyboard navigation, no mouse required.

- Terminal UI
- SSH-friendly
- Headless servers
- Scriptable

### Installation

```bash
# Install via cargo
cargo install ghost-light-wallet

# Or download binary
curl -sSL https://get.bitcoinghost.org/wallet.sh | bash
```

### Interface Preview

```text
┌─────────────────────────────────────────────────────────┐
│                    Ghost Wallet v1.0                    │
├─────────────────────────────────────────────────────────┤
│ Balance: 0.12345678 BTC                               │
│ Ghost Pay: 0.05000000 BTC (locked)                    │
├─────────────────────────────────────────────────────────┤
│ [S]end  [R]eceive  [H]istory  [L]ock  [Se]ttle  [Q]uit │
└─────────────────────────────────────────────────────────┘
```

### Basic Commands

```bash
# Create new wallet
$ ghost-light-wallet create
Generated new wallet. Backup your seed phrase!

# Check balance
$ ghost-light-wallet balance
Bitcoin:   0.12345678 BTC
Ghost Pay: 0.05000000 BTC (locked)
Total:     0.17345678 BTC

# Send payment
$ ghost-light-wallet send ghost1abc...def 0.01
Payment sent! Confirms in ~10 seconds.

# Generate receive address
$ ghost-light-wallet receive
ghost1xyz...789

# Lock funds to Ghost Pay
$ ghost-light-wallet lock 0.1
Locking 0.1 BTC to Ghost Pay vault...

# Settle back to Bitcoin
$ ghost-light-wallet settle 0.05 bc1q...
Settlement initiated. ~10 min for confirmation.
```

### Interactive Mode

Run `ghost-light-wallet` without arguments to enter interactive TUI mode. Navigate with arrow keys, select with Enter.

## Desktop GUI

### Ghost Wallet Desktop

A native desktop application with a modern interface. Built with Tauri for small size and native performance.

- Native UI
- macOS / Windows / Linux
- QR codes
- Address book

### Features

- **One-click install** — Download, install, run
- **Visual transaction history** — See all payments with details
- **QR code scanning** — Use your webcam to scan addresses
- **Contact management** — Save frequently used addresses
- **Multi-wallet support** — Manage multiple wallets
- **Dark/light themes** — Match your system preferences

### Security

- Keys encrypted at rest with your password
- Optional hardware wallet integration
- Automatic lock after inactivity
- No telemetry or analytics

## Ghost Tap (Mobile)

### Ghost Tap

Mobile wallet with NFC tap-to-pay. Pay at supported merchants by tapping your phone. [Learn more →](/ghost-tap.html)

- iOS
- Android
- NFC payments
- Biometric auth

### NFC Payments

Ghost Tap uses NFC (Near Field Communication) for tap-to-pay:

1. Merchant displays amount on their terminal
2. You tap your phone to the terminal
3. Authenticate with Face ID / fingerprint
4. Payment confirms in ~10 seconds

### Security Model

- **Secure Enclave (iOS)** — Keys never leave secure hardware
- **StrongBox (Android)** — Hardware-backed key storage
- **Biometric required** — Every payment needs authentication
- **Spending limits** — Set daily/per-transaction limits

:::warning Hot Wallet Warning
Ghost Tap is a hot wallet designed for spending money, not storing savings. Keep only what you need for daily spending. Use cold storage for larger amounts.
:::

## Hardware Wallets

### Hardware Support

Use your existing hardware wallet for Ghost payments. Keys never leave the device.

- Coldcard
- Ledger
- Trezor
- Air-gapped

### Supported Devices

| Device | Connection | Status |
| --- | --- | --- |
| Coldcard Mk4 | USB, SD card (air-gapped) | Planned |
| Ledger Nano S/X | USB, Bluetooth | Planned |
| Trezor Model T/One | USB | Planned |
| SeedSigner | QR codes (air-gapped) | Planned |

### How It Works

1. Connect hardware wallet to Ghost Wallet (desktop or CLI)
2. Ghost Wallet prepares the transaction
3. Hardware wallet displays and signs
4. Signed transaction broadcast to network

Your private keys never leave the hardware device.

## Comparison

| Feature | TUI CLI | Desktop | Ghost Tap | Hardware |
| --- | --- | --- | --- | --- |
| Ghost Pay | ✓ | ✓ | ✓ | ✓ |
| Silent Payments | ✓ | ✓ | ✓ | ✓ |
| NFC Tap-to-Pay | — | — | ✓ | — |
| Air-gapped | — | — | — | ✓ |
| SSH-friendly | ✓ | — | — | — |
| Scriptable | ✓ | — | — | — |
| Best for | Servers | Daily use | Spending | Savings |

:::info Recommendation
Most users should use **Desktop GUI** for everyday payments, **Hardware wallet** for savings, and optionally **Ghost Tap** for mobile spending money.
:::
