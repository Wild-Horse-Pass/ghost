# Light Wallet Guide

The Bitcoin Ghost Light Wallet provides full wallet functionality without running a full node. Your private keys stay on your device while a GSP (Ghost Service Provider) handles blockchain queries.

## Overview

| Aspect | Details |
|--------|---------|
| **Type** | SPV-style light client |
| **Storage** | ~50MB local cache |
| **Memory** | ~50MB RAM |
| **Sync Time** | Instant (no blockchain download) |
| **Interfaces** | CLI and TUI available |
| **Key Storage** | Encrypted locally (scrypt + ChaCha20) |
| **Network** | WebSocket connection to GSP |

## Prerequisites

- 64-bit Linux, macOS, or Windows
- Internet connection
- Access to a GSP server (public or self-hosted)

## Installation

### From Binary Release

```bash
# Download the latest release
curl -LO https://github.com/bitcoin-ghost/ghost/releases/latest/download/ghost-light-wallet-cli-linux-x64.tar.gz

# Extract
tar -xzf ghost-light-wallet-cli-linux-x64.tar.gz

# Move to PATH
sudo mv ghost-light-wallet-cli /usr/local/bin/

# Verify installation
ghost-light-wallet-cli --version
```

### From Source

```bash
# Clone repository
git clone https://github.com/bitcoin-ghost/ghost.git
cd bitcoin-ghost

# Build light wallet CLI
cargo build --release -p ghost-light-wallet-cli

# Binary at: target/release/ghost-light-wallet-cli

# Or build TUI version
cargo build --release -p ghost-light-wallet-tui
```

## Quick Start

### 1. Create a New Wallet

```bash
# Create wallet with new mnemonic
ghost-light-wallet-cli create

# You'll be prompted for:
# - Wallet name
# - Password (encrypts your keys)
# - Network (mainnet/signet/regtest)

# IMPORTANT: Write down your 24-word mnemonic!
# This is your only backup - store it securely.
```

### 2. Connect to a GSP

```bash
# Connect to a public GSP
ghost-light-wallet-cli connect --gsp wss://gsp.ghostnetwork.io

# Or use a local GSP (if running your own)
ghost-light-wallet-cli connect --gsp ws://localhost:8900/gsp/ws/v1
```

### 3. Check Your Balance

```bash
ghost-light-wallet-cli balance

# Output:
# Confirmed: 0.00000000 BTC
# Unconfirmed: 0.00000000 BTC
# Ghost Locks: 0
```

### 4. Get Your Ghost ID (Receive Address)

```bash
ghost-light-wallet-cli receive

# Output:
# Your Ghost ID: ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
#
# Share this ID to receive payments.
# Each payment generates a unique on-chain address.
```

### 5. Send a Payment

```bash
# Send to a Ghost ID
ghost-light-wallet-cli send --to ghost1abc... --amount 0.001

# Send to a standard Bitcoin address
ghost-light-wallet-cli send --to bc1q... --amount 0.001

# Send with custom fee rate
ghost-light-wallet-cli send --to ghost1abc... --amount 0.001 --fee-rate 5
```

## TUI (Terminal User Interface)

For an interactive experience, use the TUI wallet:

```bash
ghost-light-wallet-tui
```

### TUI Features

- Live balance updates
- Transaction history view
- QR code generation for Ghost ID
- Interactive send/receive dialogs
- GSP connection status
- Real-time payment notifications

### TUI Navigation

| Key | Action |
|-----|--------|
| `Tab` | Switch panels |
| `↑/↓` | Navigate lists |
| `Enter` | Select/Confirm |
| `s` | Send payment |
| `r` | Show receive address |
| `q` | Quit |
| `?` | Help |

## Configuration

### Config File Location

```
~/.ghost-wallet/config.toml
```

### Configuration Options

```toml
# Network selection
network = "mainnet"  # mainnet, signet, or regtest

# GSP connections (failover order)
[[gsp]]
url = "wss://gsp.ghostnetwork.io"
priority = 1

[[gsp]]
url = "wss://gsp2.ghostnetwork.io"
priority = 2

# Local settings
[wallet]
auto_connect = true
show_notifications = true
default_fee_rate = 3  # sat/vB

# Privacy settings
[privacy]
tor_proxy = "socks5://127.0.0.1:9050"  # Optional Tor support
```

### Environment Variables

```bash
# Override GSP URL
export GHOST_GSP_URL="wss://my-gsp.example.com"

# Set network
export GHOST_NETWORK="signet"

# Enable debug logging
export RUST_LOG="ghost_light_wallet=debug"
```

## Wallet Management

### Import Existing Wallet

```bash
# From mnemonic
ghost-light-wallet-cli import --mnemonic

# You'll be prompted to enter your 24-word phrase
```

### Export Mnemonic (Backup)

```bash
# Display mnemonic (requires password)
ghost-light-wallet-cli export-mnemonic
```

### List Wallets

```bash
ghost-light-wallet-cli list-wallets
```

### Switch Wallet

```bash
ghost-light-wallet-cli use-wallet my-wallet-name
```

### Delete Wallet

```bash
ghost-light-wallet-cli delete-wallet my-wallet-name
```

## Ghost Locks

Ghost Locks are timelocked UTXOs that provide privacy through standard denominations.

### Create a Ghost Lock

```bash
# Create a small lock (1M sats, 6-month recovery)
ghost-light-wallet-cli lock --amount small --timelock 6m

# Denomination options:
#   micro  = 10,000 sats
#   tiny   = 100,000 sats
#   small  = 1,000,000 sats
#   medium = 10,000,000 sats
#   large  = 100,000,000 sats
#   xl     = 1,000,000,000 sats

# Timelock options: 6m, 1y, 2y
```

### List Ghost Locks

```bash
ghost-light-wallet-cli locks

# Output:
# ID              | Amount   | Timelock | Expires
# ────────────────┼──────────┼──────────┼─────────────
# abc123...       | 1M sats  | 6 months | 2025-07-28
# def456...       | 10M sats | 1 year   | 2026-01-28
```

### Spend a Ghost Lock

```bash
# Spend by lock ID
ghost-light-wallet-cli unlock abc123... --to ghost1xyz...
```

## Ghost Pay (L2)

Send instant, low-fee payments via the Ghost Pay L2 network.

### L2 Balance

```bash
ghost-light-wallet-cli l2-balance

# Output:
# L2 Available: 0.05000000 BTC
# L2 Pending:   0.00100000 BTC
```

### L2 Send

```bash
ghost-light-wallet-cli l2-send --to ghost1abc... --amount 0.001
```

### L2 Deposit (L1 → L2)

```bash
ghost-light-wallet-cli l2-deposit --amount 0.01
```

### L2 Withdraw (L2 → L1)

```bash
ghost-light-wallet-cli l2-withdraw --amount 0.01
```

## Instant Payments

For small payments (~$100 or less), merchants can show "Confirmed" immediately using optimistic confirmation.

### Check Instant Capability

```bash
# Check if a lock can do instant payments
ghost-light-wallet-cli instant-check --lock lock_abc123

# Output:
# Lock: lock_abc123
# Instant Capable: Yes
# Max Instant: 100,000 sats
# Confidence: 0.95
# Valid Until Block: 847200
```

### Accept Instant Payment (Merchant)

```bash
# Accept an instant payment from a customer
ghost-light-wallet-cli instant-accept --from lock_abc123 --amount 5000

# Output:
# ✓ Instant Payment Accepted
# Payment ID: 0x1234abcd...
# Amount: 5,000 sats
# Confidence: 0.97
# Settlement Block: 847201
#
# Show customer: "Confirmed ✓"
```

### Instant Payment Limits

| Lock Type | Max Instant |
|-----------|-------------|
| Micro | 10,000 sats |
| Tiny+ | 100,000 sats |

### Monitor Lock State

Subscribe to real-time lock state updates for instant payment monitoring:

```bash
# Subscribe to lock state changes
ghost-light-wallet-cli subscribe-lock --lock lock_abc123

# Output (real-time updates):
# [12:00:01] Balance: 500,000 sats | Confirmations: 50 | Instant: Yes (max 100k)
# [12:00:11] Balance: 495,000 sats | Confirmations: 50 | Instant: Yes (max 100k)
# [12:00:21] Pending L2: 5,000 sats | Instant: No (pending payment)
```

### When to Use Instant Payments

| Scenario | Recommendation |
|----------|----------------|
| Coffee shop (<$10) | Use instant |
| Retail (<$100) | Use instant |
| Large purchases (>$100) | Wait for confirmation |
| High-value goods | Wait for L1 settlement |

## Transaction History

```bash
# Show recent transactions
ghost-light-wallet-cli history

# Show all transactions
ghost-light-wallet-cli history --all

# Filter by type
ghost-light-wallet-cli history --type received
ghost-light-wallet-cli history --type sent
ghost-light-wallet-cli history --type l2
```

## Privacy Features

### BIP-157/158 Compact Block Filters

The light wallet uses compact block filters for privacy-preserving balance queries:

1. **Download filters** from GSP (small, ~4MB/year)
2. **Scan locally** to find potential matches
3. **Request only matching blocks** from GSP
4. **Extract transactions locally**

The GSP never knows which addresses belong to your wallet.

### Tor Support

```bash
# Enable Tor for GSP connections
ghost-light-wallet-cli --tor connect --gsp wss://gsp.ghostnetwork.io
```

### Multi-GSP Failover

Configure multiple GSPs for resilience and privacy:

```toml
# In config.toml
[[gsp]]
url = "wss://gsp1.example.com"
priority = 1

[[gsp]]
url = "wss://gsp2.example.com"
priority = 2

[[gsp]]
url = "wss://gsp3.example.com"
priority = 3
```

## Security Best Practices

### DO:
- Write down your 24-word mnemonic and store it securely
- Use a strong, unique password for wallet encryption
- Verify GSP connection is using TLS (wss://)
- Keep your wallet software updated
- Use Tor for additional privacy if needed

### DON'T:
- Share your mnemonic with anyone
- Store your mnemonic digitally (photos, cloud storage)
- Use public WiFi without Tor/VPN
- Connect to untrusted GSP servers
- Ignore software update notifications

## Troubleshooting

### Connection Issues

```bash
# Check GSP connectivity
ghost-light-wallet-cli ping --gsp wss://gsp.ghostnetwork.io

# Try alternative GSP
ghost-light-wallet-cli connect --gsp wss://gsp2.ghostnetwork.io

# Check logs
RUST_LOG=debug ghost-light-wallet-cli connect
```

### Balance Not Updating

```bash
# Force rescan
ghost-light-wallet-cli rescan

# Check GSP sync status
ghost-light-wallet-cli gsp-status
```

### Transaction Stuck

```bash
# Check transaction status
ghost-light-wallet-cli tx-status <txid>

# Bump fee (RBF)
ghost-light-wallet-cli bump-fee <txid> --new-rate 10
```

### Forgot Password

If you forget your wallet password:

1. You'll need your 24-word mnemonic backup
2. Delete the encrypted wallet file
3. Import from mnemonic with a new password

```bash
# Remove old wallet
rm -rf ~/.ghost-wallet/wallets/my-wallet

# Re-import from mnemonic
ghost-light-wallet-cli import --mnemonic
```

## CLI Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--wallet <name>` | Use specific wallet |
| `--network <net>` | Network (mainnet/signet/regtest) |
| `--gsp <url>` | GSP server URL |
| `--tor` | Route through Tor |
| `--config <path>` | Config file path |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Suppress output |

### Commands

| Command | Description |
|---------|-------------|
| `create` | Create new wallet |
| `import` | Import from mnemonic |
| `connect` | Connect to GSP |
| `disconnect` | Disconnect from GSP |
| `balance` | Show balance |
| `receive` | Show Ghost ID |
| `send` | Send payment |
| `history` | Transaction history |
| `lock` | Create Ghost Lock |
| `unlock` | Spend Ghost Lock |
| `locks` | List Ghost Locks |
| `l2-balance` | L2 balance |
| `l2-send` | L2 payment |
| `l2-deposit` | Move to L2 |
| `l2-withdraw` | Move to L1 |
| `rescan` | Rescan for transactions |
| `export-mnemonic` | Show backup phrase |
| `gsp-status` | GSP connection info |

## Appendix: Ghost ID Format

Ghost IDs use bech32 encoding with the `ghost1` prefix:

```
ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
       └─────────────────────────────────┘
                  66 characters
```

Components:
- **Scan Public Key** (33 bytes): Used to detect incoming payments
- **Spend Public Key** (33 bytes): Used to authorize spending

When someone sends to your Ghost ID, they generate a unique one-time address using ECDH, ensuring each payment looks different on-chain.
