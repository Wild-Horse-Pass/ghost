# Bitcoin Ghost Wallets

Bitcoin Ghost offers multiple wallet options to suit different user needs, from lightweight mobile-friendly wallets to full-node self-custody solutions.

## Wallet Comparison

| Feature | Light Wallet | Full Node Wallet |
|---------|--------------|------------------|
| **Blockchain Storage** | None (uses GSP) | Full chain (~500GB+) |
| **Setup Time** | Instant | Hours (initial sync) |
| **Privacy** | High (keys local, GSP sees queries) | Maximum (fully local) |
| **Resource Usage** | Minimal (~50MB RAM) | Heavy (~2GB+ RAM, SSD) |
| **Internet Required** | Yes (GSP connection) | Yes (P2P network) |
| **Self-Custody** | Yes (keys never leave device) | Yes (full control) |
| **Ghost Keys** | Supported | Supported |
| **Ghost Locks** | Supported | Supported |
| **Ghost Pay (L2)** | Via GSP | Direct |

## Quick Links

- **[Light Wallet Guide](./LIGHT_WALLET.md)** - Best for most users. Fast setup, minimal resources.
- **[Full Node Wallet Guide](./FULL_NODE_WALLET.md)** - Maximum privacy and decentralization.
- **[GSP Server Guide](./GSP_SERVER.md)** - Run your own light wallet server.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           WALLET OPTIONS                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  LIGHT WALLETS                         FULL NODE WALLET                  │
│  ┌──────────────┐ ┌──────────────┐    ┌──────────────────────────────┐  │
│  │ CLI Wallet   │ │ TUI Wallet   │    │        ghostd                 │  │
│  │              │ │              │    │  ┌─────────┐  ┌────────────┐ │  │
│  │ Commands:    │ │ Interactive  │    │  │ Wallet  │  │ Full Chain │ │  │
│  │ - send       │ │ Dashboard    │    │  │ Module  │  │ Validation │ │  │
│  │ - receive    │ │              │    │  └─────────┘  └────────────┘ │  │
│  │ - balance    │ │              │    └──────────────────────────────┘  │
│  └──────┬───────┘ └──────┬───────┘                  │                   │
│         │                │                          │                   │
│         └────────┬───────┘                          │                   │
│                  │ WebSocket                        │ Local             │
│                  ▼                                  ▼                   │
│         ┌────────────────┐                ┌────────────────┐           │
│         │   GSP Server   │◄───────────────│   P2P Network  │           │
│         │  (Light Wallet │                │                │           │
│         │   Backend)     │                │                │           │
│         └────────────────┘                └────────────────┘           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Which Wallet Should I Use?

### Choose Light Wallet If:
- You want quick setup (under 1 minute)
- You have limited storage or computing power
- You're comfortable trusting a GSP server for balance queries
- You want to use Ghost on mobile or low-power devices

### Choose Full Node Wallet If:
- You want maximum privacy and decentralization
- You have 500GB+ storage and a reliable computer
- You want to support the network by running a full node
- You need to operate without depending on third-party servers

## Security Model

### Light Wallet Security
- **Private keys NEVER leave your device**
- All signing happens locally
- GSP only sees your public key and balance queries
- Encrypted local storage (scrypt + ChaCha20)
- BIP-39 mnemonic backup supported

### Full Node Wallet Security
- Complete blockchain validation
- No external dependencies for chain data
- Keys stored in local wallet database
- Full transaction history available locally

## Common Features

All Bitcoin Ghost wallets support:

1. **Ghost Keys (BIP-352 Silent Payments)**
   - Single address, unlimited unique payment destinations
   - Format: `ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...`

2. **Ghost Locks (Timelocked Recovery)**
   - Standard denominations for privacy
   - Automatic recovery after timelock expires
   - Key rotation for enhanced security

3. **Ghost Pay (L2 Payments)**
   - Instant, low-fee transactions
   - Settled to L1 in batches

## Getting Started

1. **New Users**: Start with the [Light Wallet Guide](./LIGHT_WALLET.md)
2. **Power Users**: See the [Full Node Wallet Guide](./FULL_NODE_WALLET.md)
3. **Node Operators**: Check the [GSP Server Guide](./GSP_SERVER.md)
