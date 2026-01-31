# Bitcoin Ghost Documentation

Complete documentation for the Bitcoin Ghost network - a privacy-focused Bitcoin Layer 2 with integrated mining coordination.

## Quick Navigation

### Getting Started

| Document | Description |
|----------|-------------|
| [Getting Started](./protocols/GETTING_STARTED.md) | Quick start guide for new users |
| [Wallet Overview](./wallets/README.md) | Choose the right wallet for you |
| [Deployment Runbook](./DEPLOYMENT_RUNBOOK.md) | Production deployment guide |

### Wallet Guides

| Guide | Description |
|-------|-------------|
| [Light Wallet](./wallets/LIGHT_WALLET.md) | Quick setup, minimal resources, GSP-connected |
| [Full Node Wallet](./wallets/FULL_NODE_WALLET.md) | Maximum privacy with local blockchain |
| [GSP Server](./wallets/GSP_SERVER.md) | Run your own light wallet server |

### Protocol Documentation

| Protocol | Description |
|----------|-------------|
| [Architecture](./protocols/ARCHITECTURE.md) | System design overview |
| [Ghost Keys](./protocols/GHOST_KEYS.md) | Silent Payment addresses (BIP-352) |
| [Ghost Locks](./protocols/GHOST_LOCKS.md) | Timelocked P2TR outputs |
| [Ghost Pay](./protocols/GHOST_PAY.md) | L2 payment network |
| [Wraith Protocol](./protocols/WRAITH_PROTOCOL.md) | CoinJoin mixing |
| [Reconciliation](./protocols/RECONCILIATION.md) | L1 settlement batches |
| [Consensus](./protocols/CONSENSUS.md) | BFT voting mechanism |
| [Mining Pool](./protocols/MINING_POOL.md) | Coordinated mining |

### Technical Reference

| Document | Description |
|----------|-------------|
| [Specification](./SPECIFICATION.md) | Complete technical specification |
| [Ghost Core Integration](./GHOST_CORE_INTEGRATION.md) | Bitcoin Core modifications |
| [Mining Load Balancing](./MINING_LOAD_BALANCING.md) | DNS-based miner routing and load distribution |
| [Security Audit](./SECURITY_AUDIT.md) | Security review and recommendations |
| [Testing Plan](./TESTING_PLAN.md) | Test strategy and coverage |
| [Troubleshooting](./TROUBLESHOOTING.md) | Common issues and solutions |

### Additional Protocols

| Protocol | Description |
|----------|-------------|
| [BUDS Policy](./protocols/BUDS_POLICY.md) | Transaction classification |
| [Economics](./protocols/ECONOMICS.md) | Economic model and incentives |
| [Node Capabilities](./protocols/NODE_CAPABILITIES.md) | Feature matrix |
| [ZK Proofs](./protocols/ZK_PROOFS.md) | Zero-knowledge proof usage |
| [Pruning](./protocols/PRUNING.md) | Chain pruning strategy |
| [Jump Locks](./protocols/JUMP_LOCKS.md) | Key rotation mechanism |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        BITCOIN GHOST NETWORK                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  USER LAYER                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │  Light Wallet   │  │  Full Node      │  │   Mining        │         │
│  │  (CLI/TUI)      │  │  Wallet         │  │   Dashboard     │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                     │                  │
│  SERVICE LAYER                 │                     │                  │
│  ┌────────┴────────┐           │           ┌────────┴────────┐         │
│  │   GSP Server    │           │           │   Ghost Pool    │         │
│  │  (Light Wallet  │           │           │  (Mining Coord) │         │
│  │   Backend)      │           │           │                 │         │
│  └────────┬────────┘           │           └────────┬────────┘         │
│           │                    │                     │                  │
│  PROTOCOL LAYER               │                     │                  │
│  ┌────────┴────────────────────┴─────────────────────┴────────┐        │
│  │                       ghost-core (ghostd)                   │        │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │        │
│  │  │ Ghost    │  │ Ghost    │  │ Wraith   │  │ Reconcil-│   │        │
│  │  │ Keys     │  │ Locks    │  │ Protocol │  │ iation   │   │        │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │        │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │        │
│  │  │ BIP-157  │  │ P2P      │  │ Mempool  │  │ Chain    │   │        │
│  │  │ Filters  │  │ Network  │  │          │  │ Validation│   │        │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │        │
│  └────────────────────────────────────────────────────────────┘        │
│                                  │                                      │
│  BLOCKCHAIN LAYER               │                                      │
│  ┌──────────────────────────────┴─────────────────────────────┐        │
│  │                      Bitcoin Blockchain                     │        │
│  │  (Ghost transactions anchored via OP_RETURN metadata)       │        │
│  └─────────────────────────────────────────────────────────────┘        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Ghost Keys (Silent Payments)

Privacy-preserving addresses using BIP-352:
- Single reusable address (Ghost ID)
- Each payment creates unique on-chain address
- Sender uses ECDH to derive payment address
- Receiver scans chain to detect payments

Format: `ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...`

### Ghost Locks

Timelocked UTXOs with standard denominations:
- Key path: Normal spending (efficient)
- Script path: Recovery after timelock (safety)
- Standard amounts: 10K to 1B sats
- Timelock options: 6 months, 1 year, 2 years

### Ghost Pay (L2)

Instant, low-fee payments:
- Off-chain transactions between participants
- Periodic L1 settlement batches
- Atomic swaps for trustless exchange

### Wraith Protocol

CoinJoin-style mixing:
- Multiple participants combine transactions
- Blind signatures prevent coordinator tracking
- Standard denominations for anonymity set

## Network Participants

| Role | Description | Requirements |
|------|-------------|--------------|
| **Light Wallet User** | End user with minimal setup | Internet, GSP access |
| **Full Node Operator** | Self-sovereign user | 500GB+ storage, bandwidth |
| **GSP Provider** | Serves light wallets | Full node, public endpoint |
| **Pool Operator** | Mining coordination | Full node, Ghost Pool |
| **Miner** | Block production | Mining hardware, pool connection |

## Development Resources

### Building from Source

```bash
git clone https://github.com/anthropics/bitcoin-ghost.git
cd bitcoin-ghost

# Build Rust crates
cargo build --release

# Build ghost-core (C++)
cd ghost-core
./autogen.sh
./configure
make -j$(nproc)
```

### Project Structure

```
bitcoin-ghost/
├── crates/                 # Rust libraries
│   ├── ghost-common/      # Shared utilities
│   ├── ghost-keys/        # BIP-352 key derivation
│   ├── ghost-locks/       # Ghost Lock management
│   ├── ghost-light-wallet/ # Light wallet library
│   ├── ghost-gsp/         # GSP server library
│   └── ...
├── bins/                   # Rust binaries
│   ├── ghost-light-wallet-cli/
│   ├── ghost-light-wallet-tui/
│   ├── ghost-pool/        # Mining pool node
│   ├── ghost-registry/    # Pool load balancer registry
│   └── ...
├── ghost-core/            # Modified Bitcoin Core
└── docs/                  # Documentation
    ├── protocols/         # Protocol specs
    ├── wallets/           # Wallet guides
    └── ...
```

### Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## Support

- GitHub Issues: Bug reports and feature requests
- Documentation: This directory
- Community: [Discord/Forum links]
