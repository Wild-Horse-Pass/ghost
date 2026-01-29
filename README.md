# Bitcoin Ghost v1.4

> **NOT READY FOR MAINNET** - This software is currently in development and testing. Use signet or regtest only. Mainnet use is not recommended at this time.

---

## What is Bitcoin Ghost?

**Bitcoin Ghost** is a **full-stack Bitcoin node derivative** that extends Bitcoin Core with privacy-preserving features, decentralized mining pool infrastructure, and instant payment capabilities. It's not just a mining pool - it's a complete ecosystem for running, incentivizing, and monetizing Bitcoin infrastructure.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          BITCOIN GHOST ECOSYSTEM                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────────┐                    ┌──────────────────┐              │
│   │   GHOST CORE     │◄──────────────────►│    GHOST NODE    │              │
│   │  Bitcoin Fork    │   RPC/ZMQ          │  Enhanced Node   │              │
│   │  + Ghost Features│                    │  + Verification  │              │
│   └────────┬─────────┘                    └────────┬─────────┘              │
│            │                                       │                         │
│            ▼                                       ▼                         │
│   ┌────────────────────────────────────────────────────────────┐            │
│   │                    MINING INFRASTRUCTURE                    │            │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │            │
│   │  │ GHOST POOL   │  │ COORDINATOR  │  │   TRANSLATOR     │  │            │
│   │  │ Decentralized│  │ Fire Ping LB │  │   SV1 ↔ SV2      │  │            │
│   │  │ Mining Pool  │  │              │  │                  │  │            │
│   │  └──────────────┘  └──────────────┘  └──────────────────┘  │            │
│   └────────────────────────────────────────────────────────────┘            │
│                              │                                               │
│                              ▼                                               │
│   ┌────────────────────────────────────────────────────────────┐            │
│   │                    PAYMENT LAYER (L2)                       │            │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │            │
│   │  │  GHOST PAY   │  │ GHOST LOCKS  │  │  WRAITH PROTOCOL │  │            │
│   │  │ Instant      │  │ Timelocked   │  │  CoinJoin        │  │            │
│   │  │ Payments     │  │ Recovery     │  │  Mixing          │  │            │
│   │  └──────────────┘  └──────────────┘  └──────────────────┘  │            │
│   └────────────────────────────────────────────────────────────┘            │
│                              │                                               │
│                              ▼                                               │
│   ┌────────────────────────────────────────────────────────────┐            │
│   │                    WALLET ECOSYSTEM                         │            │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │            │
│   │  │ FULL WALLET  │  │ LIGHT WALLET │  │      GSP         │  │            │
│   │  │ Qt Desktop   │  │ CLI / TUI    │  │ Service Provider │  │            │
│   │  └──────────────┘  └──────────────┘  └──────────────────┘  │            │
│   └────────────────────────────────────────────────────────────┘            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Features

### Full-Stack Bitcoin Node

| Feature | Description |
|---------|-------------|
| **Ghost Core** | Bitcoin Core fork with Silent Payments, enhanced RPC, and native Ghost protocol support |
| **Ghost Node** | Verification layer for node runner incentives with challenge-response proofs |
| **Silent Payments** | BIP-352 implementation for receiver address privacy |

### Decentralized Mining Pool

| Feature | Description |
|---------|-------------|
| **Stratum V2** | Modern mining protocol with improved security, efficiency, and job negotiation |
| **67% BFT Consensus** | Byzantine fault-tolerant payout agreement - no single point of failure |
| **BUDS Classification** | Transaction filtering based on Bitcoin Use-case Differentiation System |
| **Fire Ping Load Balancing** | Latency-aware routing to optimal pool nodes |

### Fast, Safe & Private Payments

| Feature | Description |
|---------|-------------|
| **Ghost Pay L2** | Instant off-chain payments with periodic L1 settlement |
| **Ghost Keys** | Silent Payment-style addresses - share once, receive unlimited times privately |
| **Ghost Locks** | P2TR outputs with timelocked recovery paths - your funds are always safe |
| **Wraith Protocol** | Two-phase CoinJoin mixing for transaction graph obfuscation |

### Node Runner Incentives

| Feature | Description |
|---------|-------------|
| **Verification Rewards** | Earn by proving you're running a valid node |
| **Challenge-Response** | Cryptographic proofs of block data |
| **Stake Weight** | Higher participation = higher rewards |
| **Pool Revenue Share** | Node operators share in pool profits |

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CORE LIBRARIES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │ ghost-common  │ │ghost-consensus│ │ghost-accounting│ │ ghost-storage │   │
│  │ Config, Types │ │ BFT Engine    │ │ Shares, Payouts│ │ SQLite Layer  │   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
│                                                                              │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │  ghost-buds   │ │ ghost-policy  │ │ghost-template │ │ghost-verific- │   │
│  │ Tx Classif.   │ │ Mining Rules  │ │ Block Builder │ │ ation HTTP API│   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
│                                                                              │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │  ghost-keys   │ │ ghost-locks   │ │wraith-protocol│ │ ghost-gsp     │   │
│  │ Silent Pays   │ │ Timelock UTXO │ │ CoinJoin Mix  │ │ Light Wallet  │   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Binary Applications

| Binary | Description |
|--------|-------------|
| `ghost-node` | Full Bitcoin node with Ghost enhancements |
| `ghost-qt` | Desktop wallet with full node (Qt GUI) |
| `ghost-pool` | Decentralized mining pool node |
| `ghost-coordinator` | Load balancer with Fire Ping latency measurement |
| `ghost-pay` | L2 payment node for instant off-chain transfers |
| `ghost-gsp` | Ghost Service Provider for light wallets |
| `ghost-cli` | Administration CLI for pool management |
| `ghost-wallet-cli` | Command-line wallet |
| `ghost-wallet-tui` | Terminal UI wallet |
| `ghost-light-wallet` | Lightweight wallet (connects to GSP) |
| `translator` | SV1 to SV2 protocol bridge for legacy miners |

## Quick Start

### Prerequisites

- Rust (stable toolchain)
- Bitcoin Core or Ghost Core
- SQLite 3.35+

### Build

```bash
# Clone repository
git clone https://github.com/bitcoin-ghost-v1.4/ghost.git
cd ghost

# Build all binaries
cargo build --release

# Run tests
cargo test --workspace
```

### Run a Full Node

```bash
# Start Ghost Core (Bitcoin fork)
./ghost-core/bin/ghostd -signet

# Or start the enhanced node
./target/release/ghost-node --network signet --rpc-url http://127.0.0.1:38332
```

### Run a Mining Pool Node

```bash
# Generate node identity
./target/release/ghost-cli key generate --output ~/.ghost/node.key

# Start the pool node
./target/release/ghost-pool --config examples/ghost.toml

# Check status
./target/release/ghost-cli status
```

### Run a Light Wallet

```bash
# Initialize wallet
./target/release/ghost-wallet-cli init

# Check balance
./target/release/ghost-wallet-cli balance --refresh

# Receive address
./target/release/ghost-wallet-cli receive

# Send payment
./target/release/ghost-wallet-cli send <recipient> <amount>
```

### Docker Deployment

```bash
cd docker
cp .env.example .env
# Edit .env with your settings

# Start full stack
docker-compose up -d

# Start with monitoring
docker-compose --profile monitoring up -d
```

## Configuration

See `examples/ghost.toml` for a complete configuration example.

Key settings:

```toml
[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = 38332      # Signet
network = "signet"

[network]
sv2_port = 34255      # Stratum V2 miners
sv1_port = 3333       # Stratum V1 (via translator)
http_port = 8080      # API

[pool]
treasury_address = "tb1q..."
treasury_fee_percent = 1.0

[policy]
profile = "permissive"  # bitcoin_pure, permissive, full_open

[verification]
enabled = true
reward_pool_sats = 100000000  # 1 BTC daily reward pool
```

## BUDS Policy Tiers

The **Bitcoin Use-case Differentiation System** classifies transactions:

| Tier | Description | Examples |
|------|-------------|----------|
| **T0** | Core financial | Standard payments, consolidations |
| **T1** | Extended financial | Multisig, timelocks, HTLCs |
| **T2** | Data anchoring | Small OP_RETURN (<80 bytes) |
| **T3** | Heavy data | Inscriptions, large witness data |

Policy profiles:
- `bitcoin_pure` - T0 only (financial transactions)
- `permissive` - T0 + T1 + T2 (default)
- `full_open` - All tiers allowed

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 34255 | TCP | Stratum V2 miners |
| 3333 | TCP | Stratum V1 miners |
| 8080 | TCP | HTTP API |
| 8555-8562 | TCP | P2P consensus mesh |
| 8900 | TCP | GSP WebSocket |
| 8800 | TCP | Ghost Pay API |

## Documentation

### Getting Started
- [Wallet Overview](docs/wallets/README.md) - Choose the right wallet
- [Light Wallet](docs/wallets/LIGHT_WALLET.md) - Quick setup, minimal resources
- [Full Node Wallet](docs/wallets/FULL_NODE_WALLET.md) - Maximum privacy and control

### Protocol Documentation
- [Ghost Keys](docs/protocols/GHOST_KEYS.md) - Silent Payment addresses
- [Ghost Locks](docs/protocols/GHOST_LOCKS.md) - Timelocked recovery outputs
- [Ghost Pay](docs/protocols/GHOST_PAY.md) - L2 payment network
- [Wraith Protocol](docs/protocols/WRAITH_PROTOCOL.md) - CoinJoin mixing

### API Reference
- [RPC Commands](docs/RPC_COMMANDS.md) - Full RPC documentation
- [API Endpoints](docs/API_ENDPOINTS.md) - HTTP API reference

### Operations
- [Deployment Runbook](docs/DEPLOYMENT_RUNBOOK.md) - Production deployment
- [Security Audit](docs/SECURITY_AUDIT.md) - Security review
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues

## Project Structure

```
ghost/
├── ghost-core/        # Bitcoin Core fork with Ghost features
├── crates/            # Library crates
│   ├── ghost-common/      # Shared types, config, identity
│   ├── ghost-buds/        # Transaction classification
│   ├── ghost-policy/      # Mining policy enforcement
│   ├── ghost-storage/     # SQLite database layer
│   ├── ghost-consensus/   # BFT consensus engine
│   ├── ghost-accounting/  # Share tracking, payouts
│   ├── ghost-verification/# HTTP API, node verification
│   ├── ghost-template/    # Block template construction
│   ├── ghost-keys/        # Silent Payment keys
│   ├── ghost-locks/       # Timelocked P2TR outputs
│   ├── ghost-gsp/         # Light wallet server
│   ├── ghost-gsp-proto/   # GSP protocol definitions
│   ├── ghost-light-wallet/# Light wallet library
│   ├── wraith-protocol/   # CoinJoin mixing
│   └── ghost-reconciliation/ # L1 settlement
├── bins/              # Binary applications
│   ├── ghost-node/        # Enhanced full node
│   ├── ghost-qt/          # Desktop wallet (Qt)
│   ├── ghost-pool/        # Mining pool node
│   ├── ghost-coordinator/ # Load balancer
│   ├── ghost-pay/         # L2 payment node
│   ├── ghost-gsp/         # GSP server
│   ├── ghost-cli/         # Admin CLI
│   ├── ghost-wallet-cli/  # Command-line wallet
│   ├── ghost-wallet-tui/  # Terminal UI wallet
│   ├── ghost-light-wallet-cli/ # Light wallet CLI
│   ├── ghost-light-wallet-tui/ # Light wallet TUI
│   └── translator/        # SV1↔SV2 bridge
├── docker/            # Docker deployment
├── docs/              # Documentation
├── examples/          # Example configurations
└── tests/             # Integration tests
```

## Why Bitcoin Ghost?

### For Node Operators
- **Earn rewards** for running a full node through verification challenges
- **Share in pool revenue** as a decentralized pool operator
- **Support the network** while being compensated

### For Miners
- **Decentralized pool** - no single point of failure
- **Fair payouts** - BFT consensus ensures accurate share tracking
- **Modern protocol** - Stratum V2 with full job negotiation

### For Users
- **Privacy-first** - Silent Payments, CoinJoin, and off-chain transactions
- **Instant payments** - L2 layer for immediate transfers
- **Self-custodial** - Ghost Locks ensure you always control your funds

## Development

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p ghost-consensus

# Integration tests
cargo test --test integration
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Lint
cargo clippy --all-targets --all-features

# Check documentation
cargo doc --no-deps --workspace
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## Security

For security issues, please email security@bitcoinghost.org or see [SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).

---

> **Remember:** This software is not yet production-ready. Test on signet before considering mainnet deployment.
