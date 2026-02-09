# Bitcoin Ghost

<div align="center">

```
 ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░
 ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░
 ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░
      ░              ░
```

**Incentivized Bitcoin Nodes • Decentralized Mining • Private L2 Payments**

[![Build Status](https://github.com/bitcoin-ghost/ghost/actions/workflows/ci.yml/badge.svg)](https://github.com/bitcoin-ghost/ghost/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.7.1-green.svg)](Cargo.toml)

[Website](https://bitcoinghost.org) • [Documentation](docs/) • [Whitepaper](https://bitcoinghost.org/whitepaper)

</div>

---

## What is Bitcoin Ghost?

**Bitcoin Ghost** transforms Bitcoin node operation from an altruistic contribution into a compensated service. It is a complete ecosystem that:

- **Pays node operators** through cryptographic verification challenges
- **Decentralizes mining** across a network of pool operators using ZK-BFT consensus
- **Enables instant payments** via an L2 layer with sub-second finality
- **Preserves privacy** through Silent Payments, CoinJoin mixing, and off-chain transactions

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
│   │  ┌──────────────────────────┐  ┌──────────────────────┐    │            │
│   │  │       GHOST POOL         │  │     TRANSLATOR       │    │            │
│   │  │   Decentralized Mining   │  │     SV1 ↔ SV2        │    │            │
│   │  │         Pool             │  │                      │    │            │
│   │  └──────────────────────────┘  └──────────────────────┘    │            │
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

---

## Key Features

### Node Runner Incentives

| Feature | Description |
|---------|-------------|
| **Verification Rewards** | Earn Bitcoin by proving you run a valid full node |
| **5-4-3-2-1 Share System** | More capabilities = higher rewards (Archive +5, GhostPay +4, Mining +3, BitcoinPure +2, Elder +1) |
| **Challenge-Response Proofs** | Cryptographic verification of block data and node capabilities |
| **Pool Revenue Share** | Node operators share in mining pool profits |

### Decentralized Mining Pool

| Feature | Description |
|---------|-------------|
| **ZK-BFT Consensus** | Zero-knowledge proofs replace trust - validators verify proofs, never re-execute |
| **Stratum V2** | Modern mining protocol with improved security and job negotiation |
| **BUDS Classification** | Transaction filtering based on Bitcoin Use-case Differentiation System |
| **No Single Point of Failure** | Fully distributed pool with BFT fault tolerance |

### Private & Instant Payments

| Feature | Description |
|---------|-------------|
| **Ghost Pay L2** | Off-chain payments with sub-second finality and periodic L1 settlement |
| **Ghost Keys** | BIP-352 Silent Payments - share one address, receive unlimited payments privately |
| **Ghost Locks** | P2TR outputs with timelocked recovery - your funds are always recoverable |
| **Wraith Protocol** | Two-phase CoinJoin mixing for transaction graph privacy |

---

## Quick Start

### Prerequisites

- **Rust** 1.75+ (stable toolchain)
- **Bitcoin Core** 27.0+ or Ghost Core
- **SQLite** 3.35+
- **Linux/macOS** (Windows via WSL2)

### Installation

```bash
# Clone the repository
git clone https://github.com/bitcoin-ghost/ghost.git
cd ghost

# Initialize submodules
git submodule update --init --recursive

# Build all binaries (release mode)
cargo build --release

# Verify the build
cargo test --workspace
```

### Run a Full Node (Earn Rewards)

```bash
# 1. Start Ghost Core (Bitcoin fork with Ghost features)
./ghost-core/bin/ghostd -daemon

# 2. Generate your node identity
./target/release/ghost-cli key generate --output ~/.ghost/node.key

# 3. Start the Ghost node (connects to mining pool network)
./target/release/ghost-pool --config /etc/ghost/pool.toml

# 4. Check your node status and earnings
./target/release/ghost-cli status
```

### Run a Light Wallet (Send & Receive)

```bash
# Initialize a new wallet
./target/release/ghost-light-wallet-cli init

# Get your Silent Payment receive address
./target/release/ghost-light-wallet-cli receive

# Check balance
./target/release/ghost-light-wallet-cli balance --refresh

# Send a payment
./target/release/ghost-light-wallet-cli send <recipient_address> <amount_sats>
```

### Docker Deployment

```bash
cd docker
cp .env.example .env
# Edit .env with your configuration

# Start the full stack
docker-compose up -d

# Start with monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d
```

---

## Configuration

Create `/etc/ghost/pool.toml` (or use `examples/ghost.toml`):

```toml
[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = 8332          # Mainnet (38332 for signet)
rpc_user = "your_rpc_user"
rpc_password = "your_rpc_password"
network = "main"

[network]
sv2_port = 34255         # Stratum V2 miners
sv1_port = 3333          # Stratum V1 (via translator)
http_port = 8080         # REST API

[pool]
treasury_address = "bc1q..."
treasury_fee_percent = 1.0

[policy]
profile = "permissive"   # bitcoin_pure, permissive, full_open

[verification]
enabled = true
```

---

## Architecture

### Core Components

| Crate | Purpose |
|-------|---------|
| `ghost-common` | Shared types, configuration, node identity |
| `ghost-consensus` | ZK-BFT consensus engine, P2P mesh network |
| `ghost-accounting` | Share tracking, payout calculations |
| `ghost-verification` | Node capability verification, challenge system |
| `ghost-zkp` | Zero-knowledge proof generation and verification |
| `ghost-storage` | SQLite database layer with encrypted sensitive fields |

### Payment Layer

| Crate | Purpose |
|-------|---------|
| `ghost-keys` | BIP-352 Silent Payment key derivation |
| `ghost-locks` | P2TR timelocked recovery outputs |
| `ghost-pay` | L2 instant payment channels |
| `wraith-protocol` | CoinJoin mixing coordination |
| `ghost-reconciliation` | L1 settlement and on-chain finalization |

### Wallet Infrastructure

| Crate | Purpose |
|-------|---------|
| `ghost-gsp` | Ghost Service Provider for light wallets |
| `ghost-light-wallet` | Light wallet library (connects to GSP) |
| `ghost-gsp-proto` | WebSocket protocol for GSP communication |

### Binaries

| Binary | Purpose |
|--------|---------|
| `ghost-pool` | Main pool node - mining, consensus, payouts |
| `ghost-pay` | L2 payment server |
| `ghost-gsp` | Light wallet backend service |
| `translator` | SV1 to SV2 protocol bridge |
| `ghost-cli` | Administration and status CLI |
| `ghost-light-wallet-cli` | Command-line wallet |
| `ghost-light-wallet-tui` | Terminal UI wallet |

---

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 34255 | TCP | Stratum V2 miners |
| 3333 | TCP | Stratum V1 miners (via translator) |
| 8080 | HTTP | REST API |
| 8555-8562 | TCP | P2P consensus mesh |
| 8800 | HTTP | Ghost Pay L2 API |
| 8900 | WebSocket | GSP light wallet connections |

---

## BUDS Policy System

The **Bitcoin Use-case Differentiation System** classifies transactions into tiers:

| Tier | Category | Examples | Policy |
|------|----------|----------|--------|
| **T0** | Core Financial | Standard P2PKH/P2WPKH payments, consolidations | Always included |
| **T1** | Extended Financial | Multisig, timelocks, HTLCs, Lightning | Default included |
| **T2** | Data Anchoring | Small OP_RETURN (<80 bytes), commitments | Configurable |
| **T3** | Heavy Data | Inscriptions, large witness, stamps | Opt-in only |

**Policy Profiles:**
- `bitcoin_pure` - T0 only (maximally conservative)
- `permissive` - T0 + T1 + T2 (recommended default)
- `full_open` - All tiers (no filtering)

---

## Documentation

### Getting Started
- [Wallet Overview](docs/wallets/README.md) - Choose the right wallet for your needs
- [Getting Started Guide](docs/protocols/GETTING_STARTED.md) - Step-by-step setup
- [Technical Manual](docs/TECHNICAL_MANUAL.md) - Complete reference

### Protocol Documentation
- [Ghost Keys](docs/protocols/GHOST_KEYS.md) - Silent Payment implementation
- [Ghost Locks](docs/protocols/GHOST_LOCKS.md) - Timelocked recovery system
- [Ghost Pay](docs/protocols/GHOST_PAY.md) - L2 payment network
- [Wraith Protocol](docs/protocols/WRAITH_PROTOCOL.md) - CoinJoin mixing
- [Consensus](docs/protocols/CONSENSUS.md) - ZK-BFT consensus details
- [Node Capabilities](docs/protocols/NODE_CAPABILITIES.md) - 5-4-3-2-1 verification system

### Operations
- [Deployment Runbook](docs/DEPLOYMENT_RUNBOOK.md) - Production deployment guide
- [API Endpoints](docs/API_ENDPOINTS.md) - HTTP API reference
- [RPC Commands](docs/RPC_COMMANDS.md) - Full RPC documentation
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

---

## Security

Bitcoin Ghost has undergone extensive security auditing:

- **14 rounds** of comprehensive security remediation
- **Zero critical vulnerabilities** in release
- **Continuous fuzzing** via cargo-fuzz
- **Dependency auditing** via cargo-audit

Security features:
- **P2WSH quantum-safe architecture** for future-proofing
- **Encrypted database fields** for sensitive data
- **Rate limiting** on all public APIs
- **Trusted proxy validation** for IP-based protections
- **Secure key rotation** with dual-signature proofs

Report security issues to: security@bitcoinghost.org

---

## Development

### Running Tests

```bash
# Full test suite
cargo test --workspace

# Specific crate
cargo test -p ghost-consensus

# Integration tests
cargo test --test '*'
```

### Code Quality

```bash
# Format
cargo fmt --all

# Lint (must pass with zero warnings)
cargo clippy --workspace -- -D warnings

# Security audit
cargo audit

# Generate documentation
cargo doc --no-deps --workspace --open
```

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch
3. Ensure all tests pass and clippy is clean
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**Bitcoin Ghost** - *Making node operation profitable, mining decentralized, and payments private.*

[Website](https://bitcoinghost.org) • [GitHub](https://github.com/bitcoin-ghost) • [Documentation](docs/)

</div>
