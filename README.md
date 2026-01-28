# Bitcoin Ghost v1.4

A decentralized Bitcoin mining pool with privacy-preserving L2 payments.

## Features

- **Stratum V2** - Modern mining protocol with improved security and efficiency
- **BUDS Classification** - Transaction filtering based on Bitcoin Use-case Differentiation System
- **67% BFT Consensus** - Byzantine fault-tolerant payout agreement across pool nodes
- **Ghost Pay L2** - Instant off-chain payments with periodic L1 settlement
- **Ghost Keys** - Silent Payment-style addresses for receiver privacy
- **Ghost Locks** - P2TR outputs with timelocked recovery paths
- **Wraith Protocol** - Two-phase CoinJoin mixing for enhanced privacy

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Bitcoin Ghost Pool                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │ ghost-pool  │  │ghost-coord- │  │  ghost-pay  │  │ translator│  │
│  │             │  │  inator     │  │    (L2)     │  │ (SV1→SV2) │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘  │
│         │                │                │                │        │
│  ┌──────┴────────────────┴────────────────┴────────────────┴─────┐  │
│  │                      Core Libraries                           │  │
│  │  ghost-common | ghost-consensus | ghost-accounting            │  │
│  │  ghost-storage | ghost-template | ghost-verification          │  │
│  │  ghost-buds | ghost-policy | ghost-keys | ghost-locks         │  │
│  │  wraith-protocol | ghost-reconciliation                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

| Binary | Description |
|--------|-------------|
| `ghost-pool` | Main mining pool node - handles miners, templates, consensus |
| `ghost-coordinator` | Load balancer with Fire Ping latency measurement |
| `ghost-pay` | L2 payment node for instant off-chain transfers |
| `ghost-cli` | Administration CLI for pool management |
| `translator` | SV1 to SV2 protocol bridge for legacy miners |

## Quick Start

### Prerequisites

- Rust 1.75+
- Bitcoin Core (ghost-core fork recommended)
- SQLite 3.35+

### Build

```bash
# Clone repository
git clone https://github.com/bitcoin-ghost/ghost.git
cd ghost

# Build all binaries
cargo build --release

# Run tests
cargo test --workspace
```

### Run

```bash
# Start the pool node
./target/release/ghost-pool --config examples/ghost.toml

# Check status with CLI
./target/release/ghost-cli status

# Generate a new node identity
./target/release/ghost-cli key generate --output ~/.ghost/node.key
```

### Docker

```bash
cd docker
cp .env.example .env
# Edit .env with your settings

# Start basic stack
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
rpc_port = 8332
network = "mainnet"

[network]
sv2_port = 34255      # Stratum V2 miners
sv1_port = 3333       # Stratum V1 (via translator)
http_port = 8080      # API

[pool]
treasury_address = "bc1q..."
treasury_fee_percent = 1.0

[policy]
profile = "permissive"  # bitcoin_pure, permissive, full_open
```

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 34255 | TCP | Stratum V2 miners |
| 3333 | TCP | Stratum V1 miners |
| 8080 | TCP | HTTP API |
| 8555-8562 | TCP | P2P consensus mesh |

## BUDS Policy Tiers

| Tier | Description | Examples |
|------|-------------|----------|
| T0 | Core financial | Standard payments, consolidations |
| T1 | Extended financial | Multisig, timelocks, HTLCs |
| T2 | Data anchoring | Small OP_RETURN (<80 bytes) |
| T3 | Heavy data | Inscriptions, large witness data |

Policy profiles:
- `bitcoin_pure` - T0 only (financial transactions)
- `permissive` - T0 + T1 + T2 (default)
- `full_open` - All tiers allowed

## Documentation

### Wallet Guides
- [Wallet Overview](docs/wallets/README.md) - Choose the right wallet for you
- [Light Wallet](docs/wallets/LIGHT_WALLET.md) - Quick setup, minimal resources
- [Full Node Wallet](docs/wallets/FULL_NODE_WALLET.md) - Maximum privacy and control
- [GSP Server](docs/wallets/GSP_SERVER.md) - Run your own light wallet server

### Protocol Documentation
- [Full Documentation Index](docs/README.md) - All documentation
- [Ghost Keys](docs/protocols/GHOST_KEYS.md) - Silent Payment addresses
- [Ghost Locks](docs/protocols/GHOST_LOCKS.md) - Timelocked recovery outputs
- [Ghost Pay](docs/protocols/GHOST_PAY.md) - L2 payment network

### Operations
- [Deployment Runbook](docs/DEPLOYMENT_RUNBOOK.md) - Production deployment guide
- [Security Audit](docs/SECURITY_AUDIT.md) - Security review and recommendations
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Docker Setup](docker/README.md) - Container deployment

## CLI Usage

```bash
# Pool status
ghost-cli status

# List connected miners
ghost-cli miner list

# View current round
ghost-cli round current

# Check pending payouts
ghost-cli payout pending

# View consensus peers
ghost-cli consensus peers

# Node health check
ghost-cli node health

# Output as JSON
ghost-cli --format json status
```

## Development

### Project Structure

```
bitcoin-ghost/
├── crates/           # Library crates
│   ├── ghost-common/     # Shared types, config, identity
│   ├── ghost-buds/       # Transaction classification
│   ├── ghost-policy/     # Mining policy enforcement
│   ├── ghost-storage/    # SQLite database layer
│   ├── ghost-consensus/  # BFT consensus engine
│   ├── ghost-accounting/ # Share tracking, payouts
│   ├── ghost-verification/ # HTTP API, verification
│   ├── ghost-template/   # Block template construction
│   ├── ghost-keys/       # Silent Payment keys
│   ├── ghost-locks/      # Timelocked P2TR outputs
│   ├── wraith-protocol/  # CoinJoin mixing
│   └── ghost-reconciliation/ # L1 settlement
├── bins/             # Binary applications
│   ├── ghost-pool/       # Main pool node
│   ├── ghost-coordinator/# Load balancer
│   ├── ghost-pay/        # L2 payment node
│   ├── ghost-cli/        # Admin CLI
│   └── translator/       # SV1↔SV2 bridge
├── docker/           # Docker deployment
├── docs/             # Documentation
├── examples/         # Example configurations
└── tests/            # Integration & load tests
```

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p ghost-consensus

# Integration tests
cargo test --test integration

# Load tests (large scale, run manually)
cargo test --test load_tests -- --ignored
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## Security

For security issues, please email security@bitcoin-ghost.org or see [SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
