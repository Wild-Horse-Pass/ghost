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
//| FILE: ARCHITECTURE.md                                                                                                |
//|======================================================================================================================|

# Architecture

System design and component overview for Bitcoin Ghost.

## What is Bitcoin Ghost?

Bitcoin Ghost is a **full Bitcoin node implementation** - a derivative of Bitcoin Core, similar to Bitcoin Knots, but with significant enhancements:

- **Complete Bitcoin Node**: Full block validation, UTXO management, mempool, P2P networking
- **Incentivized Operation**: Nodes earn rewards for running valuable features
- **Decentralized Mining**: Built-in mining coordination without centralized pools
- **Ghost Pay L2**: Instant payment layer with 10-second settlement
- **Enhanced Privacy**: Silent payments, Wraith mixing, encrypted metadata

## Design Principles

1. **Full Node First**: Complete Bitcoin validation with no trust assumptions
2. **Node Sovereignty**: Each node chooses its own mempool/block policy
3. **Incentive Alignment**: Nodes earn rewards for running valuable services (5-4-3-2-1)
4. **Decentralization**: No central servers, pools, or coordinators required
5. **Privacy by Default**: Silent payments, encrypted metadata, optional mixing
6. **Spam Resistance**: BUDS classification enables intelligent transaction filtering

## High-Level Overview

```
       ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
       │  Ghost Node 1  │◄────►│  Ghost Node 2  │◄────►│  Ghost Node N  │
       │ (Pool + Core)  │      │ (Pool + Core)  │      │ (Pool + Core)  │
       └───────┬────────┘      └───────┬────────┘      └───────┬────────┘
               │                       │                       │
               │     P2P Consensus (ZMQ Mesh)                  │
               └───────────────────────┴───────────────────────┘
               │                       │                       │
       ┌───────▼───────┐      ┌───────▼───────┐      ┌───────▼───────┐
       │    Miners     │      │    Miners     │      │    Miners     │
       │   (SV1/SV2)   │      │   (SV1/SV2)   │      │   (SV1/SV2)   │
       └───────────────┘      └───────────────┘      └───────────────┘

Miners use Node Finder (web tool) to discover nodes and test latency.
```

## Binary Components

| Binary | Description | Required |
|--------|-------------|----------|
| `ghost-pool` | Mining pool with Stratum/TDP, consensus, accounting, verification | Yes |
| `ghost-core` | Bitcoin Core v30.1 fork with Ghost Pay L1 integration | Yes |
| `pool-sv2` | SRI Pool - SV2 protocol distribution (TDP mode) | For SV2 |
| `translator-sv1` | SRI Translator - SV1↔SV2 conversion (TDP mode) | For SV1 miners |
| `ghost-pay` | L2 payment network node | Optional |
| `ghost-cli` | Administration CLI for pool management | Yes |

## Crate Structure

```
bitcoin-ghost/
├── crates/
│   ├── ghost-common/        # Shared types, config, identity
│   ├── ghost-buds/          # Transaction classification (BUDS)
│   ├── ghost-policy/        # Mining policy enforcement
│   ├── ghost-storage/       # SQLite database layer
│   ├── ghost-consensus/     # BFT consensus engine
│   ├── ghost-accounting/    # Share tracking, payouts
│   ├── ghost-verification/  # HTTP API, capability verification
│   ├── ghost-template/      # Block template construction
│   ├── ghost-keys/          # Silent Payment keys (Ghost Keys)
│   ├── ghost-locks/         # Timelocked P2TR outputs
│   ├── wraith-protocol/     # CoinJoin mixing
│   └── ghost-reconciliation/# L1 settlement
├── bins/
│   ├── ghost-pool/          # Main pool node
│   ├── ghost-pay/           # L2 payment node
│   ├── ghost-cli/           # Admin CLI
│   └── translator/          # SV1↔SV2 bridge
├── ghost-core/              # Bitcoin Core fork (in-repo)
├── docker/                  # Docker deployment
├── docs/                    # Documentation
└── tests/                   # Integration & load tests
```

## Node Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Ghost Node                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Ghost Pool  │  │ Ghost Core  │  │ Translator  │              │
│  │   (SV1)     │◄─┤  (Bitcoin)  │  │  (SV1→SV2)  │              │
│  └──────┬──────┘  └─────────────┘  └──────┬──────┘              │
│         │              │ RPC              │                      │
│         │              ▼                  │                      │
│         │    ┌─────────────────┐          │                      │
│         └───►│ Template Filter │◄─────────┘                      │
│              │   (BUDS/Policy) │                                 │
│              └─────────────────┘                                 │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  Consensus  │  │ HTTP API    │  │ Ghost Pay   │              │
│  │  (ZMQ Mesh) │  │ (Verify)    │  │ (L2) [opt]  │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

### TDP Mode (SRI Integration)

For Stratum V2 support, ghost-pool can run in TDP mode, serving block templates to SRI:

```
┌─────────────────────────────────────────────────────────────────┐
│                  Ghost Node (TDP Mode)                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐                               │
│  │ Ghost Pool  │  │ Ghost Core  │                               │
│  │   (TDP)     │◄─┤  (Bitcoin)  │                               │
│  │ Port 8442   │  └─────────────┘                               │
│  └──────┬──────┘       │ RPC                                    │
│         │              ▼                                        │
│         │    ┌─────────────────┐                                │
│         └───►│ Template Filter │  ◄── BUDS/Policy applied       │
│              │ (Block Builder) │                                │
│              └────────┬────────┘                                │
│                       │ Noise encrypted                         │
│                       ▼                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                  SRI Components                             │ │
│  │  ┌───────────┐           ┌─────────────┐                   │ │
│  │  │ SRI Pool  │──────────►│ Translator  │                   │ │
│  │  │ Port 34256│   SV2     │  Port 3333  │                   │ │
│  │  └───────────┘           └──────┬──────┘                   │ │
│  │                                  │ SV1                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                     │                           │
│  ┌─────────────┐  ┌─────────────┐   ▼                          │
│  │  Consensus  │  │ HTTP API    │ Miners                       │
│  │  (ZMQ Mesh) │  │ (Verify)    │ (BitAxe, etc.)               │
│  └─────────────┘  └─────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

**TDP Mode CLI Flags:**
- `--tdp-enabled` - Enable TDP server
- `--tdp-port 8442` - TDP port (Noise encrypted)
- `--no-stratum` - Disable native stratum (use SRI instead)

## Network Ports

### External Ports (Firewall Open)

| Port | Protocol | Component | Purpose |
|------|----------|-----------|---------|
| 3333 | TCP/JSON | ghost-pool | Native Stratum (SV1 miners) |
| 34255 | TCP/Noise | SRI pool | SV2 Stratum (via SRI pool_sv2) |
| 8442 | TCP/Noise | ghost-pool | TDP server (SRI integration) |
| 34256 | TCP/Noise | SRI Pool | SV2 connections (TDP mode) |
| 3333 | TCP/JSON | SRI Translator | SV1 miners (TDP mode) |
| 8080 | HTTP | ghost-pool | Verification API |
| 8333 | TCP | ghost-core | Bitcoin P2P (mainnet) |

### Internal Ports (localhost)

| Port | Protocol | Component | Purpose |
|------|----------|-----------|---------|
| 38332 | HTTP/JSON-RPC | ghost-core | Bitcoin RPC |
| 28332 | TCP/ZMQ | ghost-core | ZMQ hashblock |
| 28333 | TCP/ZMQ | ghost-core | ZMQ hashtx |

### P2P Consensus Ports (Node-to-Node)

| Port | Protocol | Pattern | Purpose |
|------|----------|---------|---------|
| 8555 | ZMQ | PUB/SUB | Share propagation |
| 8556 | ZMQ | PUB/SUB | Block announcements |
| 8557 | ZMQ | DEALER/ROUTER | Consensus voting |
| 8558 | ZMQ | PUB/SUB | Health monitoring |
| 8559 | ZMQ | REQ/REP | Peer discovery |
| 8560 | ZMQ | PUB/SUB | Elder management |
| 8561 | ZMQ | PUB/SUB | Payout proposals |
| 8562 | ZMQ | PUB/SUB | Payout transactions |
| 8563 | TCP/Noise | Point-to-point | Encrypted P2P channel |

## Data Flow

### Block Template Flow (Native Stratum)

```
1. ghost-core → getblocktemplate RPC
2. Ghost Pool receives template
3. BUDS Policy Filter applied
4. Merkle tree rebuilt
5. Coinbase constructed (pre-consensus payouts)
6. Template distributed to miners via Stratum (port 34255)
```

### Block Template Flow (TDP Mode)

```
1. ghost-core → getblocktemplate RPC
2. Ghost Pool receives template
3. BUDS Policy Filter applied
4. Merkle tree rebuilt
5. Coinbase constructed (pre-consensus payouts)
6. Template sent via TDP (Noise encrypted, port 8442)
   → SRI Pool receives template
   → SRI Pool distributes to SV2 miners (port 34256)
   → SRI Translator converts for SV1 miners (port 3333)
```

### Share Flow

```
1. Miner finds valid share
2. Submit via Stratum to connected node
3. Node validates share
4. Broadcast to P2P mesh (port 8555)
5. All nodes update pending ledger
6. If block: submit to Bitcoin network immediately
```

### Consensus Flow

```
CONTINUOUS (before block found):
1. Nodes exchange share state
2. Deterministic payout calculation
3. All nodes compute identical coinbase
4. Templates distributed with pre-built coinbase

WHEN BLOCK FOUND:
1. Winning share arrives
2. Block already ready → submit immediately
3. No consensus delay
```

## Database Schema (SQLite)

Key tables:

| Table | Purpose |
|-------|---------|
| nodes | Registered pool nodes |
| miners | Registered miners |
| rounds | Block rounds |
| shares | Share submissions |
| payouts | Payout records |
| balances | Miner/node balances |
| archive_challenges | Archive verification results |
| policy_challenges | Policy verification results |

## Ghost Core Integration

Bitcoin Core v30.1 fork with:

### New RPC Commands

| Category | Commands |
|----------|----------|
| Silent Payments | `getsilentpaymentaddress`, `derivesilentpaymentaddress`, `checksilentpayment` |
| Wraith Protocol | `createwraithtx`, `createwraithfinaltx`, `parsewraithtx` |
| Reconciliation | `createreconciliationtx`, `coordinatebatchsigning`, `combinebatchpsbt` |

### Key Modifications

- BIP-352 Silent Payments for Ghost Keys
- Ghost Lock P2TR script templates
- Wraith Protocol transaction building
- Reconciliation batch transaction support
- Ghost-branded Qt GUI

## Deployment Options

### Minimal (Pool Node Only)

```
ghost-core + ghost-pool
```

Requirements:
- 500GB storage
- 8GB RAM
- Public IP for Stratum port

### Full Node (With L2)

```
ghost-core + ghost-pool + ghost-pay
```

Additional requirements:
- More storage for L2 state
- Additional ports for L2 protocols

## Security Model

### Trust Assumptions

| Component | Trust Level |
|-----------|-------------|
| Ghost Core | Trusted (local process) |
| Pool Nodes | Untrusted (Byzantine fault tolerant) |
| Miners | Untrusted (verify all shares) |

### Key Security Properties

1. **No custodial risk**: Miners control their own addresses
2. **67% BFT**: Tolerates 33% malicious nodes
3. **Pre-computed payouts**: No post-block consensus delay
4. **L2 self-custody**: Ghost Locks have recovery paths
5. **P2P Encryption**: Noise Protocol for sensitive message encryption

### P2P Encryption (Noise Protocol)

Sensitive P2P traffic is encrypted using the Noise Protocol Framework:

**Protocol**: `Noise_XX_25519_ChaChaPoly_BLAKE2s`

| Feature | Implementation |
|---------|----------------|
| Key Exchange | X25519 ECDH |
| Cipher | ChaCha20-Poly1305 AEAD |
| Hash | BLAKE2s |
| Handshake | Noise_XX (mutual authentication) |
| Port | 8563 |

**Message Routing**:
- **ZMQ (unencrypted)**: Discovery, Health pings (broadcast messages)
- **Noise TCP (encrypted)**: Shares, Blocks, Votes, Payouts, Verification

**Configuration**:
```toml
[consensus_config]
noise_enabled = true          # Enable Noise encryption
noise_port = 8563             # Noise TCP port
noise_keypair_path = "..."    # X25519 keypair location
noise_required = false        # Reject plaintext peers
```

## Scalability

### Horizontal Scaling

- Add more pool nodes (P2P mesh scales)
- Node Finder helps miners discover optimal nodes
- Each node handles ~10,000 miners

### Vertical Scaling

- More resources per node
- Faster block validation
- Larger mempool

## Monitoring

### Health Endpoints

```
GET /api/v1/health          # Node health
GET /api/v1/stats           # Pool statistics
GET /api/v1/peers           # Connected peers
GET /api/v1/miners          # Connected miners
```

### Metrics

- Shares per second
- Block find rate
- Consensus latency
- P2P mesh connectivity

## Related Documentation

- [Mining Pool](MINING_POOL.md) - Mining operations
- [Consensus](CONSENSUS.md) - BFT consensus
- [Economics](ECONOMICS.md) - Reward distribution
- [BUDS Policy](BUDS_POLICY.md) - Transaction filtering
