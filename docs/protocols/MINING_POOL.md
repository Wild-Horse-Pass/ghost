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
//| FILE: MINING_POOL.md                                                                                                 |
//|======================================================================================================================|

# Mining Pool

Decentralized Bitcoin mining pool architecture and operation.

## Overview

Bitcoin Ghost is a **decentralized mining pool** where:
- Every pool node is equal (no central server)
- Each node builds its own blocks with its own mempool policy
- Nodes form a P2P consensus network to agree on share accounting
- Miners connect to any node and receive work-proportional rewards
- Transaction fees go to the node operator (not pool)

## Architecture

### Network Topology

```
                                ┌─────────────────┐
                                │   Coordinator   │
                                │  (Miner Routing)│
                                └────────┬────────┘
                                         │
                ┌────────────────────────┼────────────────────────┐
                │                        │                        │
       ┌────────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
       │   Ghost Node 1  │◄────►│   Ghost Node 2  │◄────►│   Ghost Node N  │
       │  (Pool + Core)  │      │  (Pool + Core)  │      │  (Pool + Core)  │
       └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                │                        │                        │
       ┌────────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
       │    Miners       │      │    Miners       │      │    Miners       │
       │  (SV1/SV2)      │      │  (SV1/SV2)      │      │  (SV1/SV2)      │
       └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### Node Components

Each Ghost Node runs:

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

## Stratum Protocol

Ghost Pool supports two mining protocol modes:

### Native Stratum (SV1)

Direct miner connections using Stratum V1 (JSON-RPC over TCP):

```json
// Subscribe
{"id": 1, "method": "mining.subscribe", "params": ["miner/1.0"]}

// Authorize
{"id": 2, "method": "mining.authorize", "params": ["bc1qaddress.worker", "x"]}

// Receive work
{"id": null, "method": "mining.notify", "params": [...]}

// Submit share
{"id": 3, "method": "mining.submit", "params": ["worker", "job_id", "extranonce2", "ntime", "nonce"]}
```

| Setting | Value |
|---------|-------|
| Port | 34255 |
| Protocol | TCP/JSON-RPC |
| Encryption | Optional TLS |

### TDP Mode with SRI (SV2)

For Stratum V2 support, ghost-pool integrates with SRI (Stratum Reference Implementation) using the Template Distribution Protocol (TDP). This architecture allows ghost-pool to control block template building while SRI handles the SV2 mining protocol.

```
┌─────────────────────────────────────────────────────────────────┐
│                     TDP Mode Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ghost-core (RPC)                                               │
│       │                                                         │
│       ▼                                                         │
│  ghost-pool (TDP Server)  ◄── BUDS/policy/custom block building │
│  --tdp-enabled --no-stratum                                     │
│       │ Noise encrypted (port 8442)                             │
│       ▼                                                         │
│  SRI Pool (pool-sv2)  ◄── SV2 protocol distribution             │
│       │ SV2 (port 34256)                                        │
│       ▼                                                         │
│  SRI Translator (translator-sv1)  ◄── SV1 ↔ SV2 conversion      │
│       │ SV1 (port 3333)                                         │
│       ▼                                                         │
│  Legacy Miners (BitAxe, ASICs)                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**TDP Mode Benefits:**
- Ghost-pool retains full control over block template construction
- BUDS policy and mempool filtering applied before template distribution
- Noise protocol encryption for secure template transport
- Full Stratum V2 protocol support via SRI
- Backward compatible with SV1 miners through SRI translator

**CLI Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--tdp-enabled` | false | Enable TDP server |
| `--tdp-port` | 8442 | TDP server port |
| `--no-stratum` | false | Disable native stratum |

**TDP Port Configuration:**

| Port | Component | Purpose |
|------|-----------|---------|
| 8442 | ghost-pool | TDP server (Noise encrypted) |
| 34256 | SRI Pool | SV2 miner/translator connections |
| 3333 | SRI Translator | SV1 miner connections |

### Username Format

```
<payout_address>.<worker_name>

Examples:
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.rig1
bc1qtest.antminer01
```

## Share Tracking

### What is a Share?

A share is proof-of-work that meets the pool difficulty but not necessarily the network difficulty.

```
Network Difficulty: 50,000,000,000,000 (example)
Pool Difficulty:           500,000,000 (example)

Share = hash < pool_difficulty_target
Block = hash < network_difficulty_target
```

### Difficulty Adjustment

Variable difficulty (vardiff) adjusts per-miner:

```rust
struct DifficultyConfig {
    min_individual_miner_hashrate: f64,  // 500 GH/s default
    shares_per_minute: f64,              // 6.0 default
    enable_vardiff: bool,                // true
}
```

Target: ~6 shares per minute per miner (adjusts difficulty to achieve this).

### Share Validation

```
1. Miner submits share
2. Node validates:
   ├── Job ID is valid
   ├── Nonce hasn't been used
   ├── Hash meets share difficulty
   └── Share is recent (not stale)
3. If valid: Record in local ledger, broadcast to mesh
4. If block: Submit to Bitcoin network immediately
```

## Consensus

### Pre-Computed Payouts

**Critical**: Coinbase outputs are agreed upon BEFORE a winning share arrives.

```
CONTINUOUS PROCESS:
1. Nodes exchange share state (P2P mesh)
2. Deterministic calculation → all nodes compute same payouts
3. Coinbase pre-built with consensus outputs
4. Template distributed to miners

WHEN BLOCK FOUND:
1. Winning share arrives
2. Block ALREADY READY (coinbase pre-built)
3. Submit to Bitcoin network IMMEDIATELY
   - No voting delay
   - No consensus delay
```

### Why Pre-Consensus?

```
OLD (BAD):
Winning share → Calculate payouts → Vote → Build coinbase → Submit
                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                         DELAY = Lost blocks to competitors

BITCOIN GHOST (GOOD):
[Pre-computed coinbase ready] → Winning share → Submit IMMEDIATELY
                                                ^^^^^^^^^^^^^^^^
                                                NO DELAY
```

### P2P Mesh

Nodes communicate via ZeroMQ:

| Port | Purpose |
|------|---------|
| 8555 | Share propagation |
| 8556 | Block announcements |
| 8557 | Consensus voting |
| 8558 | Health monitoring |
| 8559 | Peer discovery |
| 8560 | Elder management |
| 8561 | Payout proposals |
| 8562 | Payout transactions |

## Block Lifecycle

### 1. Template Generation

```
1. Bitcoin Core builds template from mempool
2. Ghost Pool receives via JSON-RPC
3. Policy filter removes rejected transactions
4. Merkle tree rebuilt
```

### 2. Share Submission

```
1. Miner finds hash meeting share difficulty
2. Submits share to connected node
3. Node validates share
4. Share proof broadcast to mesh (Port 8555)
5. All nodes record share in pending ledger
```

### 3. Block Found

```
1. Miner submits share meeting NETWORK difficulty
2. Block is ALREADY READY (coinbase pre-built)
3. Node IMMEDIATELY submits to Bitcoin network
4. Block propagated via Bitcoin P2P
5. ZMQ hashblock notification received
```

### 4. Round Completion

```
1. Finding node broadcasts BlockFound (Port 8556)
2. All nodes receive Bitcoin network confirmation
3. Round officially ends
4. Ledger transition:
   - Top 200 miners: balances paid (zeroed)
   - Top 100 nodes: balances paid (zeroed)
   - Others: balances accumulate
5. New round begins
```

## Miner Rewards

### Distribution

- **99% of subsidy** goes to miners
- Distributed proportionally to shares submitted
- Per-round accounting (each block tracks shares independently)

### Payout Rules

| Rank | Action |
|------|--------|
| Top 200 miners | Paid directly in coinbase |
| Below top 200 | Balance accumulates in ledger |
| Balance > dust | Paid when entering top 200 |

### Example

```
Round 12345:
├── Total shares: 10,000
├── Miner pool: 309,375,000 sats
├── Miner A: 1,000 shares (10%) → 30,937,500 sats
├── Miner B: 500 shares (5%) → 15,468,750 sats
└── ...
```

## Node Discovery

Miners can find optimal pool nodes through:

1. **Node Finder Tool** - Web-based tool at `https://bitcoinghost.org/node-finder.html`
   - Discovers nodes from seed nodes and P2P network
   - Tests latency from user's browser
   - Shows node availability (available/busy/full)
   - Recommends best node based on latency and availability

2. **Regional Subdomains** - Pre-configured regional endpoints
   - `eu.pool.bitcoinghost.org:3333` - Europe
   - `us.pool.bitcoinghost.org:3333` - North America
   - `asia.pool.bitcoinghost.org:3333` - Asia-Pacific

3. **Direct Connection** - Connect to any known pool node

## Miner Setup

### Requirements

- Mining hardware (ASIC/GPU/CPU)
- Network connection to pool node
- Payout address (Bitcoin address)

### Configuration

```
Pool URL: stratum+tcp://node.bitcoinghost.org:3333
Username: <your_btc_address>.<worker_name>
Password: x (or any value)
```

### Example (CGMiner)

```bash
cgminer -o stratum+tcp://node.bitcoinghost.org:3333 \
        -u bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.rig1 \
        -p x
```

## Node Operator Guide

### Running a Node

1. Install ghost-core (Bitcoin fork)
2. Install ghost-pool
3. Configure with pool.toml
4. Join the P2P mesh

### Benefits

- **TX fees**: 100% of transaction fees from blocks you find
- **Node rewards**: Shares from capabilities you provide
- **Elder status**: If among first 101 nodes

### Requirements

| Requirement | Minimum |
|-------------|---------|
| Storage | 500GB+ (archive mode) |
| Memory | 8GB RAM |
| Network | 100 Mbps, low latency |
| Uptime | 95%+ for any rewards |

## Related Documentation

- [Economics](ECONOMICS.md) - Reward distribution details
- [BUDS Policy](BUDS_POLICY.md) - Transaction filtering
- [Consensus](CONSENSUS.md) - How nodes agree
- [Architecture](ARCHITECTURE.md) - System overview
