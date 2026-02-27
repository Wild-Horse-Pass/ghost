```
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
//| FILE: SPECIFICATION.md                                                                                               |
//|======================================================================================================================|
```

# Bitcoin Ghost v1.5 - Canonical Specification

## Document Control

| Version | Date | Author |
|---------|------|--------|
| 1.5.0 | 2026-02-18 | Bitcoin Ghost Team |
| 1.4.0 | 2026-01-22 | Bitcoin Ghost Team |

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Architecture](#2-system-architecture)
3. [Components](#3-components)
4. [External Dependencies](#4-external-dependencies)
5. [Network Ports](#5-network-ports)
6. [Communication Protocols](#6-communication-protocols)
    - [6.6 Ghost Shroud](#66-ghost-shroud-transaction-relay-protection)
7. [Database Schema](#7-database-schema)
8. [Configuration](#8-configuration)
9. [Economic Model](#9-economic-model)
10. [BUDS Classification System](#10-buds-classification-system)
11. [Policy System](#11-policy-system)
12. [Template Filtering](#12-template-filtering)
13. [Verification System](#13-verification-system)
14. [Consensus System](#14-consensus-system)
15. [Node Discovery](#15-node-discovery)
16. [Ghost Pay L2](#16-ghost-pay-l2)
    - [16.9 Ghost Keys](#169-ghost-keys-silent-payment-style-addresses)
    - [16.10 Ghost Locks](#1610-ghost-locks-p2tr-utxos-with-timelocks)
    - [16.11 Jump Locks](#1611-jump-locks-risk-tiered-key-rotation)
    - [16.12 Wraith Protocol](#1612-wraith-protocol-two-phase-mixing)
    - [16.13 Reconciliation](#1613-reconciliation-system)
17. [Coinbase Structure](#17-coinbase-structure)
18. [Block Lifecycle](#18-block-lifecycle)
19. [Deployment](#19-deployment)
20. [Mining Operations](#20-mining-operations)
21. [Zero-Knowledge Proofs](#21-zero-knowledge-proofs)
22. [Security Architecture](#22-security-architecture)
23. [Ghost Reaper](#23-ghost-reaper)
24. [Ghost Haze](#24-ghost-haze)

---

## 1. Overview

### 1.1 What is Bitcoin Ghost?

Bitcoin Ghost is a **full Bitcoin node implementation** - a derivative of Bitcoin Core, similar in philosophy to Bitcoin Knots, but with significant additional capabilities:

- **Complete Bitcoin Node**: Full block validation, UTXO management, mempool, P2P networking
- **Incentivized Operation**: Nodes earn rewards for running valuable features (5-4-3-2-1 share system)
- **Decentralized Mining**: Built-in mining coordination without centralized pools
- **Ghost Pay L2**: Instant payment layer with 10-second settlement
- **Enhanced Privacy**: Silent payments, Wraith mixing, relay origin protection (Shroud)
- **Policy Sovereignty**: Each node enforces its own mempool/block policies via BUDS

### 1.2 Comparison with Other Implementations

| Feature | Bitcoin Core | Bitcoin Knots | Bitcoin Ghost |
|---------|--------------|---------------|---------------|
| Full validation | Yes | Yes | Yes |
| Custom policies | Limited | Yes | Yes + BUDS |
| Mining support | Solo only | Solo only | Decentralized mining |
| Node incentives | None | None | 5-4-3-2-1 rewards |
| L2 payments | No | No | Ghost Pay |
| Privacy features | Basic | Basic | Silent payments + Wraith + Shroud |

### 1.3 Design Principles

1. **Full Node First**: Complete Bitcoin validation with no trust assumptions
2. **Node Sovereignty**: Each node chooses its own mempool/block policy
3. **Incentive Alignment**: Nodes earn rewards for running valuable services
4. **Decentralization**: No central servers, pools, or coordinators required
5. **Privacy by Default**: Silent payments, relay origin protection, optional mixing
6. **Spam Resistance**: BUDS classification enables intelligent transaction filtering

### 1.4 Key Outcomes

- Node operators earn rewards for running verified capabilities
- Node operators keep 100% of TX fees from blocks they build
- Miners connect directly to nodes - no third-party pools required
- Instant payments via Ghost Pay L2 (10-second settlement)
- Policy sovereignty via BUDS classification system
- Treasury funds ongoing development

---

## 2. System Architecture

### 2.1 High-Level Overview

```
                                    ┌─────────────────┐
                                    │   Coordinator   │
                                    │  (Miner Routing)│
                                    └────────┬────────┘
                                             │ Routes miners to
                                             │ optimal nodes
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
           ┌────────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
           │   Ghost Node 1  │◄────►│   Ghost Node 2  │◄────►│   Ghost Node N  │
           │  (Pool + Core)  │      │  (Pool + Core)  │      │  (Pool + Core)  │
           └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                    │                        │                        │
                    │ P2P Consensus (ZMQ Mesh)                        │
                    └────────────────────────┴────────────────────────┘
                    │                        │                        │
           ┌────────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
           │    Miners       │      │    Miners       │      │    Miners       │
           │  (SV1/SV2)      │      │  (SV1/SV2)      │      │  (SV1/SV2)      │
           └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 2.2 Node Architecture

Each Ghost Node runs:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Ghost Node                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Ghost Pool  │  │ Ghost Core  │  │ Translator  │              │
│  │   (SV2)     │◄─┤  (Bitcoin)  │  │  (SV1→SV2)  │              │
│  └──────┬──────┘  └─────────────┘  └──────┬──────┘              │
│         │              │ IPC              │                      │
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

---

## 3. Components

### 3.1 Binary Components

| Binary | Description | Required |
|--------|-------------|----------|
| `ghost-pool` | Mining pool with SV1 Stratum, consensus, accounting, verification | Yes |
| `ghost-core` | Bitcoin Core v30.1 fork with Ghost Pay L1 integration | Yes |
| `translator` | SV1→SV2 proxy for upstream SV2 pools (future use) | Optional |
| `ghost-pay` | L2 payment network node | Optional |

### 3.2 ghost-pool

The main pool binary. Responsibilities:
- Accept miner connections (SV1 JSON-RPC Stratum on port 3333)
- Receive templates from Bitcoin Core via JSON-RPC
- Filter templates using BUDS/policy (if enabled)
- Distribute work to miners
- Track shares and work
- Participate in P2P consensus
- Build coinbase with all payouts
- Submit blocks to Bitcoin network
- Respond to verification challenges
- Expose HTTP API for verification

### 3.3 ghost-core

Bitcoin Core v30.1 fork with comprehensive Ghost Pay L1 integration. This is NOT just a dependency - it's a fully modified Bitcoin node with Ghost-specific features.

**Core Modifications:**
- Silent Payments (BIP-352) for Ghost Keys/Ghost ID support
- Ghost Lock P2TR script templates with timelocked recovery
- Wraith Protocol transaction building (split/merge phases)
- Reconciliation batch transaction support
- JSON-RPC interface for template distribution and block submission
- ZMQ notifications for new blocks
- Ghost-branded Qt GUI with L2 wallet integration

**New RPC Commands:**

| Category | Commands |
|----------|----------|
| Silent Payments | `getsilentpaymentaddress`, `derivesilentpaymentaddress`, `checksilentpayment`, `parseghostopreturn`, `rescansilentpayments`, `getsilentpaymentstats` |
| Wraith Protocol | `createwraithtx`, `createwraithfinaltx`, `parsewraithtx`, `shuffleoutputs` |
| Reconciliation | `createreconciliationtx`, `coordinatebatchsigning`, `combinebatchpsbt`, `estimatebatchfee`, `derivereconciliationoutputs` |

**Key Source Files:**
- `src/silentpayments.h/cpp` - BIP-352 Silent Payment implementation
- `src/ghostlock.h/cpp` - Ghost Lock P2TR script building
- `src/wallet/silentpayment_spkm.h/cpp` - Silent Payment key manager
- `src/wallet/rpc/silentpayments.cpp` - SP RPC commands
- `src/wallet/rpc/wraith.cpp` - Wraith and Reconciliation RPCs
- `src/qt/ghost*.cpp/h` - Ghost-branded Qt GUI (~165KB)

**Source**: `ghost-core/` directory (Bitcoin Core v30.1 fork)

### 3.4 translator

Protocol translation proxy (for future SV2 support). Features:
- Accepts SV1 (JSON-RPC) connections from miners
- Can convert to SV2 binary protocol for upstream SV2 pools
- Variable difficulty support
- Flexible username handling

**Note:** Currently ghost-pool natively supports SV1, so translator is optional for direct connections.

### 3.5 ghost-pay

L2 payment network (optional). Features:
- Instant off-chain payments
- 0.1% fee (10 sats + 0.1%)
- 10-second virtual blocks
- 6-hour epochs for L1 settlement
- Wraith mixing integration (fixed service fee + mining cost)

---

## 4. External Dependencies

### 4.1 Forked Repositories

| Component | Location | Base |
|-----------|----------|------|
| ghost-core | `ghost-core/` (in-repo) | Bitcoin Core v30.1 with Ghost modifications |
| SRI (Stratum V2) | https://github.com/stratum-mining/stratum | main |

**Note:** ghost-core is included directly in this repository, not as an external dependency. It contains substantial Ghost-specific modifications beyond standard Bitcoin Core.

### 4.2 Rust Crates (Key Dependencies)

| Crate | Version | Purpose |
|-------|---------|---------|
| `stratum-common` | SRI | SV2 protocol types |
| `roles_logic_sv2` | SRI | Pool logic |
| `binary_sv2` | SRI | Binary encoding |
| `noise_sv2` | SRI | Noise encryption |
| `zeromq` | latest | P2P consensus mesh |
| `rusqlite` | latest | SQLite database |
| `ed25519-dalek` | latest | Node identity signing |
| `tokio` | 1.x | Async runtime |
| `bitcoin` | 0.32.x | Bitcoin primitives |

### 4.3 System Requirements

- Linux (Ubuntu 22.04+ recommended)
- Rust 1.75+ (for building)
- SQLite 3.x
- ZeroMQ 4.x libraries (`libzmq3-dev`)

---

## 5. Network Ports

### 5.1 External Ports (Firewall Open)

| Port | Protocol | Component | Purpose |
|------|----------|-----------|---------|
| 3333 | TCP/JSON | ghost-pool | SV1 Stratum (miners) |
| 34255 | TCP/Noise | SRI pool | SV2 Stratum (via SRI pool_sv2) |
| 8080 | HTTP | ghost-pool | Verification API |
| 38333 | TCP | ghost-core | Bitcoin P2P (signet) |
| 8333 | TCP | ghost-core | Bitcoin P2P (mainnet) |

### 5.2 Internal Ports (localhost only)

| Port | Protocol | Component | Purpose |
|------|----------|-----------|---------|
| 38332 | HTTP/JSON-RPC | ghost-core | Bitcoin RPC |
| 28332 | TCP/ZMQ | ghost-core | ZMQ hashblock notifications |
| 28333 | TCP/ZMQ | ghost-core | ZMQ hashtx notifications |

### 5.3 P2P Consensus Ports (Node-to-Node)

| Port | Protocol | Pattern | Purpose |
|------|----------|---------|---------|
| 8555 | ZMQ | PUB/SUB | Share propagation |
| 8556 | ZMQ | PUB/SUB | Block announcements |
| 8557 | ZMQ | DEALER/ROUTER | Consensus voting |
| 8558 | ZMQ | PUB/SUB | Health monitoring (heartbeat) |
| 8559 | ZMQ | REQ/REP | Peer discovery |
| 8560 | ZMQ | PUB/SUB | Elder management |
| 8561 | ZMQ | PUB/SUB | Payout proposals |
| 8562 | ZMQ | PUB/SUB | Payout transactions |
| 8563 | TCP/Noise | Point-to-point | Encrypted P2P channel |

### 5.4 IPC Sockets (Unix Domain)

| Path | Protocol | Purpose |
|------|----------|---------|
| `127.0.0.1:38332` | JSON-RPC/HTTP | Bitcoin Core RPC (templates, block submission) |
| `/var/run/ghost/pool.sock` | Custom | ghost-node ↔ ghost-pool IPC (optional) |

---

## 6. Communication Protocols

### 6.1 Stratum V1 (SV1) — Primary Protocol

JSON-RPC over TCP. The node builds block templates and distributes work to miners.

**Key Methods**:
- `mining.subscribe` - Subscribe to work
- `mining.authorize` - Authenticate with username.worker
- `mining.notify` - Receive new job
- `mining.submit` - Submit share

**SV2 Note**: Stratum V2 miner-selected transactions are explicitly unsupported. Ghost nodes have full sovereignty over block template construction — BUDS policy, Reaper filtering, and transaction selection are enforced by the node, not the miner. If SV2 is ever added, it will operate in pool-controls-template mode only.

### 6.2 Bitcoin Core RPC

JSON-RPC over HTTP for template distribution and block submission.

**Key RPC Methods**:
- `getblocktemplate` - Get new block template with transactions
- `submitblock` - Submit solved block to network
- `getblockchaininfo` - Get current chain state
- `getmempoolinfo` - Get mempool statistics

**Security Features**:
- TLS required for remote connections (non-localhost)
- Block template validation before use
- Bounded fields to prevent DoS attacks

### 6.3 ZMQ Consensus Protocol

Ed25519-signed messages over ZMQ for P2P consensus.

**Message Structure**:
```
SignedMessage {
    sender: NodeId,        // 32 bytes Ed25519 pubkey
    timestamp: u64,        // Unix timestamp ms
    signature: [u8; 64],   // Ed25519 signature
    payload: ConsensusMessage,
}
```

### 6.4 Noise Protocol Encryption (P2P)

Sensitive P2P messages are encrypted using the Noise Protocol Framework for point-to-point security.

**Protocol**: `Noise_XX_25519_ChaChaPoly_BLAKE2s`
- **XX Pattern**: Mutual authentication with identity hiding
- **X25519**: Elliptic curve Diffie-Hellman key exchange
- **ChaCha20-Poly1305**: AEAD symmetric encryption
- **BLAKE2s**: Cryptographic hash function

**Transport Classification**:

| Message Type | Transport | Rationale |
|--------------|-----------|-----------|
| Discovery | ZMQ (signed) | Broadcast for initial peer finding |
| Health Ping | ZMQ (signed) | Broadcast liveness, no secrets |
| Shares | Noise TCP | Sensitive pool work data |
| Blocks | Noise TCP | Block propagation |
| Votes | Noise TCP | Consensus votes |
| Payouts | Noise TCP | Payout proposals/transactions |
| Verification | Noise TCP | Challenge/response data |

**Security Properties**:
- **Confidentiality**: All sensitive messages encrypted end-to-end
- **Authentication**: Noise_XX provides mutual authentication
- **Forward Secrecy**: Each session derives fresh keys
- **Identity Binding**: Envelope sender must match Noise peer identity
- **Anti-Replay**: Noise protocol includes anti-replay protection

**Connection Pool**:
- Established connections are pooled and reused
- Stale connections cleaned up after 5 minutes of inactivity
- Automatic reconnection on connection failure

**ConsensusMessage Types**:
- `ShareProof` - Share submission proof
- `BlockFound` - Block found announcement
- `PayoutProposal` - Proposed payout distribution
- `PayoutVote` - Vote on payout proposal
- `HealthPing` - Heartbeat (every 10s)
- `NodeRegistration` - Register with capabilities
- `ElderRevocation` - Propose elder revocation

### 6.5 HTTP Verification API

RESTful HTTP for capability verification.

**Endpoints**:
```
GET  /api/v1/verify/archive?height={n}  → ArchiveVerifyResponse
GET  /api/v1/verify/stratum             → StratumVerifyResponse
GET  /api/v1/verify/ghostpay            → GhostPayVerifyResponse
POST /api/v1/verify/policy              → PolicyVerifyResponse
GET  /api/v1/status                     → NodeStatusResponse
```

### 6.6 Ghost Shroud (Transaction Relay Protection)

Network-level privacy feature that adds a random delay (0-5 seconds) before relaying transactions to peers, preventing timing-based origin detection.

**Mechanism**:
- When a transaction enters the mempool, it is queued for relay with a random delay
- `DrainShroudQueue()` runs each message-processing cycle in `SendMessages()`
- Transactions whose delay has elapsed are relayed normally
- Mining is unaffected: transactions enter the local mempool immediately

**Configuration**: `-shroud=1` (enabled by default), `-shroud=0` to disable

**Implementation**: `net_processing.cpp` — `RelayTransaction()`, `DrainShroudQueue()`, `ShroudEntry` queue

See [Ghost Shroud](protocols/GHOST_SHROUD.md) for the full specification.

---

## 7. Database Schema

### 7.1 SQLite Database

Location: `/var/lib/ghost/ghost_pool.db`

### 7.2 Core Tables

```sql
-- Registered miners (by Noise pubkey)
CREATE TABLE miners (
    miner_id INTEGER PRIMARY KEY,
    noise_pubkey BLOB UNIQUE NOT NULL,      -- 32 bytes
    payout_address TEXT,                     -- Bitcoin address
    first_seen INTEGER NOT NULL,             -- Unix timestamp
    last_seen INTEGER NOT NULL,
    total_shares INTEGER DEFAULT 0,
    total_work REAL DEFAULT 0.0,
    is_elder INTEGER DEFAULT 0,              -- Elder status
    elder_rank INTEGER,                      -- 1-101 or NULL
    elder_registered_at INTEGER              -- Registration timestamp
);

-- Mining rounds
CREATE TABLE rounds (
    round_id INTEGER PRIMARY KEY,
    server_id INTEGER NOT NULL,
    block_height INTEGER NOT NULL,
    prev_hash BLOB NOT NULL,                 -- 32 bytes
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    total_shares INTEGER DEFAULT 0,
    total_work REAL DEFAULT 0.0,
    status TEXT DEFAULT 'active'             -- active, completed, orphaned
);

-- Shares per round per miner
CREATE TABLE shares (
    share_id INTEGER PRIMARY KEY,
    round_id INTEGER NOT NULL,
    miner_id INTEGER NOT NULL,
    share_count INTEGER NOT NULL,
    work_total REAL NOT NULL,
    last_updated INTEGER NOT NULL,
    FOREIGN KEY (round_id) REFERENCES rounds(round_id),
    FOREIGN KEY (miner_id) REFERENCES miners(miner_id),
    UNIQUE (round_id, miner_id)
);

-- Found blocks
CREATE TABLE blocks (
    block_id INTEGER PRIMARY KEY,
    block_hash BLOB NOT NULL,                -- 32 bytes
    round_id INTEGER NOT NULL,
    winning_miner_id INTEGER NOT NULL,
    block_height INTEGER NOT NULL,
    subsidy_satoshis INTEGER NOT NULL,
    tx_fees_satoshis INTEGER NOT NULL,
    pool_fee_satoshis INTEGER NOT NULL,
    treasury_fee_satoshis INTEGER NOT NULL,
    node_reward_pool_satoshis INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (round_id) REFERENCES rounds(round_id),
    FOREIGN KEY (winning_miner_id) REFERENCES miners(miner_id)
);

-- Payout records
CREATE TABLE payouts (
    payout_id INTEGER PRIMARY KEY,
    block_id INTEGER NOT NULL,
    miner_id INTEGER NOT NULL,
    amount_satoshis INTEGER NOT NULL,
    payout_type TEXT NOT NULL,               -- 'mining' or 'node_reward'
    share_count INTEGER,
    share_percentage REAL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (block_id) REFERENCES blocks(block_id),
    FOREIGN KEY (miner_id) REFERENCES miners(miner_id)
);

-- Treasury state (singleton)
CREATE TABLE treasury_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    balance_satoshis INTEGER NOT NULL DEFAULT 0,
    threshold_satoshis INTEGER NOT NULL,     -- 2100000000000 (21 BTC)
    decay_start_height INTEGER,              -- Block height when decay started
    last_updated INTEGER NOT NULL
);

-- P2P consensus nodes
CREATE TABLE nodes (
    node_id INTEGER PRIMARY KEY,
    pubkey BLOB UNIQUE NOT NULL,             -- 32 bytes Ed25519
    name TEXT,
    address TEXT NOT NULL,                   -- External address
    stratum_port INTEGER DEFAULT 3333,       -- SV1 Stratum port
    http_port INTEGER DEFAULT 8080,
    payout_address TEXT NOT NULL,
    -- Capabilities
    archive_mode INTEGER DEFAULT 0,
    public_mining INTEGER DEFAULT 0,
    ghost_pay INTEGER DEFAULT 0,
    reaper INTEGER DEFAULT 0,
    elder_status INTEGER DEFAULT 0,
    elder_number INTEGER,                    -- 1-101 or NULL
    -- Calculated shares
    total_shares INTEGER DEFAULT 0,          -- 0-15
    -- Status
    last_seen INTEGER NOT NULL,
    is_active INTEGER DEFAULT 1,
    registered_at INTEGER NOT NULL
);

-- 7-day rolling uptime samples
CREATE TABLE uptime_samples (
    sample_id INTEGER PRIMARY KEY,
    miner_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    is_online INTEGER NOT NULL,
    sample_source TEXT,                      -- 'health_ping', 'round_end'
    FOREIGN KEY (miner_id) REFERENCES miners(miner_id)
);

-- Archive challenge results
CREATE TABLE archive_challenges (
    challenge_id BLOB PRIMARY KEY,           -- 32 bytes
    target_node_id INTEGER NOT NULL,
    challenger_node_id BLOB NOT NULL,
    requested_height INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',           -- pending, passed, failed, timeout
    response_time_ms INTEGER,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (target_node_id) REFERENCES nodes(node_id)
);

-- Policy challenge results
CREATE TABLE policy_challenges (
    challenge_id BLOB PRIMARY KEY,
    target_node_id INTEGER NOT NULL,
    challenger_node_id BLOB NOT NULL,
    policy_type TEXT NOT NULL,               -- 'bitcoin_pure', etc.
    challenge_type TEXT NOT NULL,            -- 'inscription', 'brc20', etc.
    test_tx BLOB NOT NULL,
    expected_reject INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    actual_reject INTEGER,
    detected_labels TEXT,                    -- JSON array
    response_time_ms INTEGER,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (target_node_id) REFERENCES nodes(node_id)
);

-- Stratum challenge results
CREATE TABLE stratum_challenges (
    challenge_id BLOB PRIMARY KEY,
    target_node_id INTEGER NOT NULL,
    challenger_node_id BLOB NOT NULL,
    target_address TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    port_open INTEGER,
    response_time_ms INTEGER,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (target_node_id) REFERENCES nodes(node_id)
);

-- Ghost Pay challenge results
CREATE TABLE ghostpay_challenges (
    challenge_id BLOB PRIMARY KEY,
    target_node_id INTEGER NOT NULL,
    challenger_node_id BLOB NOT NULL,
    requested_l2_height INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    l2_block_hash BLOB,
    response_time_ms INTEGER,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (target_node_id) REFERENCES nodes(node_id)
);

-- Burned elder numbers (never reassigned)
CREATE TABLE burned_elder_numbers (
    elder_number INTEGER PRIMARY KEY,
    original_node_pubkey BLOB NOT NULL,
    burned_at INTEGER NOT NULL,
    reason TEXT
);
```

### 7.3 Indexes

```sql
CREATE INDEX idx_shares_round ON shares(round_id);
CREATE INDEX idx_shares_miner ON shares(miner_id);
CREATE INDEX idx_payouts_block ON payouts(block_id);
CREATE INDEX idx_payouts_miner ON payouts(miner_id);
CREATE INDEX idx_uptime_miner_time ON uptime_samples(miner_id, timestamp);
CREATE INDEX idx_nodes_active ON nodes(is_active);
CREATE INDEX idx_archive_challenges_node ON archive_challenges(target_node_id, timestamp);
CREATE INDEX idx_policy_challenges_node ON policy_challenges(target_node_id, timestamp);
CREATE INDEX idx_stratum_challenges_node ON stratum_challenges(target_node_id, timestamp);
CREATE INDEX idx_ghostpay_challenges_node ON ghostpay_challenges(target_node_id, timestamp);
```

---

## 8. Configuration

### 8.1 ghost-pool Configuration

File: `/etc/ghost/pool.toml`

```toml
# Pool identity
authority_public_key = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
authority_secret_key = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
cert_validity_sec = 3600

# Network (SV1 Stratum)
listen_address = "0.0.0.0:3333"
server_id = 1
pool_signature = "Ghost Pool Node 1"

# Coinbase
coinbase_reward_script = "addr(tb1q...)"  # Fallback payout address

# Pool branding (optional)
# pool_name = "SatoshiPool"           # Custom name in coinbase: "- G H O S T - SatoshiPool"
# coinbase_extra = "custom raw tag"   # Advanced override (takes priority over pool_name)

# Mining settings
shares_per_minute = 6.0
share_batch_size = 10
supported_extensions = []
required_extensions = []

# Template provider (Bitcoin Core IPC)
[template_provider_type.BitcoinCoreIpc]
unix_socket_path = "/home/ghost/.ghost/ghost-core/signet/node.sock"
fee_threshold = 100
min_interval = 5

# Ghost economics
pool_fee_percent = 1.0
database_path = "/var/lib/ghost/ghost_pool.db"
ipc_socket_path = "/var/run/ghost/pool.sock"
tx_fee_address = "addr(tb1q...)"  # TX fees go here (node operator)

# Treasury
[treasury_config]
treasury_address = "addr(tb1q...)"  # Controlled treasury address
threshold_btc = 21.0
decay_years = 5

# Node rewards
[node_reward_config]
node_reward_address = "addr(tb1q...)"  # Fallback if < top 100
elder_limit = 101
uptime_threshold = 95.0

# P2P Consensus
[consensus_config]
bootstrap_peers = ["tcp://83.136.251.162:8559", "tcp://85.9.198.212:8559"]
external_address = "tcp://83.136.251.162"
port_offset = 0
archive_mode = true
public_mining = true
ghost_pay = false
reaper = true

# Noise Protocol Encryption (P2P)
noise_enabled = true                           # Enable Noise encryption (default: true)
noise_port = 8563                              # TCP port for Noise connections
noise_keypair_path = "/etc/ghost/noise.key"   # X25519 keypair (auto-generated)
noise_required = false                         # Reject plaintext peers (default: false)

# Bitcoin Core ZMQ
[core_zmq_config]
hashblock_endpoint = "tcp://127.0.0.1:28332"
hashtx_endpoint = "tcp://127.0.0.1:28333"
reconnect_delay_ms = 1000

# Bitcoin Core RPC (for archive challenges)
[core_rpc_config]
url = "http://127.0.0.1:38332"
user = "ghost"
password = "your_rpc_password"
```

### 8.2 ghost-core Configuration

File: `/home/ghost/.ghost/ghost-core/ghost.conf`

```ini
# Network
chain=signet
[signet]
signetchallenge=51

# RPC
server=1
rpcuser=ghost
rpcpassword=your_rpc_password
rpcbind=0.0.0.0
rpcport=38332
rpcallowip=127.0.0.1

# IPC Mining Interface
ipcbind=unix

# ZMQ Notifications
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashtx=tcp://127.0.0.1:28333

# Performance
dbcache=4096
maxmempool=300
```

### 8.3 translator Configuration

File: `/home/ghost/.ghost/translator/config.toml`

```toml
# SV1 downstream (miners connect here)
downstream_address = "0.0.0.0"
downstream_port = 3333
max_supported_version = 2
min_supported_version = 2
downstream_extranonce2_size = 8

# Miner identity
user_identity = "translator"
aggregate_channels = false
supported_extensions = []
required_extensions = []

# Mining mode
[mining_mode]
private_mining = true
public_mining = false

# Difficulty
[downstream_difficulty_config]
min_individual_miner_hashrate = 500000000000.0  # 500 GH/s
shares_per_minute = 6.0
enable_vardiff = true

# Upstream pool connection (SV1)
[[upstreams]]
address = "127.0.0.1"
port = 3333
# Note: authority_pubkey only needed for SV2 upstream
# authority_pubkey = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
```

---

## 9. Economic Model

### 9.1 Block Reward Distribution

When a block is found:

```
Block Reward = Subsidy + TX Fees

Subsidy Distribution:
├── Pool Fee (1% of subsidy)
│   ├── Treasury Allocation (0.5% of subsidy)
│   └── Node Reward Pool (0.5% of subsidy)
└── Miner Pool (99% of subsidy)
    └── Distributed to miners proportional to work

TX Fees:
└── 100% to node operator (in coinbase, node that built the block)
```

### 9.2 Treasury

- **Address**: Controlled by Bitcoin Ghost team
- **Threshold**: 21 BTC
- **Pre-threshold**: Accumulates 0.5% of each block subsidy
- **Post-threshold**: 5-year linear decay
  - Year 1: 0.5% → 0.4%
  - Year 2: 0.4% → 0.3%
  - Year 3: 0.3% → 0.2%
  - Year 4: 0.2% → 0.1%
  - Year 5: 0.1% → 0%
- **After decay**: Full 1% pool fee goes to node rewards

### 9.3 Node Reward Pool (5-4-3-2-1 System)

Qualified nodes earn bonus shares from the node reward pool.

| Capability | Shares | Verification |
|------------|--------|--------------|
| Archive Mode | +5 | Random block retrieval challenges |
| Ghost Pay | +4 | L2 block lookup challenges |
| Public Mining | +3 | Stratum port accessibility |
| Reaper | +2 | Reaper strict mode verification |
| Elder Status | +1 | First 101 nodes, active |

**Maximum**: 15 shares (5+4+3+2+1)

**Gatekeeper**: 95% uptime over trailing 7 days required for ANY shares

#### Challenge Verification Parameters

Nodes verify each other's capabilities through periodic challenges:

| Parameter | Value |
|-----------|-------|
| Verification Interval | 300 seconds (5 minutes) |
| Challenge Timeout | 10 seconds |
| Nodes Verified Per Round | 3 nodes |
| Min Challenges for Qualification | 10 |

| Capability | Pass Rate Required |
|------------|-------------------|
| Archive Mode (+5) | 95% |
| Ghost Pay (+4) | 90% |
| Public Mining (+3) | 95% |
| Reaper (+2) | 95% |

**Challenge Process**:
1. Every 5 minutes, node selects 3 random peers to verify
2. Issues appropriate challenges for each claimed capability
3. Records pass/fail result with timestamp
4. After 10 challenges, capability is qualified if pass rate met
5. Results are shared across pool for cross-verification

**Distribution**:
- Top 100 nodes by total shares get paid in coinbase
- Proportional to shares held
- Example: Node with 15 shares gets 15/total_shares of pool

**Node Reward Ledger**:
- All qualified nodes accumulate balances over time
- Each block: node's share of pool added to their balance
- Top 100 nodes: balance paid out in coinbase (then zeroed)
- Nodes outside top 100: balance accumulates until:
  - They enter top 100, OR
  - Balance exceeds dust threshold AND periodic payout batch

```
Example:
- Node A: 15 shares, rank #50 → Paid every block
- Node B: 8 shares, rank #150 → Accumulates until in top 100
- Node B accumulates 50,000 sats over 10 blocks
- Node B enters top 100 → Gets 50,000 sats + current block share
```

### 9.4 Elder System (MPC-Based)

- **Max Elders**: 101 (matches MPC ceremony contributor limit)
- **Assignment**: First 101 nodes to contribute to the MPC ceremony, ordered by contribution position
- **Genesis**: Position 1 auto-approves locally on the genesis node
- **Subsequent Positions**: Require 67% BFT approval from existing MPC contributors
- **Permanent**: Elder positions are non-transferable; if an elder goes offline, the position is lost forever
- **Revocation**: 67% BFT vote if offline ≥7 continuous days
- **Burned Slots**: Revoked elder numbers are NEVER reassigned

### 9.5 Miner Payouts

- **Work-proportional**: Share of 99% subsidy based on work submitted
- **Per-round accounting**: Each round (block) tracks shares independently
- **Top 200 miners**: Paid directly in coinbase
- **Below top 200**: Balance accumulates until above dust threshold

### 9.6 Dust Threshold

- **Minimum payout**: 546 satoshis
- **Below dust**: Balance accumulates in ledger
- **Above dust**: Paid in next block coinbase (if in top 200/100)

---

## 10. BUDS Classification System

### 10.1 Overview

BUDS (Bitcoin Unified Data Standard) classifies transaction data by type and location.

### 10.2 Tier System

| Tier | Name | Description | Policy Decision |
|------|------|-------------|-----------------|
| T0 | Consensus | Required for validation (sigs, scripts) | Always allow |
| T1 | Economic | Standard Bitcoin usage (payments, L2) | Generally allow |
| T2 | Metadata | Application data (inscriptions, tokens) | Policy decision |
| T3 | Unknown | Unclassified or obfuscated data | Generally reject |

### 10.3 Surfaces

Where data appears in a transaction:

- `scriptpubkey` - Output scripts
- `witness_stack` - Witness data elements
- `witness_script` - P2WSH/P2TR scripts
- `scriptsig` - Legacy input scripts
- `coinbase` - Coinbase data field

### 10.4 Label Categories

```
consensus.*     - Consensus-critical (T0)
  consensus.sig           - Signatures
  consensus.pubkey        - Public keys
  consensus.script        - Script opcodes
  consensus.tapscript     - Tapscript

pay.*           - Payments (T1)
  pay.standard            - Standard P2PKH/P2WPKH
  pay.multisig            - Multisig outputs
  pay.p2sh                - Pay-to-script-hash

contracts.*     - Smart contracts (T1)
  contracts.htlc          - Hash time-locked contracts
  contracts.vault         - Vault constructs

commitment.*    - L2 commitments (T1)
  commitment.lightning    - Lightning Network
  commitment.sidechain    - Sidechain anchors

meta.*          - Metadata (T2)
  meta.inscription        - Ordinals inscriptions
  meta.ordinal            - Ordinal envelope
  meta.brc20              - BRC-20 tokens
  meta.runes              - Runes protocol
  meta.pool_tag           - Pool identification

da.*            - Data embedding (T1/T2/T3)
  da.op_return_small      - OP_RETURN ≤80 bytes (T1, needed for L2 commitments)
  da.op_return_large      - OP_RETURN >80 bytes (T2, typically rejected)
  da.excessive_witness    - Witness >400 bytes per input (T2)
  da.unknown              - Unknown data pattern (T3)
  da.obfuscated           - Appears obfuscated (T3)
```

### 10.5 Classification Process

```rust
fn classify_transaction(tx: &[u8], is_coinbase: bool) -> ClassificationResult {
    // 1. Parse transaction structure
    // 2. Scan each surface for patterns
    // 3. Assign labels to byte ranges
    // 4. Calculate ARBDA score (highest tier present)
    // 5. Return labels and score
}
```

---

## 11. Policy System

### 11.1 Policy Profiles

A profile defines which labels to allow/reject:

```rust
struct PolicyProfile {
    name: String,
    description: String,
    allow: Vec<String>,    // Glob patterns to allow
    reject: Vec<String>,   // Glob patterns to reject
    rules: NumericRules,   // Size/count limits
}
```

### 11.2 Built-in Profiles

#### bitcoin_pure (P2P Cash)
```rust
PolicyProfile::new("bitcoin_pure", "P2P Electronic Cash")
    .allow("consensus.*")
    .allow("pay.*")
    .allow("contracts.*")
    .allow("commitment.*")
    .allow("meta.pool_tag")
    .allow("da.op_return_small")     // Allow ≤80 byte OP_RETURN for L2 commitments
    .reject("meta.inscription")
    .reject("meta.ordinal")
    .reject("meta.brc20")
    .reject("meta.runes")
    .reject("da.op_return_large")    // Reject >80 byte OP_RETURN
    .reject("da.excessive_witness")
    .reject("da.unknown")
    .reject("da.obfuscated")
    .with_rules(NumericRules {
        max_op_return_bytes: 80,     // Enforces small OP_RETURN limit
        max_witness_bytes_per_input: 400,
        min_output_sats: 546,
        max_outputs: 50,
        max_tx_size: 100_000,
    })
```

**Note**: Small OP_RETURN (≤80 bytes) is explicitly allowed because it's required for:
- Lightning Network channel commitments
- Ghost Pay L1 settlement anchors
- Other legitimate L2 protocol commitments

#### permissive (Allow Known Metadata)
```rust
PolicyProfile::new("permissive", "Allow known metadata")
    .allow("consensus.*")
    .allow("pay.*")
    .allow("contracts.*")
    .allow("commitment.*")
    .allow("meta.*")
    .reject("da.unknown")
    .reject("da.obfuscated")
    .with_rules(NumericRules {
        max_op_return_bytes: 0,  // No limit
        max_witness_bytes_per_input: 0,
        min_output_sats: 330,
        max_outputs: 100,
        max_tx_size: 400_000,
    })
```

#### full_open (No Filtering)
```rust
PolicyProfile::new("full_open", "Accept everything")
    .allow("*")
    .with_rules(NumericRules::default())
```

### 11.3 Custom Profiles

Operators can create, save, load, and delete custom profiles.

```toml
# Custom profile in config
[custom_policy]
name = "my_policy"
description = "Custom policy"
allow = ["consensus.*", "pay.*", "commitment.*"]
reject = ["meta.inscription", "da.*"]

[custom_policy.rules]
max_op_return_bytes = 80
max_witness_bytes_per_input = 500
min_output_sats = 546
max_outputs = 100
```

---

## 12. Template Filtering

Transaction filtering operates at two layers for defense in depth:

**Layer 1 — Ghost Core mempool (C++, fast pattern matching):**
The Ghost Reaper runs inside Ghost Core's `PreChecks()` after `IsStandardTx()`, before UTXO lookups. It rejects common dead-code patterns before they enter the mempool or propagate to peers:
- Inscription envelopes (`OP_FALSE OP_IF ... OP_ENDIF` in witness)
- Oversized OP_RETURN (configurable, default 83 bytes)
- Drop stuffing (`<push ≥76 bytes> OP_DROP` in witness)
- Fake pubkeys in bare multisig (invalid 0x02/0x03 prefix)
- P2TR annex abuse (last witness element starting with 0x50)

Configuration: `-ghostreaper` (enabled/disabled, default: enabled)

**Layer 2 — Ghost Pool template (Rust, full analysis):**
The existing Reaper in ghost-pool runs the complete 8-vector analysis including taint-tracking simulation, unreachable code flow analysis, and legacy scriptSig detection during template construction. This catches anything the fast C++ layer misses.

### 12.1 Flow

```
P2P tx received → Ghost Core mempool
       │
       ├── IsStandardTx()         (Bitcoin Core policy)
       ├── IsGhostReaperClean()   (Layer 1 — fast C++ pattern check)
       └── Fee/UTXO checks
       │
       ▼ Accepted into mempool
Bitcoin Core (RPC)
       │
       ▼ getblocktemplate
┌──────────────────┐
│  Ghost Pool      │
│                  │
│  1. Receive      │
│  2. Classify     │◄─── BUDS Classifier
│  3. Validate     │◄─── Policy Validator
│  4. Reaper       │◄─── Layer 2 (full 8-vector analysis)
│  5. Filter       │
│  6. Rebuild      │◄─── Merkle Rebuild
│  7. Distribute   │
└──────────────────┘
       │
       ▼ mining.notify
    Miners
```

### 12.2 Steps

1. **Receive**: Get template from Bitcoin Core via RPC
2. **Classify**: Run BUDS classifier on each non-coinbase transaction
3. **Validate**: Check each transaction against active policy profile
4. **Reaper**: Run full dead-code analysis (taint tracking, flow analysis)
5. **Filter**: Remove rejected transactions
6. **Rebuild**: Recompute merkle tree with remaining transactions
7. **Distribute**: Send filtered template to miners

### 12.3 Merkle Rebuild

When transactions are filtered out, the merkle tree must be rebuilt:

```rust
fn rebuild_merkle_tree(
    coinbase_txid: [u8; 32],
    filtered_txids: &[[u8; 32]]
) -> Vec<[u8; 32]> {
    // Build merkle path for coinbase
    // Used by miners to compute merkle root
}
```

### 12.4 Policy Verification

For +2 shares (Reaper):
1. Other nodes send test transactions containing dead code patterns
2. Node must correctly detect and reject corpse transactions
3. Challenger verifies Reaper strict mode is active and filtering correctly
4. Results stored in database
5. Qualification: 10+ challenges, 95% pass rate

---

## 13. Verification System

### 13.1 HTTP Verification Endpoints

Each node exposes HTTP endpoints for verification:

#### Archive Verification (+5 shares)
```
GET /api/v1/verify/archive?height={random_height}

Response:
{
    "height": 100000,
    "block_hash": "00000000...",
    "tx_count": 1234,
    "timestamp": 1234567890,
    "verified": true
}
```

#### Stratum Verification (+3 shares)
```
GET /api/v1/verify/stratum

Response:
{
    "port_open": true,
    "stratum_port": 3333,
    "connected_miners": 5,
    "protocol": "sv1",
    "verified": true
}
```
Plus: TCP probe to stratum port

#### Ghost Pay Verification (+4 shares)
```
GET /api/v1/verify/ghostpay

Response:
{
    "l2_running": true,
    "l2_height": 50000,
    "l2_synced": true,
    "active_locks": 10,
    "verified": true
}
```

#### Policy Verification (+2 shares)
```
POST /api/v1/verify/policy
Content-Type: application/json

{
    "test_tx": "0100000001...",  // Raw transaction hex
    "policy": "bitcoin_pure"
}

Response:
{
    "accepted": false,
    "rejected_labels": ["meta.inscription"],
    "arbda_score": "T2",
    "verified": true
}
```

### 13.2 Verification Protocol

1. **Selection**: Every 5 minutes, each node selects 3 random peers
2. **Challenge**: Send verification request to selected peers
3. **Response**: Peer processes and responds
4. **Validation**: Challenger validates response
5. **Recording**: Result stored in database with signature
6. **Aggregation**: Stats calculated over 7-day window

### 13.3 Anti-Gaming Measures

- Random target selection
- Random parameters (block heights, test transactions)
- Multiple verifiers (each node checked by many)
- Signed results (audit trail)
- Timeout penalties (no response = fail)

### 13.4 Qualification Thresholds

| Capability | Min Challenges | Pass Rate |
|------------|----------------|-----------|
| Archive | 10 | 95% |
| Stratum | 10 | 95% |
| Ghost Pay | 10 | 90% |
| Policy | 10 | 95% |

---

## 14. Consensus System

### 14.1 Overview

67% Byzantine Fault Tolerant (BFT) consensus for:
- Share accounting agreement
- Payout proposal approval
- Elder registration/revocation

### 14.2 Share Propagation

```
Node A finds valid share
       │
       ▼ PUB (Port 8555)
┌──────────────────────────────────────┐
│           ZMQ Mesh Network           │
│  Node B ◄──► Node C ◄──► Node D      │
│     │          │          │          │
│     ▼          ▼          ▼          │
│  SUB        SUB        SUB           │
│  Record     Record     Record        │
└──────────────────────────────────────┘
```

### 14.3 Payout Consensus

When a block is found:

1. Finding node creates `PayoutProposal`
2. Proposal broadcast to mesh (Port 8561)
3. Each node validates proposal
4. Nodes vote approve/reject (Port 8557)
5. At 67% approval: consensus reached
6. Finding node broadcasts `PayoutTransaction`
7. Round transitions, ledgers updated

### 14.4 Consensus States

```
Pending → Collecting → Approved
              │
              ├──────→ Rejected
              │
              └──────→ TimedOut (fallback)
```

### 14.5 Message Signing

All consensus messages are Ed25519 signed:

```rust
struct SignedMessage {
    sender: [u8; 32],      // Ed25519 public key
    timestamp: u64,        // Unix timestamp ms
    signature: [u8; 64],   // Ed25519 signature
    payload: Vec<u8>,      // Serialized message
}
```

### 14.6 Health Monitoring

- Heartbeat every 10 seconds (Port 8558)
- Missed heartbeats tracked
- 7+ days offline triggers revocation eligibility

---

## 15. Node Discovery

### 15.1 Purpose

Help miners discover and connect to optimal pool nodes based on:
- Latency (lowest RTT from miner's location)
- Availability (node status: available/busy/full)

### 15.2 Discovery Methods

**1. Node Finder (Web Tool)**
- Browser-based tool at `https://bitcoinghost.org/node-finder.html`
- Discovers nodes from seed nodes and P2P network
- Tests latency to each node's `/health` endpoint
- Shows availability status without exposing exact capacity
- Recommends best node based on availability and latency

**2. Regional Subdomains**
- `eu.pool.bitcoinghost.org:3333` - Europe
- `us.pool.bitcoinghost.org:3333` - North America
- `asia.pool.bitcoinghost.org:3333` - Asia-Pacific

**3. Direct Connection**
- Connect directly to any known pool node's Stratum port

### 15.3 Node Discovery API

Pool nodes expose discovery endpoints:

```
GET /api/v1/network/public-nodes
Returns: List of peer addresses for discovery

GET /api/v1/node/public-info
Returns: Node name, region, status, stratum endpoint
```

**Status Values:**
- `available` - Under 50% capacity, accepting miners
- `busy` - 50-90% capacity, still accepting miners
- `full` - Over 90% capacity, may reject new connections

### 15.4 Security Considerations

- Exact capacity numbers are NOT exposed (prevents targeted attacks)
- Only status (available/busy/full) is shown
- Nodes can evict lowest-hashrate miners when at capacity

---

## 16. Ghost Pay L2

### 16.1 Overview

Optional Layer 2 payment network for instant, low-fee transfers.

### 16.2 Architecture

```
L1 (Bitcoin)
    │
    │ Deposits / Withdrawals
    ▼
┌──────────────────────────┐
│       Ghost Pay L2       │
│                          │
│  Virtual Blocks (10s)    │
│  Epochs (2,160 = 6h)     │
│  Ghost Locks (P2TR)      │
│  Wraith Mixing           │
└──────────────────────────┘
    │
    │ Instant Payments
    ▼
Users
```

### 16.3 Fee Structure

| Service | Fee |
|---------|-----|
| Transfer | 10 sats + 0.1% |
| Wraith Mix | Fixed service fee (500-10,000 sats) + mining cost share |

**Note**: Wraith v2 uses fixed service fees per denomination (Micro: 500, Small: 2,000, Medium: 5,000, Large: 10,000 sats) plus at-cost mining fees split across all participants. Jump sessions (key rotation) charge mining cost only — no service fee. Mining costs vary with fee rate and are transparent to users.

### 16.4 Settlement

| Class | Batching | Delay |
|-------|----------|-------|
| Express | Every epoch | ~6 hours |
| Standard | Every 4 epochs | ~24 hours |
| Economy | Weekly | ~7 days |

### 16.5 Wraith Protocol (Mixing)

Two-phase CoinJoin mixing with Schnorr blind signatures for private entry into Ghost Pay.

**Phases:**
1. Phase 1 (Split): N inputs → OPP×N intermediate Ghost Locks
2. Phase 2 (Merge): OPP×N intermediates → N final Ghost Locks
3. OPP (outputs per participant) varies by tier: 2, 4, 5, 8, or 10

**Coordination:** Distributed — any Ghost node can coordinate sessions. No central operator.

**Denominations:** 0.001, 0.01, 0.1, 1 BTC (fixed service fees: 500, 2K, 5K, 10K sats)

**Session Types:** Mix (service fee + mining) or Jump (mining cost only, for key rotation)

**Participant Tiers:** Micro (500), Small (320), Medium (260), Standard (250), Large (170), Whale (140)

**Anonymity Set:** 140-500 participants per session — order of magnitude larger than other CoinJoin protocols

**Privacy:** Schnorr blind signatures ensure the coordinating node cannot link inputs to outputs. Encrypted OP_RETURN markers (v3) prevent metadata leakage. All intermediate outputs are identical within a session (M-23 invariant).

### 16.6 ZK Proofs

Zero-Knowledge proofs are used for:

1. **Balance Verification**: Prove sufficient balance without revealing amount
2. **Transfer Validity**: Prove transfer is valid without revealing parties
3. **Settlement Batching**: Prove batch is correct without revealing individual txs
4. **Wraith Mixing**: Additional privacy layer for mixing proofs

**ZK System**: Groth16 or similar SNARK for efficiency

```
User wants to transfer:
1. Create ZK proof of:
   - Balance ≥ amount + fee
   - No double-spend
   - Valid signature
2. Submit proof + encrypted transfer
3. Validators verify proof (not contents)
4. Transfer executed privately
```

### 16.7 L2 Fee Distribution

L2 fees (Wraith mixing + reconciliation) are distributed:

```
L2 Fee Income
     │
     ├──► Ghost Pay Node Reward Pool (split among +4 share nodes)
     │    Ratio: Inverse of treasury decay
     │    Pre-threshold: 50%
     │    Post-decay: 100%
     │
     └──► Treasury
          Ratio: Same as L1 treasury allocation
          Pre-threshold: 50%
          Post-decay: 0%
```

**Example (pre-threshold)**:
- Wraith fees collected: 100,000 sats
- Ghost Pay nodes: 50,000 sats (split by shares among +4 nodes only)
- Treasury: 50,000 sats

**Example (post-decay)**:
- Wraith fees collected: 100,000 sats
- Ghost Pay nodes: 100,000 sats (treasury gets nothing)

**Important**: Only nodes with Ghost Pay capability (+4 shares) receive L2 fee distributions. This incentivizes running L2 infrastructure.

### 16.8 Reconciliation

Periodic L1 settlement of L2 state:

```
Every Epoch (6 hours):
1. Calculate net L2 balance changes
2. Create L1 settlement transaction
3. Batch multiple user withdrawals
4. Single OP_RETURN commitment anchor
5. Broadcast to Bitcoin network
```

Reconciliation fees contribute to L2 fee pool (section 16.7).

### 16.9 Ghost Keys (Silent Payment Style Addresses)

Ghost Keys are the identity foundation of Ghost Pay, based on BIP-352 Silent Payments.
They enable unlinkable stealth addresses where each payment creates a unique address
that only the recipient can detect.

#### 16.9.1 Key Structure

```rust
struct GhostKeys {
    scan_secret: SecretKey,   // Used to detect incoming payments
    spend_secret: SecretKey,  // Used to spend received funds
}

struct GhostId {
    scan_pubkey: PublicKey,   // Shared publicly for receiving
    spend_pubkey: PublicKey,  // Shared publicly for receiving
}
```

#### 16.9.2 Ghost ID Format

Ghost IDs use bech32 encoding with `ghost` human-readable part:

```
ghost1<bech32_encoded_scan_pubkey_spend_pubkey>

Example: ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
```

The encoded data is: `scan_pubkey (33 bytes) || spend_pubkey (33 bytes)`

#### 16.9.3 Payment Derivation

When sending to a Ghost ID:

```
1. Sender generates ephemeral keypair (e, E = e*G)
2. Compute shared secret: S = SHA256(e * scan_pubkey)
3. Compute tweak: t = SHA256(S || output_index || nonce)
4. Compute output pubkey: P = spend_pubkey + t*G
5. Create P2TR output to P
6. Include E in OP_RETURN (GPGL marker + ephemeral pubkey)
```

#### 16.9.4 Payment Detection (Scanning)

Receiver scans transactions:

```
1. Find OP_RETURN with GPGL marker, extract ephemeral pubkey E
2. Compute shared secret: S = SHA256(scan_secret * E)
3. For each output index, compute tweak: t = SHA256(S || index || nonce)
4. Compute expected pubkey: P = spend_pubkey + t*G
5. If output matches P, payment belongs to us
6. Derive spend key: spend_key = spend_secret + t
```

#### 16.9.5 Unlinkability

- Each payment creates a unique address
- No correlation between payments to same Ghost ID
- Only scan key holder can detect payments
- OP_RETURN ephemeral key is common pattern, not identifying

### 16.10 Ghost Locks (P2TR UTXOs with Timelocks)

Ghost Locks are the on-chain representation of funds in Ghost Pay. They use
Taproot outputs with key path spending and script path recovery.

#### 16.10.1 Lock Structure

```rust
struct GhostLock {
    lock_pubkey: XOnlyPublicKey,      // Key path spending (normal use)
    recovery_pubkey: XOnlyPublicKey,  // Script path recovery (emergencies)
    denomination: Denomination,        // Standard denomination tier
    timelock_tier: TimelockTier,      // Recovery timelock duration
    creation_height: u32,             // Block height when created
}
```

#### 16.10.2 P2TR Script Structure

```
Taproot Output:
├── Key Path: lock_pubkey (efficient, private normal spending)
└── Script Path:
    └── Recovery Leaf:
        <recovery_height> OP_CLTV OP_DROP
        <recovery_pubkey> OP_CHECKSIG
```

#### 16.10.3 Standard Denominations

| Tier | Name | Amount | Use Case |
|------|------|--------|----------|
| Micro | Micro | 10,000 sats | Tiny payments |
| Tiny | Tiny | 100,000 sats | Small payments |
| Small | Small | 1,000,000 sats (0.01 BTC) | Regular payments |
| Medium | Medium | 10,000,000 sats (0.1 BTC) | Larger payments |
| Large | Large | 100,000,000 sats (1 BTC) | Big transfers |
| XL | Extra Large | 1,000,000,000 sats (10 BTC) | Whale transfers |

Standard denominations enable:
- Efficient batching in Wraith mixing
- Privacy through uniformity
- Predictable fee calculations

#### 16.10.4 Timelock Tiers

| Tier | Duration | Blocks | Use Case |
|------|----------|--------|----------|
| Short | 6 months | ~26,280 | Active users, frequent rotation |
| Standard | 1 year | ~52,560 | Default, balanced security |
| Long | 2 years | ~105,120 | Cold storage, maximum security |

Recovery becomes available after `creation_height + timelock_blocks`.

#### 16.10.5 Ghost Lock ID

Deterministic identifier for a lock:

```rust
fn ghost_lock_id(
    lock_pubkey: &XOnlyPublicKey,
    recovery_pubkey: &XOnlyPublicKey,
    creation_height: u32,
    denomination_sats: u64,
) -> [u8; 32] {
    tagged_hash("GhostLock/v1",
        lock_pubkey || recovery_pubkey || creation_height || denomination_sats)
}
```

### 16.11 Jump Locks (Risk-Tiered Key Rotation)

Jump Locks provide proactive security through automatic key rotation based on
balance-at-risk tiers.

#### 16.11.1 Risk Tiers

| Tier | Balance Threshold | Rotation Period | Rationale |
|------|-------------------|-----------------|-----------|
| Low | < 0.1 BTC | 30 days | Minimal risk, infrequent rotation |
| Medium | 0.1 - 1 BTC | 14 days | Moderate risk, regular rotation |
| High | > 1 BTC | 7 days | High risk, frequent rotation |

#### 16.11.2 Jump Process

```
1. Approaching jump deadline (rotation period)
2. Generate new Ghost Lock with fresh keys
3. Create atomic swap: old_lock -> new_lock
4. Old lock spent via key path
5. New lock created with reset rotation timer
6. Process is non-interactive (wallet handles automatically)
```

#### 16.11.3 Jump Lock Benefits

- **Proactive Security**: Keys rotate before compromise window grows
- **Balance-Aware**: Higher balances get more frequent rotation
- **Automatic**: Wallet software manages rotation
- **Atomic**: Old → New is single transaction, no fund exposure
- **Privacy**: Each jump creates fresh unlinkable lock

#### 16.11.4 Jump Scheduling

```rust
fn calculate_jump_deadline(
    lock: &GhostLock,
    current_height: u32,
) -> u32 {
    let tier = JumpRiskTier::from_sats(lock.denomination.sats());
    lock.creation_height + tier.rotation_blocks()
}

impl JumpRiskTier {
    fn rotation_blocks(&self) -> u32 {
        match self {
            JumpRiskTier::Low => 144 * 30,    // 30 days
            JumpRiskTier::Medium => 144 * 14, // 14 days
            JumpRiskTier::High => 144 * 7,    // 7 days
        }
    }
}
```

### 16.12 Wraith Protocol (Two-Phase Mixing)

Wraith Protocol provides private entry from public Bitcoin into Ghost Pay
through two-phase split-merge mixing.

#### 16.12.1 Overview

```
Phase 1 (Split):   N inputs  → 10N intermediate Ghost Locks
Phase 2 (Merge):   10N intermediates → N final Ghost Locks

Result: User starts with 1 public UTXO, ends with 1 clean Ghost Lock
Trail is broken: No link between public input and final output
```

#### 16.12.2 Participant Tiers

| Tier | Min Participants | Anonymity Set | Wait Time |
|------|------------------|---------------|-----------|
| Express | 25 | Moderate | Minutes |
| Quick | 50 | Good | Hours |
| Small | 100 | Better | ~1 day |
| Medium | 250 | Strong | ~2 days |
| Standard | 500 | Very Strong | ~3 days |
| Large | 750 | Excellent | ~5 days |
| Whale | 1000 | Maximum | ~7 days |

#### 16.12.3 Wraith Denominations

| Denomination | Input (with 1% fee) | Output | Intermediate (10x split) |
|--------------|---------------------|--------|--------------------------|
| Micro | 10,100 sats | 10,000 sats | 1,000 sats |
| Small | 1,010,000 sats | 1,000,000 sats | 100,000 sats |
| Medium | 10,100,000 sats | 10,000,000 sats | 1,000,000 sats |
| Large | 101,000,000 sats | 100,000,000 sats | 10,000,000 sats |

#### 16.12.4 Blind Signatures

Wraith uses **interactive Schnorr blind signatures** for unlinkability. This provides
cryptographically proven blindness and unlinkability under standard assumptions (DLOG, ROM).

**Protocol Flow (3 rounds):**

```
Step 1: Nonce Exchange
  - Coordinator generates random nonce k, computes R = k*G
  - Coordinator sends R to participant

Step 2: Blinding & Challenge
  - Participant generates random blinding factors α and β
  - Participant computes blinded nonce: R' = R + α*G + β*X
  - Participant computes challenge: c = H(R' || X || m)
  - Participant computes blinded challenge: c' = c + β
  - Participant sends c' to coordinator

Step 3: Signing
  - Coordinator computes: s = k + c'*x (mod n)
  - Coordinator sends s to participant

Step 4: Unblinding
  - Participant computes: s' = s + α
  - Final signature is (R', s') on message m
```

**Verification (standard Schnorr):**
```
s'*G == R' + c*X   where c = H(R' || X || m)
```

**Security Properties:**
- **Blindness**: Coordinator never sees m, R', or c
- **Unforgeability**: Only coordinator can produce valid signatures (DLOG + ROM)
- **Unlinkability**: Final (R', s') cannot be linked to signing session (R, c', s)

**Implementation Notes:**
- Nonces are single-use (consumed after signing to prevent reuse attacks)
- Session-specific signing keys prevent cross-session correlation
- Challenge hash uses BIP-340 tagged hash: `H = SHA256(SHA256(tag) || SHA256(tag) || data)`

**References:**
- Schnorr blind signatures: https://eprint.iacr.org/2019/877
- BIP-340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

#### 16.12.5 Phase Execution

**Phase 1 (Split)**:
```
1. Collect N participants with matching denomination
2. Each participant contributes 1 input
3. For each of 10 intermediate addresses per participant:
   a. Coordinator sends nonce R to participant
   b. Participant blinds address, sends blinded challenge c'
   c. Coordinator signs, returns signature scalar s
   d. Participant unblinds to get valid token (R', s')
4. Construct split transaction: N inputs → 10N outputs
5. Transaction includes OP_RETURN marker: "WR1" (Wraith Phase 1)
6. All participants sign
7. Broadcast and confirm
```

**Phase 2 (Merge)** (next epoch):
```
1. Same participants, 10 intermediates each as inputs
2. For each participant's final output address:
   a. Coordinator sends nonce R
   b. Participant blinds, sends blinded challenge
   c. Coordinator signs, returns scalar
   d. Participant unblinds to get token
3. Construct merge transaction: 10N inputs → N outputs
4. Transaction includes OP_RETURN marker: "WR2" (Wraith Phase 2)
5. All participants sign
6. Broadcast and confirm
```

**Phase-Specific Timeouts:**
| Phase | Timeout | Purpose |
|-------|---------|---------|
| Participant Collection | 24 hours | Wait for N participants |
| Input Collection | 2 hours | Collect UTXOs from participants |
| Phase Execution | 1 hour | Signing coordination |
| Phase Confirmation | 6 hours | Wait for on-chain confirmation |
| Overall Session | 7 days | Maximum total session duration |

#### 16.12.6 Thresholds

| Threshold | Value | Purpose |
|-----------|-------|---------|
| Minimum Execution | 50% | Force execute if half show up |
| Early Execution | 75% | Optional early if 3/4 ready |
| Refund Vote | 67% | Supermajority can abort |
| Timeout | 7 days | Maximum wait before refund |

### 16.13 Reconciliation System

Reconciliation batches L2 state changes for L1 settlement.

#### 16.13.1 Settlement Classes

| Class | Batching | Min Participants | Max Epochs | Fee |
|-------|----------|------------------|------------|-----|
| Express | Every epoch | 10 | 1 | Higher |
| Standard | Every 4 epochs | 25 | 4 | Medium |
| Economy | Weekly | 50 | 28 | Lower |

#### 16.13.2 Batch Rules

```rust
struct BatchRules {
    settlement_class: SettlementClass,
    min_participants: usize,    // Minimum for batch to execute
    max_idle_ratio: f64,        // Maximum inactive locks (50%)
    max_extension: u32,         // Deadline extension multiplier
}
```

#### 16.13.3 Idle Lock Handling

Locks that haven't been active (spent/received) within a batch period:

- **Idle Ratio**: Maximum 50% of batch can be idle locks
- **Forced Rotation**: Idle locks may be force-rotated to fresh keys
- **Fee Penalty**: Idle locks pay slightly higher fees
- **Purpose**: Prevent anonymity set degradation from stale UTXOs

#### 16.13.4 Settlement Transaction

```
L2 Settlement TX:
├── Inputs: L2 state commitments (previous epoch)
├── Outputs:
│   ├── Withdrawal outputs (users exiting L2)
│   ├── Change output (remaining L2 balance)
│   └── OP_RETURN: L2 state commitment anchor
└── Fees: Paid from L2 fee pool
```

---

## 17. Coinbase Structure

### 17.1 Output Breakdown

Single coinbase transaction with multiple outputs:

```
Coinbase TX Outputs (max 301):
├── Output 0: TX Fees → Node Operator
├── Output 1: Treasury Allocation → Treasury Address
├── Outputs 2-101: Node Rewards → Top 100 Nodes (by shares)
└── Outputs 102-301: Miner Payouts → Top 200 Miners (by balance)
```

### 17.2 Coinbase ScriptSig Tag

The coinbase scriptsig contains a pool identification tag visible on block explorers.
Operators can customize this via the `pool_name` config option:

| Priority | Source | Example Tag |
|----------|--------|-------------|
| 1 (highest) | `coinbase_extra` (raw override) | Whatever string is set |
| 2 | `pool_name` (formatted) | `- G H O S T - SatoshiPool` |
| 3 (default) | Mining mode | `- G H O S T - PublicPool` |

Default tags by mining mode: `PublicPool`, `PrivatePool`, `PrivateSolo`.

Constraints: ASCII printable, max 30 characters (keeps total tag under 242-byte coinbase limit).

### 17.3 Limits

| Output Type | Max Count |
|-------------|-----------|
| TX Fees | 1 |
| Treasury | 1 |
| Node Rewards | 100 |
| Miner Payouts | 200 |
| **Total** | **301** |

### 17.4 Amount Calculation

```rust
// Block found
let subsidy = calculate_subsidy(height);  // 3.125 BTC at current halving
let tx_fees = template.tx_fees;           // Sum of all tx fees

// Pool fee (1% of subsidy only)
let pool_fee = subsidy * 0.01;

// Treasury (0.5% of subsidy, pre-threshold)
let treasury = subsidy * 0.005;

// Node reward pool (0.5% of subsidy, pre-threshold)
let node_pool = subsidy * 0.005;

// Miner pool (99% of subsidy)
let miner_pool = subsidy - pool_fee;

// TX fees go entirely to node operator
let node_tx_fees = tx_fees;
```

### 17.5 Example (3.125 BTC Block)

```
Subsidy:           312,500,000 sats (3.125 BTC)
TX Fees:            10,000,000 sats (0.1 BTC)

Pool Fee (1%):       3,125,000 sats
├── Treasury:        1,562,500 sats (0.5%)
└── Node Rewards:    1,562,500 sats (0.5%)

Miner Pool (99%): 309,375,000 sats

Coinbase Outputs:
├── Node Operator:   10,000,000 sats (TX fees)
├── Treasury:         1,562,500 sats
├── Top 100 Nodes:    1,562,500 sats (divided by shares)
└── Top 200 Miners: 309,375,000 sats (divided by work)
```

---

## 18. Block Lifecycle

### 18.1 Pre-Consensus (Continuous)

**CRITICAL**: Coinbase outputs are agreed upon BEFORE a winning share arrives.
This ensures zero delay when a block is found.

```
CONTINUOUS PROCESS (every new template):

1. Bitcoin Core builds template from mempool
2. Ghost Pool receives via IPC
3. Policy filter removes rejected transactions
4. Merkle tree rebuilt

5. LEDGER CONSENSUS (P2P):
   - Nodes exchange current share state (Port 8555)
   - Nodes agree on miner ledger balances
   - Nodes agree on node reward ledger balances
   - Deterministic calculation ensures all nodes compute same outputs

6. Coinbase PRE-BUILT with consensus outputs:
   - TX Fees → Node operator (this node's address)
   - Treasury → Treasury address
   - Top 100 Nodes → Node reward outputs (by shares)
   - Top 200 Miners → Miner payout outputs (by balance)

7. Template distributed to miners with pre-built coinbase
```

### 18.2 Share Submission (Continuous)

```
1. Miner finds hash meeting share difficulty
2. Submits share to connected node
3. Node validates share
4. Share proof broadcast to mesh (Port 8555)
5. All nodes record share in pending ledger
6. Ledger state updated (triggers coinbase recalculation)
```

### 18.3 Block Found (Instant Submission)

```
1. Miner submits share meeting NETWORK difficulty
2. Block is ALREADY READY (coinbase pre-built via consensus)
3. Node IMMEDIATELY submits to Bitcoin network
   - No waiting for voting
   - No consensus delay
   - Winning nonce + pre-agreed coinbase = complete block
4. Block propagated via Bitcoin P2P
5. ZMQ hashblock notification received
```

### 18.4 Post-Block Confirmation

```
AFTER block is already submitted:

1. Finding node broadcasts BlockFound (Port 8556)
2. All nodes receive Bitcoin network confirmation
3. Round officially ends
4. Ledger transition:
   - Pending ledger → Consensus ledger
   - Top 200 miners: balances paid (set to 0)
   - Top 100 nodes: balances paid (set to 0)
   - Others: balances accumulate
5. New round begins with fresh pending ledger
```

### 18.5 Why Pre-Consensus?

Traditional pools have a latency problem:
```
OLD (BAD):
Winning share → Calculate payouts → Vote → Build coinbase → Submit block
                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                         DELAY = Lost blocks to competitors
```

Bitcoin Ghost pre-computes:
```
NEW (GOOD):
[Pre-computed coinbase ready] → Winning share → Submit IMMEDIATELY
                                                ^^^^^^^^^^^^^^^^
                                                NO DELAY
```

### 18.6 Ledger State Machine

```
┌─────────────┐    Share     ┌─────────────┐
│   Pending   │◄────────────►│  Consensus  │
│   Ledger    │   Propagate  │   Ledger    │
└──────┬──────┘              └──────┬──────┘
       │                            │
       │ Block Found                │ Reference for
       │                            │ payout calculation
       ▼                            ▼
┌─────────────┐              ┌─────────────┐
│  Transition │─────────────►│    Paid     │
│   (atomic)  │   Top 200/100│  (zeroed)   │
└─────────────┘              └─────────────┘
       │
       │ Others
       ▼
┌─────────────┐
│ Accumulated │ (balance carries forward)
└─────────────┘
```

---

## 19. Deployment

### 19.1 Directory Structure

```
/opt/ghost/
├── bin/
│   ├── ghost-pool
│   ├── ghost-core-launcher
│   └── translator
└── lib/
    └── libbitcoin*.so

/etc/ghost/
├── pool.toml
└── translator.toml

/home/ghost/.ghost/
├── ghost-core/
│   ├── ghost.conf
│   ├── signet/
│   │   ├── blocks/
│   │   ├── chainstate/
│   │   └── node.sock
│   └── mainnet/
│       └── ...
└── translator/
    └── config.toml

/var/lib/ghost/
├── ghost_pool.db
└── logs/
```

### 19.2 Systemd Services

#### ghost-core.service
```ini
[Unit]
Description=Ghost Core (Bitcoin) with IPC Mining
After=network.target

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/ghost-core-launcher -m node \
    -datadir=/home/ghost/.ghost/ghost-core \
    -conf=ghost.conf
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### ghost-pool.service
```ini
[Unit]
Description=Ghost Mining Pool (SV2)
After=network.target ghost-core.service
Requires=ghost-core.service

[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/var/lib/ghost
ExecStart=/opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### translator.service
```ini
[Unit]
Description=Ghost SV1→SV2 Translator
After=network.target ghost-pool.service

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/translator --config /etc/ghost/translator.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 19.3 Firewall Rules

```bash
# SV1 Stratum (main pool)
ufw allow 3333/tcp

# SV2 Stratum (reserved for future use)
# ufw allow 34255/tcp

# HTTP API
ufw allow 8080/tcp

# P2P Consensus (node-to-node)
ufw allow 8555:8562/tcp

# Bitcoin P2P
ufw allow 38333/tcp  # signet
# ufw allow 8333/tcp  # mainnet
```

### 19.4 Network Configuration

| Network | Chain | RPC Port | P2P Port | signetchallenge |
|---------|-------|----------|----------|-----------------|
| Private Signet | signet | 38332 | 38333 | 51 |
| Public Signet | signet | 38332 | 38333 | (default) |
| Mainnet | main | 8332 | 8333 | N/A |

---

## 20. Mining Operations

### 20.1 Stratum V1 (Native)

Ghost-pool provides a native SV1 stratum server on port 3333. Miners connect directly with worker name format `<bitcoin_address>.<worker_id>`.

Key protocol methods:
1. `mining.subscribe` - Get extranonce1
2. `mining.authorize` - Authenticate (payout_address.worker)
3. `mining.notify` - Receive jobs
4. `mining.submit` - Submit shares

### 20.2 Variable Difficulty (Vardiff)

Per-miner difficulty targeting approximately 4 shares/minute:

| Parameter | Value |
|-----------|-------|
| Target rate | 4 shares/min |
| Initial difficulty | 2000 |
| Retarget window | 30 seconds, after 4+ shares |
| Max change factor | 4.0x |

Adjustments are sent via `mining.set_difficulty` notification after share acceptance.

### 20.3 Share Validation

| Check | Purpose | Threshold |
|-------|---------|-----------|
| Job existence | Prevent stale submissions | Template ID tracking |
| Nonce uniqueness | Prevent duplicate shares | LRU cache |
| Hash validation | Verify PoW | Pool difficulty |
| Timestamp bounds | Prevent replay | +/- 2min future, +/- 10min past |
| Rate limiting | Prevent spam | 100 shares/sec/miner |
| Work anomaly | Detect inflation | 1.0x network difficulty max |


### 20.4 Round Management

Rounds track share accounting between blocks:

1. Block found: snapshot round shares
2. Calculate payout distribution
3. Create new round
4. Continue accepting shares

### 20.5 Pre-Consensus Coinbase

Coinbase outputs are computed **before** a winning share arrives, eliminating consensus delay at block discovery:

```
Every 5 minutes (or template change):
  Nodes calculate deterministic payouts
  Same inputs → same outputs (no voting needed)
  Templates distributed with pre-built coinbase

Winning share arrives:
  Submit block IMMEDIATELY (no consensus round)
```

### 20.6 Replay Attack Prevention

Three-layer defense against message replay in the P2P mesh:

**Layer 1 - Deduplication Window**: Tracks `(sender_id, sequence_number)` pairs. 60-second window with 100,000 message capacity. FIFO eviction when full.

**Layer 2 - Timestamp Validation**: Messages must be within 5 minutes of current time. Checked before deduplication.

**Layer 3 - Sequence Monotonicity**: Per-sender tracking of highest sequence seen. Rejects `sequence <= highest_seen`. Handles wrap-around via epoch tracking.

### 20.7 Ban Management

| Reason | Base Duration | Description |
|--------|---------------|-------------|
| Equivocation | 24 hours | Conflicting votes |
| RateLimitExceeded | 1 hour | Too many messages |
| InvalidMessages | 30 minutes | Malformed messages |
| ProtocolViolation | 24 hours | Protocol violations |

**Escalation**: Multiplier `2^(count - 1)`, capped at 16x. Decay: count decreases by 1 for each 7-day period since last ban.

---

## 21. Zero-Knowledge Proofs

### 21.1 Groth16 SNARKs

Ghost uses Groth16 proofs over BLS12-381 with a sender-side proof architecture:

| Proof Type | Purpose | Public Inputs | Constraints | Size |
|-----------|---------|---------------|-------------|------|
| NoteSpend | Note spending / transfer validity | commitment_root, nullifier, change_commitment, recipient_commitment | ~12,675 (depth-40) | 192 bytes |
| Payout | Distribution validity | epoch, totals | ~2,500 | 192 bytes |

Proof structure: A (48 bytes, G1) + B (96 bytes, G2) + C (48 bytes, G1).

### 21.2 Circuit Design

**NoteSpendCircuit**: Sender-side proof for spending a note in the L2 commitment tree. Uses MiMC (82 rounds) for hashing, depth-40 Merkle inclusion proofs. Senders generate proofs locally (~170ms); validators verify in ~5ms. Public inputs: `commitment_root`, `nullifier`, `change_commitment`, `recipient_commitment`. Replaced the earlier BlockCircuit (February 2026 L2 redesign).

**PayoutCircuit**: Proves payout distribution preserves sum (miners + nodes + treasury = total) with 64-bit amount bounds.

**NullifierRouteHandler**: Validates sender-side proofs, routes transactions by nullifier prefix for deterministic validator assignment, manages all-node BFT checkpoints (every 10 seconds, 67% threshold).

**EpochManager**: Manages L2 epoch lifecycle — tree compaction, epoch transitions, proposer rotation, commitment tree maintenance.

### 21.3 MPC Ceremony

Parameters are generated through a rolling Multi-Party Computation ceremony. See [MPC Ceremony](protocols/MPC_CEREMONY.md) for the full specification. MPC uses `NoteSpendCircuit::dummy(40)` for parameter generation (~3-4s per contribution).

Summary:
- First 101 contributors become Elders (+1 share)
- 1-of-N security model (one honest participant sufficient)
- Parameters stored in `~/.ghost/mpc_params/`

### 21.4 Verification

- With verifying key: cryptographic verification (~5ms for NoteSpend proofs)
- Without verifying key: fail closed (reject all proofs in production)
- Subgroup checks on deserialization prevent invalid curve attacks

### 21.5 Metadata Encryption

Payment metadata (labels and memos) is encrypted with ChaCha20-Poly1305:
- Fixed 80-byte ciphertext prevents size fingerprinting
- HKDF key derivation with domain separation
- Label: 4 bytes, Memo: up to 59 bytes UTF-8

---

## 22. Security Architecture

### 22.1 Mining Security

| Threat | Mitigation |
|--------|------------|
| Stale shares | Dual validation (wall clock + monotonic) |
| Address spoofing | HMAC-SHA256 payout commitment |
| Share spam | Rate limiting (100/sec/miner) |
| Work inflation | 1.0x network difficulty cap |
| TOCTOU races | Snapshot-based payout hash capture |

### 22.2 P2P Security

| Threat | Mitigation |
|--------|------------|
| Message replay | 3-layer defense (dedup + timestamp + sequence) |
| Memory exhaustion | 100k message cap, per-sender limits |
| Cache flushing | Per-sender tracking (10k max each) |
| Topic spoofing | Topic validation against envelope type |
| Plaintext sniffing | Noise Protocol encryption |

### 22.3 Consensus Security

| Threat | Mitigation |
|--------|------------|
| Vote forgery | Ed25519 signatures with round_id |
| Equivocation | Detection + proof broadcast + ban |
| Weak voter set | 7-day uptime + PoW requirement |
| Centralized elders | BFT approval from >67% of previous epoch |

### 22.4 Cryptographic Security

| Threat | Mitigation |
|--------|------------|
| Key material leakage | Zeroize with volatile writes |
| Timing attacks | Constant-time comparisons |
| RNG failure | Shannon entropy validation |
| Signature replay | Domain separation + ceremony binding |

### 22.5 ZK Security

| Threat | Mitigation |
|--------|------------|
| Forged proofs | Groth16 soundness + MPC ceremony |
| Simulated proofs | Runtime check + feature gate |
| Cross-ceremony replay | Unique ceremony_id binding |
| Indefinite ceremony | 101-contribution ossification |
| Parameter corruption | Magic markers + version gaps |

---

## 23. Ghost Reaper

Dead code detection engine for witness scripts. Analyzes transactions during block template construction and filters those with excessive dead code ("Corpses").

### 23.1 Detection Vectors

8 detection vectors: inscription envelopes, drop stuffing, unreachable code, fake pubkeys, oversized OP_RETURN, annex presence, excess witness data, and legacy scriptSig data.

### 23.2 Operating Modes

| Mode | Behavior |
|------|----------|
| Strict | Any dead code = Corpse (filtered) |
| Moderate | Allow <=80 bytes AND <=10% dead code ratio |
| Monitor | Log only, no filtering |

### 23.3 Integration

Runs in `TemplateProcessor.apply_custom_policy()` **before** BUDS classification. Operates independently from BUDS -- classifies transaction *content* (dead bytes) rather than *purpose* (policy tiers).

Running in **strict** mode grants +2 shares in the 5-4-3-2-1 node capability system.

See [Ghost Reaper](protocols/GHOST_REAPER.md) for the full specification.

---

## 24. Ghost Haze

Selective archive stripping and real-time data purification for Ghost Core (Bitcoin Core fork). Provides legal protection against embedded content liability by ensuring hazeable data (witness, scriptSig, OP_RETURN, coinbase arbitrary data) never touches persistent storage.

### 24.1 Node Modes

| Mode | Storage | Legal Liability | Description |
|------|---------|-----------------|-------------|
| Mode A (Hazed) | ~193 GB | None | All hazeable content stripped; structural economic graph preserved |
| Mode B (Full Archive) | ~718 GB | Full | Standard Bitcoin Core behavior |

### 24.2 Ghost Exorcism

Runtime process that validates blocks in RAM and writes only structural data to disk. Hazeable content passes through volatile memory during validation and is purged.

### 24.3 Ghost Exorcist

Conversion tool that transforms existing full archive nodes to hazed nodes. Strips hazeable content, writes structural archive, generates Legal Compliance Packet.

### 24.4 Zero Custom Records

Bitcoin's existing cryptographic commitments (txids, witness commitments) serve as proof of destroyed content. No per-field haze records needed.

See [Ghost Haze](protocols/GHOST_HAZE.md) for the full specification.

---

## Appendix A: Message Types

### A.1 Consensus Messages

```rust
enum ConsensusMessage {
    // Share tracking
    ShareProof(ShareProof),

    // Block events
    BlockFound(BlockFound),

    // Payout consensus
    PayoutProposal(PayoutProposal),
    PayoutVote(PayoutVote),
    PayoutTransaction(PayoutTransaction),

    // Health
    HealthPing(HealthPing),

    // Node management
    NodeRegistration(NodeRegistration),
    ElderRevocation(ElderRevocation),

    // Discovery
    DiscoveryRequest(DiscoveryRequest),
    DiscoveryResponse(DiscoveryResponse),
}
```

### A.2 Verification Messages

```rust
// Archive
struct ArchiveVerifyRequest { height: u64 }
struct ArchiveVerifyResponse { height, block_hash, tx_count, timestamp, verified }

// Stratum
struct StratumVerifyResponse { port_open, stratum_port, connected_miners, protocol, verified }

// GhostPay
struct GhostPayVerifyResponse { l2_running, l2_height, l2_synced, active_locks, verified }

// Policy
struct PolicyVerifyRequest { test_tx: Vec<u8>, policy: String }
struct PolicyVerifyResponse { accepted, rejected_labels, arbda_score, verified }
```

---

## Appendix B: Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1001 | SHARE_INVALID | Share does not meet difficulty |
| 1002 | SHARE_DUPLICATE | Share already submitted |
| 1003 | SHARE_STALE | Share for old round |
| 2001 | CONSENSUS_TIMEOUT | Voting timed out |
| 2002 | CONSENSUS_REJECTED | Proposal rejected by 67%+ |
| 3001 | TEMPLATE_ERROR | Failed to get template from Core |
| 3002 | FILTER_ERROR | Policy filter failed |
| 4001 | VERIFY_TIMEOUT | Verification timed out |
| 4002 | VERIFY_FAILED | Verification check failed |

---

## Appendix C: Constants

```rust
// Economic
const POOL_FEE_PERCENT: f64 = 1.0;
const TREASURY_THRESHOLD_SATS: u64 = 2_100_000_000_000; // 21 BTC
const TREASURY_DECAY_YEARS: u32 = 5;
const DUST_THRESHOLD_SATS: u64 = 546;

// Coinbase limits
const MAX_MINER_OUTPUTS: usize = 200;
const MAX_NODE_OUTPUTS: usize = 100;

// Node rewards (5-4-3-2-1)
const ARCHIVE_MODE_SHARES: i32 = 5;
const GHOST_PAY_SHARES: i32 = 4;
const PUBLIC_MINING_SHARES: i32 = 3;
const BITCOIN_PURE_SHARES: i32 = 2;
const ELDER_STATUS_SHARES: i32 = 1;
const MAX_NODE_SHARES: i32 = 15;

// Uptime
const UPTIME_GATEKEEPER_THRESHOLD: f64 = 95.0;
const UPTIME_WINDOW_DAYS: u64 = 7;

// Elder
const MAX_ELDERS: u32 = 101;
const ELDER_OFFLINE_THRESHOLD_DAYS: u64 = 7;

// Consensus
const BFT_THRESHOLD_PERCENT: u64 = 67;
const CONSENSUS_TIMEOUT_MS: u64 = 5000;
const HEALTH_PING_INTERVAL_SECS: u64 = 10;

// Verification
const VERIFICATION_INTERVAL_SECS: u64 = 300;
const VERIFICATION_TIMEOUT_SECS: u64 = 10;
const MIN_CHALLENGES_FOR_QUALIFICATION: usize = 10;
const ARCHIVE_PASS_RATE: f64 = 0.95;
const POLICY_PASS_RATE: f64 = 0.95;
const STRATUM_PASS_RATE: f64 = 0.95;
const GHOSTPAY_PASS_RATE: f64 = 0.90;

// Ports
const SV1_STRATUM_PORT: u16 = 3333;          // Main pool (active)
const SV2_STRATUM_PORT: u16 = 34255;         // Reserved for future use
const HTTP_API_PORT: u16 = 8080;
const COORDINATOR_PORT: u16 = 8333;
const SHARE_PROPAGATION_PORT: u16 = 8555;
const BLOCK_ANNOUNCEMENT_PORT: u16 = 8556;
const CONSENSUS_VOTING_PORT: u16 = 8557;
const HEALTH_MONITORING_PORT: u16 = 8558;
const DISCOVERY_PORT: u16 = 8559;
const ELDER_MANAGEMENT_PORT: u16 = 8560;
const PAYOUT_PROPOSAL_PORT: u16 = 8561;
const PAYOUT_TRANSACTION_PORT: u16 = 8562;
const NOISE_ENCRYPTED_PORT: u16 = 8563;      // Noise Protocol encrypted channel
```

---

## Appendix D: Glossary

| Term | Definition |
|------|------------|
| ARBDA | Arbitrary Data score - highest BUDS tier in transaction |
| BFT | Byzantine Fault Tolerant - consensus model tolerating 33% malicious nodes |
| BUDS | Bitcoin Unified Data Standard - transaction classification system |
| Coinbase | First transaction in block, creates new coins |
| Corpse | Transaction containing dead code exceeding Reaper thresholds |
| Elder | One of first 101 MPC ceremony contributors (+1 share) |
| Exorcism | Runtime process that strips hazeable data before writing to disk |
| Exorcist | Archive conversion tool (full archive to hazed) |
| Gatekeeper | 95% uptime requirement for any node rewards |
| Ghost Haze | State of a node with irreversibly stripped archive |
| Ghost Pay | Layer 2 instant payment network |
| Groth16 | Zero-knowledge proof system used for block/payout proofs |
| GSB | Ghost Stripped Block - file format for hazed archives |
| IPC | Inter-Process Communication via Unix socket |
| Merkle Path | Proof of transaction inclusion in block |
| MPC | Multi-Party Computation - ceremony for ZK parameter generation |
| Noise | Encryption protocol for Stratum V2 and P2P consensus |
| Noise_XX | Noise handshake pattern with mutual authentication |
| Reaper | Dead code detection engine for witness scripts |
| Round | Period between blocks (one block = one round) |
| Share | Proof of work below pool difficulty |
| Shroud | Random relay delay for transaction origin protection |
| SV1 | Stratum V1 - legacy JSON-RPC protocol |
| SV2 | Stratum V2 - modern binary protocol with encryption |
| TDP | Template Distribution Protocol - template delivery to SRI |
| Template | Block template from Bitcoin Core |
| Wraith | Privacy mixing protocol in Ghost Pay |

---

*End of Specification*
