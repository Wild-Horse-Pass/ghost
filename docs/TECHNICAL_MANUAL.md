# Bitcoin Ghost - Complete Technical Manual

## Document Information

| Version | Date | Status |
|---------|------|--------|
| 1.0.0 | 2026-02-06 | Complete |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Decentralized Mining](#3-decentralized-mining)
4. [P2P Consensus Network](#4-p2p-consensus-network)
5. [Payment Systems](#5-payment-systems)
6. [Privacy Protocols](#6-privacy-protocols)
7. [Zero-Knowledge Proofs](#7-zero-knowledge-proofs)
8. [Node Capability System](#8-node-capability-system)
9. [Economic Model](#9-economic-model)
10. [Security Architecture](#10-security-architecture)
11. [Database Schema](#11-database-schema)
12. [Configuration Reference](#12-configuration-reference)
13. [Deployment Guide](#13-deployment-guide)

---

# 1. Executive Summary

## 1.1 What is Bitcoin Ghost?

Bitcoin Ghost is a **full Bitcoin node implementation** - similar to Bitcoin Core or Bitcoin Knots, but with significant enhancements. Like its predecessors, Ghost validates blocks, maintains the UTXO set, and participates in the Bitcoin network. Unlike them, Ghost adds:

- **Incentivized Node Operation**: Nodes earn rewards for running valuable features
- **Decentralized Mining**: Built-in mining coordination without centralized pools
- **Ghost Pay L2**: Instant, private payment layer with 10-second settlement
- **Privacy Features**: Silent payments, Wraith mixing, encrypted metadata
- **Policy Sovereignty**: Each node enforces its own mempool/block policies

## 1.2 Comparison with Other Implementations

| Feature | Bitcoin Core | Bitcoin Knots | Bitcoin Ghost |
|---------|--------------|---------------|---------------|
| Full validation | Yes | Yes | Yes |
| Custom policies | Limited | Yes | Yes + BUDS classification |
| Mining support | Solo only | Solo only | Decentralized pool built-in |
| Node incentives | None | None | 5-4-3-2-1 share system |
| L2 payments | No | No | Ghost Pay (10s settlement) |
| Privacy | Basic | Basic | Silent payments + Wraith |
| Light wallets | No | No | GSP backend built-in |

## 1.3 Core Components

| Component | Purpose |
|-----------|---------|
| **ghostd** | Full node daemon (Bitcoin Core derivative) |
| **ghost-pool** | Mining coordination and node incentives |
| **Ghost Pay** | L2 instant payment network |
| **Wraith Protocol** | CoinJoin mixing for private entry |
| **Ghost Locks** | P2TR timelocked outputs |
| **Silent Payments** | Stealth address implementation (BIP-352 style) |
| **GSP** | Light wallet backend server |

## 1.4 Design Principles

1. **Full Node First**: Complete Bitcoin validation - no shortcuts or trust assumptions
2. **Node Sovereignty**: Each node chooses its own mempool/block policy
3. **Incentive Alignment**: Nodes earn rewards for running valuable features
4. **Decentralization**: No central servers, pools, or coordinators required
5. **Privacy by Default**: Silent payments, encrypted metadata, optional mixing
6. **Spam Resistance**: BUDS classification enables intelligent transaction filtering

## 1.5 Why Run a Ghost Node?

Running a Ghost node provides benefits beyond running Bitcoin Core:

| Benefit | Description |
|---------|-------------|
| **Earn Rewards** | Nodes with verified capabilities earn shares of block rewards |
| **Mine Without Pools** | Connect miners directly - no third-party pool required |
| **Keep TX Fees** | Block-finding nodes keep 100% of transaction fees |
| **Instant Payments** | Accept Ghost Pay for 10-second settlement |
| **Policy Control** | Filter spam/inscriptions via BUDS without external tools |
| **Light Wallet Support** | Serve your own light wallets via built-in GSP |

---

# 2. System Architecture

## 2.1 Ghost as a Bitcoin Node

Bitcoin Ghost extends Bitcoin Core with additional capabilities while maintaining full compatibility:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         BITCOIN GHOST NODE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │     ghostd      │  │   ghost-pool    │  │    Ghost Pay    │     │
│  │  (Full Node)    │  │ (Mining + Incen)│  │   (L2 Network)  │     │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘     │
│           │                    │                    │               │
│  ┌────────▼────────────────────▼────────────────────▼────────┐     │
│  │                    Shared State Layer                      │     │
│  │         (UTXO Set, Mempool, Block Database, L2 State)      │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
    Bitcoin P2P          Ghost Mesh           Miners/Wallets
     Network              Network              Connections
```

## 2.2 Network Overview

Ghost nodes form a peer-to-peer network for consensus on mining rewards and L2 state:

```
          ┌────────────────────────────────────────────────────┐
          │                                                    │
 ┌────────▼────────┐          ┌─────────────────┐    ┌────────▼────────┐
 │  Ghost Node 1   │◄────────►│  Ghost Node 2   │◄──►│  Ghost Node N   │
 │ (Full Node +    │          │ (Full Node +    │    │ (Full Node +    │
 │  Mining + L2)   │          │  Mining + L2)   │    │  Mining + L2)   │
 └────────┬────────┘          └────────┬────────┘    └────────┬────────┘
          │                            │                      │
          │      Ghost Consensus Network (ZMQ Mesh)           │
          └────────────────────────────┴──────────────────────┘
          │                            │                      │
 ┌────────▼────────┐          ┌────────▼────────┐    ┌────────▼────────┐
 │     Miners      │          │  Light Wallets  │    │   Ghost Pay     │
 │   (SV1/SV2)     │          │   (via GSP)     │    │     Users       │
 └─────────────────┘          └─────────────────┘    └─────────────────┘
```

## 2.3 Node Components

Each Ghost Node runs:

| Process | Binary | Purpose |
|---------|--------|---------|
| Pool | `ghost-pool` | Mining coordination, share tracking, payouts |
| Core | `ghostd` | Bitcoin node with Ghost extensions |
| GSP | Integrated | Light wallet backend (port 8900) |

## 2.3 Network Ports

### Mining Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 3333 | Stratum V1 | Legacy miner connections (via translator) |
| 34255 | Stratum V1 | Native SV1 connections |
| 34256 | Stratum V2 | SV2 connections (via SRI) |
| 8442 | TDP | Template Distribution Protocol (Noise encrypted) |

### P2P Mesh Ports (ZMQ)

| Port | Protocol | Purpose |
|------|----------|---------|
| 8555 | PUB/SUB | Share propagation |
| 8556 | PUB/SUB | Block announcements |
| 8557 | PUB/SUB | Consensus voting |
| 8558 | PUB/SUB | Health monitoring (10-second pings) |
| 8559 | PUB/SUB | Peer discovery |
| 8560 | PUB/SUB | Elder management |
| 8561 | PUB/SUB | Payout proposals |
| 8562 | PUB/SUB | Payout transactions |
| 8563 | TCP | Noise Protocol encrypted channel |

### Service Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8332 | HTTP | Bitcoin Core RPC |
| 8333 | TCP | Bitcoin P2P network |
| 8800 | HTTP | Ghost Pay API |
| 8900 | WebSocket | GSP light wallet backend |

## 2.4 Data Flow

### Block Template Flow

```
Bitcoin Core (getblocktemplate RPC)
    ↓
ghost-pool (TemplateProcessor)
    ↓
BUDS Classifier (classify transactions)
    ↓
Policy Filter (apply node's policy)
    ↓
Merkle Tree Rebuild (filtered txs)
    ↓
Payout Calculation (miner + node shares)
    ↓
Pre-Consensus Coinbase Construction
    ↓
Distribute to Miners (Stratum/TDP)
```

### Share Submission Flow

```
Miner Submit (job_id, nonce, extranonce2, ntime)
    ↓
Job Validation (exists, not expired)
    ↓
Duplicate Check (LRU cache)
    ↓
Hash Validation (meets difficulty)
    ↓
Timestamp Validation (±2min future, ±10min past)
    ↓
Rate Limit Check (100 shares/sec max)
    ↓
Record in Pending Ledger
    ↓
Broadcast to P2P Mesh (port 8555)
    ↓
If meets network difficulty → Submit Block
```

---

# 3. Decentralized Mining

Ghost eliminates the need for centralized mining pools. Every Ghost node can accept miners directly, and the network coordinates reward distribution via BFT consensus.

## 3.1 How It Differs from Traditional Pools

| Aspect | Centralized Pool | Ghost Decentralized Mining |
|--------|------------------|---------------------------|
| Server | Single point of failure | Any node can accept miners |
| Trust | Pool operator controls payouts | BFT consensus on rewards |
| Fees | Pool takes 1-3% | Node keeps TX fees, 1% to network |
| Policy | Pool decides block content | Each node has sovereignty |
| Custody | Pool holds funds | Direct to miner addresses |

## 3.2 Stratum Support

### Native Stratum V1 (Port 34255)

Direct miner connections using JSON-RPC:

```
1. mining.subscribe → Get extranonce1
2. mining.authorize → Authenticate (payout_address.worker)
3. mining.notify ← Receive jobs
4. mining.submit → Submit shares
```

### Stratum V2 via SRI (Port 34256)

Modern protocol with binary framing and encryption:

```
Bitcoin Core
    ↓
ghost-pool (TDP Server, port 8442)
    ↓ Noise encrypted
SRI Pool (pool-sv2)
    ├→ SV2 Miners (modern ASICs)
    └→ SRI Translator → SV1 Miners (legacy)
```

## 3.2 Template Distribution Protocol (TDP)

Ghost-pool acts as a TDP server for the SRI stack:

- **Port**: 8442 (TCP with Noise Protocol encryption)
- **Transport**: Noise_XX handshake for forward secrecy
- **Content**: Pre-filtered block templates with Ghost coinbase

Benefits:
- Ghost retains full template control
- BUDS policy applied before distribution
- SV2 support via SRI without protocol changes
- Backward compatible with SV1 via translator

## 3.3 Share Validation

### Security Checks

| Check | Purpose | Threshold |
|-------|---------|-----------|
| Job existence | Prevent stale submissions | Template ID tracking |
| Nonce uniqueness | Prevent duplicate shares | LRU cache |
| Hash validation | Verify PoW | Pool difficulty |
| Timestamp bounds | Prevent replay attacks | ±2min future, ±10min past |
| Rate limiting | Prevent spam | 100 shares/sec/miner |
| Work anomaly | Detect inflation | 1.0x network difficulty max |

### Payout Commitment

Miners commit to payout addresses using HMAC-SHA256:

```
commitment = HMAC-SHA256(secret, address || timestamp)
```

- Prevents address spoofing after share submission
- Expires after configured period
- Clock manipulation detected via monotonic time

## 3.4 Difficulty Adjustment (Vardiff)

Per-miner difficulty targeting ~6 shares/minute:

| Parameter | Value |
|-----------|-------|
| Target rate | 6 shares/min |
| Min difficulty | 0.001 |
| Max difficulty | 1,000,000 |
| Retarget interval | 60 seconds |
| Max change factor | 4.0x |
| Min shares for retarget | 10 |

## 3.5 Round Management

Rounds track share accounting between blocks:

```rust
struct Round {
    id: u64,
    block_height: u64,
    shares: HashMap<MinerId, u64>,  // work per miner
    total_work: u64,
    started_at: Instant,
}
```

When a block is found:
1. Snapshot round shares
2. Calculate payout distribution
3. Create new round
4. Continue accepting shares

## 3.6 Pre-Consensus Coinbase

**Key Innovation**: Coinbase outputs are computed BEFORE a winning share arrives.

Traditional flow (with delay):
```
Winning share → Calculate payouts → Vote → Build coinbase → Submit
                                     ↑
                              CONSENSUS DELAY
```

Ghost flow (no delay):
```
[Pre-computed coinbase] → Winning share → Submit IMMEDIATELY
```

How it works:
1. Every 5 minutes (or template change): nodes calculate deterministic payouts
2. Same inputs → same outputs (no voting needed)
3. Templates distributed with pre-built coinbase
4. When block found: submit immediately, no consensus delay

---

# 4. P2P Consensus Network

## 4.1 ZMQ Mesh Architecture

The consensus layer uses ZeroMQ PUB/SUB sockets with topic-based routing:

```rust
pub struct MeshNetwork {
    identity: Arc<NodeIdentity>,
    peers: RwLock<HashMap<NodeId, Peer>>,
    dedup_cache: RwLock<DeduplicationCache>,
    handlers: Vec<Arc<dyn MessageHandler>>,
}
```

### Message Envelope

```rust
pub struct MessageEnvelope {
    pub msg_type: MessageType,
    pub sender: NodeId,                 // Ed25519 public key
    pub timestamp: u64,                 // Unix milliseconds
    pub sequence: u64,                  // Monotonic counter
    pub signature: [u8; 64],            // Ed25519 signature
    pub payload: Vec<u8>,               // JSON message
}
```

Signature formula:
```
signature = Sign(payload_bytes || sequence_le_bytes)
```

## 4.2 Message Types

| Type | Topic | Purpose |
|------|-------|---------|
| Vote | vote | BFT consensus votes |
| EquivocationProof | equivoc | Byzantine behavior evidence |
| ShareProof | share | Share propagation |
| BlockFound | block | Block announcements |
| HealthPing | health | Node liveness (10 sec) |
| Discovery | discovery | Peer discovery |
| ElderUpdate | elder | Elder list changes |
| PayoutProposal | payout | Payout distribution proposals |
| VerificationResult | verify | Capability verification |
| ZkBlockProposal | zkproposal | ZK block proposals |
| ZkVote | zkvote | ZK consensus votes |
| MpcContribution | mpc | MPC ceremony messages |

## 4.3 Replay Attack Prevention

Three-layer defense:

### Layer 1: Deduplication Window
- Tracks `(sender_id, sequence_number)` pairs
- 60-second window, 100,000 message capacity
- FIFO eviction when full

### Layer 2: Timestamp Validation
- Messages must be within 5 minutes of current time
- Checked BEFORE deduplication

### Layer 3: Sequence Monotonicity
- Per-sender tracking of highest sequence seen
- Rejects `sequence <= highest_seen`
- Handles wrap-around via epoch tracking

## 4.4 BFT Voting

### Voting Session

```rust
pub struct VotingSession {
    round_id: RoundId,
    proposal_hash: [u8; 32],
    eligible_voters: HashSet<NodeId>,  // From canonical elder list
    votes: HashMap<NodeId, Vote>,
    timeout_ms: u64,
}
```

### Threshold Calculation

- Minimum voters: 4 (for f=1 Byzantine tolerance)
- Consensus threshold: 67% (ceiling)
- Examples:
  - 4 voters → 3 required
  - 10 voters → 7 required
  - 100 voters → 67 required

### Vote Structure

```rust
pub struct Vote {
    voter: NodeId,
    approve: bool,
    signature: [u8; 64],
    timestamp: u64,
}
```

Signing formula:
```
message = SHA256(
    b"GhostVote/v1" ||
    round_id_le_bytes ||
    proposal_hash ||
    voter_id ||
    [approve_byte]
)
signature = Sign(message)
```

### Equivocation Detection

When a voter sends conflicting votes (approve then reject):
1. Both signatures verified
2. `VoteEquivocationProof` created with both votes
3. Broadcast to network
4. Voter banned via BanManager

## 4.5 Health Monitoring

### Health Ping Contents

```rust
pub struct HealthPing {
    node_id: NodeId,
    public_address: String,
    block_height: u32,
    round_id: u64,
    capabilities: NodeCapabilities,
    miner_count: u32,
    timestamp: u64,
    pow_proof: Option<(nonce, difficulty)>,
}
```

- Broadcast every 10 seconds
- PoW proof for Sybil resistance
- Rate limited: 10 burst, 1/second sustained

## 4.6 Ban Management

### Ban Reasons and Durations

| Reason | Base Duration | Description |
|--------|---------------|-------------|
| Equivocation | 24 hours | Conflicting votes |
| RateLimitExceeded | 1 hour | Too many messages |
| InvalidMessages | 30 minutes | Malformed messages |
| ProtocolViolation | 24 hours | Protocol violations |

### Escalation for Repeat Offenders

Multiplier formula: `2^(effective_count - 1)`, capped at 16x

- 1st ban: 1x base duration
- 2nd ban: 2x base duration
- 3rd ban: 4x base duration
- 4th ban: 8x base duration
- 5th+ ban: 16x base duration

Decay: Count decreases by 1 for each 7-day period since last ban.

## 4.7 Noise Protocol Encryption

Sensitive messages use Noise_XX for encryption:

**Plaintext (broadcast)**: Discovery, HealthPing
**Encrypted (point-to-point)**: Vote, ShareProof, BlockFound, PayoutProposal, MpcContribution

Configuration:
```rust
pub struct MeshConfig {
    noise_enabled: bool,        // Default: true
    noise_port: u16,            // Default: 8563
    noise_keypair_path: Option<PathBuf>,
}
```

## 4.8 Canonical Elder List

### Elder Entry

```rust
pub struct ElderEntry {
    node_id: NodeId,
    registered_epoch: u64,
    pow_nonce: u64,
    pow_difficulty: u32,
    first_seen: u64,
    uptime_at_registration: f64,
}
```

### Registration Requirements

1. Valid PoW proof (nonce verifies against node ID)
2. 95%+ uptime over 7 days
3. >67% approval from previous epoch's elders

### List Structure

```rust
pub struct CanonicalElderList {
    epoch: u64,
    elders: Vec<ElderEntry>,
    merkle_root: [u8; 32],
    approval_signatures: Vec<ElderApproval>,
    activated_at: u64,
}
```

---

# 5. Payment Systems

## 5.1 Silent Payments (BIP-352 Style)

### Ghost Keys

```rust
pub struct GhostKeys {
    scan_secret: SecretKey,   // Detects payments
    spend_secret: SecretKey,  // Spends funds
}

pub struct GhostId {
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
}
```

### Encoding

Bech32m with network-specific HRPs:
- Mainnet: `ghost1...`
- Testnet: `tghost...`
- Signet: `sghost...`
- Regtest: `rghost...`

### Payment Derivation (v2)

```
1. Generate ephemeral keypair
2. ECDH: S = SHA256(ephemeral_secret * scan_pubkey)
3. Tweak: t = SHA256("ghost/silent-payment/v2" || S || k)
4. Output: P = spend_pubkey + tweak*G
5. Store ephemeral pubkey in OP_RETURN with "GPGL" marker
```

### Scanning

```rust
pub struct PaymentDetector {
    ghost_keys: GhostKeys,
    max_k: u32,  // Default: 10, recovery: up to 10,000
}
```

- Constant-time comparison (prevents timing attacks)
- Parallel batch scanning with Rayon
- Returns: output pubkey, index, k value, tweak, amount

## 5.2 Ghost Pay L2

### Architecture

```
L1 (Bitcoin)
    │
    │ Deposits (Wraith or Direct)
    ▼
┌─────────────────────────────────┐
│    Ghost Pay L2                 │
├─────────────────────────────────┤
│ Virtual Blocks: 10 seconds      │
│ Epochs: 2,160 VBs = 6 hours     │
│ State: Merkle tree of balances  │
└─────────────────────────────────┘
    │
    │ Withdrawals (Settlement)
    ▼
L1 (Bitcoin)
```

### Fee Structure

| Operation | Fee |
|-----------|-----|
| Transfer | 10 sats + 0.1% |
| Wraith mixing | 1% (covers L1 tx fees) |

### Transfer Process

1. Create transfer with ZK proof of balance
2. Submit to L2 validators
3. Proof verified, contents hidden
4. State updated atomically
5. Confirmation in ~10 seconds

## 5.3 Light Wallet

### Architecture

```rust
pub struct LightWallet {
    master_key: Arc<RwLock<MasterKey>>,
    gsp_client: Arc<GspClient>,
    cache: Arc<WalletCache>,
    config: WalletConfig,
}
```

### Key Features

- BIP-39 mnemonic (24 words)
- Local signing (keys never leave device)
- SQLite cache for offline access
- WebSocket connection to GSP

### GSP (Ghost Service Provider)

Backend service allowing light wallets to operate without full nodes:

- Port 8900 (HTTP + WebSocket)
- Schnorr proof-based authentication
- JWT sessions after auth
- Real-time balance updates
- BIP-157 filter support

## 5.4 Reconciliation (L1 Settlement)

### Settlement Process

```
L2 Balance
    ↓
Settlement Request (ownership proof)
    ↓
Batch Formation (10-1000 settlements)
    ↓
Merkle Commitment
    ↓
L1 Transaction
    ↓
Dispute Window (144 blocks)
    ↓
Finalization
```

### Ownership Proof

```rust
pub struct OwnershipProof {
    signature: [u8; 64],  // Schnorr
    pubkey: [u8; 32],     // X-only
}
```

Domain: `GhostSettlement/Ownership/v1`

### Batch Rules

| Parameter | Value |
|-----------|-------|
| Minimum batch size | 10 |
| Maximum batch size | 1000 |
| Batch timeout | 6 hours |
| Minimum settlement | 10,000 sats |

---

# 6. Privacy Protocols

## 6.1 Wraith Protocol (CoinJoin Mixing)

### Overview

Two-phase split-merge mixing for private entry:

```
Phase 1 (Split): N inputs → 10N intermediate Ghost Locks
Phase 2 (Merge): 10N intermediates → N final Ghost Locks
```

### Denominations

| Denomination | Satoshis | Fee (1%) |
|--------------|----------|----------|
| Micro | 10,000 | 100 |
| Small | 1,000,000 | 10,000 |
| Medium | 10,000,000 | 100,000 |
| Large | 100,000,000 | 1,000,000 |

### Participant Tiers

| Tier | Balance Range | Min Participants |
|------|---------------|------------------|
| Micro | 0.001-0.01 BTC | 400 |
| Small | 0.01-0.1 BTC | 340 |
| Medium | 0.1-1 BTC | 290 |
| Standard | 1-10 BTC | 250 |
| Large | 10-50 BTC | 195 |
| Whale | 50+ BTC | 160 |

### Session Lifecycle

```
WaitingForParticipants (24h timeout)
    ↓
CollectingInputs (2h timeout)
    ↓
ExecutingPhase1 (1h timeout)
    ↓
WaitingPhase1Confirmation (6h timeout)
    ↓
ExecutingPhase2 (1h timeout)
    ↓
WaitingPhase2Confirmation (6h timeout)
    ↓
Completed / Failed / Refunded
```

### Blind Signatures

Schnorr blind signatures for unlinkability:

1. **Nonce Generation**: Coordinator creates R = k*G
2. **Blinding**: Participant computes R' = R + α*G + β*X
3. **Signing**: Coordinator returns s = k + c'*x
4. **Unblinding**: Participant computes s' = s + α

Security properties:
- Coordinator cannot link request to signature
- Nonces bound to specific participants
- Token replay detection (14-day cache)

### Encrypted OP_RETURN Markers

Wraith transactions use encrypted markers instead of plain-text:

```rust
fn generate_encrypted_marker(phase: u8, session_id: &[u8; 32]) -> [u8; 32]
```

Makes Wraith transactions indistinguishable from random on-chain.

## 6.2 Ghost Locks

### Structure

P2TR outputs with two spending paths:

1. **Key Path**: Normal spend with Ghost key (efficient)
2. **Script Path**: Recovery after timelock (emergency)

### Denominations

| Denomination | Satoshis |
|--------------|----------|
| Micro | 10,000 |
| Tiny | 100,000 |
| Small | 1,000,000 |
| Medium | 10,000,000 |
| Large | 100,000,000 |
| XL | 1,000,000,000 |

### Timelock Tiers

| Tier | Duration | Blocks |
|------|----------|--------|
| Short | 6 months | ~26,280 |
| Standard | 1 year | ~52,560 |
| Long | 2 years | ~105,120 |

## 6.3 Jump Locks (Risk-Tiered Key Rotation)

Automatic key rotation based on balance-at-risk:

| Risk Tier | Balance | Rotation Period |
|-----------|---------|-----------------|
| Low | < 0.1 BTC | 30 days |
| Medium | 0.1-1 BTC | 14 days |
| High | > 1 BTC | 7 days |

## 6.4 Metadata Encryption

Payment metadata (labels + memos) encrypted with ChaCha20-Poly1305:

- Fixed 80-byte ciphertext (prevents size fingerprinting)
- HKDF key derivation with domain separation
- Label: 4 bytes, Memo: up to 59 bytes UTF-8

---

# 7. Zero-Knowledge Proofs

## 7.1 Groth16 SNARKs

Ghost uses Groth16 proofs over BLS12-381:

```rust
pub struct BlockProof {
    proof: Vec<u8>,  // 192 bytes exactly
    // A: 48 bytes (G1), B: 96 bytes (G2), C: 48 bytes (G1)
}
```

### Proof Types

| Type | Purpose | Public Inputs |
|------|---------|---------------|
| Block Proof | Block validity | prev_root, new_root |
| Payout Proof | Distribution validity | epoch, totals |

### Proving Modes

**Legacy Mode**: Proves payment validity only
**Full ZK Mode**: Proves complete state transitions (no re-execution needed)

## 7.2 Circuit Design

### BlockCircuit

```rust
pub struct BlockCircuit<F: PrimeField> {
    payments: Vec<PaymentCircuit<F>>,
    state_transitions: Vec<PaymentStateTransitionCircuit<F>>,
    prev_state_root: Option<F>,
    new_state_root: Option<F>,
}
```

Synthesize logic:
- Empty blocks: `prev_root == new_root`
- Full ZK: Chain state transitions through all payments

### PaymentCircuit

Proves single payment validity:
- Sender balance ≥ amount (no underflow)
- Sender balance after = before - amount
- Recipient balance after = before + amount
- No overflow

### PayoutCircuit

Proves payout distribution:
- Sum preservation: miners + nodes + treasury = total
- All amounts fit in 64 bits
- Metadata commitment (epoch, counts)

## 7.3 MPC Ceremony

### Rolling MPC Architecture

Parameters improve as elders contribute:

- Elder 1: Genesis parameters
- Elders 2-100: Each contribution activates immediately
- Elder 101: Parameters **ossify permanently**
- Elders 102+: No contribution (ceremony closed)

**1-of-N Security**: Only ONE honest participant needed.

### CeremonyManager

```rust
pub struct CeremonyManager {
    state: RwLock<CeremonyState>,
    files: ParameterFiles,
    block_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
    payout_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
}

pub struct CeremonyState {
    contribution_count: u32,      // 0-101
    current_params_hash: [u8; 32],
    is_ossified: bool,
    ceremony_id: [u8; 32],        // Unique per ceremony
}
```

### Time-Based Ossification

Ceremony auto-ossifies 30 days after genesis:
- Prevents indefinite contribution windows
- Enforced: `now - genesis_timestamp >= 30 days`

### Contribution Structure

```rust
pub struct MpcContribution {
    position: u32,
    prev_params_hash: [u8; 32],  // Chain link
    new_params_hash: [u8; 32],
    proof: ContributionProof,    // Schnorr PoK for tau, alpha, beta
}
```

### Toxic Waste Security

```rust
impl Drop for ToxicWaste {
    fn drop(&mut self) {
        self.tau_bytes.zeroize();    // Volatile write
        self.alpha_bytes.zeroize();
        self.beta_bytes.zeroize();
        compiler_fence(SeqCst);      // Memory barrier
    }
}
```

### Parameter Files

```
mpc_params/
├── block_params_v0.bin      # Genesis
├── block_params_v1.bin      # After elder 2
├── ...
├── block_params_v100.bin    # After elder 101 (ossified)
├── block_params_current.bin # Symlink to latest
├── payout_params_v*.bin
└── block_vk.bin, payout_vk.bin
```

## 7.4 Verification

```rust
pub struct BlockVerifier {
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
}
```

- **With VK**: Cryptographic verification (~10ms)
- **Without VK**: Fail closed (reject all proofs in production)

Subgroup checks performed on deserialization to prevent invalid curve attacks.

---

# 8. Node Capability System

## 8.1 The 5-4-3-2-1 Share Model

Nodes earn shares based on **verified** capabilities:

| Capability | Shares | Description |
|------------|--------|-------------|
| Archive Mode | +5 | Full blockchain (600GB+), fast retrieval |
| Ghost Pay | +4 | L2 payment network operation |
| Public Mining | +3 | Open Stratum port to miners |
| Bitcoin Pure | +2 | BUDS policy enforcement |
| Elder Status | +1 | First 101 nodes (non-renewable) |

**Maximum**: 15 shares per node

## 8.2 Gatekeeper Requirement

Before ANY shares count:
- **95% uptime over trailing 7 days**
- Expected: 60,480 heartbeats (1 per 10 sec)
- Minimum: 57,456 (95%)

Below 95% → 0 shares, no rewards.

## 8.3 Verification System

### Periodic Verification (Every 5 Minutes)

```
VerificationTask::verify_cycle()
  ├─ Select 3 random peers
  └─ For each peer:
      ├─ Query /health → discover claimed capabilities
      └─ Issue challenges:
          ├─ Archive: Random block retrieval
          ├─ Policy: Transaction classification
          ├─ Stratum: Port accessibility
          └─ GhostPay: L2 block lookup
```

### Challenge Types

| Capability | Challenge | Pass Rate |
|------------|-----------|-----------|
| Archive | Random block height retrieval | 95% |
| Ghost Pay | L2 state Merkle proof | 90% |
| Public Mining | Stratum handshake | 95% |
| Bitcoin Pure | Tx classification | 95% |

### Qualification Requirements

1. 10+ total challenges
2. Required pass rate (per capability)
3. 10+ unique challengers (Sybil prevention)
4. 95% uptime (gatekeeper)

### Database Tables

```sql
archive_challenges(node_id, challenger_id, block_height, passed, timestamp)
policy_challenges(node_id, challenger_id, expected_tier, actual_tier, passed, timestamp)
stratum_challenges(node_id, challenger_id, connected, latency_ms, passed, timestamp)
ghostpay_challenges(node_id, challenger_id, response_valid, passed, timestamp)
```

## 8.4 Payout Integration

When block found:

```rust
// Get VERIFIED capabilities only
let qualified_shares = qualification_provider.get_all_qualified_nodes();

// Replace claimed with verified
data.node_shares = qualified_shares;

// Calculate payouts with verified capabilities
let proposal = creator.create_proposal(data)?;
```

---

# 9. Economic Model

## 9.1 Block Reward Distribution

| Component | Recipient | Percentage |
|-----------|-----------|------------|
| TX Fees (100%) | Block-finding node | 100% |
| Subsidy (99%) | Miners | Proportional to shares |
| Pool Fee (1%) | Treasury + Nodes | Split |

## 9.2 Pool Fee Breakdown

The 1% pool fee is split:

| Component | Percentage | Recipient |
|-----------|------------|-----------|
| Treasury | Variable | Development fund |
| Node Rewards | Remainder | Top 100 nodes by shares |

## 9.3 Miner Payouts

- Top 200 miners by work receive payouts
- Proportional to difficulty-weighted shares
- Dust (< 546 sats) redistributed to node pool

## 9.4 Node Payouts

- Top 100 nodes by verified capability shares
- Proportional to share count (0-15 per node)
- Dust redistributed to top capability node

## 9.5 Dust Handling

No satoshis are lost:
- Miner dust → Node reward pool
- Node dust → Top capability node
- TX fee dust → Block-finding node

---

# 10. Security Architecture

## 10.1 Mining Security

| Threat | Mitigation |
|--------|------------|
| Stale shares | Dual validation (wall clock + monotonic) |
| Address spoofing | HMAC-SHA256 payout commitment |
| Share spam | Rate limiting (100/sec/miner) |
| Work inflation | 1.0x network difficulty cap |
| TOCTOU races | Snapshot-based payout hash capture |

## 10.2 P2P Security

| Threat | Mitigation |
|--------|------------|
| Message replay | 3-layer defense (dedup + timestamp + sequence) |
| Memory exhaustion | 100k message cap, per-sender limits |
| Cache flushing | Per-sender tracking (10k max each) |
| Topic spoofing | Topic validation against envelope type |
| Plaintext sniffing | Noise Protocol encryption |

## 10.3 Consensus Security

| Threat | Mitigation |
|--------|------------|
| Vote forgery | Ed25519 signatures with round_id |
| Equivocation | Detection + proof broadcast + ban |
| Weak voter set | 7-day uptime + PoW requirement |
| Centralized elders | BFT approval from >67% of previous epoch |

## 10.4 Cryptographic Security

| Threat | Mitigation |
|--------|------------|
| Key material leakage | Zeroize with volatile writes |
| Timing attacks | Constant-time comparisons |
| RNG failure | Shannon entropy validation |
| Signature replay | Domain separation + ceremony binding |

## 10.5 ZK Security

| Threat | Mitigation |
|--------|------------|
| Forged proofs | Groth16 soundness + MPC ceremony |
| Simulated proofs | Runtime check + feature gate |
| Cross-ceremony replay | Unique ceremony_id binding |
| Indefinite ceremony | 30-day auto-ossification |
| Parameter corruption | Magic markers + version gaps |

---

# 11. Database Schema

## 11.1 Core Tables

### miners
```sql
CREATE TABLE miners (
    id INTEGER PRIMARY KEY,
    miner_id TEXT UNIQUE NOT NULL,
    payout_address TEXT NOT NULL,
    total_shares INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);
```

### nodes
```sql
CREATE TABLE nodes (
    id INTEGER PRIMARY KEY,
    node_id TEXT UNIQUE NOT NULL,
    public_address TEXT,
    capabilities INTEGER DEFAULT 0,
    uptime_percent REAL DEFAULT 0,
    first_seen INTEGER NOT NULL
);
```

### rounds
```sql
CREATE TABLE rounds (
    id INTEGER PRIMARY KEY,
    round_id TEXT UNIQUE NOT NULL,
    block_height INTEGER NOT NULL,
    block_hash TEXT,
    total_work INTEGER DEFAULT 0,
    payout_status TEXT DEFAULT 'pending',
    created_at INTEGER NOT NULL
);
```

### shares
```sql
CREATE TABLE shares (
    id INTEGER PRIMARY KEY,
    round_id TEXT NOT NULL,
    miner_id TEXT NOT NULL,
    work INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (round_id) REFERENCES rounds(round_id)
);
```

## 11.2 Challenge Tables

### archive_challenges
```sql
CREATE TABLE archive_challenges (
    id INTEGER PRIMARY KEY,
    node_id TEXT NOT NULL,
    challenger_id TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    block_hash TEXT,
    passed INTEGER NOT NULL,
    timestamp INTEGER NOT NULL
);
```

### policy_challenges
```sql
CREATE TABLE policy_challenges (
    id INTEGER PRIMARY KEY,
    node_id TEXT NOT NULL,
    challenger_id TEXT NOT NULL,
    challenge_type TEXT NOT NULL,
    expected_tier INTEGER NOT NULL,
    actual_tier INTEGER NOT NULL,
    passed INTEGER NOT NULL,
    timestamp INTEGER NOT NULL
);
```

## 11.3 Elder Tables

### canonical_elder_lists
```sql
CREATE TABLE canonical_elder_lists (
    epoch INTEGER PRIMARY KEY,
    merkle_root BLOB NOT NULL,
    elder_count INTEGER NOT NULL,
    activated_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
```

### elder_entries
```sql
CREATE TABLE elder_entries (
    id INTEGER PRIMARY KEY,
    epoch INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    registered_epoch INTEGER NOT NULL,
    pow_nonce INTEGER NOT NULL,
    pow_difficulty INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    FOREIGN KEY (epoch) REFERENCES canonical_elder_lists(epoch)
);
```

---

# 12. Configuration Reference

## 12.1 Pool Configuration (pool.toml)

```toml
[pool]
# Mining mode: "public_pool", "private_pool", "private_solo"
mining_mode = "public_pool"

# Node identity
signing_key = "64_hex_chars"

# Network
listen_address = "0.0.0.0"
stratum_port = 34255
tdp_port = 8442

# Bitcoin Core RPC
bitcoin_rpc_url = "http://127.0.0.1:8332"
bitcoin_rpc_user = "ghost"
bitcoin_rpc_password = "password"

# P2P Mesh
mesh_listen_address = "0.0.0.0"
mesh_base_port = 8555

# Database
data_dir = "/var/lib/ghost"

[payout]
# Treasury address (mainnet)
treasury_address = "bc1q..."

# Minimum payout (satoshis)
min_payout = 10000

[difficulty]
# Vardiff target (shares per minute)
target_shares_per_minute = 6

# Difficulty bounds
min_difficulty = 0.001
max_difficulty = 1000000
```

## 12.2 Environment Variables

```bash
# Production ZK parameters
ZK_PARAMS_PATH=/var/lib/ghost/mpc_params

# Logging
RUST_LOG=info,ghost_pool=debug

# Bitcoin network
BITCOIN_NETWORK=signet
```

---

# 13. Deployment Guide

## 13.1 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Disk | 100 GB SSD | 1 TB NVMe |
| Network | 100 Mbps | 1 Gbps |

## 13.2 Installation

```bash
# Build from source
cargo build --release -p ghost-pool

# Install
sudo cp target/release/ghost-pool /opt/ghost/bin/

# Create config
sudo mkdir -p /etc/ghost
sudo cp config/mainnet.toml /etc/ghost/pool.toml
```

## 13.3 Service Configuration

```ini
# /etc/systemd/system/ghost-pool.service
[Unit]
Description=Ghost Pool Node
After=network.target bitcoind.service

[Service]
Type=simple
User=ghost
ExecStart=/opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 13.4 Production Checklist

- [ ] Bitcoin Core synced and running
- [ ] Node identity key generated
- [ ] MPC parameters downloaded/verified
- [ ] Firewall configured (ports 8555-8563, 34255)
- [ ] TLS certificates for public endpoints
- [ ] Monitoring configured (logs, metrics)
- [ ] Backup strategy for database

## 13.5 Monitoring Commands

```bash
# Check service status
systemctl status ghost-pool

# View logs
journalctl -u ghost-pool -f

# Check peer connections
curl http://localhost:8800/api/v1/health

# Check mining stats
curl http://localhost:8800/api/v1/stats
```

---

# Appendix A: Glossary

| Term | Definition |
|------|------------|
| **BFT** | Byzantine Fault Tolerant - consensus that tolerates 1/3 malicious nodes |
| **BUDS** | Bitcoin Unidentified Dust Spam - transaction classification system |
| **Elder** | First 101 registered nodes with special status |
| **Ghost ID** | Silent payment address (scan + spend pubkeys) |
| **Ghost Lock** | P2TR output with recovery timelock |
| **GSP** | Ghost Service Provider - light wallet backend |
| **MPC** | Multi-Party Computation - ceremony for ZK parameter generation |
| **TDP** | Template Distribution Protocol - template delivery to SRI |
| **Wraith** | CoinJoin mixing protocol for private entry |

# Appendix B: Port Reference

| Port | Protocol | Service |
|------|----------|---------|
| 3333 | TCP | Stratum V1 (translator) |
| 8332 | HTTP | Bitcoin Core RPC |
| 8333 | TCP | Bitcoin P2P |
| 8442 | TCP | TDP (Noise encrypted) |
| 8555-8562 | ZMQ | P2P mesh |
| 8563 | TCP | Noise encrypted channel |
| 8800 | HTTP | Ghost Pay API |
| 8900 | WS | GSP WebSocket |
| 34255 | TCP | Native Stratum V1 |
| 34256 | TCP | Stratum V2 (SRI) |

# Appendix C: File Paths

| Path | Purpose |
|------|---------|
| `/opt/ghost/bin/ghost-pool` | Pool binary |
| `/etc/ghost/pool.toml` | Configuration |
| `/var/lib/ghost/ghost.db` | SQLite database |
| `/var/lib/ghost/node.key` | Node identity |
| `/var/lib/ghost/mpc_params/` | ZK parameters |
| `/var/lib/bitcoin/` | Bitcoin Core data |

---

*Document generated: 2026-02-06*
*Bitcoin Ghost v1.6.0*
