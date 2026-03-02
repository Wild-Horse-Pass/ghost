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
//| FILE: CONSENSUS.md                                                                                                   |
//|======================================================================================================================|
```

# Consensus

Byzantine Fault Tolerant consensus for decentralized pool operation.

## Overview

Bitcoin Ghost uses BFT (Byzantine Fault Tolerant) consensus to coordinate between pool nodes. This enables:
- Decentralized operation (no central server)
- Agreement on share accounting
- Pre-computed payouts (zero block submission delay)
- Tolerance of up to 33% malicious nodes

## BFT Threshold

**67% of nodes must agree for consensus.**

| Total Nodes | Required Agreement | Max Faulty |
|-------------|-------------------|------------|
| 3 | 2 | 1 |
| 10 | 7 | 3 |
| 100 | 67 | 33 |

## What Gets Consensus?

### Share Accounting

All nodes must agree on:
- Which shares were submitted
- Which miner submitted each share
- Difficulty-weighted work totals
- Current ledger balances

### Payout Calculation

Deterministic from share state:
- Top 200 miners and their balances
- Top 100 nodes and their shares
- Treasury allocation
- Coinbase output amounts

### Node State

- Elder status
- Capability verification results
- Uptime tracking

## Pre-Computed Payouts

**Critical design**: Payouts are agreed BEFORE a block is found.

### Why Pre-Compute?

Traditional pools:
```
Block found → Calculate payouts → Vote → Build coinbase → Submit
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                    DELAY = Lost blocks to competitors
```

Bitcoin Ghost:
```
[Continuous consensus on payouts] → Block found → Submit IMMEDIATELY
                                                  ^^^^^^^^^^^^^^^^^^
                                                  ZERO DELAY
```

### How It Works

```
CONTINUOUS PROCESS (every new template):

1. Shares submitted by miners
2. Nodes propagate share proofs (Port 8555)
3. All nodes update local ledger
4. Deterministic calculation → same payouts everywhere
5. Coinbase pre-built with consensus outputs
6. Template distributed to miners

WHEN BLOCK FOUND:

1. Winning share arrives
2. Block ALREADY READY (coinbase pre-built)
3. Submit to Bitcoin network IMMEDIATELY
4. No voting, no delay
```

## P2P Mesh

Nodes communicate via ZeroMQ sockets:

| Port | Pattern | Purpose |
|------|---------|---------|
| 8555 | PUB/SUB | Share propagation |
| 8556 | PUB/SUB | Block announcements |
| 8557 | PUB/SUB | Consensus voting |
| 8558 | PUB/SUB | Health monitoring |
| 8559 | PUB/SUB | Peer discovery |
| 8560 | PUB/SUB | Elder management |
| 8561 | PUB/SUB | Payout proposals |
| 8562 | PUB/SUB | Payout transactions |

### Mesh Topology

Every node connects to every other node:
```
    Node A ◄───────► Node B
       ▲               ▲
       │               │
       ▼               ▼
    Node C ◄───────► Node D
```

Full mesh ensures:
- No single point of failure
- Fast propagation (one hop)
- Direct communication

## Share Propagation

### Share Proof

When a miner submits a share:

```rust
struct ShareProof {
    miner_id: String,
    job_id: [u8; 32],
    nonce: u32,
    ntime: u32,
    extranonce2: Vec<u8>,
    hash: [u8; 32],
    difficulty: f64,
    timestamp: u64,
    node_signature: [u8; 64],
}
```

### Propagation

```
1. Miner submits share to Node A
2. Node A validates share
3. Node A signs share proof
4. Node A broadcasts to all peers (Port 8555)
5. All nodes receive and validate
6. All nodes update their ledger
```

### Conflict Resolution

If nodes receive conflicting shares:
- First-seen wins (by timestamp)
- Signature proves which node received first
- Deterministic tiebreaker: lower hash wins

## Voting (When Needed)

Most consensus is implicit (deterministic calculation). Explicit voting is used for:
- Elder revocation
- Emergency actions
- Network upgrades

### Vote Message

```rust
struct VoteMessage {
    proposal_id: [u8; 32],
    voter_id: [u8; 32],
    vote: bool,
    signature: [u8; 64],
    timestamp: u64,
}
```

### Voting Process

```
1. Proposal created (e.g., revoke Elder #47)
2. Proposal broadcast to mesh
3. Nodes vote yes/no
4. Votes collected until deadline
5. If ≥67% yes: action executed
6. If <67% yes: proposal rejected
```

### Vote Types

| Vote Type | Threshold | Timeout |
|-----------|-----------|---------|
| Elder revocation | 67% | 24 hours |
| Emergency action | 90% | 1 hour |
| Network upgrade | 95% | 7 days |

## Ledger State Machine

### State Transitions

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

### Ledger Entries

```rust
struct LedgerEntry {
    id: String,                // Miner or node ID
    balance_sats: u64,         // Current balance
    shares_this_round: u64,    // Shares in current round
    last_activity: u64,        // Last timestamp
}
```

## Health Monitoring

### Heartbeat

Nodes send heartbeats every 10 seconds:

```rust
struct Heartbeat {
    node_id: [u8; 32],
    height: u64,
    connected_miners: u32,
    uptime_secs: u64,
    timestamp: u64,
    signature: [u8; 64],
}
```

### Failure Detection

| Condition | Action |
|-----------|--------|
| No heartbeat for 30s | Mark as possibly offline |
| No heartbeat for 60s | Mark as offline |
| No heartbeat for 7 days | Eligible for Elder revocation |

### Uptime Calculation

```rust
fn calculate_uptime(node_id: &[u8; 32], window: Duration) -> f64 {
    let samples = db.query(
        "SELECT timestamp FROM heartbeats
         WHERE node_id = ? AND timestamp > ?",
        node_id, now() - window
    );

    let expected = window.as_secs() / 10; // One per 10 seconds
    let received = samples.len();

    received as f64 / expected as f64
}
```

**95% uptime required for any node rewards.**

## Deterministic Calculation

Payouts must be identical across all nodes. This is achieved through:

### Sorted Order

```rust
// Miners sorted by balance (descending), then ID
let top_miners = ledger.miners()
    .sorted_by(|a, b| b.balance.cmp(&a.balance)
        .then(a.id.cmp(&b.id)))
    .take(200);

// Nodes sorted by shares (descending), then ID
let top_nodes = ledger.nodes()
    .sorted_by(|a, b| b.shares.cmp(&a.shares)
        .then(a.id.cmp(&b.id)))
    .take(100);
```

### Fixed-Point Arithmetic

Avoid floating-point inconsistencies:

```rust
// Use basis points (1/100th of a percent)
let pool_fee_bps = 100; // 1%
let treasury_bps = 50;  // 0.5%

let pool_fee = (subsidy * pool_fee_bps) / 10000;
let treasury = (subsidy * treasury_bps) / 10000;
```

### Timestamp Rounding

Round timestamps to avoid tiny differences:

```rust
fn canonical_timestamp(ts: u64) -> u64 {
    ts - (ts % 10) // Round to 10-second boundary
}
```

## Network Partitions

If the network splits:

### During Partition

- Each partition continues operating
- Only partition with >67% can reach consensus
- Minority partition cannot submit blocks

### After Healing

- Nodes exchange state
- Longer chain wins
- Ledger reconciled
- Normal operation resumes

## Configuration

```toml
[consensus]
# BFT threshold (percentage)
threshold = 67

# Consensus timeout (milliseconds)
timeout_ms = 5000

# Heartbeat interval (seconds)
heartbeat_interval = 10

# Minimum uptime for rewards
min_uptime = 0.95

[consensus.ports]
share_propagation = 8555
block_announcement = 8556
voting = 8557
health = 8558
discovery = 8559
```

## Monitoring

### Consensus Health

```bash
# Check consensus status
ghost-cli consensus status

# View connected peers
ghost-cli consensus peers

# Check vote status
ghost-cli consensus votes
```

### Metrics

| Metric | Healthy | Warning |
|--------|---------|---------|
| Peer count | ≥3 | <3 |
| Consensus latency | <1s | >5s |
| Share propagation | <100ms | >500ms |
| Uptime | ≥95% | <95% |

## L2 BFT Checkpoints

### All-Node Checkpoints

Ghost Pay L2 transactions are finalized via all-node BFT checkpoints (no elder dependency):

```
Every 10 seconds:
1. NullifierRouteHandler collects validated transactions
2. Checkpoint proposal broadcast to all nodes
3. All nodes vote (67% threshold)
4. On approval: transactions finalized, commitment tree updated
```

### External Submission Path (ghost-pay → ghost-pool → mesh)

When a wallet submits a NoteSpend transfer to ghost-pay, the verified transaction flows through:

```
Wallet                  ghost-pay                   ghost-pool                All Nodes
  │                        │                           │                        │
  ├─ POST /transfer ──────►│                           │                        │
  │                        ├─ verify proof (~5ms)      │                        │
  │                        ├─ check nullifier          │                        │
  │                        ├─ update local tree        │                        │
  │                        ├─ POST /api/v1/l2/submit ─►│                        │
  │                        │                           ├─ submit_external_     │
  │                        │                           │  transfer()            │
  │                        │                           ├─ handle_transfer()     │
  │                        │                           ├─ broadcast to mesh ───►│
  │                        │                           │                        │
  │                        │                           │   (checkpoint cycle)   │
  │                        │                           │◄── votes ──────────────┤
  │                        │                           ├─ 67% quorum reached   │
  │                        │                           │                        │
  │                        │◄─ POST /api/v1/l2/finalize│                        │
  │                        ├─ apply to balance tree    │                        │
  │                        ├─ persist state            │                        │
  │                        ├─ delete pending           │                        │
```

### NullifierRouteHandler.submit_external_transfer()

Entry point for externally-verified L2 transactions (from ghost-pay):

1. Calls `handle_transfer()` for proof validation and nullifier checking
2. If confirmed, broadcasts `L2TransferConfirmationMessage` to mesh
3. Broadcasts signed `L2TransferBroadcastMessage` for all-node replication
4. Transaction enters `confirmed_pool` on all nodes, awaiting next checkpoint

### Full 8-Step Checkpoint Lifecycle

```
1. Transactions accumulate in confirmed_pool (via broadcast)
2. Every 10 seconds, designated proposer calls propose_checkpoint()
3. Checkpoint includes all confirmed txs; pool is drained
4. Proposal broadcast to all nodes
5. Non-proposers validate via handle_checkpoint_proposal() → produce vote
6. Votes collected via handle_checkpoint_vote()
7. At 67% quorum → checkpoint finalized:
   ├── Nullifiers persisted to DB
   ├── Commitment tree root updated
   ├── Checkpoint record stored (height, epoch, state_root)
   └── FinalizeFn callback invoked: finalize_fn(height, state_root, tx_count)
8. ghost-pay receives finalization → applies transfers, persists, cleans up
```

### FinalizeFn Callback

```rust
type FinalizeFn = Arc<dyn Fn(u64, [u8; 32], u32) + Send + Sync>;
//                       height  state_root  tx_count
```

- Wired at startup when `config.ghost_pay.is_some()`
- Called once per finalized checkpoint with the committed state
- ghost-pay uses this to apply finalized transfers to its balance tree

### EpochManager

The EpochManager handles L2 epoch lifecycle:
- **Tree compaction**: Prunes spent notes from commitment tree
- **Epoch transitions**: Advances epoch counter, triggers settlement
- **Proposer rotation**: Different node proposes each checkpoint
- **Commitment tree**: Maintains depth-20 MiMC Merkle tree

### NullifierRouteHandler
- Validates sender-side Groth16 proofs (GhostNoteSpendCircuit, ~5ms each)
- Routes transactions by nullifier prefix for deterministic validator assignment
- Manages checkpoint proposals and BFT voting
- Produces epoch transition proposals

**Key files:**
- `crates/ghost-consensus/src/nullifier_route_handler.rs`
- `crates/ghost-consensus/src/epoch_manager.rs`

## Related Documentation

- [Architecture](ARCHITECTURE.md) - System overview
- [Mining Pool](MINING_POOL.md) - Share handling
- [Economics](ECONOMICS.md) - Payout calculation
- [Ghost Pay](GHOST_PAY.md) - L2 payment network
- [ZK Proofs](ZK_PROOFS.md) - GhostNoteSpendCircuit details
