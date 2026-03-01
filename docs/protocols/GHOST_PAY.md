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
//| FILE: GHOST_PAY.md                                                                                                   |
//|======================================================================================================================|
```

# Ghost Pay

Layer 2 payment network for instant, low-fee transfers.

## Overview

Ghost Pay is an optional Layer 2 network built on top of Bitcoin Ghost. It provides:
- Instant transfers (10-second virtual blocks)
- Low fees (share of batch mining costs only)
- Privacy (ZK proofs, Ghost Keys)
- Bitcoin settlement (periodic reconciliation)

## Architecture

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

## Fee Structure

| Service | Fee |
|---------|-----|
| Transfer | Share of batch mining costs |
| Wraith Mix | Fixed service fee (500-10,000 sats) + mining cost share |

### Fee Details

Transfers carry no protocol fee. Users pay only their proportional share of the batch mining cost when their L2 state is settled to L1. Mining costs vary with network fee rates and are split across all participants in a reconciliation batch.

## Time Units

### Virtual Blocks

- **Duration**: 10 seconds
- **Purpose**: Fast confirmation for L2 transfers
- **Finality**: Instant within L2

### Epochs

- **Duration**: 2,160 virtual blocks = 6 hours
- **Purpose**: L1 settlement batching
- **Finality**: Bitcoin confirmation

```
Virtual Block Timeline:
│ VB 1 │ VB 2 │ VB 3 │ ... │ VB 2160 │
└───────────────────────────────────────┘
                 Epoch 1
```

## Deposit (Entry to L2)

### Via Wraith (Private)

Best for privacy - breaks the link between your public Bitcoin and L2 balance:

```
1. Join Wraith mixing session
2. Submit public UTXO as input
3. Complete two-phase mixing
4. Receive clean Ghost Lock in L2
5. Balance available for instant transfers
```

### Direct Deposit

Faster but less private:

```
1. Create Ghost Lock on L1
2. Register lock with L2 network
3. Wait for Bitcoin confirmation
4. Balance available in L2
```

## Transfer (Within L2)

Transfers use sender-side NoteSpend proofs for instant, private transfers:

```
1. Wallet selects unspent note, gets Merkle proof, generates GhostNoteSpendWitness
2. Wallet generates Groth16 proof locally (~170ms) via NoteSpendClientProver
3. Submit to ghost-pay POST /api/v1/confidential/transfer
4. ghost-pay verifies via GhostNoteVerifier (~5ms), updates tree
5. ghost-pay relays to ghost-pool POST /api/v1/l2/submit
6. NullifierRouteHandler.submit_external_transfer() validates + mesh broadcast
7. BFT checkpoint (every 10s, 67% threshold) finalizes
8. Finalization callback: ghost-pool POSTs to ghost-pay /api/v1/l2/finalize
```

### Transfer Privacy

| What's Hidden | What's Visible |
|---------------|----------------|
| Sender identity | Transfer occurred |
| Recipient identity | Approximate timing |
| Exact amount | Fee paid |

## Withdrawal (Exit to L1)

### Standard Withdrawal

```
1. Request withdrawal
   ├── Destination L1 address
   ├── Amount
   └── Settlement class (Express/Standard/Economy)

2. Queue for reconciliation batch

3. Settlement transaction broadcast
   └── Your output included

4. Wait for Bitcoin confirmation
   └── Funds on L1
```

### Settlement Classes

| Class | Batching | Wait Time | Fee |
|-------|----------|-----------|-----|
| Express | Every epoch | ~6 hours | Higher |
| Standard | Every 4 epochs | ~24 hours | Medium |
| Economy | Weekly | ~7 days | Lower |

### Emergency Exit

If L2 fails, you can always exit via Ghost Lock recovery:

```
1. Wait for timelock to expire
2. Spend via recovery path
3. Funds directly on L1
```

## State Model

### Note/UTXO Model (February 2026 Redesign)

L2 uses a **note/UTXO model** rather than an account model. Each deposit or transfer creates notes (commitments) stored in a Merkle commitment tree (depth 20, MiMC 82 rounds). Notes are spent by revealing a nullifier and providing a Groth16 proof (GhostNoteSpendCircuit).

```
Commitment Tree (depth-20, ~1M capacity):
├── Note 0: commit(value=1.5M, pubkey, randomness, epoch)
├── Note 1: commit(value=250K, pubkey, randomness, epoch)
├── Note 2: commit(value=10M, pubkey, randomness, epoch)
└── ... (sparse — uses precomputed zero hashes)
```

**Spending a note:**
1. Sender generates GhostNoteSpendCircuit proof locally (~170ms)
2. Proof reveals: nullifier (prevents double-spend), change commitment, recipient commitment
3. NullifierRouteHandler verifies proof (~5ms) and routes by nullifier prefix
4. BFT checkpoint confirms transaction (every 10 seconds, all-node, 67% threshold)

### State Commitments

Each epoch, state root (commitment tree root) is committed to L1:

```
State Root = CommitmentTree.root() (MiMC Merkle root)

L1 Anchor:
OP_RETURN GPRC <version> <epoch> <state_root>
```

This enables:
- Verification of L2 state
- Fraud proofs if needed
- Historical audit

## Privacy Features

### Ghost Keys

Recipients use Ghost Keys for unlinkable addresses:
- Single Ghost ID, unlimited payment addresses
- No address reuse
- Receiver privacy

### ZK Proofs (Sender-Side)

Transfers use sender-side Groth16 proofs (GhostNoteSpendCircuit):
- Senders prove note ownership and balance sufficiency locally (~170ms)
- Validators verify proof only (~5ms), never see amounts or balances
- ~12,675 constraints at depth-20 Merkle tree, MiMC 82 rounds
- Nullifiers prevent double-spending and enable deterministic routing

### Wraith Mixing

Entry via Wraith breaks the link to public Bitcoin:
- Two-phase split-merge mixing (140-500 participants per session)
- Blind signatures for unlinkability
- Coordinator cannot link inputs to outputs
- Distributed coordination — any Ghost node can run sessions
- Fixed service fees (500-10K sats) + at-cost mining
- Jump sessions for key rotation at mining cost only (no service fee)

## Running a Ghost Pay Node

### Requirements

| Requirement | Value |
|-------------|-------|
| Base node | ghost-pool + ghost-core |
| Additional storage | ~2 GB/year |
| Network | Low latency for consensus |
| Uptime | 90%+ for +4 shares |

### Configuration

```toml
[ghost_pay]
enabled = true
l2_port = 9333
epoch_length = 2160

[ghost_pay.fees]
transfer_protocol_fee = 0  # No protocol fee on transfers
```

### Rewards

Nodes running Ghost Pay earn:
- +4 shares in node reward pool
- Share of L2 fee income
- Only among Ghost Pay nodes

## L2 API Endpoints

| Endpoint | Method | Service | Purpose |
|----------|--------|---------|---------|
| `/api/v1/confidential/transfer` | POST | ghost-pay | NoteSpend proof submission from wallets |
| `/api/v1/l2/submit` | POST | ghost-pool | Mesh relay (called by ghost-pay after verification) |
| `/api/v1/l2/finalize` | POST | ghost-pay | Consensus finalization callback (from ghost-pool) |
| `/api/v1/mpc/params` | GET | ghost-pool | MPC parameter download for light wallets |
| `/api/v1/confidential/tree` | GET | ghost-pay | Current commitment tree state (root, next_index) |
| `/api/v1/confidential/shield` | POST | ghost-pay | Shield plaintext balance into commitment |

## ParamsCache Flow

Light wallets use `ParamsCache` to download and cache NoteSpend MPC proving parameters:

```
ParamsCache::ensure_params(host, port)
    │
    ├── Cache hit: ~/.ghost/wallet/params/note_spend_params_current.bin exists (≥100KB)
    │   └── Return cached path immediately
    │
    └── Cache miss:
        ├── GET http://{host}:{port}/api/v1/mpc/params
        ├── Validate response ≥ MIN_PARAMS_SIZE (100KB)
        ├── Atomic write: temp file → rename (prevents partial downloads)
        └── Return cached path
```

- Cache location: `~/.ghost/wallet/params/`
- Filename: `note_spend_params_current.bin`
- Minimum valid size: 100,000 bytes (~1.4MB expected)
- HTTP timeout: 60 seconds

## Finalization Callback

When a BFT checkpoint reaches 67% quorum, ghost-pool invokes the finalization callback to notify ghost-pay:

```rust
type FinalizeFn = Arc<dyn Fn(u64, [u8; 32], u32) + Send + Sync>;
//                       height  state_root  tx_count
```

- Wired when `config.ghost_pay.is_some()` in ghost-pool startup
- ghost-pay applies finalized transfers to its balance tree
- Persists updated state and deletes pending transfer records
- Ensures ghost-pay state stays in sync with L2 consensus

## User Wallet Integration

### Balance View

```
Ghost Pay Wallet:
├── L2 Balance: 1,500,000 sats
├── Pending In: 50,000 sats (1 conf)
├── Pending Out: 0 sats
└── Available: 1,500,000 sats
```

### Actions

| Action | Speed | Confirmations |
|--------|-------|---------------|
| L2 Transfer | ~10 seconds | 1 virtual block |
| Wraith Entry | Hours-days | 2 L1 blocks |
| Direct Deposit | ~1 hour | 6 L1 blocks |
| Withdrawal | 6h - 7d | Settlement class |

## Security Model

### Trust Assumptions

| Component | Trust Level |
|-----------|-------------|
| L1 Bitcoin | Maximally secure |
| L2 State | Validator majority |
| ZK Proofs | Cryptographic |
| Ghost Locks | Self-custody |

### Worst Case: L2 Failure

If L2 completely fails:
1. Ghost Lock timelock expires
2. User spends via recovery path
3. Funds secured on L1

**No funds can be permanently lost** due to L2 issues.

### Fraud Prevention

- ZK proofs prevent invalid transfers
- State commitments enable verification
- Recovery paths ensure self-custody

## Comparison

| Feature | Ghost Pay | Lightning | Liquid |
|---------|-----------|-----------|--------|
| Settlement | Batched | Per-channel | 2-way peg |
| Entry privacy | High (Wraith) | Low | Low |
| Transfer privacy | High (ZK) | Medium | Medium |
| Custody | Non-custodial | Non-custodial | Federated |
| Instant | ~10s | Instant | ~1 min |
| Capacity | Unlimited | Per-channel | Unlimited |

## Common Workflows

### Private Savings

```
1. Wraith mix public Bitcoin into L2
2. Store as Ghost Lock
3. Automatic Jump Lock rotation
4. Withdraw when needed
```

### Regular Payments

```
1. Deposit via Wraith (one-time)
2. Make instant L2 transfers
3. Recipients withdraw or spend in L2
4. Periodic reconciliation settles L1
```

### Merchant Acceptance

```
1. Merchant posts Ghost ID
2. Customer sends L2 transfer
3. Merchant sees payment in ~10s
4. Merchant withdraws in batches (low fees)
```

## Instant Payments

For small payments (~$100 or less), Ghost Pay supports **optimistic confirmation** - showing "Confirmed" immediately while actual settlement happens on the next virtual block.

### How It Works

```
1. Customer initiates payment
2. Merchant wallet checks sender's lock:
   ├── Is lock Active?
   ├── Has 6+ confirmations?
   ├── No pending L1 transactions?
   ├── Low jump urgency?
   └── Sufficient balance?

3. If all conditions pass:
   └── Show "Confirmed ✓" immediately

4. Settlement happens on next virtual block (~10 seconds)
```

### Instant Payment Conditions

For a payment to qualify as instant, the sender's Ghost Lock must meet:

| Condition | Requirement | Why |
|-----------|-------------|-----|
| Active State | Lock is active (not frozen/spent) | Basic validity |
| Confirmations | 6+ L1 confirmations | Deep enough to trust |
| Low Jump Urgency | < 50% through rotation window | Not about to rotate |
| No Pending L1 | No mempool transactions | Can't double-spend |
| No Pending L2 | No pending L2 transfers | Can't overspend |
| Sufficient Balance | Balance >= amount | Has the funds |
| Denomination | Micro or Tiny locks | Risk-appropriate |

### Instant Payment Limits

| Lock Denomination | Max Instant Payment |
|-------------------|---------------------|
| Micro (10k sats) | 10,000 sats |
| Tiny (100k sats) | 100,000 sats |
| Small+ | 100,000 sats (capped) |

**Maximum instant payment is 100,000 sats (~$100)** regardless of lock size.

### Confidence Scores

Each instant capability check returns a confidence score:

| Confidence | Display | Meaning |
|------------|---------|---------|
| 0.95+ | High | Very safe to accept |
| 0.80-0.95 | Medium | Generally safe |
| 0.50-0.80 | Low | Exercise caution |
| < 0.50 | Not instant | Wait for confirmation |

### Example: Coffee Shop

```
Customer: Pays 5,000 sats for coffee
Merchant wallet:
  ├── Checks sender lock: Active, 50 confirmations, low urgency
  ├── Instant capable: Yes (max 100,000 sats, confidence 0.97)
  └── Shows: "Confirmed ✓"

Customer leaves with coffee
Settlement happens ~10 seconds later
```

### Risk Model

Instant payments are "optimistic" - the merchant trusts that:
1. The sender won't double-spend (requires L1 tx + 6 confirmations)
2. Settlement will complete (happens automatically)

**Risk is capped at 100,000 sats** - appropriate for retail transactions.

### For Merchants

Enable instant payments in your wallet:

```bash
# Check if payment can be instant
ghost-wallet check-instant --lock lock_abc123 --amount 5000

# Accept instant payment
ghost-wallet accept-instant --from lock_abc123 --amount 5000

# Output:
# ✓ Instant payment accepted
# Payment ID: 0x1234...
# Settlement block: 847201
# Confidence: 0.97
```

## Related Documentation

- [Ghost Keys](GHOST_KEYS.md) - Recipient addresses
- [Ghost Locks](GHOST_LOCKS.md) - UTXO format
- [Wraith Protocol](WRAITH_PROTOCOL.md) - Private entry
- [Reconciliation](RECONCILIATION.md) - L1 settlement
- [ZK Proofs](ZK_PROOFS.md) - Transfer privacy
