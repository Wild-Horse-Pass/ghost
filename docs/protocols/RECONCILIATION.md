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
//| FILE: RECONCILIATION.md                                                                                              |
//|======================================================================================================================|
```

# Reconciliation

L1 settlement system for Ghost Pay L2.

## Overview

Reconciliation is the process of settling L2 state changes to the Bitcoin L1 blockchain. Users can either:
- **Exit to L1**: Withdraw funds completely from Ghost Pay
- **Roll forward**: Keep funds in L2 with updated state commitment

Settlement happens in batches for efficiency, with different service classes offering trade-offs between speed and cost.

## Settlement Classes

| Class | Batching | Min Participants | Max Wait | Fee Level |
|-------|----------|------------------|----------|-----------|
| Express | Every epoch (6h) | 10 | 1 epoch | Higher |
| Standard | Every 4 epochs (24h) | 25 | 4 epochs | Medium |
| Economy | Weekly | 50 | 28 epochs | Lower |

### Choosing a Class

- **Express**: Need funds on L1 quickly, willing to pay premium
- **Standard**: Normal withdrawals, balanced cost/speed
- **Economy**: Not time-sensitive, optimize for lowest fees

## How It Works

### Epoch Cycle

```
Epoch 0 ─────────────────────────────────────────────────────
    │
    │ L2 Transfers (instant, off-chain)
    │ Wraith mixing sessions
    │ Jump lock rotations
    ▼
Epoch 1 (6 hours later) ─────────────────────────────────────
    │
    │ Calculate net balance changes
    │ Batch withdrawal requests
    │ Create settlement transaction
    ▼
Settlement TX broadcast ─────────────────────────────────────
    │
    │ Wait for confirmation
    ▼
Next Epoch begins ───────────────────────────────────────────
```

### Settlement Transaction Structure

```
L2 Settlement TX:
├── Inputs:
│   ├── L2 pool UTXO (previous epoch state)
│   └── Fee input (from L2 fee pool)
├── Outputs:
│   ├── Withdrawal outputs (users exiting L2)
│   │   ├── User A: 0.5 BTC to their L1 address
│   │   ├── User B: 0.1 BTC to their L1 address
│   │   └── ...
│   ├── Change output (remaining L2 balance)
│   └── OP_RETURN: L2 state commitment anchor
└── Signatures: Coordinator + participant threshold
```

## Exit to L1 (Withdrawal)

### User Flow

```
1. User requests withdrawal in wallet
   - Specify amount
   - Provide L1 destination address
   - Choose settlement class

2. Request queued for next batch
   - Express: Next epoch
   - Standard: Within 24 hours
   - Economy: Within 7 days

3. Batch executes at epoch boundary
   - User's withdrawal included in settlement TX
   - Funds sent to L1 address

4. Wait for confirmation
   - 1-6 blocks depending on fee level
   - User notified when confirmed
```

### Minimum Withdrawal

- Must exceed dust threshold (546 sats)
- Must cover L1 transaction fee share
- Recommended minimum: 10,000 sats

## Roll Forward (Stay in L2)

Users not withdrawing have their state rolled forward:

```
Previous Epoch State:
├── User A: 1.0 BTC
├── User B: 0.5 BTC
└── User C: 0.3 BTC

L2 Activity:
├── User A sends 0.2 BTC to User B
└── User C receives 0.1 BTC from mixing

New Epoch State:
├── User A: 0.8 BTC
├── User B: 0.7 BTC
└── User C: 0.4 BTC
```

The new state is committed on-chain via OP_RETURN anchor, but no L1 outputs are created for users staying in L2.

## Batch Rules

```rust
struct BatchRules {
    settlement_class: SettlementClass,
    min_participants: usize,    // Minimum for batch to execute
    max_idle_ratio: f64,        // Maximum inactive locks (50%)
    max_extension: u32,         // Deadline extension multiplier
}
```

### Minimum Participants

Batches require minimum participants for:
- Fee efficiency (shared costs)
- Privacy (larger anonymity set)

If minimums aren't met, batch is delayed until next epoch or until threshold reached.

### Idle Lock Handling

Locks inactive within a batch period:

| Condition | Action |
|-----------|--------|
| < 50% idle | Normal batch |
| ≥ 50% idle | Force rotation of idle locks |
| Persistently idle | Fee penalty applied |

This prevents anonymity set degradation from stale UTXOs.

## Fee Distribution

Reconciliation fees contribute to the L2 fee pool:

```
Reconciliation Fee Income
         │
         ├──► Ghost Pay Node Reward Pool (50-100%)
         │    Based on treasury decay schedule
         │
         └──► Treasury (0-50%)
              Based on treasury decay schedule
```

Only nodes running Ghost Pay (+4 shares) receive these fees.

## State Commitment

Each settlement includes an OP_RETURN anchor:

```
OP_RETURN GPRC <version> <epoch_number> <state_root>

Where:
- GPRC: Ghost Pay Reconciliation marker
- version: Protocol version (1 byte)
- epoch_number: Sequential epoch counter (4 bytes)
- state_root: Merkle root of L2 state (32 bytes)
```

This enables:
- Verification that L2 state matches L1 commitment
- Historical audit of all state transitions
- Fraud proofs if coordinator misbehaves

## Failure Handling

### Batch Fails to Execute

If a batch cannot execute (insufficient participants, coordinator failure):
- Batch delayed to next epoch
- No funds lost (still in previous state)
- Users can switch to different settlement class

### Coordinator Failure

If coordinator goes offline:
- Users can recover via Ghost Lock recovery path
- Recovery timelock provides self-custody safety net
- No central point of failure for fund safety

### Double-Spend Attempt

If malicious actor tries to double-spend:
- L1 transaction fails (UTXO already spent)
- L2 state rolled back to last valid state
- Malicious actor's funds may be slashed

## Emergency Exit

Users can exit directly to L1 without reconciliation:

```
Emergency Exit Conditions:
├── Coordinator unreachable for 24+ hours
├── Settlement repeatedly failing
└── User explicitly requests emergency exit

Process:
1. Wait for Ghost Lock recovery timelock to expire
2. Spend via recovery path directly to L1
3. L2 balance is forfeit (already on L1)
```

This is a last resort - normal reconciliation is preferred.

## Comparison with Other L2s

| Feature | Ghost Pay | Lightning | Liquid |
|---------|-----------|-----------|--------|
| Settlement | Batched epochs | Per-channel | 2-way peg |
| Exit time | 6h - 7d | Instant (cooperative) | 2 days |
| Exit cost | Shared in batch | Per-channel | Fixed |
| Privacy | High (batched) | Medium | Medium |
| Custody | Non-custodial | Non-custodial | Federated |

## Implementation Details

### Batch Coordinator

```rust
async fn execute_batch(epoch: u64, class: SettlementClass) {
    // 1. Collect withdrawal requests
    let withdrawals = get_pending_withdrawals(epoch, class);

    if withdrawals.len() < class.min_participants() {
        // Delay to next epoch
        return;
    }

    // 2. Calculate new state
    let new_state = calculate_new_state(epoch);

    // 3. Build settlement transaction
    let tx = build_settlement_tx(withdrawals, new_state);

    // 4. Collect signatures
    let signed_tx = coordinate_signing(tx).await;

    // 5. Broadcast
    broadcast_transaction(signed_tx).await;

    // 6. Wait for confirmation
    wait_for_confirmation(signed_tx.txid()).await;

    // 7. Update L2 state
    commit_new_state(new_state);
}
```

## Related Documentation

- [Ghost Pay](GHOST_PAY.md) - The L2 network
- [Ghost Locks](GHOST_LOCKS.md) - The UTXO format
- [Economics](ECONOMICS.md) - Fee structure and distribution
