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

# Ghost Pay

Layer 2 payment network for instant, low-fee transfers.

## Overview

Ghost Pay is an optional Layer 2 network built on top of Bitcoin Ghost. It provides:
- Instant transfers (10-second virtual blocks)
- Low fees (10 sats + 0.1%)
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
| Transfer | 10 sats + 0.1% |
| Wraith Mix | 1% (L1 tx fees deducted from this) |

### Fee Examples

| Transfer Amount | Fee |
|-----------------|-----|
| 10,000 sats | 20 sats (10 + 10) |
| 100,000 sats | 110 sats (10 + 100) |
| 1,000,000 sats | 1,010 sats (10 + 1,000) |

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

Transfers are instant and private:

```
1. Create transfer request
   ├── Recipient's Ghost ID
   ├── Amount
   └── ZK proof of sufficient balance

2. Submit to L2 validators
   └── Proof verified (not contents)

3. State updated
   ├── Sender balance decreased
   └── Recipient balance increased

4. Confirmation
   └── Next virtual block (~10 seconds)
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

### Balance Tracking

L2 tracks balances by Ghost Lock ID:

```
L2 State:
├── GhostLock_A: 1,500,000 sats
├── GhostLock_B: 250,000 sats
├── GhostLock_C: 10,000,000 sats
└── ...
```

### State Commitments

Each epoch, state root is committed to L1:

```
State Root = MerkleRoot(all_balances)

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

### ZK Proofs

Transfers use ZK proofs:
- Prove balance sufficient without revealing amount
- Validators verify proof, not transaction details
- Strong privacy guarantees

### Wraith Mixing

Entry via Wraith breaks the link to public Bitcoin:
- Two-phase split-merge mixing
- Blind signatures for unlinkability
- Coordinator cannot link inputs to outputs

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
transfer_base_sats = 10
transfer_percent = 0.001  # 0.1%
```

### Rewards

Nodes running Ghost Pay earn:
- +4 shares in node reward pool
- Share of L2 fee income
- Only among Ghost Pay nodes

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

## Related Documentation

- [Ghost Keys](GHOST_KEYS.md) - Recipient addresses
- [Ghost Locks](GHOST_LOCKS.md) - UTXO format
- [Wraith Protocol](WRAITH_PROTOCOL.md) - Private entry
- [Reconciliation](RECONCILIATION.md) - L1 settlement
- [ZK Proofs](ZK_PROOFS.md) - Transfer privacy
