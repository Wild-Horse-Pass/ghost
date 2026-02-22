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
