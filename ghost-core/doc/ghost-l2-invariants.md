# Ghost L2 Invariants - No Loss of Funds

This document defines the critical invariants that must hold to ensure no loss of
user funds in the Ghost Network Layer 2 system.

## Fundamental Principle

> **Users must ALWAYS be able to recover their funds on Layer 1 (Bitcoin),
> regardless of the state of Layer 2 infrastructure.**

---

## Core Invariants

### INV-1: Unilateral Exit

**Statement**: A user can exit L2 to L1 without cooperation from any other party.

**Mechanism**:
- Ghost Lock outputs have two spending paths
- Key-path: Normal operation (requires lock_key)
- Recovery path: After timelock, requires only recovery_key (user-controlled)

**Proof**:
```
After CSV timelock expires:
  User signs with recovery_key → Funds return to user's L1 wallet
  No coordinator, sequencer, or counterparty signature required
```

**Failure modes protected against**:
- Coordinator offline/malicious
- Network partition
- Sequencer censorship

---

### INV-2: Timelock Bound

**Statement**: Recovery is guaranteed within a bounded time period.

**Parameters**:
| Constraint | Blocks | Time |
|------------|--------|------|
| Minimum timelock | 1,008 | ~1 week |
| Maximum timelock | 52,560 | ~1 year |
| Default timelock | 26,280 | ~6 months |

**Guarantee**: Funds locked in Ghost Lock are recoverable within at most 52,560
blocks (~1 year) under any circumstance.

---

### INV-3: Key Sovereignty

**Statement**: Users retain exclusive control over recovery keys.

**Requirements**:
1. Recovery keys are generated client-side
2. Recovery keys are never transmitted to L2 infrastructure
3. Recovery keys are stored in user's wallet (not L2 state)

**Verification**: Recovery path script uses user-provided recovery_pubkey:
```
<timelock> OP_CSV OP_DROP <recovery_pubkey> OP_CHECKSIG
```

---

### INV-4: Denomination Integrity

**Statement**: L2 cannot create obligations exceeding L1 collateral.

**Mechanism**:
- Standard denominations enforce uniform output values
- Total L2 balance ≤ Sum of Ghost Lock UTXOs on L1
- No fractional reserve possible

**Audit**: L1 chain state is authoritative for total supply.

---

### INV-5: Double-Spend Prevention

**Statement**: A Ghost Lock UTXO can only be spent once.

**Mechanism**: Standard Bitcoin consensus rules
- Each UTXO exists in exactly one unspent state
- Spending requires valid signature for one of:
  - Key-path (tweaked lock_key)
  - Script-path Leaf 0 (lock_key)
  - Script-path Leaf 1 (recovery_key after timelock)

**L2 responsibility**: Track which UTXOs are committed to L2 channels.

---

### INV-6: Reorg Safety

**Statement**: Chain reorganizations do not cause permanent fund loss.

**Handling**:

| Reorg Depth | Response |
|-------------|----------|
| 1-6 blocks | Wait for additional confirmations |
| 6+ blocks | Pause L2 operations, verify UTXO state |
| Deep reorg | Manual intervention, restore from confirmed state |

**Requirements**:
1. L2 must track confirmation depth of Ghost Lock UTXOs
2. Unconfirmed UTXOs must not be considered final
3. State must be reconstructable from L1 chain

---

### INV-7: State Recoverability

**Statement**: L2 state can be reconstructed from L1 chain data.

**Mechanism**:
- OP_RETURN markers identify Ghost transactions
- Ephemeral pubkeys enable Silent Payment detection
- Session IDs link related transactions

**Recovery process**:
1. Scan L1 chain for Ghost Lock UTXOs (via OP_RETURN markers)
2. Use wallet's scan key to detect owned outputs
3. Reconstruct channel/payment state from on-chain data

---

### INV-8: Fee Solvency

**Statement**: L2 operations cannot leave users unable to pay L1 fees.

**Requirements**:
1. Recovery transactions must have sufficient fees
2. Fee estimation accounts for congestion scenarios
3. Users should maintain fee reserve

**Mitigation**: Recovery transactions use standard P2TR, eligible for
fee bumping via CPFP if needed.

---

## Threat Model

### Trusted Components

| Component | Trust Level | Failure Impact |
|-----------|-------------|----------------|
| Bitcoin L1 | Full | Catastrophic (system failure) |
| User's keys | Full | Loss of user's funds only |
| Ghost node | Partial | Degraded service, not fund loss |
| Coordinator | None | Cannot steal funds |

### Attack Vectors

| Attack | Mitigation |
|--------|------------|
| Coordinator steals funds | INV-1: Unilateral exit |
| Coordinator censors user | INV-1: Recovery after timelock |
| Key compromise (lock_key) | INV-3: Recovery key is separate |
| Key compromise (recovery_key) | Attacker must wait for timelock |
| Both keys compromised | User error, not protocol failure |
| L1 reorg | INV-6: Confirmation requirements |
| L2 state corruption | INV-7: Reconstruct from L1 |

---

## Verification Checklist

### For Protocol Implementation

- [ ] Recovery path uses only user-controlled keys
- [ ] Timelock values within safe bounds
- [ ] No coordinator signature in recovery path
- [ ] State reconstructable from L1 data alone

### For Wallet Implementation

- [ ] Recovery keys generated and stored locally
- [ ] Recovery keys never sent to network
- [ ] User can export recovery keys
- [ ] Recovery transaction can be built offline

### For Node Implementation

- [ ] Tracks Ghost Lock UTXO confirmations
- [ ] Handles reorgs correctly (INV-6)
- [ ] Provides state reconstruction API
- [ ] Fee estimation includes safety margin

---

## Testing Requirements

### Unit Tests

1. Ghost Lock construction produces valid P2TR
2. Recovery path spendable after timelock
3. Recovery path NOT spendable before timelock
4. Key-path spending works with lock_key
5. Script-path Leaf 0 works with lock_key

### Integration Tests

1. Full cycle: deposit → L2 operations → withdrawal
2. Recovery: deposit → coordinator failure → recovery spend
3. Reorg handling: confirm → reorg → state consistency

### Stress Tests

1. Mass exit: many users recover simultaneously
2. Fee spike: recovery during high-fee environment
3. Long timelock: verify recovery after extended period

---

## Incident Response

### Fund Recovery Procedure

If L2 infrastructure is unavailable:

1. **Identify affected UTXOs**
   - Scan L1 for Ghost Lock outputs owned by user
   - Use wallet's scan key to detect Silent Payments

2. **Wait for timelock**
   - Check CSV value in recovery script
   - Monitor block height

3. **Broadcast recovery transaction**
   - Build transaction spending via Leaf 1 (recovery path)
   - Sign with recovery_key
   - Broadcast to Bitcoin network

4. **Verify recovery**
   - Confirm transaction included in block
   - Funds now in standard P2TR output (user-controlled)

### Emergency Contacts

For protocol-level issues affecting multiple users:
- GitHub Issues: [ghost-core repository]
- Security: [security contact]

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01 | Initial specification |
