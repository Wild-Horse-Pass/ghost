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
//| FILE: WRAITH_PROTOCOL.md                                                                                             |
//|======================================================================================================================|
```

# Wraith Protocol

Two-phase CoinJoin mixing for private entry into Ghost Pay.

## Overview

Wraith Protocol breaks the link between public Bitcoin UTXOs and Ghost Pay balances through a coordinated two-phase mixing process. Users enter with a public UTXO and exit with a clean, unlinkable Ghost Lock.

```
Phase 1 (Split):   N inputs  → 10N intermediate Ghost Locks
Phase 2 (Merge):   10N intermediates → N final Ghost Locks

Result: User starts with 1 public UTXO, ends with 1 clean Ghost Lock
Trail is broken: No link between public input and final output
```

## Why Two Phases?

Single-phase CoinJoin has a weakness: if all participants are known, the mapping between inputs and outputs can sometimes be inferred through amount analysis or timing correlation.

Wraith's two-phase approach:
1. **Phase 1 (Split)**: Each input becomes 10 smaller outputs, creating 10x more outputs than inputs
2. **Phase 2 (Merge)**: 10 intermediates merge back into 1 final output

The intermediate phase creates a combinatorial explosion of possible mappings, making analysis computationally infeasible.

## Fee Structure

| Item | Amount |
|------|--------|
| Mixing Fee | 1% of denomination |
| L1 Transaction Fees | Deducted from the 1% |

Users pay exactly 1% regardless of network conditions. The pool absorbs variable L1 costs.

## Denominations

Standard denominations ensure all outputs look identical:

| Denomination | Input (with fee) | Output | Intermediate (10x split) |
|--------------|------------------|--------|--------------------------|
| Micro | 10,100 sats | 10,000 sats | 1,000 sats |
| Small | 1,010,000 sats | 1,000,000 sats | 100,000 sats |
| Medium | 10,100,000 sats | 10,000,000 sats | 1,000,000 sats |
| Large | 101,000,000 sats | 100,000,000 sats | 10,000,000 sats |

## Participant Tiers

Choose your anonymity set size vs wait time:

| Tier | Min Participants | Anonymity Set | Typical Wait |
|------|------------------|---------------|--------------|
| Express | 25 | Moderate | Minutes |
| Quick | 50 | Good | Hours |
| Small | 100 | Better | ~1 day |
| Medium | 250 | Strong | ~2 days |
| Standard | 500 | Very Strong | ~3 days |
| Large | 750 | Excellent | ~5 days |
| Whale | 1000 | Maximum | ~7 days |

## Blind Signatures

Wraith uses **Schnorr blind signatures** to ensure the coordinator cannot link inputs to outputs.

### How It Works

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

### Security Properties

- **Blindness**: Coordinator never sees the message m, blinded nonce R', or challenge c
- **Unforgeability**: Only the coordinator can produce valid signatures
- **Unlinkability**: Final signature (R', s') cannot be linked to signing session (R, c', s)

## Phase Execution

### Phase 1 (Split)

```
1. Collect N participants with matching denomination
2. Each participant contributes 1 input UTXO
3. For each of 10 intermediate addresses per participant:
   a. Coordinator sends nonce R
   b. Participant blinds address, sends blinded challenge c'
   c. Coordinator signs, returns signature scalar s
   d. Participant unblinds to get valid token (R', s')
4. Construct split transaction: N inputs → 10N outputs
5. Transaction includes OP_RETURN marker: "WR1" (Wraith Phase 1)
6. All participants sign their input
7. Broadcast and wait for confirmation
```

### Phase 2 (Merge)

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

## Timeouts

| Phase | Timeout | Purpose |
|-------|---------|---------|
| Participant Collection | 24 hours | Wait for N participants |
| Input Collection | 2 hours | Collect UTXOs from participants |
| Phase Execution | 1 hour | Signing coordination |
| Phase Confirmation | 6 hours | Wait for on-chain confirmation |
| Overall Session | 7 days | Maximum total session duration |

## Thresholds

| Threshold | Value | Purpose |
|-----------|-------|---------|
| Minimum Execution | 50% | Force execute if half the participants show up |
| Early Execution | 75% | Optional early start if 3/4 are ready |
| Refund Vote | 67% | Supermajority can abort and refund |
| Timeout | 7 days | Maximum wait before automatic refund |

## Session States

```
WaitingForParticipants → CollectingInputs → ExecutingPhase1
                                                  ↓
                                      WaitingPhase1Confirmation
                                                  ↓
                                           ExecutingPhase2
                                                  ↓
                                      WaitingPhase2Confirmation
                                                  ↓
                                             Completed
```

Failed or timed-out sessions transition to `Failed` or `Refunded`.

## User Flow

1. **Select denomination**: Choose amount to mix (must match standard tier)
2. **Join session**: Register for a mixing session matching your denomination
3. **Wait for participants**: Session fills to minimum threshold
4. **Provide input**: Submit your public UTXO to the coordinator
5. **Sign Phase 1**: Participate in blind signing, sign split transaction
6. **Wait for confirmation**: Phase 1 confirms on-chain
7. **Sign Phase 2**: Participate in blind signing, sign merge transaction
8. **Receive clean output**: Final Ghost Lock is yours, unlinkable to input

## Privacy Guarantees

1. **Coordinator blindness**: Cannot link which input maps to which output
2. **No logging**: Coordinator only sees blinded data
3. **Uniform outputs**: All outputs are identical denomination
4. **Timing obfuscation**: Random delays between phases
5. **Combinatorial anonymity**: 10x split creates massive possible mappings

## Failure Handling

If a participant disappears:
- Session waits until timeout
- If above 50% threshold, proceeds without them
- Below 50%, session aborts and refunds

If coordinator fails:
- Participants can recover funds via Ghost Lock recovery path
- Timelocked recovery ensures funds are never permanently lost

## Related Documentation

- [Ghost Locks](GHOST_LOCKS.md) - The output format for mixed funds
- [Ghost Pay](GHOST_PAY.md) - The L2 network where mixed funds can be used
- [Reconciliation](RECONCILIATION.md) - How to exit back to L1
