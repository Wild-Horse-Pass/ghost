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
Phase 1 (Split):   N inputs  → OPP×N intermediate Ghost Locks
Phase 2 (Merge):   OPP×N intermediates → N final Ghost Locks

OPP (outputs per participant) varies by tier: 2, 4, 5, 8, or 10
Result: User starts with 1 public UTXO, ends with 1 clean Ghost Lock
Trail is broken: No link between public input and final output
```

## Why Two Phases?

Single-phase CoinJoin has a weakness: if all participants are known, the mapping between inputs and outputs can sometimes be inferred through amount analysis or timing correlation.

Wraith's two-phase approach:
1. **Phase 1 (Split)**: Each input becomes OPP smaller outputs (2-10 depending on tier)
2. **Phase 2 (Merge)**: OPP intermediates merge back into 1 final output

The intermediate phase creates a combinatorial explosion of possible mappings, making analysis computationally infeasible.

## Fee Structure

Wraith uses a transparent fixed service fee per denomination plus at-cost mining:

```
user_pays = output_sats + service_fee + mining_cost_share
```

### Service Fees

Fixed per denomination (charged on Mix sessions only):

| Denomination | Output | Service Fee | Overhead |
|---|---|---|---|
| Micro | 100,000 sats | 500 sats | 0.5% |
| Small | 1,000,000 sats | 2,000 sats | 0.2% |
| Medium | 10,000,000 sats | 5,000 sats | 0.05% |
| Large | 100,000,000 sats | 10,000 sats | 0.01% |

### Mining Cost

Bitcoin transaction fees are split evenly across all participants:

| Denomination | Typical Mining Cost (10 sat/vB) | Total Overhead |
|---|---|---|
| Micro | ~3,000 sats/user | ~3.5% |
| Small | ~5,000 sats/user | ~0.7% |
| Medium | ~6,000 sats/user | ~0.1% |
| Large | ~7,000 sats/user | ~0.02% |

Mining cost varies with fee rate. Users see the full breakdown before joining.

### Session Types

| Type | Service Fee | Mining Cost | Use Case |
|---|---|---|---|
| **Mix** | Yes | Yes | Normal CoinJoin mixing |
| **Jump** | **None** | Yes | Key rotation via Wraith (at-cost only) |

Jump sessions allow users to rotate keys through Wraith mixing without paying service fees, providing unlinkable key rotation at mining cost only.

## Denominations

Standard denominations ensure all outputs look identical within a session:

| Denomination | Output | Min Input | Service Fee | Short Code |
|---|---|---|---|---|
| Micro | 100,000 sats (0.001 BTC) | 100,500 sats | 500 sats | MI |
| Small | 1,000,000 sats (0.01 BTC) | 1,002,000 sats | 2,000 sats | SM |
| Medium | 10,000,000 sats (0.1 BTC) | 10,005,000 sats | 5,000 sats | MD |
| Large | 100,000,000 sats (1 BTC) | 100,010,000 sats | 10,000 sats | LG |

Min input = output + service_fee (excludes mining cost, which is estimated at join time).

### Intermediate Amounts

Phase 1 splits each output into OPP intermediates. All intermediates within a session are identical (privacy invariant M-23):

| Denomination | OPP=2 | OPP=4 | OPP=5 | OPP=8 | OPP=10 |
|---|---|---|---|---|---|
| Micro | 50,000 | 25,000 | 20,000 | 12,500 | 10,000 |
| Small | 500,000 | 250,000 | 200,000 | 125,000 | 100,000 |
| Medium | 5,000,000 | 2,500,000 | 2,000,000 | 1,250,000 | 1,000,000 |
| Large | 50,000,000 | 25,000,000 | 20,000,000 | 12,500,000 | 10,000,000 |

All OPP values {2, 4, 5, 8, 10} divide all denominations evenly — no rounding, no remainder.

## Participant Tiers

Tiers determine the anonymity set size, OPP (outputs per participant), and typical wait time. Participant counts are optimized for Phase 2 transaction size (90,000 vbyte budget):

| Tier | Balance Range | Participants | OPP | Intermediates | Typical Wait |
|---|---|---|---|---|---|
| Micro | 0.001-0.01 BTC | 500 | 2 | 1,000 | ~12 hours |
| Small | 0.01-0.1 BTC | 320 | 4 | 1,280 | ~24 hours |
| Medium | 0.1-1 BTC | 260 | 5 | 1,300 | ~2 days |
| Standard | 1-10 BTC | 250 | 5 | 1,250 | ~3 days |
| Large | 10-50 BTC | 170 | 8 | 1,360 | ~5 days |
| Whale | 50+ BTC | 140 | 10 | 1,400 | ~7 days |

### Transaction Size Constraints

Phase 2 (Merge) is the binding constraint because it has OPP inputs per participant (vs 1 input in Phase 1):

| Tier | Phase 1 vbytes | Phase 2 vbytes | Within 90K Limit |
|---|---|---|---|
| Micro | 72,000 | 79,500 | Yes |
| Small | 73,600 | 88,000 | Yes |
| Medium | 62,140 | 86,580 | Yes |
| Standard | 59,750 | 83,250 | Yes |
| Large | 68,510 | 86,190 | Yes |
| Whale | 68,320 | 87,220 | Yes |

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
3. For each of OPP intermediate addresses per participant:
   a. Coordinator sends nonce R
   b. Participant blinds address, sends blinded challenge c'
   c. Coordinator signs, returns signature scalar s
   d. Participant unblinds to get valid token (R', s')
4. Construct split transaction: N inputs → OPP×N outputs
5. Transaction includes encrypted OP_RETURN marker (v3: 32-byte opaque hash)
6. All participants sign their input
7. Broadcast and wait for confirmation
```

### Phase 2 (Merge)

```
1. Same participants, OPP intermediates each as inputs
2. For each participant's final output address:
   a. Coordinator sends nonce R
   b. Participant blinds, sends blinded challenge
   c. Coordinator signs, returns scalar
   d. Participant unblinds to get token
3. Construct merge transaction: OPP×N inputs → N outputs
4. Transaction includes encrypted OP_RETURN marker (v3: 32-byte opaque hash)
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

## Coordination Model

Wraith sessions are coordinated by Ghost pool nodes. Any node operator can run Wraith sessions — there is no central coordinator or single entity that controls mixing. This is fundamentally different from centralized mixing services:

- **No single point of failure**: If one coordinator node goes down, others continue operating
- **No single entity to seize**: Law enforcement cannot shut down Wraith by targeting one company
- **Permissionless**: Any Ghost node can coordinate sessions as part of normal pool operation
- **Blind signatures**: Even the coordinating node cannot link inputs to outputs

The coordinator role is distributed across the entire Ghost node network, providing both decentralization and the large anonymity sets that come from having a shared infrastructure.

## Comparison with Other CoinJoin Protocols

### Privacy Set Size

| Protocol | Participants per Round | Phases | Coordination |
|---|---|---|---|
| **Wraith** | **140-500** | 2 (split + merge) | Distributed (any Ghost node) |
| Wasabi (WabiSabi) | ~60 avg | 1 | Community coordinators |
| Whirlpool | 5 (fixed) | 1 (free remixes) | Centralized (seized 2024) |
| JoinMarket | 8-10 default | 1 | Decentralized P2P market |

Wraith's anonymity set is an order of magnitude larger than any other Bitcoin CoinJoin implementation.

### Fee Comparison

**At 0.01 BTC (1,000,000 sats):**

| Protocol | Service Fee | Mining | Total |
|---|---|---|---|
| **Wraith** | 2,000 sats (fixed) | ~5,000 sats (split across N) | ~7,000 sats |
| Wasabi | 3,000 sats (0.3%) | ~5,000 sats | ~8,000 sats |
| Whirlpool | 50,000 sats (5% one-time) | included | 50,000 sats |
| JoinMarket | ~500-1,000 sats | taker pays all | ~2,000-5,000 sats |

**At 1 BTC (100,000,000 sats):**

| Protocol | Service Fee |
|---|---|
| **Wraith** | **10,000 sats (0.01%)** |
| Wasabi | 300,000 sats (0.3%) |
| Whirlpool | 2,500,000 sats (5%) |
| JoinMarket | ~100,000 sats (~0.1%) |

Wraith's fixed fees make it dramatically cheaper for large amounts.

### Architecture Comparison

| | Wraith | Wasabi | Whirlpool | JoinMarket |
|---|---|---|---|---|
| **Coordinator** | Distributed (any node) | Community coordinators | Single operator (seized) | P2P market |
| **Single point of failure** | No | Reduced | Fatal (proven) | No |
| **Equal amounts** | Yes (4 denominations) | Variable (WabiSabi) | Yes (4 pools) | No |
| **Blind signing** | Schnorr blind sigs | WabiSabi credentials | Chaumian blind sigs | None |
| **Two-phase mixing** | Yes (epoch gap) | No | No | No |
| **Key rotation (Jump)** | At-cost (no service fee) | N/A | N/A | N/A |
| **Status (2026)** | Active | Active (community-run) | Dead (seized April 2024) | Active (low liquidity) |

### Key Differentiators

1. **Largest anonymity set**: 140-500 participants vs 5-60 for alternatives
2. **Two-phase design**: Split-merge with epoch gap adds temporal unlinkability
3. **Distributed coordination**: No single coordinator to seize or shut down
4. **Fixed fees**: Cheapest for large amounts (0.01% at 1 BTC vs 0.3-5%)
5. **Jump sessions**: Free key rotation through Wraith at mining cost only
6. **Integrated with Ghost Pay**: Not a standalone mixer but part of the L2 entry flow

## Related Documentation

- [Ghost Locks](GHOST_LOCKS.md) - The output format for mixed funds
- [Ghost Pay](GHOST_PAY.md) - The L2 network where mixed funds can be used
- [Reconciliation](RECONCILIATION.md) - How to exit back to L1
