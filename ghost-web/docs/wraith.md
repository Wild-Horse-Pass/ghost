# Wraith

*A two-phase coordinator-blinded CoinJoin. Public Bitcoin UTXOs go in, Ghost Locks come out, and no one — not even the protocol coordinator — knows which input maps to which output.*

## The problem

If you take a public BTC balance and just create a Ghost Lock with it, the chain shows the link: address X spent N satoshis to a Ghost Lock UTXO. Anyone watching the chain can correlate. The privacy you get from Ghost Pay's L2 starts the moment you're inside; it doesn't apply to the deposit transaction itself.

CoinJoin is the standard fix — many users sign one transaction with many inputs and many identical outputs, breaking the input→output link. Single-phase CoinJoin works, but it has known weaknesses: amount-analysis attacks, timing-correlation attacks against the coordinator, and the basic problem that with only N participants the anonymity set is exactly N.

Wraith does CoinJoin in two phases on purpose, and uses Schnorr blind signatures so the coordinator literally can't see which output it's signing for. The result is an anonymity set that's combinatorial in size, not linear.

## What Wraith does

```
Phase 1 (Split):    N participants × 1 input    →   N × OPP intermediate Ghost Locks
Phase 2 (Merge):    N × OPP intermediates       →   N final Ghost Locks
```

`OPP` is "outputs per participant" — between 2 and 10 depending on tier. Each user puts in one UTXO, gets back one final Ghost Lock, but the path between is a fan-out / fan-in that's impossible to trace from the outside.

The intermediate phase is what makes the math work:

- After Phase 1, the chain shows N×OPP intermediate UTXOs of identical denomination, indistinguishable from each other.
- A user's path through the system is one specific subset of OPP intermediates (the ones that came from their input and feed their output).
- The number of valid mappings between inputs and outputs grows combinatorially with N and OPP. With 250 participants and OPP=5, the valid-mapping space is astronomically large; brute-force correlation isn't viable.

## Tiers

Different denominations get different participant counts and OPP values. Phase 2 transaction size is the binding constraint (90 000 vbyte budget per Bitcoin's standardness rules), and Phase 2 has OPP inputs per participant — so larger denominations need fewer participants but more outputs each:

| Tier | Balance range | Participants | OPP | Intermediate UTXOs | Typical wait |
|---|---|---|---|---|---|
| Micro | 0.001 – 0.01 BTC | 500 | 2 | 1 000 | ~12 h |
| Small | 0.01 – 0.1 BTC | 320 | 4 | 1 280 | ~24 h |
| Medium | 0.1 – 1 BTC | 260 | 5 | 1 300 | ~2 d |
| Standard | 1 – 10 BTC | 250 | 5 | 1 250 | ~3 d |
| Large | 10 – 50 BTC | 170 | 8 | 1 360 | ~5 d |
| Whale | 50+ BTC | 140 | 10 | 1 400 | ~7 d |

The wait time is dominated by participant collection. A Wraith session needs at least the tier's participant count before it starts — the coordinator pools requests until threshold, then runs both phases. For Micro tier this happens within hours; for Whale tier you might wait a week for enough peers at the same denomination.

OPP values `{2, 4, 5, 8, 10}` divide every denomination cleanly — no rounding, no leftover sats.

## Schnorr blind signatures

This is the protocol's trick. The coordinator validates that a participant is authorised to receive an output, but never sees which output. The math:

```
Step 1: Nonce exchange
  Coordinator: k ←$- secp256k1, R = k·G          ← random per participant
  Coordinator → Participant: R

Step 2: Blinding + challenge
  Participant: α, β ←$- secp256k1               ← random blinding factors
               R' = R + α·G + β·X                ← blinded nonce (X = coordinator pubkey)
               c  = H(R' ‖ X ‖ m)                ← Fiat-Shamir challenge over the recipient address m
               c' = c + β                         ← blinded challenge
  Participant → Coordinator: c'

Step 3: Signing
  Coordinator: s = k + c'·x  (mod n)              ← x = coordinator secret
  Coordinator → Participant: s

Step 4: Unblinding
  Participant: s' = s + α
  Final token: (R', s') is a valid Schnorr signature on m
```

What the coordinator sees: random `c'` values. What the coordinator never sees: the message `m` (the recipient address), the blinded nonce `R'`, or the unblinded signature `(R', s')` that ends up on chain.

When the participant later submits the signed token at the output address, the coordinator can verify the signature is valid (came from a legitimate session participant) but can't tell *which* participant produced it. That's the unlinkability property.

## A worked example

Imagine a Standard-tier session: 250 participants, OPP = 5.

**Phase 1 (Split):**
```
Tx in:  250 inputs × ~1 BTC each (each participant's funding UTXO)
Tx out: 1250 outputs × 0.2 BTC each (250 × 5 intermediate Ghost Locks)
```

After confirmation, the chain shows 1 250 identical 0.2 BTC P2TR outputs. To correlate input X with the 5 specific outputs that belong to it, an attacker needs information that the coordinator never had and the participants never published.

**Phase 2 (Merge):**
```
Tx in:  1250 inputs × 0.2 BTC each (each participant's 5 intermediates)
Tx out: 250 outputs × 1 BTC each (final Ghost Locks, one per participant)
```

After Phase 2, the chain shows 250 identical 1 BTC Ghost Locks. The user who put in 1.0027 BTC at the start is now the holder of one specific 1 BTC Ghost Lock — but linking their original input to that specific output requires breaking the combinatorial mixing, which isn't computationally feasible at this participant count.

The 0.0027 BTC overhead is fees: 2 000 sats service fee + ~5 000 sats mining cost share for two transactions. ~0.27 % overhead at this denomination.

## Fee structure

Two components, both transparent:

**Service fee** (fixed per denomination, charged on Mix sessions only):

| Denomination | Output | Service fee | Overhead |
|---|---|---|---|
| Micro | 100 000 sats | 500 sats | 0.5 % |
| Small | 1 000 000 sats | 2 000 sats | 0.2 % |
| Medium | 10 000 000 sats | 5 000 sats | 0.05 % |
| Large | 100 000 000 sats | 10 000 sats | 0.01 % |

**Mining cost** (Bitcoin transaction fee, split evenly across participants). Varies with current fee rate. At 10 sat/vB:

| Denomination | Mining cost / participant | Total overhead |
|---|---|---|
| Micro | ~3 000 sats | ~3.5 % |
| Small | ~5 000 sats | ~0.7 % |
| Medium | ~6 000 sats | ~0.1 % |
| Large | ~7 000 sats | ~0.02 % |

Wallets show the full breakdown — service fee + projected mining cost — before the user commits to joining a session.

**Jump sessions** (key rotation only — see [Locks](#locks) for context) charge no service fee, only the mining cost share. Used when a user wants to refresh their Ghost Lock keys without paying the privacy-mix premium.

## Session timing

| Phase | Timeout | Notes |
|---|---|---|
| Participant collection | 24 h | Pool requests until threshold (or session expires unfilled) |
| Input collection | 2 h | Collect UTXOs from confirmed participants |
| Signing coordination | 1 h | Blind-signature exchange + transaction signing |
| On-chain confirmation | 6 h | Wait for ≥6 confirmations of each phase |
| Overall session | 7 d | Hard cap from start to final confirmation |

If a session times out at any phase, refunds are issued; nobody loses funds beyond the gas spent.

## What Wraith protects against

| Attacker | Outcome |
|---|---|
| Passive chain observer | **Strong protection.** Cannot determine input→output mapping. The combinatorial space at full tier (e.g. 250×5) is computationally infeasible to brute-force. |
| Coordinator-on-the-side | **Strong protection.** Schnorr blind signatures mean even the coordinator literally never sees which output it's signing. |
| Sybil attack on participant pool | **Moderate protection.** If an attacker controls 90 % of session participants, the anonymity set shrinks to the honest minority. Tier minimums are calibrated so even with significant Sybil dilution, anonymity remains meaningful. |
| Timing analysis (cross-session) | **Moderate protection.** A user who Wraiths immediately after receiving a public payment leaks correlation through timing. Best practice is to wait, vary timing, or chain multiple sessions. |
| Amount-correlation across sessions | **Strong protection if denominations match.** A user who Wraiths exactly 1 BTC in a Standard session, holds for a week, then Wraiths 1 BTC out — the two sessions are unlinkable as long as the holder period is longer than typical session times. |

## What Wraith doesn't do

- **It doesn't hide the existence of mixing.** A Phase 1 transaction with 250 inputs and 1 250 identical-amount outputs is visibly a CoinJoin. The OP_RETURN marker (v3: 32-byte opaque hash) confirms it as Wraith specifically. Anyone watching the chain knows mixing happened — they just can't tell which user mapped to which output.
- **It doesn't help if you spend the output non-privately afterwards.** A clean Ghost Lock spent immediately to a known address re-correlates. Wraith only protects the input→output linkage of one session; downstream privacy is the wallet's responsibility.
- **It doesn't work for arbitrary amounts.** Standard denominations only. If you have 0.073 BTC, you'll Wraith multiple Small denominations and the wallet handles change. There's no "0.073 BTC tier".
- **It doesn't run online forever.** A full Whale-tier session can take a week. The wallet handles the long-running coordination, but the participant has to keep the signing key reachable until Phase 2 confirms.
- **It isn't free.** Service fees + mining costs are real. For Micro tier the overhead can be ~3.5%; for Large tier it's effectively rounding error. Plan according to denomination.

## Privacy stack context

| Layer | Primitive | What it protects |
|---|---|---|
| Receive | [Ghost Keys](#keys) | Address-to-identity linkability |
| **Mix** | **Wraith** | **Input-to-output graph linkability** |
| Hold | [Locks](#locks) | Custody primitive — recovery without revealing structure |
| Move | Ghost Pay L2 | On-chain transaction visibility |
| Relay | [Shroud](#shroud) | Transaction-origin timing |

Wraith is the layer that breaks the on-chain trail between your public Bitcoin and your Ghost Pay balance. Use it once on entry, once on exit, and your L1 footprint is two confirmed CoinJoin participations rather than a complete spending history.

## Source

| File | Purpose |
|---|---|
| `crates/wraith-protocol/src/coordinator.rs` | Session coordinator, blind signatures, participant matching |
| `crates/wraith-protocol/src/session.rs` | Per-session participant state machine |
| `crates/wraith-protocol/src/executor.rs` | Round execution / transaction broadcast |
| `crates/wraith-protocol/src/blind.rs` | Schnorr blind-signature primitives |
| `crates/wraith-protocol/src/denomination.rs` | Tier constants, OPP values |
