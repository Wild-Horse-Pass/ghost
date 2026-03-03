# Wraith Protocol — Privacy Model

## Overview

Wraith is Ghost's on-chain mixing protocol. It breaks the transaction graph trail so that an observer with full blockchain access cannot link a participant's input UTXO to their output UTXO. This document explains the layered defenses that make Wraith unlinkable.

## The Problem

A naive CoinJoin is vulnerable to amount correlation, timing analysis, and coordinator collusion. If Alice sends 1.37 GHOST into a mix and 1.37 GHOST comes out, the trail is obvious. Wraith solves this through a combination of structural, cryptographic, statistical, and temporal defenses.

## Two-Phase Split-Merge Architecture

Wraith does not use a single CoinJoin transaction. It splits mixing across two separate on-chain transactions separated by at least one block:

**Phase 1 — Split:** N participants each contribute 1 input. The transaction produces N × OPP intermediate Ghost Lock outputs, where OPP (outputs per participant) ranges from 2 to 10 depending on the denomination tier. For the Standard tier with 250 participants and OPP=5, this means 250 inputs → 1,250 identical intermediate outputs.

**Phase 2 — Merge:** The 1,250 intermediates from Phase 1 become inputs to a second transaction that produces 250 final outputs, one per participant.

An observer sees two large transactions with hundreds of identical-amount UTXOs. There is no on-chain signal indicating which subset of the 1,250 intermediates maps to which final output. The combinatorial explosion (choosing 5 from 1,250 for each participant) makes brute-force linkage computationally infeasible.

## Blind Signatures

The coordinator orchestrating the mix never learns which output address belongs to which participant. This is enforced cryptographically through Schnorr blind signatures:

1. The coordinator generates a nonce R = kG and sends it to the participant.
2. The participant blinds their output address with random factors α and β, computes a blinded challenge c', and sends c' to the coordinator.
3. The coordinator signs the blinded challenge: s = k + c'x.
4. The participant unblinds to obtain a valid signature (R', s') on their output address.

The coordinator produces a valid signature on an address it never sees. Even a fully compromised coordinator cannot link inputs to outputs. The blind signature scheme provides two guarantees:

- **Blindness:** The coordinator cannot determine which address it signed.
- **Unforgeability:** Only the coordinator can produce valid signatures, preventing participants from injecting unauthorized outputs.

Nonces expire after 1 hour and are capped at 100 per participant to prevent resource exhaustion. RNG entropy is validated using Shannon entropy analysis, runs tests, and unique byte counts to guard against RNG failure.

## Uniform Denominations

Every output within a session is exactly the same amount. This eliminates amount-based clustering entirely. An observer cannot distinguish one participant's output from another because they are all identical.

The denomination tiers and their properties:

| Tier | Balance Range | Output Amount | OPP | Max Participants | Anonymity Set |
|------|---------------|---------------|-----|------------------|---------------|
| Micro | 100K–1M sats | 100K sats | 2 | 500 | 500 |
| Small | 1M–10M sats | 1M sats | 4 | 320 | 320 |
| Medium | 10M–100M sats | 10M sats | 5 | 260 | 260 |
| Standard | 100M–1B sats | 100M sats | 5 | 250 | 250 |
| Large | 1B–10B sats | 1B sats | 8 | 170 | 170 |
| Whale | 10B+ sats | 10B sats | 10 | 140 | 140 |

A critical invariant enforced in code: the denomination output amount must be exactly divisible by OPP with zero remainder. This ensures all intermediate outputs are bit-for-bit identical in value, leaving no residual amount that could be used as a fingerprint.

Service fees are charged at the L2 layer through shielded note reduction, not at L1 input time, so they do not appear on-chain and cannot be used for correlation.

## Phase Key Separation

An observer who identifies Phase 1 of a session must not be able to link it to Phase 2 of the same session. Wraith enforces this through phase-specific key derivation:

```
phase_key = SHA256("wraith/phase-key/v1" || session_id || phase_number)
```

Phase 1 and Phase 2 produce different OP_RETURN markers derived from different keys. Even with knowledge of the protocol, an observer cannot determine whether two transactions belong to the same mixing session without knowing the session ID, which is never published on-chain.

## Entry Timing Defenses

Network-level observers watching mempool propagation or peer connections could attempt to correlate participants by when they join a session. Wraith defeats this with four mechanisms:

**Random delay.** Each entry is delayed by an exponentially distributed random interval. The default configuration uses a mean delay between 1 and 60 seconds, clamped to a maximum of 3× the mean (180 seconds). If the RNG fails, a fixed 5-second fallback is used rather than proceeding with zero delay.

**Batching.** Entries are accumulated and released in groups. The default minimum batch size is 5 entries, with a maximum wait of 30 seconds. An observer sees batches of entries arriving simultaneously rather than individual entries that could be correlated.

**Jitter.** A ±500ms random noise is added to all timings to smooth arrival patterns and prevent statistical reconstruction.

**Cover traffic.** Optional dummy join attempts (10% ratio by default) are generated and submitted. These are indistinguishable from real entries to external observers. They are identified internally only at execution time by their empty participant data.

Three configuration presets are available:

- **Default:** 1–60s delay, batch size 5, 500ms jitter, 10% cover traffic.
- **Low-latency:** 100ms–5s delay, batch size 3, no cover traffic. Less privacy, faster mixing.
- **High-privacy:** 5–300s delay, batch size 10, 2s jitter, 20% cover traffic. Maximum privacy, slower mixing.

## Output Shuffling

Both phases shuffle all outputs using fresh OS-level CSPRNG entropy before constructing the transaction. The shuffle seed incorporates the session ID and 32 bytes from `getrandom()`, ensuring that output positions are unpredictable and uncorrelated with input order. An observer cannot infer input-output mappings from positional analysis.

## Transaction Size Uniformity

All tiers are sized to fit within a 90KB transaction budget. Phase 2 is the binding constraint because it has more inputs (N × OPP intermediates vs N direct inputs in Phase 1):

```
Phase 2 vbytes = N × OPP × 58 (inputs) + N × 43 (outputs)
```

Every tier's participant count is calibrated so this stays under 90,000 vbytes. This means all Wraith transactions look structurally similar on-chain regardless of tier, preventing tier identification through transaction size analysis.

## Anti-Griefing

A reputation system prevents participants from disrupting sessions by registering and then refusing to sign:

- Participants receive strikes for failed sessions (not signing, timeout).
- Three strikes result in a ban.
- Successful participation reduces strike count by one, allowing rehabilitation.
- Participant identities are stored as SHA256 hashes for privacy.

## Token Replay Prevention

Blind signature tokens are cached for 14 days (2× the maximum session duration of 7 days) with a capacity of 10 million tokens. Age-based expiry runs first, with capacity-based eviction as a fallback. This prevents a participant from reusing a blind token to claim multiple outputs from a single registration.

## Attack Summary

| Attack Vector | Defense |
|---------------|---------|
| Follow amounts through the mix | All outputs in a session are identical denomination |
| Correlate input position to output position | CSPRNG shuffle with fresh entropy per execution |
| Compromise the coordinator | Blind signatures — coordinator never sees output addresses |
| Link Phase 1 transaction to Phase 2 | Phase-specific derived keys produce different OP_RETURN markers |
| Network timing analysis | Entry delays + batching + jitter + cover traffic |
| Identify tier from transaction size | All tiers fit within 90KB, structurally uniform |
| Fee-based fingerprinting | Service fees charged at L2, invisible on-chain |
| Griefing / denial of service | 3-strike reputation system with hash-based identity |
| Token replay | 14-day token cache with 10M capacity |
| RNG failure | Entropy validation (Shannon + runs test + unique byte count) |

## Anonymity Guarantees

The minimum anonymity set across all tiers is 140 participants (Whale tier). For the most common tier (Standard), the anonymity set is 250. Combined with blind signatures and the two-phase structure, the best an observer with full blockchain and network access can determine is that a given output belongs to one of the N participants in that session. No further narrowing is possible without breaking the discrete logarithm assumption underlying the blind signature scheme.
