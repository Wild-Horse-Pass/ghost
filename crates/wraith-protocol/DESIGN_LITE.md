# Wraith Lite — Design Document v1.0

Status: **FINAL — signed off, refactor in progress against this spec.**

All eight open questions from the v0.1 draft have been resolved. Decisions
recorded in §15 below. Subsequent sections updated to reflect those
decisions; what was previously "proposed" is now "specified."

## 0. Why this exists

The current two-phase split→merge protocol has three cumulative problems that
together make it unfit for production:

1. **Participant dropout leaks privacy.** If a participant disappears between
   Phase 1 and Phase 2, the protocol broadcasts Phase 1 anyway and the
   dropout's intermediate UTXOs sit on-chain unspent — recoverable by chain
   analysis. There is no recovery path in the current code.
2. **Round duration is 18–45 hours by default.** Driven by two chain
   confirmations + generous timeout buffers. Users won't tolerate it.
3. **No real Sybil resistance.** A malicious coordinator can stuff a round
   with fake participants and de-anonymise the real ones at will.

Wraith Lite drops the two-phase architecture entirely in favour of
**single-round atomic CoinJoin** (Whirlpool-style), keeps the architectural
differentiators that are real (coordinator pool with failover, Jump-lock
integration, Schnorr blind signatures, tier system), and adds the missing
pieces (Sybil resistance via bonds, demand-driven session creation, remix
queue).

The protocol's name does not change. The underlying transaction shape does.

## 1. Goals (explicit, in priority order)

1. **Works.** Survives malicious participants, malicious coordinators (within
   reason), unreliable networks, and routine reorgs. Funds are never locked
   indefinitely. Privacy claims hold under stated threat models, not just
   ideal conditions.
2. **Useful for users.** Round duration measured in tens of minutes, not
   tens of hours. Wallet UX is "click mix, walk away, come back to mixed
   coins." No long-running attention required.
3. **Generates revenue.** The coordinator pool operator earns a service fee
   per Mix round, denominated as a percentage of the tier amount. Economics
   are sustainable at realistic throughput.

## 2. Non-goals (explicit)

- **Threshold blind signatures (DKG across coordinators) are NOT in v1.** The
  audit's "concurrent trust distribution" answer is the right eventual
  destination but it's months of cryptographic engineering. v1 ships with
  per-coordinator signing keys and a re-blind-on-failover model.
- **Mempool-level privacy (Dandelion++ etc.) is NOT in scope.** The wallet's
  Phase 9 Shroud relay handles wallet-side broadcast timing.
- **Decentralised coordinator selection (P2P / market-based) is NOT in v1.**
  The pool is operator-administered. JoinMarket-style continuous matching is
  a future option, not a v1 feature.
- **Fee discovery via auction / market is NOT in v1.** Fees are
  tier-fixed, configurable per pool but constant within a tier.

## 3. Threat model

Privacy holds against:

- **Passive blockchain observer.** Cannot link a participant's pre-mix input
  to their post-mix output above the round's anonymity set, nor across
  rounds remixed in the queue.
- **Single compromised coordinator.** Cannot forge tokens, cannot link
  blinded inputs to blinded outputs, cannot front-run a round (other
  coordinators in the pool see session activity via gossip and would notice
  fake-but-unique sessions).
- **Sybil-attacking participant.** Cannot register more identities than
  their bonded collateral allows. Dropouts are slashed.
- **Network partition / coordinator failure.** Round survives via the
  re-bind handoff; participant loses ~100ms of work, not their place.

Privacy does NOT hold against:

- **Coordinator pool collusion.** If all Active+Standby coordinators are run
  by the same entity (or seizable by the same jurisdiction), they can pool
  state and de-anonymise. v1 assumes the pool operator is honest. v2
  introduces threshold sigs to remove this assumption.
- **Global passive adversary** with both wallet HTTP traffic and on-chain
  visibility. Tor + Shroud delay reduce but do not eliminate this.
- **Coordinator-driven Sybil** if the bond requirement is bypassed (e.g.
  coordinator forges bond receipts). Mitigated by bond proofs being
  on-chain or in ghost-pay's L2 ledger, both verifiable by the wallet.

## 4. Architecture overview

```
       wallet ─┬─ wraith-wallet-core (this crate's eventual client)
               │
               ▼
     ╔═════════════════════════════════════════╗
     ║          Active Coordinator             ║       ← single point at a time,
     ║  - creates sessions on demand           ║         rotates on failure
     ║  - holds per-session blind-sign key     ║
     ║  - signs / collects / broadcasts        ║
     ╚═════════════════════════════════════════╝
              ▲           ▲           ▲
              │ gossip    │ gossip    │ gossip   ← session metadata, heartbeats
              │           │           │
       ┌──────┴────┐ ┌────┴─────┐ ┌───┴──────┐
       │ Standby A │ │ Standby B│ │ Standby C│  ← pre-positioned, ready to promote
       └───────────┘ └──────────┘ └──────────┘
```

The pool registry (which lives in GSP for v1, since GSP already knows the
network topology) lets wallets discover the current Active. Wallets do all
their session work directly with whichever coordinator is currently Active.

## 5. Wallet API (RPCs the wallet calls against the coordinator)

Single-round flow, in order:

1. **`pool.discover()`** → `{ active_url, standby_urls[], supported_tiers[] }`
   Wallet caches; refreshes on heartbeat or failover.

2. **`session.find_or_create(tier, denomination, ghost_pay_session_token)`**
   → `{ session_id, slots_filled, slots_total, estimated_start, bond_required_sats }`
   The Active either returns an existing open session at this tier or
   creates one. Bond is a small fraction of denomination (default 0.5%),
   payable from the wallet's L2 balance.

3. **`session.bond(session_id, ghost_pay_bond_proof)`** → `{ bond_id, expires_at }`
   Bond is escrowed in ghost-pay's L2 until session closes. Slashed on
   no-show or no-sign; refunded on completion.

4. **`session.blind_sign_request(session_id, blinded_request, bond_id)`**
   → `{ blinded_signature, coordinator_pubkey }`
   Wallet unblinds locally → token signed under coordinator_pubkey.

5. **`session.submit_token(session_id, unblinded_token, output_address, input_commitment)`**
   → `{ ack, position_in_round }`
   Token + output address presented anonymously (different network identity
   from registration; ideally over Tor).

6. **`session.poll_status(session_id)`** → `{ phase, participant_count, signing_progress }`
   Polled. State enum: `Filling | Locked | Signing | Broadcasting | Complete | Failed`.

7. **`session.submit_signature(session_id, signature_share)`** → `{ ack }`
   Called once during the `Signing` phase.

8. **`session.outcome(session_id)`** → `{ txid, my_outputs[], remix_queue_position }`
   After broadcast.

For the remix queue:

9. **`remix.enqueue(output_id, target_tier, max_remixes)`** → `{ queue_id }`
10. **`remix.status(queue_id)`** → `{ rounds_completed, next_session_eta }`

## 6. Coordinator pool & gossip protocol

Standbys learn about sessions through a small gossip protocol that pushes
session state changes from the Active to every other coordinator in the
pool. State replicated per session:

- Session metadata: `{ id, tier, denomination, created_at, expires_at }`
- Participant list: `{ ghost_id, bond_id, blinded_request, registered_at }` per participant
- Output map: `{ unblinded_token, output_address }` per submitted output
- Phase state: `Filling | Locked | Signing | Broadcasting | Complete | Failed`

State NOT replicated:

- The Active's blind-signing keypair. (Different per-coordinator. Not
  shareable in v1.)
- Already-issued blind signatures. (These are valid only under Active's key;
  on failover wallets re-blind under the new Active's key, see §7.)

### Wire format (v1 implementation)

The gossip protocol ships as `SessionGossipEvent` JSON over an HTTP POST
to `/api/v1/internal/gossip` on every peer coordinator. Three variants:

- `SessionCreated { session: LiteSession }` — new session created. Standby
  inserts (or overwrites — Active's view is canonical).
- `ParticipantAdded { session_id, participant, new_state }` — wallet joined.
  Standby appends the participant if not already present (idempotent).
- `StateChanged { session_id, new_state }` — phase transition that wasn't
  already covered by `ParticipantAdded` (e.g. tick-driven `Filling → Locked`,
  forced `→ Failed`, the `Locked → Signing → Broadcasting → Complete` chain).

Each event is fire-and-forget per peer with a 5s timeout. A peer that's slow
or unreachable is logged and the event is dropped — every event is idempotent
and the next event (or future reconciliation snapshot) catches the peer up.
Events are pushed only; v1 has no pull-on-promotion path. A Standby that
joins late stays empty until the next event lands.

### Configuration

The Active is configured with `--peers` (or `WRAITH_COORDINATOR_PEERS`,
comma-separated base URLs of every other coordinator in the pool). Standbys
expose the receive endpoint by default; an empty `--peers` list runs solo
with no replication.

The `/api/v1/internal/` prefix is operator-firewalled to the pool's address
range until a shared-secret HMAC header lands. v1 trusts peers on a private
network.

## 7. Failover semantics — the re-blind handoff

The protocol crate's existing comments (`coordinator_redundancy.rs:63–66`)
flag threshold blind sigs as the "future" answer. v1 takes a simpler path
that's defensible now.

Failover sequence:

1. Active1 fails. Heartbeat timeout fires (default 30s).
2. Pool elects Standby with highest trust score → promotes to Active2.
3. Active2 publishes `pool.coordinator_changed(new_active=Active2)` to all
   live wallet sessions.
4. Each wallet's session task observes the change. For each in-flight session:
   - If wallet is in **Filling** phase: re-blind under Active2's pubkey,
     re-submit blind-sign request. Lost work: ~100ms. Place in queue: kept.
   - If wallet is in **Locked** phase (session full, awaiting Signing):
     re-blind not needed; participant identity persists via bond_id.
   - If wallet is in **Signing** phase: signature collection continues with
     Active2's broadcast logic. Signatures already collected by Active1 are
     part of the replicated session state.
   - If wallet is in **Broadcasting** phase: tx already on the wire. Active2
     just monitors confirmation.

Failover during the brief blind-signing window (step 4 in the wallet API)
is the only case where a wallet does measurable extra work. Everything else
is transparent. **The round itself never breaks.** That's the core failover
claim.

## 8. Round mechanics — single-round atomic CoinJoin

Tier-defined participant range: each tier has `min_participants` and
`max_participants`. A session in `Filling` phase fires when EITHER
`max_participants` is reached OR `min_participants` is reached and the
session has been open for `tier.fill_window_secs` (default 5 minutes).

Transaction shape (Mix session):

```
inputs:                                outputs:
  participant 1 input UTXO  ────►        participant 1 mixed output (= denom)
  participant 2 input UTXO  ────►        participant 2 mixed output (= denom)
  ...                                    ...
  participant N input UTXO  ────►        participant N mixed output (= denom)
                                         coordinator service fee output
                                         change outputs (one per participant if needed)
```

All mixed outputs are the same value (= tier denomination). Output ordering
is shuffled via ChaCha20Rng seeded from session_id, same as the existing
code. Service fee is a single output to the coordinator's fee address.
Change outputs (when an input is larger than denom + fee_share) go back to
each participant individually.

Tier table (final):

| Tier id | Denom | Min participants | Max | Fill window | Service fee | Bond rate |
|---|---|---|---|---|---|---|
| `100k_sats` | 100,000 sats   | 5 | 20  | 5 min | 0.5% | 0.5% |
| `1m_sats`   | 1,000,000 sats | 5 | 30  | 5 min | 0.5% | 0.5% |
| `10m_sats`  | 10,000,000 sats | 5 | 50  | 5 min | 0.5% | 0.5% |
| `100m_sats` | 100,000,000 sats | 5 | 100 | 5 min | 0.5% | 0.5% |

Round duration target: median 25 minutes (mostly chain confirmation), p99
60 minutes.

## 9. Remix queue

The Whirlpool-style killer feature. After a round completes, the wallet's
outputs may opt to enrol in subsequent rounds without further user action.

User configures at enqueue time:

- `max_remixes`: integer, default 3, hard-cap 10.
- `target_tier`: usually same as source, but downgrade to smaller tiers is
  allowed (1 × 1M-sat output → 10 × 100k-sat outputs over multiple rounds).
- `cash_out_address`: where the final output goes after `max_remixes`.

Mechanics:

- Coordinator maintains a `remix_queue` keyed by tier.
- After each round completes, queued outputs are auto-enrolled in the next
  open session at their target tier.
- If no session is open within `tier.queue_timeout` (default 1 hour), wallet
  is notified; user picks: enrol again, or cash out now.
- Each remix charges its own service fee (transparent to user but factored
  into expected revenue).

Privacy effect: K remixes ≈ N^K effective anonymity set (where N is the
average per-round participant count), minus correlation effects from
re-using the same wallet identity. Diminishing returns past K=5.

## 10. Jump-locks integration

`SessionType::Jump` survives the pivot unchanged in spirit. Single-round
mechanics, but:

- Inputs are existing Ghost Lock UTXOs.
- Outputs are new Ghost Lock UTXOs (with rotated keys).
- Service fee is **0** (mining cost only) — already what the existing code
  enforces via the Mix vs Jump split.
- Reconciliation hooks (the `wraith_fee_routing.rs` integration tests
  validate this): on broadcast, ghost-pay's reconciliation engine is
  notified that locks are rotated and updates state.

The `test_900_jump_lock_full_lifecycle()` machinery adapts directly. The
phase-machine collapse means the test gets simpler, not more complex.

## 11. Revenue model

**Per-round revenue** (Mix sessions only):

```
fee_per_round = participant_count × denomination × fee_rate
```

At the proposed tier table with `fee_rate = 0.5%`:

| Tier | Min revenue/round | Max revenue/round |
|---|---|---|
| Spark   | 5 × 100k × 0.5% = 2.5k sats | 20 × 100k × 0.5% = 10k sats |
| Ember   | 5 × 1M × 0.5% = 25k sats     | 30 × 1M × 0.5% = 150k sats |
| Flame   | 5 × 10M × 0.5% = 250k sats   | 50 × 10M × 0.5% = 2.5M sats |
| Inferno | 5 × 100M × 0.5% = 2.5M sats  | 100 × 100M × 0.5% = 50M sats |

**Throughput model.** With 25-min median round duration and 4 tiers running
concurrently, ~57 rounds/tier/day. Median revenue per tier per day at
mid-fill (≈ 15 participants/round average across tiers):

| Tier | Avg revenue/round (15 ppts) | Daily (×57) |
|---|---|---|
| Spark   | 7.5k sats | 0.0043 BTC | $258 (at $60k) |
| Ember   | 75k sats | 0.043 BTC | $2,580 |
| Flame   | 750k sats | 0.43 BTC | $25,800 |
| Inferno | 7.5M sats | 4.3 BTC | $258,000 |

**Realistic targets.** Tier participation will be heavily skewed toward
small tiers; assume only 10% of demand reaches Inferno-tier. Realistic
v1 modelled revenue:

- 80% of rounds in Spark + Ember = $2,000/day
- 15% of rounds in Flame = $4,000/day
- 5% of rounds in Inferno = $13,000/day

≈ **$19,000/day = $7M/year gross** at full fill.

Operating costs (5 coordinator nodes at $200/mo + bandwidth + maintenance)
= $25k/year. Margin is real.

Caveat: this assumes meaningful adoption. Whirlpool's actual peak was in
the same order of magnitude (Samourai claimed ≈$15k/day). The model is
sound; the bottleneck is user acquisition, not protocol economics.

**Fee collection.** Service fee is paid as one transaction output to the
coordinator's fee address per round. The pool operator runs a process that
sweeps fee outputs daily. No L2 indirection — fees settle on-chain
immediately, no reliance on ghost-pay being up.

## 12. Sybil resistance — the bond mechanism

A new piece, not in the existing code.

At `session.bond()`, the wallet escrows `bond_required_sats` from its L2
balance. Default is 0.5% of denomination — same magnitude as the service
fee.

- **On round completion**: bond refunded to the participant.
- **On no-show during Filling phase**: bond held until session-fill timeout,
  then refunded (no penalty for changing your mind during the open window).
- **On no-sign during Signing phase** (the actual griefing case): bond
  slashed. Half goes to the round's other participants (compensates for
  delay); half goes to the coordinator pool's protocol fund.

A wallet that wants to flood the network with fake participants now has to
fund N bonds across N ghost_ids. At 0.5% of tier × N participants required
to actually break the round (e.g. ~80% of the round's slots), the attacker
spends roughly 0.4% of the entire round's notional value to grief one
round. Defense scales linearly with attack scale — cheap for one grief,
expensive for sustained denial.

The bond UTXO movement is observable on chain in the L2 ledger. The
defense to "the bond reveals timing" is that bond posting happens in a
random window before the round (entry_timing.rs's role) and bonds are
posted to a single shared coordinator pool address (so observer sees one
bond posted, not "ghost_X paid bond Y at time Z").

## 13. Migration plan from current code

Path: **subtractive replacement, not feature flag.**

The two-phase code has dropout-leak as a fundamental design flaw. There is
no future timeline where the two-phase model comes back to address it
short of going to threshold blind signatures (which we'd build differently
anyway). Keeping two-phase code under `#[cfg(feature = "two-phase")]` is
dead-weight maintenance.

Concrete migration:

- **Delete:** the `Phase` enum, two-phase fields in `WraithSession`,
  inter-phase transition logic in `executor.rs`, the
  `WaitingPhase{1,2}Confirmation` states, fee_pad logic in
  `denomination.rs`, the OPP (outputs-per-participant > 1) machinery.
- **Simplify:** `executor.rs` from ~1000 lines to probably ~300. Single
  transaction-builder path. No fee_pad calculations.
- **Add:** session.find_or_create RPC, session.bond + bond verification,
  remix queue (new module `remix.rs`), session-metadata gossip in
  coordinator_redundancy.rs.
- **Keep:** `blind.rs` (well-built), `coordinator_redundancy.rs`'s pool +
  rotation machinery, `entry_timing.rs`, `tier.rs` (with new tier table),
  `rpc.rs` (extended).
- **Tests:** ~60% of existing tests survive. e2e test rewrites for
  single-round (smaller). Phase-specific tests delete entirely.
  Add: bond slashing tests, remix queue tests, malicious-coordinator
  Sybil tests, failover-during-blind-sign tests.

Estimated work: **2 weeks for a focused person.** Wallet participant
module on top once protocol changes ship: ~1 week.

## 14. Deferred / future work

Listed so they don't get rediscovered as gaps later:

- **Threshold blind signatures (DKG across coordinators).** The principled
  failover model. Removes the "trust the operator runs honest standbys"
  assumption. Several months of careful crypto + integration. v2.
- **Continuous matching coordinator** (no discrete `Filling` phase).
  JoinMarket-style. Better UX for low-traffic tiers. v2 or v3.
- **Bonds posted on L1, not L2.** If ghost-pay's L2 isn't trusted as the
  bond ledger, an L1-bonded variant is buildable. Adds a pre-mix
  transaction (Whirlpool's Tx0 model, kind of). Unclear if worth the
  complexity.
- **Anonymous fee payments.** Service fees today flow to one coordinator
  address per round, observable. A blinded fee channel (similar to
  WabiSabi's KVAC credentials) could anonymise the fee path itself.
- **Dandelion++ coordinator-side relay.** Beyond Shroud's wallet-side
  delay, broadcast itself can be relayed through random peers. v2.
- **Multi-coordinator co-signing** (option (b) failover from the
  discussion). Not strictly necessary if re-blind on failover is
  acceptable, but reduces wallet-side complexity.
- **Gossip pull-on-promotion / reconciliation snapshot.** v1 ships push-only
  HTTP gossip (§6). A Standby that boots after the Active has been running
  starts empty until the next event lands. v2 adds a `GET /api/v1/internal/snapshot`
  endpoint so a fresh Standby can catch up to the current session set on
  startup, plus an HMAC header on `/api/v1/internal/*` so the routes can
  safely live on a public address.

## 15. Resolved decisions (v1.0 sign-off)

All resolved. Refactor begins against this spec.

| # | Decision | Resolution |
|---|---|---|
| 1 | Tier names | **Denom-named.** `100k_sats` / `1m_sats` / `10m_sats` / `100m_sats`. |
| 2 | Service fee rate | **0.5%.** Whirlpool parity. Per-tier override possible later if needed. |
| 3 | Bond mechanism | **L2 (ghost-pay).** L1's only advantage was independence from L2 availability; that's defused by #6. L2 wins on speed (no chain-confirmation wait), privacy (bonds invisible to chain analysis), cost (no mining fees per bond), and UX. |
| 4 | Remix queue default | **Opt-in.** User explicitly enrols at round-end. |
| 5 | Min participants per round | **5.** Whirlpool's number, well-tested for fill rate vs. anonymity set. |
| 6 | Behaviour when L2 down | **N/A — assumed never to happen.** Rationale: ghost-pay L2 outage means every node is fucked at the operator's level; if that's happening, Wraith rounds aren't the priority. Defensive code path: in-flight rounds proceed with their existing bond commitments; new rounds queue until L2 returns. |
| 7 | Coordinator pool size | **1 Active + 3 Standbys.** |
| 8 | Mainnet gating | **None.** Wallet allows Wraith Lite rounds on mainnet from day one. |

The next step is the protocol crate refactor against this spec. Wallet
participant module follows.
