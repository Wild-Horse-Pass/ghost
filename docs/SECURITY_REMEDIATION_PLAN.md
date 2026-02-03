# Security Audit Remediation Plan

**Created:** 2026-02-03
**Audit Issues:** 11 CRITICAL, 13 HIGH, 15 MEDIUM, 12 LOW
**Estimated Duration:** 4-6 weeks
**Status:** Planning

---

## Execution Strategy

Per CLAUDE.md:
- Use subagents for parallel work on independent crates
- Serialize when changes have dependencies
- Run tests after every change
- No quick fixes - root cause only

### Dependency Graph

```
Phase 1 (Foundation) - No dependencies, can parallelize
├── ZK-C1, ZK-C2, ZK-C3 (ghost-zkp)
├── GL-C1, GL-H1, GL-H2 (ghost-locks)
└── WR-C1, WR-C2 (wraith-protocol)

Phase 2 (Consensus) - Depends on ghost-common changes
├── P2P-C1, P2P-C2 (ghost-consensus)
└── P2P-H1, P2P-H2 (ghost-consensus)

Phase 3 (Payout) - Depends on Phase 2 (verification system)
├── PO-C2 (ghost-pool + ghost-verification)
└── PO-C1, PO-H1, PO-H2, PO-H3 (ghost-accounting)

Phase 4 (Cleanup) - Depends on all above
└── All MEDIUM and LOW issues
```

---

## Phase 1: Foundation Fixes (Week 1-2)

### 1.1 ZK Proof Verification [crypto-agent]

**Crate:** `ghost-zkp`
**Parallelizable:** Yes (independent crate)

#### ZK-C1: Remove Simulated Verification [CRITICAL]
- [ ] File: `crates/ghost-zkp/src/payout_verifier.rs:176-187`
- [ ] Remove simulated verification fallback
- [ ] Return `false` (or error) if no verification key present
- [ ] Add `#[cfg(test)]` guard if simulation needed for tests only

```rust
// BEFORE (dangerous)
true  // Always accepts!

// AFTER (fail closed)
if self.prepared_vk.is_none() {
    error!("No verification key - cannot verify proof");
    return false;
}
```

#### ZK-C2: Implement Real BlockVerifier [CRITICAL]
- [ ] File: `crates/ghost-zkp/src/verifier.rs:70-122`
- [ ] Add Groth16 verification using bellperson
- [ ] Store actual PreparedVerifyingKey, not just metadata
- [ ] Verify proof against public inputs

#### ZK-C3: Add All Public Inputs [CRITICAL]
- [ ] File: `crates/ghost-zkp/src/payout_verifier.rs:203-204`
- [ ] File: `crates/ghost-zkp/src/circuit/payout.rs`
- [ ] Expose as public inputs:
  - `total_available` (existing)
  - `miner_sum` (add)
  - `node_sum` (add)
  - `treasury_amount` (add)
  - `epoch` (add)
- [ ] Update circuit to constrain all public inputs
- [ ] Update verifier to check all public inputs

#### ZK-H1: Replace Weak Hash with Poseidon [HIGH]
- [ ] File: `crates/ghost-zkp/src/circuit/state_transition.rs:364-390`
- [ ] File: `crates/ghost-zkp/src/circuit/merkle.rs:229-256`
- [ ] Add neptune or poseidon crate dependency
- [ ] Replace `simple_hash` (a*b + a + b) with Poseidon
- [ ] Update all Merkle tree operations

#### ZK-H2: Document MPC Ceremony Requirement [HIGH]
- [ ] File: `crates/ghost-zkp/src/payout_prover.rs:182-184`
- [ ] Add prominent warning comment about trusted setup
- [ ] Create `docs/ZK_TRUSTED_SETUP.md` with ceremony instructions
- [ ] Add runtime check/warning if using non-ceremony parameters

#### ZK-H3: Add Subgroup Checks [HIGH]
- [ ] File: `crates/ghost-zkp/src/payout_verifier.rs:230-263`
- [ ] Verify points are on curve AND in prime-order subgroup
- [ ] Use `is_torsion_free()` check after deserialization

#### ZK-M1: Proof Malleability - Commit to Metadata [MEDIUM]
- [ ] Hash all proof metadata (epoch, counts) into a commitment
- [ ] Include commitment as public input

#### ZK-M2: Add Range Proof on total_available [MEDIUM]
- [ ] File: `crates/ghost-zkp/src/circuit/payout.rs:77-83`
- [ ] Add 64-bit range check constraint

#### ZK-M3: Use Checked Arithmetic [MEDIUM]
- [ ] File: `crates/ghost-zkp/src/payout_verifier.rs:117-121`
- [ ] Replace `saturating_add` with `checked_add`
- [ ] Return error on overflow

**Tests:**
```bash
cargo test -p ghost-zkp
# New tests:
# - test_verifier_fails_without_vk
# - test_all_public_inputs_verified
# - test_poseidon_hash_collision_resistant
# - test_subgroup_check_rejects_invalid
```

---

### 1.2 Ghost Locks [crypto-agent]

**Crate:** `ghost-locks`
**Parallelizable:** Yes (independent crate)

#### GL-C1: Fix CLTV vs CSV Mismatch [CRITICAL]
- [ ] File: `crates/ghost-locks/src/script.rs:45-55`
- [ ] Decision: Use CSV (relative) to match C++ implementation
- [ ] Change `OP_CLTV` to `OP_CSV`
- [ ] Update `recovery_height()` to return relative block count
- [ ] Rename to `recovery_blocks()` for clarity

```rust
// BEFORE
.push_opcode(OP_CLTV)  // Absolute

// AFTER
.push_opcode(OP_CSV)   // Relative - matches C++
```

#### GL-H1: Document nSequence Requirements [HIGH]
- [ ] File: `crates/ghost-locks/src/script.rs`
- [ ] Add constant: `pub const RECOVERY_NSEQUENCE: u32 = 0xFFFFFFFE;`
- [ ] Add documentation explaining nSequence < 0xFFFFFFFF requirement
- [ ] Create helper function for building recovery transactions

#### GL-H2: Fix Taproot Tree Structure [HIGH]
- [ ] File: `crates/ghost-locks/src/script.rs:76-84`
- [ ] Match C++ two-leaf structure:
  - Leaf 0 (depth 1): normal script `<lock_pubkey> OP_CHECKSIG`
  - Leaf 1 (depth 1): recovery script
- [ ] Update all address derivation to use new tree

```rust
// BEFORE (single leaf)
TaprootBuilder::new().add_leaf(0, recovery_script)

// AFTER (two leaves, balanced)
TaprootBuilder::new()
    .add_leaf(1, normal_script)?
    .add_leaf(1, recovery_script)?
```

#### GL-M1: Enforce State Transitions [MEDIUM]
- [ ] File: `crates/ghost-locks/src/lock.rs:184`
- [ ] Replace `set_state()` with `transition()` that validates
- [ ] Remove direct state setter

#### GL-M2: Check State in is_recovery_available [MEDIUM]
- [ ] File: `crates/ghost-locks/src/lock.rs`
- [ ] Add `self.state == LockState::Active` check

#### GL-L1: Fix Denomination Code Collision [LOW]
- [ ] File: `crates/ghost-locks/src/denomination.rs:83-92`
- [ ] Change Micro="Mi" or "u", Medium="Me" or "m"

#### GL-L2: Validate Creation Height [LOW]
- [ ] File: `crates/ghost-locks/src/timelock.rs`
- [ ] Reject creation_height > 100_000_000

#### GL-L3: Add Minimum Timelock Validation [LOW]
- [ ] Add `MIN_RECOVERY_TIMELOCK = 1008` constant (1 week)
- [ ] Validate in lock creation

**Tests:**
```bash
cargo test -p ghost-locks
# New tests:
# - test_csv_relative_timelock
# - test_taproot_tree_matches_cpp
# - test_state_transition_validation
# - test_recovery_requires_active_state
```

---

### 1.3 Wraith Protocol [crypto-agent]

**Crate:** `wraith-protocol`
**Parallelizable:** Yes (independent crate)

#### WR-C1: Always Use Entropy in Shuffle [CRITICAL]
- [ ] File: `crates/wraith-protocol/src/executor.rs:155-159, 299-304`
- [ ] Remove/deprecate `build_split_transaction()` and `build_merge_transaction()`
- [ ] Make `_with_entropy` versions the only public API
- [ ] Generate CSPRNG entropy internally if not provided

```rust
// REMOVE these public methods:
pub fn build_split_transaction(...) // REMOVE
pub fn build_merge_transaction(...) // REMOVE

// KEEP only:
pub fn build_split_transaction_with_entropy(...)
pub fn build_merge_transaction_with_entropy(...)
```

#### WR-C2: Anonymous Token Submission [CRITICAL]
- [ ] File: `crates/wraith-protocol/src/coordinator.rs:315-345`
- [ ] Redesign token submission to not require ghost_id
- [ ] Options:
  1. Separate anonymous channel for token submission
  2. Blind token verification without identity linkage
  3. Onion routing for token submission
- [ ] Remove `participant.tokens = tokens` linkage

#### WR-H1: Bind Nonces to Participants [HIGH]
- [ ] File: `crates/wraith-protocol/src/blind.rs:307-337`
- [ ] Include ghost_id in nonce session_id generation
- [ ] Verify requestor matches nonce owner before signing

#### WR-H2: Detect Duplicate Addresses [HIGH]
- [ ] File: `crates/wraith-protocol/src/coordinator.rs:400-420`
- [ ] Maintain HashSet of all addresses across participants
- [ ] Reject duplicate addresses

#### WR-H3: Reduce Data Retention Window [HIGH]
- [ ] File: `crates/wraith-protocol/src/coordinator.rs:836-886`
- [ ] Delete participant-specific data immediately after TX broadcast
- [ ] Keep only: session_id, txids, participant_count (no ghost_id linkage)

#### WR-M1: Use CSPRNG for Shuffle [MEDIUM]
- [ ] File: `crates/wraith-protocol/src/executor.rs:543-570`
- [ ] Replace LCG with ChaCha20Rng

```rust
// BEFORE (weak LCG)
rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);

// AFTER (strong CSPRNG)
use rand_chacha::ChaCha20Rng;
let mut rng = ChaCha20Rng::from_seed(seed_bytes);
items.shuffle(&mut rng);
```

#### WR-M2: Rate Limit Nonce Generation [MEDIUM]
- [ ] File: `crates/wraith-protocol/src/blind.rs:273-301`
- [ ] Add per-participant rate limiting
- [ ] Add max active nonces cap
- [ ] Auto-expire old nonces

#### WR-M3: Implement Participant Reputation [MEDIUM]
- [ ] Track non-signing participants
- [ ] Ban repeat offenders
- [ ] Consider requiring small deposits

#### WR-M4: Session-Specific Participant IDs [MEDIUM]
- [ ] File: `crates/wraith-protocol/src/coordinator.rs:92-106`
- [ ] Derive session-specific ID: `H(ghost_id || session_id)`
- [ ] Prevents cross-session tracking

#### WR-L1: Verify Session ID Uniqueness [LOW]
- [ ] File: `crates/wraith-protocol/src/session.rs:127-130`
- [ ] Check against existing sessions before accepting

#### WR-L2: Verify UTXO Existence [LOW]
- [ ] File: `crates/wraith-protocol/src/coordinator.rs:225-240`
- [ ] Query Bitcoin node to verify UTXO is unspent

#### WR-L3: Use Monotonic Clock for Timeouts [LOW]
- [ ] File: `crates/wraith-protocol/src/session.rs:196-201`
- [ ] Replace SystemTime with Instant for timeout calculations

**Tests:**
```bash
cargo test -p wraith-protocol
# New tests:
# - test_shuffle_uses_csprng
# - test_token_submission_unlinkable
# - test_nonce_bound_to_participant
# - test_duplicate_address_rejected
```

---

## Phase 2: Consensus Fixes (Week 2-3)

### 2.1 P2P Consensus [consensus-agent]

**Crate:** `ghost-consensus`
**Depends on:** ghost-common (for identity/PoW)

#### P2P-C1: Enforce PoW on Voter Registration [CRITICAL]
- [ ] File: `crates/ghost-consensus/src/health_handler.rs:95-181`
- [ ] Require PoW proof in health ping message
- [ ] Verify PoW before calling elder_callback
- [ ] Add `pow_proof: PowProof` field to HealthPing message

```rust
// BEFORE
callback(envelope.sender);  // No verification!

// AFTER
if !envelope.pow_proof.verify(&envelope.sender, NODE_ID_POW_DIFFICULTY) {
    warn!("Rejected node without valid PoW");
    return Ok(());
}
callback(envelope.sender);
```

#### P2P-C2: Rate Limit Voter Registration [CRITICAL]
- [ ] File: `crates/ghost-consensus/src/health_handler.rs`
- [ ] Add rate limiting for new voter registrations
- [ ] Require minimum uptime before voting eligibility
- [ ] Add cooldown between registration attempts

#### P2P-H1: Add Vote Equivocation Detection [HIGH]
- [ ] File: `crates/ghost-consensus/src/voting.rs:94-98`
- [ ] Store vote signatures, not just vote decisions
- [ ] Detect if voter signs both approve AND reject
- [ ] Create equivocation proof for conflicting votes

```rust
struct VoteRecord {
    decision: VoteDecision,
    signature: [u8; 64],
}

// Check for equivocation
if let Some(existing) = self.votes.get(&vote.voter) {
    if existing.decision != vote.decision {
        // EQUIVOCATION! Same voter, different decisions
        return VoteResult::Equivocation(EquivocationProof::from_votes(existing, &vote));
    }
}
```

#### P2P-H2: Include round_id in Vote Signature [HIGH]
- [ ] File: `crates/ghost-consensus/src/voting.rs:256-258`
- [ ] Sign: `H(round_id || proposal_hash || voter_id || decision)`
- [ ] Prevents vote replay across rounds

#### P2P-M1: Validate Envelope Timestamps [MEDIUM]
- [ ] File: `crates/ghost-consensus/src/message_validator.rs`
- [ ] Reject messages with timestamp > 5 minutes from current time

#### P2P-M2: Extend Dedup Mechanism [MEDIUM]
- [ ] File: `crates/ghost-consensus/src/mesh.rs:67-68`
- [ ] Store message hashes persistently (not just IDs)
- [ ] Or combine with timestamp validation

#### P2P-M3: Add Rate Limiting to Health Pings [MEDIUM]
- [ ] File: `crates/ghost-consensus/src/health_handler.rs`
- [ ] Apply token bucket rate limiting (like VoteHandler)

#### P2P-M4: Add Rate Limiting to ZK Vote Handler [MEDIUM]
- [ ] File: `crates/ghost-consensus/src/zk_vote_handler.rs`
- [ ] Add rate limiter similar to VoteHandler

#### P2P-M5: Implement Automatic Fork Resolution [MEDIUM]
- [ ] File: `crates/ghost-consensus/src/reorg.rs`
- [ ] Auto-resolve forks based on vote counts or chain weight

#### P2P-M6: Include Voter ID in Vote Signature Data [MEDIUM]
- [ ] File: `crates/ghost-consensus/src/voting.rs:256-258`
- [ ] Add voter identity to signed data

#### P2P-L1: Optimize Seen Message Eviction [LOW]
- [ ] File: `crates/ghost-consensus/src/mesh.rs:234-251`
- [ ] Replace HashMap + sorting with LRU cache

**Tests:**
```bash
cargo test -p ghost-consensus
# New tests:
# - test_pow_required_for_registration
# - test_vote_equivocation_detected
# - test_vote_replay_rejected_different_round
# - test_rate_limiting_health_pings
```

---

## Phase 3: Payout Fixes (Week 3-4)

### 3.1 Payout Logic [mining-agent + verification-agent]

**Crates:** `ghost-pool`, `ghost-accounting`, `ghost-verification`
**Depends on:** Phase 2 (consensus/verification system)

#### PO-C1: Unify Pool Fee Constant [CRITICAL]
- [ ] File: `crates/ghost-common/src/constants.rs:42`
- [ ] File: `bins/ghost-pool/src/treasury.rs:18`
- [ ] Use single source of truth in ghost-common
- [ ] Use basis points (100 = 1%) to avoid float ambiguity
- [ ] Remove duplicate constant from treasury.rs

```rust
// ghost-common/src/constants.rs
pub const POOL_FEE_BASIS_POINTS: u64 = 100;  // 1% = 100 bps

// Usage
let pool_fee = subsidy_sats * POOL_FEE_BASIS_POINTS / 10000;
```

#### PO-C2: Require Verified Capabilities [CRITICAL]
- [ ] File: `bins/ghost-pool/src/round.rs:315-324`
- [ ] File: `bins/ghost-pool/src/payout.rs:638-659`
- [ ] Make QualifiedCapabilityProvider REQUIRED, not optional
- [ ] Fail payout calculation if provider not configured
- [ ] Implement the missing verification task (per CLAUDE.md)

```rust
// BEFORE
if let Some(ref provider) = self.qualification_provider {
    // Optional verification
}

// AFTER
let provider = self.qualification_provider
    .as_ref()
    .ok_or(PayoutError::NoVerificationProvider)?;
// Mandatory verification
```

**Sub-tasks for PO-C2 (from CLAUDE.md):**
- [ ] Implement periodic verification task (every 5 minutes)
- [ ] Use `ghost-verification/src/client.rs` to issue challenges
- [ ] Calculate pass rate from challenge results
- [ ] Only use QUALIFIED capabilities (10+ challenges, 95% pass rate)

#### PO-H1: Don't Lose TX Fees [HIGH]
- [ ] File: `crates/ghost-accounting/src/payout.rs:179-189`
- [ ] Fail block production if block finder's address not found
- [ ] Never silently redirect TX fees to treasury

#### PO-H2: Use Integer Arithmetic [HIGH]
- [ ] File: `crates/ghost-accounting/src/payout.rs:219`
- [ ] File: `bins/ghost-pool/src/payout.rs:402-405`
- [ ] Replace all `f64` share calculations with integer basis points
- [ ] Use u128 intermediate values to prevent overflow

```rust
// BEFORE (floating point)
let amount = (pool_amount as f64 * share_percent) as u64;

// AFTER (integer with basis points)
let amount = (pool_amount as u128 * share_bps as u128 / 10000) as u64;
```

#### PO-H3: Unify Payout Implementation [HIGH]
- [ ] File: `crates/ghost-accounting/src/payout.rs:111-114`
- [ ] File: `bins/ghost-pool/src/treasury.rs`
- [ ] Consolidate to single implementation
- [ ] Follow ECONOMICS.md specification (99% miners, 1% fee)

#### PO-M1: Handle Node Dust Explicitly [MEDIUM]
- [ ] File: `bins/ghost-pool/src/payout.rs:551-556`
- [ ] Remove misleading warning
- [ ] Ensure dust is accounted for in return value

#### PO-M2: Require Treasury Address [MEDIUM]
- [ ] File: `bins/ghost-pool/src/payout.rs:63-72`
- [ ] Remove empty default for treasury_address
- [ ] Add startup validation

#### PO-M3: Fix Treasury Rounding [MEDIUM]
- [ ] File: `bins/ghost-pool/src/treasury.rs:147-148`
- [ ] Use proper integer division with remainder handling

#### PO-M4: Validate Miner Work Values [MEDIUM]
- [ ] File: `bins/ghost-pool/src/round.rs:243`
- [ ] Add sanity check on work values
- [ ] Cap single share's contribution

#### PO-L1: Persist Duplicate Share Detection [LOW]
- [ ] File: `bins/ghost-pool/src/round.rs:222-228`
- [ ] Store submitted share hashes in database

#### PO-L2: Error on Hash Mismatch in Release [LOW]
- [ ] File: `bins/ghost-pool/src/payout.rs:692`
- [ ] Replace debug_assert with proper error handling

#### PO-L3: Use Consistent Recipient ID Hashing [LOW]
- [ ] File: `crates/ghost-accounting/src/payout.rs:236-239`
- [ ] Use hash like bins/ghost-pool does

**Tests:**
```bash
cargo test -p ghost-pool
cargo test -p ghost-accounting
# New tests:
# - test_verified_capabilities_required
# - test_tx_fees_not_lost
# - test_integer_arithmetic_no_float
# - test_treasury_address_required
```

---

## Phase 4: Cleanup & Testing (Week 4-5)

### 4.1 Remaining MEDIUM/LOW Issues

#### All Components
- [ ] Run full test suite: `cargo test --workspace`
- [ ] Run clippy: `cargo clippy --workspace`
- [ ] Run audit: `cargo audit`
- [ ] Update all documentation affected by changes

### 4.2 Integration Testing

- [ ] Deploy to signet with all fixes
- [ ] Run 1000+ transactions through each subsystem
- [ ] Verify:
  - [ ] ZK proofs correctly verified (no simulation)
  - [ ] Ghost Locks spend correctly between Rust/C++
  - [ ] Wraith sessions maintain unlinkability
  - [ ] Node capabilities are VERIFIED before payout
  - [ ] PoW required for consensus participation

### 4.3 Re-Audit

- [ ] Document all changes made
- [ ] Request follow-up security audit
- [ ] Address any new findings

---

## Verification Checklist

### Before Each Commit
- [ ] `cargo test -p <crate>` passes
- [ ] `cargo clippy -p <crate>` has no warnings
- [ ] Changes match plan exactly

### Before Phase Completion
- [ ] All items in phase checked off
- [ ] Integration tests pass
- [ ] No regressions in other components

### Before Mainnet
- [ ] All 51 issues addressed
- [ ] External re-audit complete
- [ ] No CRITICAL or HIGH issues remain
- [ ] Signet deployment stable for 1 week

---

## Agent Assignment

| Phase | Agent | Crates |
|-------|-------|--------|
| 1.1 | crypto-agent | ghost-zkp |
| 1.2 | crypto-agent | ghost-locks |
| 1.3 | crypto-agent | wraith-protocol |
| 2.1 | consensus-agent | ghost-consensus |
| 3.1 | mining-agent + verification-agent | ghost-pool, ghost-accounting, ghost-verification |
| 4.x | test-agent | all |

### Parallelization Strategy

**Week 1-2 (Parallel):**
```
[crypto-agent: ZK fixes] || [crypto-agent: Ghost Locks] || [crypto-agent: Wraith]
```

**Week 2-3 (Sequential after common changes):**
```
ghost-common changes → [consensus-agent: P2P fixes]
```

**Week 3-4 (Sequential after verification):**
```
verification system complete → [mining-agent: Payout fixes]
```

**Week 4-5:**
```
[test-agent: Full integration testing]
```

---

## Progress Tracking

| ID | Severity | Status | Assignee | PR |
|----|----------|--------|----------|-----|
| ZK-C1 | CRITICAL | [ ] Pending | | |
| ZK-C2 | CRITICAL | [ ] Pending | | |
| ZK-C3 | CRITICAL | [ ] Pending | | |
| ZK-H1 | HIGH | [ ] Pending | | |
| ZK-H2 | HIGH | [ ] Pending | | |
| ZK-H3 | HIGH | [ ] Pending | | |
| GL-C1 | CRITICAL | [ ] Pending | | |
| GL-H1 | HIGH | [ ] Pending | | |
| GL-H2 | HIGH | [ ] Pending | | |
| WR-C1 | CRITICAL | [ ] Pending | | |
| WR-C2 | CRITICAL | [ ] Pending | | |
| WR-H1 | HIGH | [ ] Pending | | |
| WR-H2 | HIGH | [ ] Pending | | |
| WR-H3 | HIGH | [ ] Pending | | |
| P2P-C1 | CRITICAL | [ ] Pending | | |
| P2P-C2 | CRITICAL | [ ] Pending | | |
| P2P-H1 | HIGH | [ ] Pending | | |
| P2P-H2 | HIGH | [ ] Pending | | |
| PO-C1 | CRITICAL | [ ] Pending | | |
| PO-C2 | CRITICAL | [ ] Pending | | |
| PO-H1 | HIGH | [ ] Pending | | |
| PO-H2 | HIGH | [ ] Pending | | |
| PO-H3 | HIGH | [ ] Pending | | |
| ... | ... | ... | ... | ... |

---

## Notes

- **No quick fixes**: Every change must address root cause
- **Test everything**: No item marked complete without passing tests
- **Document changes**: Update relevant docs as we go
- **Re-audit required**: External auditor must verify fixes before mainnet
