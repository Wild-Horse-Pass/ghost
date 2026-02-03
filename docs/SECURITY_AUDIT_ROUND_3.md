# Bitcoin Ghost Security Audit - Round 3

**Date:** 2026-02-03
**Auditor:** Security Review Team
**Scope:** Verification of Round 2 remediation + comprehensive pre-mainnet security assessment
**Status:** Complete

---

## Executive Summary

This third security audit was conducted to:
1. Verify all 9 Round 2 security fixes are properly implemented
2. Identify any new vulnerabilities introduced by the fixes
3. Assess overall mainnet deployment readiness

### Key Findings

| Category | Round 2 Fixes Verified | New Issues Found |
|----------|------------------------|------------------|
| ZK Verification | 4/4 (100%) | 5 (1 HIGH, 2 MEDIUM, 2 LOW) |
| Wraith Protocol | 2/2 (100%) | 5 (2 MEDIUM, 3 LOW) |
| P2P Consensus | 1/1 (100%) | 2 (2 LOW) |
| Payout Logic | 2/2 (100%) | 0 |
| Dependencies | N/A | 1 (1 MEDIUM) |
| Code Quality | N/A | 2 (2 HIGH - TODOs) |

### Overall Assessment

| Metric | Status |
|--------|--------|
| Round 2 Fixes | **ALL VERIFIED** (9/9) |
| New CRITICAL Issues | **0** |
| New HIGH Issues | **3** |
| New MEDIUM Issues | **5** |
| New LOW Issues | **7** |
| Mainnet Ready | **CONDITIONAL** - See recommendations |

---

## 1. Round 2 Remediation Verification

### 1.1 ZK Verification Fixes (4/4 Verified)

#### ZK-R2-C1: Checked Arithmetic - **PASS**

**Evidence:** `types.rs` and `payment.rs` correctly use `checked_add`/`checked_sub`:

```rust
// types.rs:208-216
pub fn sender_balance_after(&self) -> Option<u64> {
    self.sender_balance_before.checked_sub(self.amount)  // CORRECT
}

pub fn recipient_balance_after(&self) -> Option<u64> {
    self.recipient_balance_before.checked_add(self.amount)  // CORRECT
}

// payment.rs:61-88 - Returns Result with proper error types
pub fn new(...) -> Result<Self, PaymentCircuitError> {
    let sender_balance_after = match (sender_balance_before, amount) {
        (Some(b), Some(a)) => Some(b.checked_sub(a).ok_or(
            PaymentCircuitError::SenderBalanceUnderflow { balance: b, amount: a }
        )?),
        _ => None,
    };
    // ...
}
```

**Verification:** No `saturating_add` or `saturating_sub` found in ghost-zkp crate.

---

#### ZK-R2-C2: Real Groth16 Implementation - **PASS**

**Evidence:** `prover.rs` implements real Groth16 via bellperson:

```rust
// prover.rs:313-341
fn generate_groth16_proof(
    &self,
    circuit: BlockCircuit<Fr>,
    params: &Parameters<Bls12>,
) -> ZkResult<Vec<u8>> {
    let proof = create_random_proof(circuit, params, &mut rand::thread_rng())?;

    // Serialize: A(48) + B(96) + C(48) = 192 bytes
    let mut proof_bytes = Vec::with_capacity(GROTH16_PROOF_SIZE);
    proof_bytes.extend_from_slice(&proof.a.to_compressed());
    proof_bytes.extend_from_slice(&proof.b.to_compressed());
    proof_bytes.extend_from_slice(&proof.c.to_compressed());
    Ok(proof_bytes)
}
```

**Note:** Simulation fallback exists when params unavailable - see new issue ZK3-H1.

---

#### ZK-R2-H1: MiMC 23 Rounds - **PASS**

**Evidence:** `mimc.rs` correctly sets 23 rounds:

```rust
// mimc.rs:23
pub const MIMC_ROUNDS: usize = 23;  // ~115 bits security

// mimc.rs:32-36 - 23 prime constants
let primes: [u64; MIMC_ROUNDS] = [
    7, 13, 19, 31, 43, 61, 79, 97, 113, 131,
    149, 167, 181, 199, 211, 229, 241, 263, 277, 293,
    307, 317, 337,
];
```

---

#### ZK-R2-H2: State Tree Uses MiMC - **PASS**

**Evidence:** `state_tree.rs` imports and uses MiMC:

```rust
// state_tree.rs:14
use crate::circuit::mimc::{bytes_to_field, field_to_bytes, mimc_hash_native};

// state_tree.rs:178-184
fn hash_leaf(&self, balance: u64) -> [u8; 32] {
    let hash = mimc_hash_native(balance_field, domain_sep);  // USES MiMC
    field_to_bytes(hash)
}
```

**Verification:** No SHA256 usage in merkle operations.

---

### 1.2 Wraith Protocol Fixes (2/2 Verified)

#### WR2-H1: Token Replay Prevention - **PASS**

**Evidence:** `coordinator.rs` implements `used_tokens` HashSet:

```rust
// coordinator.rs:232
used_tokens: HashSet<[u8; 32]>,

// coordinator.rs:558-564 - Replay check BEFORE verification
for token in &tokens {
    let hash = Self::compute_token_hash(token);
    if self.used_tokens.contains(&hash) {
        return Err(WraithError::InvalidInput("Token replay detected".into()));
    }
}

// coordinator.rs:579-581 - Tokens marked as used after verification
for token in &tokens {
    self.used_tokens.insert(Self::compute_token_hash(token));
}
```

---

#### WR2-H2: Timing Attack Fix - **PASS**

**Evidence:** `blind.rs` uses remove-first pattern:

```rust
// blind.rs:441-456
// SECURITY: Remove nonce FIRST to prevent timing attacks
let nonce = self
    .active_nonces
    .remove(&challenge.session_id)  // REMOVE FIRST
    .ok_or_else(|| WraithError::MissingData("Nonce session not found or consumed".into()))?;

// Verify requestor matches AFTER removal
if let Some(ref bound_id) = nonce.bound_ghost_id {
    if bound_id != requesting_ghost_id {
        // Nonce is already consumed - no information leaked
        return Err(WraithError::InvalidSignature(...));
    }
}
```

---

### 1.3 P2P/Payout Fixes (3/3 Verified)

#### P2P-C3: Rate Limiting in ZkPayoutVoteHandler - **PASS**

**Evidence:** `zk_payout_handler.rs` has rate limiter:

```rust
// zk_payout_handler.rs:155
rate_limiter: RateLimiter,

// zk_payout_handler.rs:617-628
if !self.rate_limiter.check_and_consume(&envelope.sender) {
    return Err(GhostError::RateLimited(...));
}
```

---

#### PO-C3: Verification Provider Required - **PASS**

**Evidence:** `payout.rs` requires verification provider:

```rust
// payout.rs:791-799
pub fn handle_solo_block_found(&self, mut data: SoloBlockFoundData) -> GhostResult<[u8; 32]> {
    let provider = self.qualification_provider
        .as_ref()
        .ok_or_else(|| GhostError::NoVerificationProvider)?;  // REQUIRED
```

---

#### PO-H4: TX Fees Unallocated Tracking - **PASS**

**Evidence:** `types.rs` has field with serde default:

```rust
// types.rs:259-262
#[serde(default)]
pub tx_fees_unallocated: Satoshis,

// payout.rs:243,276-282 - Properly tracked
let mut tx_fees_unallocated: u64 = 0;
// ...
tx_fees_unallocated = fee_dist.tx_fees_to_block_finder;
```

---

## 2. New Issues Identified

### 2.1 HIGH Severity

#### ZK3-H1: Groth16 Simulation Fallback Active in Production

**Location:** `crates/ghost-zkp/src/prover.rs:288-294`

**Description:** The prover falls back to simulated (non-cryptographic) proofs when Groth16 parameters are unavailable:

```rust
} else {
    warn!("Groth16 parameters not available, using simulated proof");
    self.generate_proof_bytes(witness, cs.num_constraints())  // SHA256-based, NO security
}
```

**Impact:** If production provers are created without `new_with_setup()`, block proofs provide ZERO cryptographic guarantees. Attackers could forge proofs.

**Recommendation:**
1. Add `#[cfg(not(feature = "production"))]` guard around simulation fallback
2. Make `has_groth16_params()` check mandatory before proof generation
3. Remove simulation fallback entirely for mainnet

---

#### TODO-H1: Slashing Mechanism Incomplete

**Location:** `crates/ghost-consensus/src/vote_handler.rs:685-686`

**Description:** Equivocation detection exists but slashing is not implemented:

```rust
// TODO: Broadcast equivocation proof to network for slashing
// TODO: Ban the equivocating node
```

**Impact:** Validators can equivocate (double-vote) without penalty, undermining BFT security guarantees.

**Recommendation:** Implement node banning and slashing before mainnet.

---

#### TODO-H2: ghost-pay Compilation Error

**Location:** `bins/ghost-pay/src/main.rs:657`

**Description:** Code calls non-existent `set_state()` method:

```rust
ghost_lock.set_state(LockState::Jumping);  // Method doesn't exist
```

**Impact:** ghost-pay binary cannot compile, L2 payment functionality unavailable.

**Recommendation:** Change to `ghost_lock.transition(StateTransition::Jump)?`

---

### 2.2 MEDIUM Severity

#### ZK3-M1: Unwraps in Verifier Code

**Location:** `crates/ghost-zkp/src/verifier.rs:256,274,292`

**Description:** Groth16 point deserialization uses `.unwrap()` which can panic on malformed proofs:

```rust
a.unwrap()  // Can panic on invalid proof bytes
```

**Impact:** Malformed proofs cause verifier crash (DoS).

**Recommendation:** Convert to `ok_or(ZkError::InvalidProof)?`.

---

#### ZK3-M2: Placeholder Intermediate Roots

**Location:** `crates/ghost-zkp/src/prover.rs:513-526`

**Description:** V2 proving uses placeholder zeros for intermediate roots:

```rust
Some(Fr::ZERO)  // PLACEHOLDER - NOT CORRECT FOR CHAINED PROOFS
```

**Impact:** Multi-transaction block proofs will have incorrect intermediate state.

**Recommendation:** Implement proper intermediate root computation.

---

#### WR3-M1: Memory Growth in used_tokens

**Location:** `crates/wraith-protocol/src/coordinator.rs:232`

**Description:** `used_tokens` HashSet grows unboundedly - tokens are added but never removed.

**Impact:** Long-running coordinators may experience memory exhaustion.

**Recommendation:** Clear `used_tokens` when session reaches terminal state.

---

#### WR3-M2: used_tokens Not Purged for Privacy

**Location:** `crates/wraith-protocol/src/coordinator.rs:1214-1268`

**Description:** `purge_sensitive_data()` does NOT clear `used_tokens`.

**Impact:** Token hashes retained could be used for cross-reference attacks.

**Recommendation:** Add `self.used_tokens.clear()` to `purge_sensitive_data()`.

---

#### DEP-M1: Unsound lru Dependency

**Location:** Cargo.lock (via ratatui)

**Description:** `lru 0.12.5` has RUSTSEC-2026-0002 - `IterMut` violates Stacked Borrows causing undefined behavior.

**Impact:** TUI components using `ratatui` may exhibit undefined behavior.

**Recommendation:** Update `ratatui` when a fix is available or replace `lru` usage.

---

### 2.3 LOW Severity

| ID | Location | Description |
|----|----------|-------------|
| ZK3-L1 | mimc.rs:32-43 | MiMC constant derivation comment doesn't match code |
| ZK3-L2 | state_tree.rs:191-192 | `unwrap_or(Fr::ZERO)` silently masks errors |
| WR3-L1 | blind.rs:452 | Error message reveals nonce binding status |
| WR3-L2 | blind.rs:215 | `active_nonces` not thread-safe |
| WR3-L3 | coordinator.rs | No size limit on used_tokens |
| P2P3-L1 | zk_payout_handler.rs:67-70 | Rate limit config may be too permissive |
| P2P3-L2 | vote_handler.rs:64 | Token bucket uses floating point |

---

## 3. Dependency Security

### Cargo Audit Results

| Severity | Count | Action Required |
|----------|-------|-----------------|
| Critical | 0 | None |
| High | 0 | None |
| Medium | 1 | Update when available |
| Low/Unmaintained | 4 | Monitor for replacements |

**Unmaintained Dependencies:**
- bincode 1.3.3 (RUSTSEC-2025-0141)
- number_prefix 0.4.0 (RUSTSEC-2025-0119)
- paste 1.0.15 (RUSTSEC-2024-0436)
- proc-macro-error 1.0.4 (RUSTSEC-2024-0370)

---

## 4. Unsafe Code Analysis

**3 instances found** - all acceptable:

| Location | Usage | Risk |
|----------|-------|------|
| ghost-pool-core/share.rs | `NonZeroUsize::new_unchecked(1)` | None - compile-time constant |
| ghost-verification/routes.rs | FFI for `statvfs` | Low - standard filesystem call |

---

## 5. Mainnet Readiness Assessment

### BLOCKERS (Must Fix)

| Issue | Severity | Effort |
|-------|----------|--------|
| TODO-H2: ghost-pay compilation | HIGH | 5 min |
| ZK3-H1: Remove simulation fallback | HIGH | 1 hour |
| TODO-H1: Implement node banning | HIGH | 4 hours |

### RECOMMENDED (Should Fix)

| Issue | Severity | Effort |
|-------|----------|--------|
| ZK3-M1: Verifier unwraps | MEDIUM | 30 min |
| WR3-M2: Purge used_tokens | MEDIUM | 15 min |
| ZK3-M2: Intermediate roots | MEDIUM | 2 hours |

### DEFERRED (Post-Launch)

- All LOW severity issues
- Unmaintained dependency updates
- Rate limiter tuning

---

## 6. Comparison to Previous Audits

| Metric | Round 1 | Round 2 | Round 3 |
|--------|---------|---------|---------|
| Total Issues | 51 | 39 | 15 |
| CRITICAL | 11 | 3 | 0 |
| HIGH | 13 | 6 | 3 |
| Fixes Verified | N/A | 47/49 | 9/9 (100%) |

**Trend:** Security posture improving. No new CRITICAL issues. All Round 2 fixes verified.

---

## 7. Recommendations

### Immediate Actions (Before Mainnet)

1. **Fix ghost-pay compilation** - Change `set_state()` to `transition()`
2. **Disable simulation fallback** - Add feature flag or remove entirely
3. **Implement node banning** - Complete the TODO in vote_handler.rs

### Pre-Launch Checklist

- [ ] All 3 HIGH issues resolved
- [ ] Groth16 parameters loaded via MPC ceremony
- [ ] 1 week signet deployment with fixes
- [ ] Bug bounty program active
- [ ] Monitoring for equivocation in place

### Post-Launch Improvements

- Address MEDIUM issues within 30 days
- Monitor unmaintained dependencies
- Consider V2 proving intermediate root implementation

---

## 8. Conclusion

**Round 2 Remediation Status:** ALL 9 FIXES VERIFIED (100%)

The Bitcoin Ghost codebase has significantly improved security posture:
- All CRITICAL Round 2 issues properly fixed
- No new CRITICAL vulnerabilities introduced
- ZK proofs use real Groth16 (with caveat)
- Privacy protections enhanced in Wraith Protocol
- Rate limiting consistent across handlers

**Mainnet Readiness:** CONDITIONAL

The codebase is close to mainnet ready. Three HIGH issues must be resolved:
1. ghost-pay compilation (trivial fix)
2. Simulation fallback removal (deployment concern)
3. Node banning for equivocation (security completeness)

With these fixes, the project can proceed to mainnet deployment.

---

## Auditor Sign-Off

This audit represents a thorough verification of Round 2 remediation and comprehensive assessment of mainnet readiness. All 9 Round 2 fixes have been verified as correctly implemented. The 3 HIGH severity issues identified are addressable within a short timeframe.

**Recommendation:** Address HIGH issues, then proceed to mainnet launch.

**Estimated Remediation Time:** 1-2 days for HIGH issues

---

*Audit conducted on commit 9a7b1f8 (security: Complete Round 2 security remediation)*
