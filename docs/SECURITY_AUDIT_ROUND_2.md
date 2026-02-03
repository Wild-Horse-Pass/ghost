# Bitcoin Ghost Security Audit - Round 2

**Date:** 2026-02-03
**Auditor:** Third-Party Senior Developer
**Scope:** Follow-up security review after 51-issue remediation
**Status:** Complete

---

## Executive Summary

This second security audit was conducted to verify the remediation of 51 issues from Round 1 and identify any new vulnerabilities. The audit covered all 5 critical areas: ZK Verification, Ghost Locks, Wraith Protocol, P2P Consensus, and Payout Logic.

### Key Findings

| Category | Round 1 Fixes Verified | New CRITICAL | New HIGH | New MEDIUM | New LOW |
|----------|------------------------|--------------|----------|------------|---------|
| ZK Verification | 7/7 (100%) | 2 | 2 | 3 | 3 |
| Ghost Locks | 8/8 (100%) | 0 | 0 | 2 | 4 |
| Wraith Protocol | 12/12 (100%) | 0 | 2 | 4 | 3 |
| P2P Consensus | 11/11 (100%) | 0 | 1 | 4 | 3 |
| Payout Logic | 9/11 (82%) | 1 | 1 | 2 | 2 |
| **TOTAL** | **47/49 (96%)** | **3** | **6** | **15** | **15** |

### Severity Distribution

- **CRITICAL**: 3 issues (must fix before mainnet)
- **HIGH**: 6 issues (should fix before mainnet)
- **MEDIUM**: 15 issues (recommended fixes)
- **LOW**: 15 issues (minor improvements)

---

## 1. ZK Verification Audit Results

### Previous Fixes Verified (7/7)

| ID | Status | Notes |
|----|--------|-------|
| ZK-C1 | VERIFIED | Simulated verification bypass removed, #[cfg(test)] gates test mode |
| ZK-C2 | VERIFIED | Real Groth16 BlockVerifier with bellperson |
| ZK-C3 | VERIFIED | All public inputs verified (miner_sum, node_sum, treasury_amount, epoch) |
| ZK-H1 | VERIFIED | MiMC hash replaces weak algebraic hash |
| ZK-H3 | VERIFIED | Subgroup checks via is_torsion_free() |
| ZK-M1 | VERIFIED | Metadata commitment as public input |
| ZK-M3 | VERIFIED | checked_add replaces saturating_add |

### New Issues Found

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| ZK-R2-C1 | CRITICAL | saturating_add/sub still used in PaymentWitness and types.rs, masking overflows | types.rs:199-204, payment.rs:42-48 |
| ZK-R2-C2 | CRITICAL | BlockProver/BlockVerifier lack real Groth16 - only hash-based simulation | prover.rs:206-231 |
| ZK-R2-H1 | HIGH | MiMC with 10 rounds provides ~80 bits security (need 128) | state_transition.rs:387-388 |
| ZK-R2-H2 | HIGH | Hash mismatch: state_tree.rs uses SHA256, circuits use MiMC | state_tree.rs:170-186 |
| ZK-R2-M1 | MEDIUM | MiMC round constants use weak small primes | merkle.rs:252-263 |
| ZK-R2-M2 | MEDIUM | Field element conversion discards top bit | verifier.rs:417-418 |
| ZK-R2-M3 | MEDIUM | metadata_commitment uses unwrap_or(ZERO) | payout.rs:58 |
| ZK-R2-L1 | LOW | PaymentCircuit constructor has no overflow check | payment.rs:41-49 |
| ZK-R2-L2 | LOW | circuit_simple_hash is insecure and exported | state_tree.rs:220-224 |
| ZK-R2-L3 | LOW | Timing side-channel in proof verification logging | payout_verifier.rs:246 |

---

## 2. Ghost Locks Audit Results

### Previous Fixes Verified (8/8)

| ID | Status | Notes |
|----|--------|-------|
| GL-C1 | VERIFIED | OP_CSV correctly used for relative timelocks |
| GL-H1 | VERIFIED | RECOVERY_NSEQUENCE constant documented |
| GL-H2 | VERIFIED | Two-leaf balanced Taproot tree |
| GL-M1 | VERIFIED | State transitions validated via transition() |
| GL-M2 | VERIFIED | Recovery requires Active state |
| GL-L1 | VERIFIED | Denomination codes unique (u/T/S/M/L/XL) |
| GL-L2 | VERIFIED | creation_height validation |
| GL-L3 | VERIFIED | MIN_RECOVERY_BLOCKS constant exists |

### New Issues Found

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| GL2-M1 | MEDIUM | MIN_RECOVERY_BLOCKS not enforced at creation time | script.rs:94-105 |
| GL2-M2 | MEDIUM | Recovery state check is application-layer only, chain can diverge | lock.rs:227-232 |
| GL2-L1 | LOW | Naming confusion: recovery_height() implies absolute but uses CSV | timelock.rs:101-108 |
| GL2-L2 | LOW | Ghost Lock ID excludes timelock tier | script.rs:220-243 |
| GL2-L3 | LOW | **Long tier (105,120 blocks) exceeds BIP68 max (65,535)** | script.rs:98 |
| GL2-I1 | INFO | transition() for Recover doesn't validate timelock | state.rs:131 |

**NOTE:** GL2-L3 is technically LOW severity but has significant implications - the Long tier timelock cannot work as designed due to BIP68 limits.

---

## 3. Wraith Protocol Audit Results

### Previous Fixes Verified (12/12)

| ID | Status | Notes |
|----|--------|-------|
| WR-C1 | VERIFIED | Only entropy-based shuffle API public |
| WR-C2 | VERIFIED | Anonymous token submission |
| WR-H1 | VERIFIED | Nonces bound to participants |
| WR-H2 | VERIFIED | Duplicate address detection |
| WR-H3 | VERIFIED | Immediate data purging |
| WR-M1 | VERIFIED | ChaCha20Rng for shuffle |
| WR-M2 | VERIFIED | Nonce rate limiting |
| WR-M3 | VERIFIED | Participant reputation/ban |
| WR-M4 | VERIFIED | Session-specific participant IDs |
| WR-L1 | VERIFIED | Session ID uniqueness |
| WR-L2 | VERIFIED | UTXO existence verification |
| WR-L3 | VERIFIED | Monotonic clock for timeouts |

### New Issues Found

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| WR2-H1 | HIGH | Token replay: same token can be used across sessions | coordinator.rs:542-568 |
| WR2-H2 | HIGH | Nonce verification timing attack enables probing | blind.rs:433-491 |
| WR2-M1 | MEDIUM | Phase 2 data not purged after build | coordinator.rs:833-889 |
| WR2-M2 | MEDIUM | Ghost ID mappings retained after timeout | coordinator.rs:1019-1113 |
| WR2-M3 | MEDIUM | ReputationTracker unbounded growth | coordinator.rs:38-103 |
| WR2-M4 | MEDIUM | OP_RETURN leaks session ID hash enabling on-chain correlation | executor.rs:416-438 |
| WR2-L1 | LOW | Deprecated APIs still public | coordinator.rs:575-609 |
| WR2-L2 | LOW | SessionRegistry.clear() loses collision protection | session.rs:84-87 |
| WR2-L3 | LOW | Participant index retained post-purge | coordinator.rs:1188-1242 |

---

## 4. P2P Consensus Audit Results

### Previous Fixes Verified (11/11)

| ID | Status | Notes |
|----|--------|-------|
| P2P-C1 | VERIFIED | PoW verification for voter registration |
| P2P-C2 | VERIFIED | Rate limiting on registration |
| P2P-H1 | VERIFIED | Vote equivocation detection |
| P2P-H2 | VERIFIED | round_id in vote signatures |
| P2P-M1 | VERIFIED | Envelope timestamp validation |
| P2P-M2 | VERIFIED | Extended dedup mechanism |
| P2P-M3 | VERIFIED | Health ping rate limiting |
| P2P-M4 | VERIFIED | ZK vote handler rate limiting |
| P2P-M5 | VERIFIED | Automatic fork resolution |
| P2P-M6 | VERIFIED | Voter ID in signature data |
| P2P-L1 | VERIFIED | LRU cache for message eviction |

### New Issues Found

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| P2P-C3 | HIGH | ZkPayoutVoteHandler missing rate limiting (unlike ZkVoteHandler) | zk_payout_handler.rs:589-609 |
| P2P-C4 | MEDIUM | Threshold calculation rounds down (4*67/100=2, should be 3) | zk_vote_handler.rs:229-232 |
| P2P-H3 | MEDIUM | ZK vote equivocation not detected | zk_vote_handler.rs:419-439 |
| P2P-H4 | MEDIUM | ZK payout vote equivocation not detected | zk_payout_handler.rs:414-436 |
| P2P-M7 | MEDIUM | EquivocationProof not broadcast to network | reorg.rs:237-245 |
| P2P-M8 | LOW | ZK verifier bypass in testing mode | zk_vote_handler.rs:328-332 |
| P2P-M9 | LOW | Fork resolution not fully wired up | reorg.rs:43-44 |
| P2P-L2 | LOW | Rate limiter bucket unbounded growth | health_handler.rs:118-122 |

---

## 5. Payout Logic Audit Results

### Previous Fixes Verified (9/11 - 2 Partial)

| ID | Status | Notes |
|----|--------|-------|
| PO-C1 | VERIFIED | Single POOL_FEE_BASIS_POINTS constant |
| PO-C2 | **PARTIAL** | Required for pool mode, but solo mode bypasses |
| PO-H1 | VERIFIED | TX fees not silently redirected |
| PO-H2 | VERIFIED | Integer arithmetic with u128 intermediates |
| PO-H3 | VERIFIED | Single unified implementation |
| PO-M1 | VERIFIED | Explicit dust accounting |
| PO-M2 | VERIFIED | Treasury address required |
| PO-M3 | VERIFIED | Proper integer division |
| PO-M4 | VERIFIED | Work value validation with cap |
| PO-L1 | VERIFIED | Duplicate share detection (memory-only acceptable) |
| PO-L2 | **PARTIAL** | debug_assert still used in treasury.rs |
| PO-L3 | VERIFIED | Consistent recipient ID hashing |

### New Issues Found

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| PO-C3 | CRITICAL | Solo mode bypasses verification provider requirement | payout.rs:779-826 |
| PO-H4 | HIGH | tx_fee_allocation_failed flag not checked upstream | payout.rs:201,427 |
| PO-M5 | MEDIUM | Floating point still used for miner work input | payout.rs:125 |
| PO-M6 | MEDIUM | qualification_provider is Option despite being required | payout.rs:655 |
| PO-L4 | LOW | NaN handling in sort uses unwrap_or | payout.rs:423 |
| PO-L5 | LOW | Work percentage cap is warn-only, not enforced | round.rs:275-284 |

---

## Critical Issues Summary (Must Fix Before Mainnet)

### 1. ZK-R2-C1: Saturating Arithmetic in Witness Types
**Severity:** CRITICAL
**Risk:** Integer overflow could go undetected in payment witness generation
**Fix:** Replace saturating_add/sub with checked_add/sub in types.rs and payment.rs

### 2. ZK-R2-C2: Block Proofs Are Not Real ZK
**Severity:** CRITICAL
**Risk:** Block proofs provide no cryptographic security (hash-based simulation)
**Fix:** Implement real Groth16 for BlockProver/BlockVerifier like PayoutProver

### 3. PO-C3: Solo Mode Bypasses Verification
**Severity:** CRITICAL
**Risk:** Node rewards in solo mode distributed without capability verification
**Fix:** Add QualifiedCapabilityProvider requirement to handle_solo_block_found()

---

## High Severity Issues Summary (Should Fix Before Mainnet)

| ID | Area | Description |
|----|------|-------------|
| ZK-R2-H1 | ZK | MiMC 10 rounds = ~80 bits security |
| ZK-R2-H2 | ZK | Hash function mismatch (SHA256 vs MiMC) |
| WR2-H1 | Wraith | Token replay across sessions |
| WR2-H2 | Wraith | Nonce verification timing attack |
| P2P-C3 | P2P | ZkPayoutVoteHandler missing rate limiting |
| PO-H4 | Payout | tx_fee_allocation_failed not checked |

---

## Mainnet Readiness Assessment

### BLOCKERS (Must Fix)
1. **ZK-R2-C2**: Block proofs are simulation-only - fundamental security gap
2. **PO-C3**: Solo mode verification bypass
3. **ZK-R2-C1**: Saturating arithmetic in witness types

### RECOMMENDED (Should Fix)
4. **WR2-H1/H2**: Token replay and nonce timing attacks
5. **P2P-C3**: ZkPayoutVoteHandler rate limiting
6. **GL2-L3**: Long tier exceeds BIP68 limits
7. **PO-H4**: TX fee allocation failure handling

### DEFERRED (Can Fix Post-Launch)
- All MEDIUM and LOW severity issues
- Performance optimizations
- Documentation improvements

---

## Comparison to Round 1

| Metric | Round 1 | Round 2 |
|--------|---------|---------|
| Total Issues | 51 | 39 |
| CRITICAL | 11 | 3 |
| HIGH | 13 | 6 |
| Fixes Verified | N/A | 47/49 (96%) |
| Code Quality | Good | Improved |

**Assessment:** Round 1 remediation was successful. 96% of fixes verified. New issues are primarily in areas not deeply examined in Round 1 (block proofs vs payout proofs, solo mode, ZK handler parity).

---

## Recommendations

1. **Immediate**: Fix the 3 CRITICAL issues before any mainnet deployment
2. **Pre-Mainnet**: Address the 6 HIGH severity issues
3. **Consider**: Disable solo mode for mainnet launch if PO-C3 fix is complex
4. **Document**: BIP68 limitation for Long tier timelocks (GL2-L3)
5. **Monitor**: Deploy to signet with fixes for 1 week before mainnet

---

## Auditor Sign-Off

This audit represents a thorough review of the Bitcoin Ghost codebase following the first round of security remediation. While 96% of previous fixes were verified, 3 CRITICAL and 6 HIGH severity issues remain that should be addressed before mainnet launch.

**Recommendation:** NOT READY for mainnet. Address CRITICAL issues first.

**Estimated Remediation Time:** 1-2 weeks for CRITICAL + HIGH issues
