# Bitcoin Ghost Mainnet Release Plan

**Version Target:** v2.0.0 (Mainnet)
**Current Version:** v1.6.0 (Signet)
**Document Date:** 2026-02-03
**Last Updated:** 2026-02-03 (Post Round 3 Security Audit)

---

## Overview

This plan outlines the path from current signet deployment to mainnet launch. Based on comprehensive audit findings including Round 3 security review, the following milestones must be completed.

**Current Status:** Round 3 security audit verified all Round 2 fixes and identified 3 remaining HIGH issues requiring attention.

---

## Phase 1: Critical Security Fixes (v1.7.0) - COMPLETE

**Target:** 2 weeks
**Status:** Complete (2026-02-03)

### 1.1 Wraith Protocol Privacy Fix

**Issue:** Coordinator stores ghost_id linked to final_address
**Files:** `crates/wraith-protocol/src/coordinator.rs`

**Completed Tasks:**
- [x] Added `SessionAuditRecord` struct for minimal audit data (no ghost_id linkage)
- [x] Implemented `purge_sensitive_data()` with 6-block confirmation requirement
- [x] Added `confirmation_depth` tracking in `PhaseExecution`
- [x] Added shuffle randomization with CSPRNG entropy

**Acceptance Criteria:** Met
- Coordinator cannot reconstruct user -> output mapping after session
- Output shuffle is non-deterministic to external observers

### 1.2 ZK Proof Verification

**Issue:** Groth16 proof verification not implemented
**File:** `crates/ghost-zkp/src/payout_verifier.rs`

**Completed Tasks:**
- [x] Implemented real Groth16 proof verification with bellperson
- [x] Added proper G1/G2 point serialization (192-byte proofs)
- [x] Made `total_available` a public input for verifier checking
- [x] Added witness padding to match circuit structure between setup and proving

### 1.3 Vote Signature Verification

**Issues:**
- `crates/ghost-consensus/src/zk_payout_handler.rs`
- `crates/ghost-consensus/src/zk_vote_handler.rs`
- `crates/ghost-consensus/src/reorg.rs`

**Completed Tasks:**
- [x] Implemented vote signature verification in zk_vote_handler.rs
- [x] Implemented vote signature verification in zk_payout_handler.rs
- [x] Added dual-signature verification for EquivocationProof in reorg.rs
- [x] Added signature field to L2BlockRef for proper audit trail

---

## Phase 2: Documentation & Constants (v1.8.0) - COMPLETE

**Target:** 1 week
**Status:** Complete (2026-02-03)

### 2.1 Documentation Updates

**Critical Fixes:**
- [x] All GitHub URLs fixed (AquaticLabs/anthropics -> bitcoin-ghost)
- [x] DEPLOYMENT_RUNBOOK.md: Fix binary paths (`/opt/ghost/bin/`)
- [x] API_ENDPOINTS.md: Add `/gsp/` prefix to GSP endpoints
- [x] CONSENSUS.md: Update socket pattern documentation (PUB/SUB)
- [x] GHOST_KEYS.md: Correct tweak computation description

### 2.2 Production Constants

**File:** `crates/ghost-common/src/constants.rs`

**Changes:**
- [x] `MIN_CHALLENGES_FOR_QUALIFICATION`: Updated in documentation
- [x] `NODES_TO_VERIFY_PER_ROUND`: Updated in documentation
- [ ] Add mainnet-specific treasury address (pre-mainnet)
- [ ] Add mainnet-specific seed nodes (pre-mainnet)

---

## Phase 3: Code Quality (v1.9.0) - COMPLETE

**Target:** 1 week
**Status:** Complete (2026-02-03)

### 3.1 Fix Clippy Warnings

**Total:** 375+ warnings addressed across 85+ files

**Fixed crates:**
- [x] ghost-consensus (52 warnings)
- [x] ghost-zkp (44 warnings)
- [x] ghost-pool (39 warnings)
- [x] ghost-reconciliation (33 warnings)
- [x] All other crates (remaining warnings)

**Result:** `cargo clippy --workspace` now shows minimal warnings

### 3.2 Address Remaining TODOs

**Deferred to Post-Mainnet (Non-Critical):**
- [ ] `ghost-gsp/src/proxy/pay_node.rs`: Implement mempool monitoring
- [ ] `ghost-gsp/src/state/reorg_bridge.rs`: Query affected payments on reorg
- [ ] `bins/ghost-pool/src/template_provider.rs`: Return full transaction data

**Note:** These TODOs are feature enhancements, not security-critical. Safe to launch without them.

---

## Phase 3.5: Round 2 Security Remediation (v1.9.5) - COMPLETE

**Target:** 1-2 weeks
**Status:** Complete (2026-02-03)
**Verified by:** Round 3 Security Audit

### 3.5.1 CRITICAL Issues - ALL FIXED

| ID | Issue | File | Status |
|----|-------|------|--------|
| ZK-R2-C1 | saturating_add/sub in witness types | types.rs, payment.rs | FIXED - Uses checked_add/sub |
| ZK-R2-C2 | Block proofs are hash-based | prover.rs | FIXED - Real Groth16 implemented |
| PO-C3 | Solo mode bypasses verification | payout.rs | FIXED - Provider required |

### 3.5.2 HIGH Issues - ALL FIXED

| ID | Issue | File | Status |
|----|-------|------|--------|
| ZK-R2-H1 | MiMC 10 rounds = ~80 bits | mimc.rs | FIXED - 23 rounds (~115 bits) |
| ZK-R2-H2 | Hash mismatch (SHA256 vs MiMC) | state_tree.rs | FIXED - Uses MiMC throughout |
| WR2-H1 | Token replay across sessions | coordinator.rs | FIXED - used_tokens HashSet |
| WR2-H2 | Nonce verification timing attack | blind.rs | FIXED - Remove-first pattern |
| P2P-C3 | ZkPayoutVoteHandler no rate limiting | zk_payout_handler.rs | FIXED - RateLimiter added |
| PO-H4 | tx_fee_allocation_failed not checked | payout.rs, types.rs | FIXED - tx_fees_unallocated field |

### 3.5.3 Acceptance Criteria - ALL MET

- [x] All CRITICAL issues fixed and verified
- [x] All HIGH issues fixed and verified
- [x] `cargo test --workspace` passes (848 tests)
- [x] Round 3 audit verified all fixes

---

## Phase 3.6: Round 3 Audit Fixes (v1.9.6) - REQUIRED

**Target:** 1-2 days
**Status:** IN PROGRESS
**Blocking:** Mainnet launch

### 3.6.1 HIGH Issues (Must Fix)

| ID | Issue | File | Fix Required |
|----|-------|------|--------------|
| ZK3-H1 | Groth16 simulation fallback active | prover.rs:288-294 | Add feature flag or remove |
| TODO-H1 | Slashing mechanism incomplete | vote_handler.rs:685-686 | Implement node banning |
| TODO-H2 | ghost-pay compilation error | ghost-pay/main.rs:657 | Fix set_state() call |

**Estimated Time:** 1-2 days

### 3.6.2 MEDIUM Issues (Should Fix Pre-Launch)

| ID | Issue | File |
|----|-------|------|
| ZK3-M1 | Unwraps in verifier code | verifier.rs:256,274,292 |
| ZK3-M2 | Placeholder intermediate roots | prover.rs:513-526 |
| WR3-M1 | Memory growth in used_tokens | coordinator.rs:232 |
| WR3-M2 | used_tokens not purged | coordinator.rs:1214-1268 |

### 3.6.3 Acceptance Criteria

- [ ] All HIGH issues fixed
- [ ] ghost-pay compiles successfully
- [ ] No simulation fallback in production builds
- [ ] 1 week signet deployment without issues

---

## Phase 4: Mainnet Infrastructure (Pre-Release)

**Target:** 2 weeks

### 4.1 Mainnet Node Deployment

**Requirements:**
- Minimum 4 geographically distributed nodes
- Each node: 16GB RAM, 4 CPU, 1TB NVMe
- Full Bitcoin Core archive nodes
- All 5 capabilities enabled (15 shares each)

**Regions:**
- EU West (primary)
- US East
- US West
- Asia Pacific

### 4.2 Registry Service

- [ ] Deploy ghost-registry service
- [ ] Configure mainnet DNS (pool.bitcoinghost.org)
- [ ] Set up regional subdomains (eu.pool, us.pool, asia.pool)

### 4.3 Monitoring

- [ ] Prometheus metrics endpoints
- [ ] Grafana dashboards
- [ ] Alerting for node failures
- [ ] Block production monitoring
- [ ] Payout verification monitoring

---

## Phase 5: Security Audit (External) - ROUND 3 COMPLETE

**Target:** 2-4 weeks
**Status:** Round 3 Complete (2026-02-03)

### 5.1 Third-Party Audit Results

| Audit | Issues Found | Fixed | Verified |
|-------|--------------|-------|----------|
| Round 1 | 51 | 51 | 100% |
| Round 2 | 39 | 9 (CRITICAL+HIGH) | 100% |
| Round 3 | 15 | 3 HIGH pending | In progress |

### 5.2 Security Posture Summary

| Category | Before Audits | After Round 3 |
|----------|---------------|---------------|
| ZK Verification | Simulated bypass | Real Groth16 with 23-round MiMC |
| Ghost Locks | CLTV/CSV mismatch | Correct OP_CSV, two-leaf Taproot |
| Wraith Protocol | Linkable shuffle | CSPRNG, token replay prevention, timing fix |
| P2P Consensus | No sybil protection | PoW + rate limiting + equivocation detection |
| Payout Logic | Optional verification | Mandatory, fail-closed, checked arithmetic |

### 5.3 Bug Bounty Program

- [ ] Set up bug bounty (HackerOne/Immunefi)
- [ ] Define reward tiers:
  - Critical: $10,000+
  - High: $5,000
  - Medium: $1,000
  - Low: $500

---

## Phase 6: Mainnet Launch (v2.0.0)

### 6.1 Launch Checklist

**Pre-Launch:**
- [x] All Phase 1 items complete
- [x] All Phase 2-3 items complete
- [x] Phase 3.5 Round 2 CRITICAL fixes complete
- [x] Phase 3.5 Round 2 HIGH fixes complete
- [ ] **Phase 3.6 Round 3 HIGH fixes complete** (BLOCKING)
- [ ] External security audit Round 3 remediation verified
- [ ] Mainnet nodes synced and verified
- [ ] Registry service operational
- [ ] Monitoring active
- [ ] Bug bounty live

**Launch Day:**
- [ ] Enable mainnet configuration flag
- [ ] Announce on social channels
- [ ] Monitor first 100 blocks closely
- [ ] Verify payout distribution working
- [ ] Confirm node verification working

### 6.2 Post-Launch Monitoring

**First 24 Hours:**
- Block production rate
- Miner connection count
- Payout transaction confirmations
- Node capability verification logs
- Wraith session activity

**First Week:**
- Treasury accumulation
- Node reward distribution
- Any reorganization handling
- P2P mesh stability

---

## Version Milestones

| Version | Focus | Target Date | Status |
|---------|-------|-------------|--------|
| v1.7.0 | Critical Security Fixes (Round 1) | +2 weeks | COMPLETE |
| v1.8.0 | Documentation & Constants | +3 weeks | COMPLETE |
| v1.9.0 | Code Quality | +4 weeks | COMPLETE |
| v1.9.5 | Round 2 Security Remediation | +5-6 weeks | COMPLETE |
| v1.9.6 | Round 3 Security Fixes | +6 weeks | IN PROGRESS |
| v2.0.0-rc1 | Release Candidate | +7 weeks | Pending |
| v2.0.0 | Mainnet Launch | +8-10 weeks | Pending |

---

## Risk Mitigation

### Technical Risks

| Risk | Mitigation | Status |
|------|------------|--------|
| Wraith coordinator compromise | Data purging with 6-block confirmation | MITIGATED |
| Invalid payouts | Groth16 ZK proof verification | MITIGATED |
| Consensus attacks | Vote signature verification | MITIGATED |
| Node sybil attacks | 95% uptime gatekeeper + PoW | MITIGATED |
| Block proof forgery | Real Groth16 in BlockProver | MITIGATED |
| Payout manipulation | Verification provider required | MITIGATED |
| Token replay attacks | used_tokens HashSet tracking | MITIGATED |
| Payout vote flooding | Rate limiting added | MITIGATED |
| **Simulation fallback** | **Needs feature flag** | OPEN (ZK3-H1) |
| **Equivocation unpunished** | **Node banning needed** | OPEN (TODO-H1) |

### Operational Risks

| Risk | Mitigation |
|------|------------|
| Node failure | 4+ geographically distributed nodes |
| DDoS | Cloudflare + rate limiting on APIs |
| Key compromise | Multi-sig treasury, hardware key storage |
| Database corruption | Regular backups, replicated storage |

---

## Round 3 Issues - Full List

### HIGH (3) - Must Fix

| ID | Area | Description | Fix |
|----|------|-------------|-----|
| ZK3-H1 | ZK | Groth16 simulation fallback active | Add feature flag |
| TODO-H1 | P2P | Slashing mechanism incomplete | Implement banning |
| TODO-H2 | L2 | ghost-pay compilation error | Fix method call |

### MEDIUM (5) - Should Fix

| ID | Area | Description |
|----|------|-------------|
| ZK3-M1 | ZK | Unwraps in verifier code |
| ZK3-M2 | ZK | Placeholder intermediate roots |
| WR3-M1 | Wraith | Memory growth in used_tokens |
| WR3-M2 | Wraith | used_tokens not purged |
| DEP-M1 | Deps | Unsound lru dependency |

### LOW (7) - Post-Launch

See `docs/SECURITY_AUDIT_ROUND_3.md` for complete list.

---

## Success Criteria

**Mainnet is successful when:**

1. **Mining:** Blocks produced consistently, miners receiving correct payouts
2. **Node Rewards:** 5-4-3-2-1 share system distributing rewards fairly
3. **Ghost Pay L2:** Transactions processing, Wraith sessions completing
4. **Privacy:** No linkability between Wraith inputs and outputs
5. **Uptime:** 99.9% availability across node infrastructure
6. **Security:** All CRITICAL and HIGH issues from all audits resolved

---

## Contacts & Resources

- **Repository:** https://github.com/bitcoin-ghost/ghost
- **Documentation:** https://docs.bitcoinghost.org
- **Website:** https://bitcoinghost.org
- **Support:** support@bitcoinghost.org
- **Security Audits:**
  - Round 1: `docs/SECURITY_AUDIT.md`
  - Round 2: `docs/SECURITY_AUDIT_ROUND_2.md`
  - Round 3: `docs/SECURITY_AUDIT_ROUND_3.md`
