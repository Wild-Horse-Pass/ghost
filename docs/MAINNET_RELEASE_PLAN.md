# Bitcoin Ghost Mainnet Release Plan

**Version Target:** v2.0.0 (Mainnet)
**Current Version:** v1.6.0 (Signet)
**Document Date:** 2026-02-03
**Last Updated:** 2026-02-03 (Phase 2 & 3 Complete)

---

## Overview

This plan outlines the path from current signet deployment to mainnet launch. Based on comprehensive audit findings, the following milestones must be completed.

---

## Phase 1: Critical Security Fixes (v1.7.0) - ✅ COMPLETE

**Target:** 2 weeks
**Status:** Complete (2026-02-03)

### 1.1 Wraith Protocol Privacy Fix ✅

**Issue:** Coordinator stores ghost_id linked to final_address
**Files:** `crates/wraith-protocol/src/coordinator.rs`

**Completed Tasks:**
- [x] Added `SessionAuditRecord` struct for minimal audit data (no ghost_id linkage)
- [x] Implemented `purge_sensitive_data()` with 6-block confirmation requirement
- [x] Added `confirmation_depth` tracking in `PhaseExecution`
- [x] Added shuffle randomization with CSPRNG entropy

**Acceptance Criteria:** ✅ Met
- Coordinator cannot reconstruct user → output mapping after session
- Output shuffle is non-deterministic to external observers

### 1.2 ZK Proof Verification ✅

**Issue:** Groth16 proof verification not implemented
**File:** `crates/ghost-zkp/src/payout_verifier.rs`

**Completed Tasks:**
- [x] Implemented real Groth16 proof verification with bellperson
- [x] Added proper G1/G2 point serialization (192-byte proofs)
- [x] Made `total_available` a public input for verifier checking
- [x] Added witness padding to match circuit structure between setup and proving

### 1.3 Vote Signature Verification ✅

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

## Phase 2: Documentation & Constants (v1.8.0) - ✅ COMPLETE

**Target:** 1 week
**Status:** Complete (2026-02-03)

### 2.1 Documentation Updates ✅

**Critical Fixes:**
- [x] All GitHub URLs fixed (AquaticLabs/anthropics → bitcoin-ghost)
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

## Phase 3: Code Quality (v1.9.0) - ✅ COMPLETE

**Target:** 1 week
**Status:** Complete (2026-02-03)

### 3.1 Fix Clippy Warnings ✅

**Total:** 375+ warnings addressed across 85+ files

**Fixed crates:**
- [x] ghost-consensus (52 warnings)
- [x] ghost-zkp (44 warnings)
- [x] ghost-pool (39 warnings)
- [x] ghost-reconciliation (33 warnings)
- [x] All other crates (remaining warnings)

**Result:** `cargo clippy --workspace` now shows 0 warnings

### 3.2 Address Remaining TODOs

**Deferred to Post-Mainnet (Non-Critical):**
- [ ] `ghost-gsp/src/proxy/pay_node.rs`: Implement mempool monitoring
- [ ] `ghost-gsp/src/state/reorg_bridge.rs`: Query affected payments on reorg
- [ ] `bins/ghost-pool/src/template_provider.rs`: Return full transaction data

**Note:** These TODOs are feature enhancements, not security-critical. Safe to launch without them.

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

## Phase 5: Security Audit (External)

**Target:** 2-4 weeks

### 5.1 Third-Party Audit Scope

**Critical Areas:**
1. Wraith Protocol blind signatures
2. Ghost Lock timelock implementation
3. Payout distribution logic
4. P2P consensus mechanism
5. ZK proof verification

### 5.2 Bug Bounty Program

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
- [ ] External security audit complete
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
| v1.7.0 | Critical Security Fixes | +2 weeks | ✅ COMPLETE |
| v1.8.0 | Documentation & Constants | +3 weeks | ✅ COMPLETE |
| v1.9.0 | Code Quality | +4 weeks | ✅ COMPLETE |
| v2.0.0-rc1 | Release Candidate | +6 weeks | Pending |
| v2.0.0 | Mainnet Launch | +8-10 weeks | Pending |

---

## Risk Mitigation

### Technical Risks

| Risk | Mitigation | Status |
|------|------------|--------|
| Wraith coordinator compromise | Data purging with 6-block confirmation | ✅ Mitigated |
| Invalid payouts | Groth16 ZK proof verification | ✅ Mitigated |
| Consensus attacks | Vote signature verification | ✅ Mitigated |
| Node sybil attacks | 95% uptime gatekeeper already implemented | ✅ Mitigated |

### Operational Risks

| Risk | Mitigation |
|------|------------|
| Node failure | 4+ geographically distributed nodes |
| DDoS | Cloudflare + rate limiting on APIs |
| Key compromise | Multi-sig treasury, hardware key storage |
| Database corruption | Regular backups, replicated storage |

---

## Success Criteria

**Mainnet is successful when:**

1. **Mining:** Blocks produced consistently, miners receiving correct payouts
2. **Node Rewards:** 5-4-3-2-1 share system distributing rewards fairly
3. **Ghost Pay L2:** Transactions processing, Wraith sessions completing
4. **Privacy:** No linkability between Wraith inputs and outputs
5. **Uptime:** 99.9% availability across node infrastructure

---

## Contacts & Resources

- **Repository:** https://github.com/bitcoin-ghost/ghost
- **Documentation:** https://docs.bitcoinghost.org
- **Website:** https://bitcoinghost.org
- **Support:** support@bitcoinghost.org
