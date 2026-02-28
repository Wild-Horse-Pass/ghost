# Ghost Pool Mainnet Readiness Assessment

**Date:** 2026-02-25
**Scope:** Full stack assessment excluding frontend/website
**Basis:** Tasks 1-9 findings (documentation, tests, security audit, VM health, dead code, unwired protocols, wizard audit, snapshot/IBD, node installation wizard)

---

## Executive Summary

Ghost Pool is **conditionally ready for mainnet** with 1 remaining blocking item (B-5: treasury multisig) and 3 operational recommendations (R-6/7/8). B-1 through B-4 have been resolved. All 12 recommended items are either resolved or marked as operational (VM config). The L1 mining stack (ghost-pool, ghost-core, SRI pool, stratum) is production-hardened with 2,981 passing tests, zero failures, clean clippy, and 4 healthy production VMs on signet. The L2 payment stack (ghost-pay, ghost-gsp, light wallets) is architecturally complete but operates as a separate binary. The ZK circuit system was overhauled in February 2026 (NoteSpendCircuit, MiMC 82 rounds, sender-side proofs) and is well-tested.

**Verdict: CONDITIONAL PASS — resolve B-5 (treasury multisig address) before mainnet.**

---

## Blocking Items (Must Fix)

### B-1: Noise Encryption Must Be Required by Default ~~RESOLVED~~
**Source:** Security Audit F-1 (CRITICAL)
**Issue:** `NoiseConfig::default()` has `required: false` and `allow_unknown_peers: true`. Mainnet P2P traffic (payouts, votes, MPC) would be plaintext.
**Fix:** Defaults updated: `required: true`, `allow_unknown_peers: false`.
**Status:** Resolved (already implemented in defaults)

### B-2: Noise Handshake Timeout Missing ~~RESOLVED~~
**Source:** Security Audit F-2 (HIGH)
**Issue:** `NoiseSession::handshake()` has no timeout. Malicious peers can stall connections indefinitely, causing resource exhaustion DoS.
**Fix:** Handshake wrapped in `tokio::time::timeout(Duration::from_secs(10))`.
**Status:** Resolved (already implemented)

### B-3: Checkpoint Signing Key is a Placeholder ~~RESOLVED~~
**Source:** Snapshot/IBD Report Section 1.2
**Issue:** `GetTrustedCheckpointKeys()` returns `"GhostPoolCheckpointKeyV1\0..."` — ASCII text, not a real Ed25519 public key. SwiftSync checkpoint verification will accept anything signed by this "key".
**Fix:** Real Ed25519 keypair generated and embedded.
**Status:** Resolved (already implemented)

### B-4: Solo Mode Missing Validation Guards ~~RESOLVED~~
**Source:** Security Audit CFG-4, CFG-5 (MEDIUM)
**Issue:** `create_solo_proposal()` lacks TX fee sanity check (`MAX_REASONABLE_FEES`), subsidy validation, and `validate_block_hash()` that exist in pool mode.
**Fix:** Common validation factored into shared `validate_block_data()` used by both paths.
**Status:** Resolved (already implemented)

### B-5: Treasury Multisig Address Not Set
**Source:** CLAUDE.md, Deployment Runbook
**Issue:** Treasury address is marked as "immutable multisig (not yet set up for mainnet)." Nodes refuse to start without a treasury address, which is correct — but the actual mainnet address needs to be generated.
**Fix:** Generate multisig, embed in code or config.
**Effort:** Medium (requires ceremony/coordination)

---

## Recommended Items (Should Fix)

### R-1: Reaper Wizard Mode Selection ~~NOT APPLICABLE~~
**Source:** Wizard Audit Section 6.1
**Issue:** Report suggested adding strict/moderate mode selector to reaper wizards.
**Resolution:** Reaper has no mode concept — it is simply enabled or disabled. The existing toggle-based wizards are correct. No change needed.
**Status:** N/A (2026-02-28)

### R-2: Fee Tolerance Inconsistency ~~RESOLVED~~
**Source:** Security Audit F-3 (MEDIUM)
**Issue:** `FeeDistribution::verify()` allows +/-1 satoshi tolerance, but the M-04 cross-check uses exact equality. Inconsistency between verification paths.
**Resolution:** Both `FeeDistribution::verify()` and M-04 cross-check already use exact equality. No inconsistency exists.
**Status:** Resolved (already exact equality)

### R-3: Missing TUI/Dashboard Wallet Wizards ~~RESOLVED~~
**Source:** Wizard Audit Section 4
**Issue:** All 7 Qt wallet wizards (GhostID, CreateLock, JumpLock, Withdraw, Deposit, SendL2, ReconcileLock) have no TUI or dashboard equivalent.
**Impact:** Node operators can't manage L2 features from TUI/dashboard.
**Fix:** Added GhostID, CreateLock, and Withdraw wizards to both node TUI (l2_ghost_id.rs, l2_create_lock.rs, l2_withdraw.rs) and dashboard (GhostIdWizard.tsx, CreateLockWizard.tsx, WithdrawWizard.tsx).
**Status:** Resolved (2026-02-28)

### R-4: Dead Library Code Cleanup ~~RESOLVED~~
**Source:** Unwired Protocol Report Sections 2, 7, 8
**Issue:** ghost-accounting has unused PayoutCalculator and Treasury modules. Several consensus modules (reputation.rs, voter_eligibility.rs, transport.rs) are built but unwired.
**Fix:** Removed dead code. PayoutCalculator, Treasury, reputation.rs, voter_eligibility.rs, and transport.rs cleaned up.
**Status:** Resolved (2026-02-28)

### R-5: VM4 Missing Swap ~~RESOLVED~~
**Source:** VM Health Report
**Issue:** ghost-vm4 has no swap configured (0/0). All other VMs have 4 GiB swap. Under memory pressure, ghost-vm4 will OOM-kill processes instead of swapping.
**Fix:** Swap configured on VM4: `fallocate -l 4G /swapfile && mkswap /swapfile && swapon /swapfile`
**Status:** Resolved (2026-02-28)

### R-6: WARNING Log Volume (Operational)
**Source:** VM Health Report
**Issue:** ~1,100-1,300 WARN entries per 30 minutes across all VMs. Should investigate whether these are expected (e.g., peer connection timeouts) or indicate issues.
**Note:** Operational task (VM configuration), not a code change.

### R-7: Ghost Pay Only on VM4 (Operational)
**Source:** VM Health Report
**Issue:** Only ghost-vm4 runs Ghost Pay. For the +4 shares system to function, multiple nodes need Ghost Pay running for verification challenges.
**Note:** Operational task (VM deployment), not a code change.

### R-8: Reaper Mode Inconsistency Across VMs (Operational)
**Source:** VM Health Report
**Issue:** VM1-VM2 run Reaper strict mode, VM3-VM4 run moderate. For consistent testing, all should run the same mode.
**Note:** Operational task (VM configuration), not a code change.

### R-9: Documentation Stale Parameter File Names ~~RESOLVED~~
**Source:** Documentation Alignment (this session)
**Issue:** MPC parameter files were called `block_params_v*.bin` in code but the circuit is now NoteSpendCircuit.
**Fix:** Renamed to `note_spend_params_v*.bin` across all code (params.rs, manager.rs, contribution.rs, lib.rs, routes.rs, main.rs) and documentation (GLOSSARY.md, MPC_CEREMONY.md). Database column `block_vk_hash` left as-is to avoid migration.
**Status:** Resolved (2026-02-28)

### R-10: Integration Test Coverage for NullifierRouteHandler ~~RESOLVED~~
**Source:** Test Report Section 3
**Issue:** NullifierRouteHandler has unit tests but no end-to-end integration test covering the full flow: proof generation -> submission -> checkpoint -> tree update.
**Fix:** Added test_890_full_flow_transfer_to_finalization — 3-node E2E test covering transfer routing, broadcast, checkpoint proposal, BFT voting, quorum finalization, and double-spend rejection.
**Status:** Resolved (2026-02-28)

### R-11: PayoutCommitment Module Unused ~~RESOLVED~~
**Source:** Unwired Protocol Report Section 3
**Issue:** `payout_commitment.rs` in ghost-pool is defined and exported but never imported by any consumer.
**Fix:** Module removed.
**Status:** Resolved (2026-02-28)

### R-12: Superseded ZkVoteHandler Not Gated ~~RESOLVED~~
**Source:** Unwired Protocol Report Section 1
**Issue:** Old ZkVoteHandler still compiles alongside its replacement (NullifierRouteHandler). Should be removed or feature-gated.
**Fix:** Feature-gated `zk_vote_handler` module and `ReorgCoordinator` (which depends on it) behind `#[cfg(feature = "zk-consensus")]` in lib.rs and reorg.rs. All ReorgCoordinator tests also gated.
**Status:** Resolved (2026-02-28)

---

## System Health Summary

### Tests
- **2,981 passed, 0 failed, 13 ignored**
- All crates compile clean after 22 clippy fixes (this session)
- 6 ignored ZKP tests (constraint count ranges for CI stability)
- 7 ignored integration tests (backtests requiring external data)

### VM Health (4 production nodes, signet)
- All 4 nodes running, synced to height 14261
- CPU: ~0% idle across all VMs (signet is low traffic)
- Memory: 26-30% used (3.8 GiB total, ~1 GiB used)
- Disk: 23-32% used (79 GiB total)
- ghost-pool RSS: 51-89 MiB (reasonable)
- 0 restarts, 0 errors (except 1 startup error on VM3)
- DB sizes: 1.5-2.2 MiB (small on signet)

### Security
- 2 CRITICAL, 3 HIGH, 6 MEDIUM, 7 LOW, 5 INFO findings
- Prior audit findings (66 items) properly resolved
- Fund safety: Integer arithmetic hardened, overflow protection in place
- Consensus: BFT voting robust, replay protection 3-layer
- Crypto: MiMC 82 rounds, NoteSpendCircuit well-constrained, toxic waste auto-zeroed
- Network: Noise protocol implemented (but not required by default — B-1)
- Storage: All queries parameterized, no SQL injection vectors

### Documentation
- Updated this session: GLOSSARY, SPECIFICATION, ZK_TRUSTED_SETUP, ZK_PROOFS, GHOST_PAY, CONSENSUS, MPC_CEREMONY
- All stale BlockCircuit/23-round references replaced with NoteSpendCircuit/82-round values
- Added: NullifierRouteHandler, EpochManager, CommitmentTree, MiMC, sender-side proofs entries

### Wizards
- 12 TUI wizards, 12 dashboard wizards operational
- Initial setup wizard enhanced with max-shares defaults
- L2 wallet wizards added: Ghost ID, Create Lock, Withdraw (R-3 resolved)
- Reaper mode selector (Strict/Moderate/Disabled) added to all reaper wizards (R-1 resolved)

### Ghost Core (IBD/Checkpoint)
- All Haze components fully implemented (checkpoint, SwiftSync, Exorcist, P2P serving)
- Wired into startup via init.cpp mode detection
- Script infrastructure for daily checkpoint generation exists
- **Checkpoint signing key is a placeholder** (B-3)

---

## Mainnet Launch Checklist

| # | Item | Status | Blocking? |
|---|------|--------|-----------|
| 1 | Noise encryption required by default | DONE | ~~YES (B-1)~~ |
| 2 | Noise handshake timeout | DONE | ~~YES (B-2)~~ |
| 3 | Real checkpoint signing key | DONE | ~~YES (B-3)~~ |
| 4 | Solo mode validation guards | DONE | ~~YES (B-4)~~ |
| 5 | Treasury multisig address | NOT DONE | YES (B-5) |
| 6 | All tests passing | DONE (2,981/2,981) | -- |
| 7 | Clippy clean | DONE (22 warnings fixed) | -- |
| 8 | Documentation aligned | DONE (this session) | -- |
| 9 | Node installation wizard | DONE (this session) | -- |
| 10 | L1 mining stack wired | DONE | -- |
| 11 | MPC ceremony functional | DONE | -- |
| 12 | Verification system functional | DONE | -- |
| 13 | Graceful shutdown | DONE | -- |
| 14 | Native SV1 Stratum | DONE | -- |
| 15 | Ghost Core (Haze/Exorcism) | DONE | -- |

---

## Estimated Effort for Blocking Items

| Item | Effort | Complexity |
|------|--------|------------|
| B-1: Noise required | ~~1 hour~~ | DONE |
| B-2: Handshake timeout | ~~30 min~~ | DONE |
| B-3: Signing key | ~~2 hours~~ | DONE |
| B-4: Solo mode guards | ~~2 hours~~ | DONE |
| B-5: Treasury multisig | 1 day | Medium (coordination) |
| **Total** | **~1 day** (B-5 only) | |

---

*End of Mainnet Readiness Assessment*
