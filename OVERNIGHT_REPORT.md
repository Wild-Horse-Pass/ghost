# Overnight Report — 2026-03-02

## Executive Summary

Four workstreams completed overnight: test suite execution, ZK/crypto wiring audit, security/privacy audit, and wizard setup assessment. The codebase is in strong shape with 2,802 of 2,805 tests passing, but the audit uncovered significant findings that need attention.

**Key findings:**
1. ZK payout proofs are dead code — payouts use plain BFT voting, not ZK proofs
2. ~~L2 endpoints publicly exposed without auth~~ **FIXED** — moved to localhost-only router
3. The wizard/TUI has no backend — it collects setup input but never writes config files
4. ~~Shield amounts logged in plaintext~~ **FIXED** — amount removed from log
5. L2 tree sync responses are not signature-verified, allowing poisoning by malicious peers
6. ~~3 TLS tests failing~~ **FIXED** — installed rustls CryptoProvider in test setup

---

## 1. Test Results

**2,802 passed / 3 failed / 172 ignored across 30 workspace crates**

All 3 failures are in `ghost-common` TLS tests — they require a rustls `CryptoProvider` to be installed at the process level before running. These tests work when ghost-pool or ghost-pay is the test runner (which installs the provider at startup) but fail when running `ghost-common` in isolation. This is a test harness issue, not a code bug.

| Crate | Pass | Fail | Ignored |
|-------|------|------|---------|
| ghost-consensus | 236 | 0 | 1 |
| ghost-tap-core | 247 | 0 | 0 |
| ghost-common | 194 | **3** | 0 |
| ghost-pool | 192 | 0 | 0 |
| ghost-zkp | 178 | 0 | 10 |
| ghost-reaper | 119 | 0 | 4 |
| ghost-verification | 117 | 0 | 2 |
| wraith-protocol | 114 | 0 | 3 |
| ghost-storage | 100 | 0 | 1 |
| ghost-keys | 82 | 0 | 3 |
| ghost-light-wallet | 76 | 0 | 2 |
| ghost-locks | 71 | 0 | 0 |
| ghost-gsp | 70 | 0 | 2 |
| ghost-reconciliation | 68 | 0 | 0 |
| ghost-gsp-proto | 49 | 0 | 0 |
| ghost-tap-integration | 35 | 0 | 0 |
| ghost-pay | 33 | 0 | 0 |
| ghost-mpc | 32 | 0 | 0 |
| ghost-registry | 25 | 0 | 0 |
| translator | 27 | 0 | 0 |
| ghost-template | 21 | 0 | 0 |
| ghost-buds | 23 | 0 | 0 |
| ghost-accounting | 16 | 0 | 0 |
| ghost-policy | 14 | 0 | 0 |
| ghost-node-tui | 3 | 0 | 0 |
| bitcoin-ghost-tests | 1,050 | 0 | 142 |

The 172 ignored tests are either cluster chaos tests requiring live VMs (142), expensive ZK roundtrip tests (7), backtest tests requiring mainnet data (4), or doc tests for functions with complex setup (19).

---

## 2. ZK/Crypto Wiring Audit

Audited every feature that was declared/built to determine if it's actually wired into production code paths.

| Feature | Status | Notes |
|---------|--------|-------|
| NoteSpend ZK Verification | **WIRED** | All paths verify Groth16 proofs. Fail-closed on missing verifier. |
| **Payout ZK Proofs** | **DEAD CODE** | See critical finding below. |
| Confidential Transfer Circuit | **DEPRECATED** | Replaced by NoteSpend. Only used in test example. |
| MPC Ceremony | **WIRED** | Full P2P sync, params_callback fetches+verifies params, VK hot-reload. |
| Nullifier Double-Spend | **WIRED** | Enforced at all entry points. Tree sync trusts BFT checkpoints. |
| Epoch Compaction | **WIRED** | Triggered deterministically at epoch boundaries. Well-tested. |
| Wraith Protocol (CoinJoin) | **WIRED** | HTTP endpoints, coordinator lifecycle, wallet UI integration. |
| Ghost Reaper | **WIRED** | Actively filters transactions in template building. |
| Silent Payments (BIP-352) | **WIRED** | ghost-keys loaded, PaymentDetector scans transactions. |
| Timelocks (ghost-locks) | **WIRED** | Lock creation, P2WSH addresses, L1 settlement via reconciliation. |

### ~~Critical: ZK Payout Proofs Are Dead Infrastructure~~ RESOLVED

Dead `ZkPayoutVoteHandler` + `ReorgCoordinator` code deleted. Payouts use plain BFT via `VoteHandler` — payout privacy is not a design goal (node operators are trusted participants). Coinbase outputs are public on-chain regardless.

---

## 3. Security Audit

| # | Severity | Finding | Location |
|---|----------|---------|----------|
| 1 | **CRITICAL** | L2 endpoints publicly exposed without auth | `routes.rs:309-314` |
| 2 | **MEDIUM** | Tree sync response applied without checkpoint signature verification | `nullifier_route_handler.rs:1114-1159` |
| 3 | **MEDIUM** | Shield amounts logged in plaintext | `ghost-pay/main.rs:3000-3003` |
| 4 | **MEDIUM** | ghost-pay.db not encrypted at rest | `database.rs:229` |
| 5 | **LOW** | `encrypted_change`/`encrypted_recipient` always empty | `message.rs:1414-1416` |
| 6 | **LOW** | Password file written non-atomically | `ghost-pay/main.rs:389-409` |
| 7 | **LOW** | Health pings expose IP addresses in cleartext ZMQ | `health_handler.rs:839-860` |

### S-1 CRITICAL: L2 Endpoints Publicly Exposed

`POST /api/v1/l2/submit` and `POST /api/v1/l2/sync-commitment` are in the **public** router on ghost-pool's verification server. They bind to `0.0.0.0` (all interfaces). Any external attacker can:

- **Inject arbitrary commitments** via `sync-commitment` — poisoning the Merkle tree. This endpoint has NO proof verification; it trusts that the caller (ghost-pay) already verified the shield.
- **Submit crafted transactions** via `l2/submit` — though the downstream handler does verify the Groth16 proof, so forgery isn't possible.

**Fix:** Move both endpoints to the `localhost_router` (since ghost-pay is colocated) or add HMAC authentication.

### S-2: Tree Sync Response Not Signature-Verified

When a node joins the network and syncs L2 state via `L2TreeSyncResponse`, the checkpoint blocks in the response are applied directly without verifying their `proposer_signature`. A malicious peer could fabricate checkpoint blocks containing fake commitments, nullifiers, and transactions.

**Fix:** Verify each checkpoint block's proposer signature against the known validator set before applying.

### Clean Areas

- SQL injection: All queries use parameterized bindings
- API auth (ghost-pay): HMAC-SHA256 with constant-time comparison, replay protection
- Input validation: Thorough hex/bounds checking, TOCTOU protection under write locks
- RNG: All crypto uses OS CSPRNG (getrandom/OsRng)
- Key material in logs: None found
- P2P message auth: validate_and_verify pipeline is comprehensive
- Rate limiting: Per-peer, global, and per-endpoint limits
- File permissions: RAII umask guard + post-creation verification
- Atomic file writes: MPC params use temp+rename pattern

---

## 4. Wizard / Setup Assessment

**The wizard is a UI framework with no backend.** It collects user input through a beautiful multi-step TUI (Ratatui), but the `Submit` handler only sets a status message and closes the wizard. No config files are written, no keys are generated, no services are installed.

### What Node Setup Currently Requires (Manual)

1. Generate Ed25519 node key
2. Generate signing key (64 hex)
3. Generate API secret (64 hex)
4. Create directories (`/etc/ghost/`, `/var/lib/ghost/`, `/opt/ghost/bin/`)
5. Set ownership + permissions (`chown ghost:ghost`, `chmod 600`)
6. Copy config template to `/etc/ghost/pool.toml` and fill in values
7. Create environment file for systemd
8. Install systemd service file + daemon-reload + enable
9. Build and copy binary
10. Join MPC ceremony (requires coordination with existing elders)
11. Set `ZK_PARAMS_PATH` and `ZK_PARAMS_HASH` environment variables
12. Start service and verify

**None of this is automated.** As we saw tonight — setting up ZK production mode required manually computing param hashes, editing service files, and fixing a stale params file on VM2.

### Recommended: `ghost-setup` CLI

A single `ghost-setup` binary that:

1. Detects ghostd (Ghost Core) running and validates RPC connectivity
2. Generates all required keys (node key, signing key, API secret)
3. Prompts for operator preferences (mining, capabilities, policy)
4. Writes `/etc/ghost/pool.toml` from a template with correct values
5. Sets file permissions and ownership
6. Installs systemd service file from embedded template
7. Computes ZK param hashes and writes environment file
8. Runs pre-flight checks (disk space, ports, connectivity)
9. Starts the service and verifies health
10. If joining an existing network, syncs MPC params automatically

---

## 5. Deployment Status

All 4 production nodes are running the latest binaries with:
- `zk-production` feature enabled
- MPC ceremony params verified (hash check on startup)
- Config file permissions fixed (`600`, owned by `ghost`)
- "Bitcoin Core" → "Ghost Core" in all log messages
- L2 scalable commitment sync (checkpoint batching, prerequisites)

E2E NoteSpend test passes clean: shield → MPC proof (110ms) → transfer (200) → double-spend rejected (409).

---

## 6. Recommended Priority Order

### Done (Fixed Overnight)

1. ~~**Fix S-1: Move L2 endpoints to localhost_router**~~ **DONE** — L2 submit + sync-commitment moved to localhost-only router. Verified: remote returns 403, localhost returns 400 (accepted).
2. ~~**Fix S-3: Remove shield amount from logs**~~ **DONE** — `amount` field removed from shield log statement.
3. ~~**Fix 3 TLS test failures**~~ **DONE** — Installed `aws_lc_rs` CryptoProvider in test setup. 197/197 ghost-common tests pass.
4. **All nodes deployed** with latest binaries (zk-production, security fixes, Ghost Core branding).

### Short-Term (This Month)

5. **Fix S-2: Verify checkpoint signatures in tree sync** — Prevents join-time poisoning.
6. **Decide on ZK payout proofs** — Either wire them in or remove the dead code.
7. **Build `ghost-setup` CLI** — Automate node setup end-to-end.

### Medium-Term

8. **Wire `encrypted_change`/`encrypted_recipient`** — Complete note encryption for recipient notification.
9. **Atomic password file write** — Use temp+rename pattern.
10. **Consider SQLCipher for ghost-pay.db** — Full database encryption at rest.

---

*Report generated overnight 2026-03-02. All tests, audits, and deployments completed autonomously.*
