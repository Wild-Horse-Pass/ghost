# Ghost Pool Codebase Audit Report

**Date**: 2026-02-22
**Scope**: Full codebase audit of `/home/defenwycke/dev/projects/ghost`
**Files audited**: 408 Rust source files across bins/, crates/, tests/, and supporting infrastructure

---

## Executive Summary

The Ghost Pool codebase demonstrates significant security-conscious engineering, with extensive documentation of prior audit fixes (H-FUND-*, CRIT-MINE-*, M-*, etc.). The payout calculation, treasury decay, and consensus voting systems show particularly careful attention to integer arithmetic, overflow protection, and fund safety. However, the audit identified several issues ranging from critical to informational that should be addressed before mainnet deployment.

---

## CRITICAL Severity

### C-01: Solo Mode Treasury Address Fallback Bypasses Security

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, line 657-660
**Category**: Loss-of-Fund Scenario
**Impact**: In solo mode, if `treasury_address_snapshot` is `None`, the code silently falls back to the config address via `unwrap_or_else`. In pool mode (line 455-463), the same condition returns an error. This inconsistency means solo mode can proceed with an uncaptured treasury address, creating a TOCTOU vulnerability the pool mode explicitly fixed.

```rust
// Solo mode (VULNERABLE):
let treasury_address = data.treasury_address_snapshot.clone().unwrap_or_else(|| {
    warn!("No treasury address snapshot in solo mode - using current config");
    self.config.treasury_address.clone().unwrap_or_default()
});

// Pool mode (SECURE):
let treasury_address = match data.treasury_address_snapshot.clone() {
    Some(addr) => addr,
    None => {
        return Err(ghost_common::error::GhostError::PayoutCalculation(
            "No treasury address snapshot in BlockFoundData..."
        ));
    }
};
```

**Suggested fix**: Apply the same error-return pattern in `create_solo_proposal()` as in `create_proposal()`. The treasury address snapshot should be mandatory in both paths.

### C-02: Address Validation Uses NetworkUnchecked Throughout

**File**: Multiple locations in `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs` (lines 1079, 1108, 1144)
**Category**: Loss-of-Fund Scenario
**Impact**: All address validation uses `bitcoin::Address<NetworkUnchecked>`, which only verifies that the address string parses correctly but does NOT verify it matches the configured network (mainnet/signet/testnet/regtest). A miner could provide a testnet address on mainnet, which would parse successfully, be included in the coinbase, and create an unspendable output. The comment at line 1087-1090 explicitly acknowledges this gap:

```rust
// Note: We're lenient here - we just check that it parses.
// The actual network validation would require checking against self.config
```

**Suggested fix**: Call `.require_network()` on the parsed address using the network from `self.config.network` to reject cross-network addresses.

### C-03: std::sync::RwLock unwrap() Calls Can Poison and Crash

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/main.rs`, lines 124, 149, 162, 165, 168, 171, 174, 177, 180
**Category**: Error Handling / Race Condition
**Impact**: The `CachedGspHandler` uses `std::sync::RwLock` (not `parking_lot::RwLock`) and calls `.write().unwrap()` / `.read().unwrap()`. If a thread panics while holding the lock, the lock becomes poisoned. Subsequent `.unwrap()` calls will panic, crashing the entire node. Since these methods are called from the verification HTTP server endpoints and the background polling task, a single panic in the GSP polling loop would cascade and crash all GSP health checks.

```rust
let mut state = poll_cache.write().unwrap();  // line 124 - panics if poisoned
self.cache.read().unwrap().enabled             // line 162 - panics if poisoned
```

**Suggested fix**: Either use `parking_lot::RwLock` (which is already used everywhere else in the codebase and does not have poisoning), or handle the poison case gracefully with `.unwrap_or_else(|e| e.into_inner())`.

### C-04: danger_accept_invalid_certs(true) in Production Code

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/main.rs`, line 111
**Category**: Security Issue
**Impact**: The GSP health check HTTP client is configured with `danger_accept_invalid_certs(true)`. While this is for localhost polling, the `gsp_url` is configurable and could point to a remote server. An attacker performing a MITM attack on the GSP connection could inject false health status, causing the node to report incorrect GhostPay capability and potentially earn undeserved shares.

```rust
let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(5))
    .danger_accept_invalid_certs(true)  // <-- disables TLS verification
    .build()
```

**Suggested fix**: Remove `danger_accept_invalid_certs(true)`. If self-signed certs are needed for localhost, add explicit certificate pinning or restrict the URL to loopback addresses only.

---

## HIGH Severity

### H-01: Solo Payout Address Not Validated as Bitcoin Address

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, lines 594-606
**Category**: Loss-of-Fund Scenario
**Impact**: In `create_solo_proposal()`, the `solo_payout_address` is used directly without `validate_payout_address()` check. The address is hashed and stored as `recipient_id`, and the raw bytes are used as the output address. If the solo payout address is malformed, this creates an unspendable coinbase output. Pool mode miners go through `validate_payout_address()` at line 761, but the solo path skips this.

```rust
miner_payouts.push(PayoutEntry {
    address: data.solo_payout_address.into_bytes(),  // No validation!
    amount: solo_miner_amount,
    recipient_id,
    payout_type: PayoutType::Mining,
});
```

**Suggested fix**: Call `self.validate_payout_address()` on the solo payout address before building the payout entry.

### H-02: Fee Distribution verify() Mismatch Is Only Warned, Not Rejected

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, lines 538-544
**Category**: Loss-of-Fund Scenario
**Impact**: After creating the payout proposal, `fee_dist.verify()` is called but its failure only triggers a `warn!()`. The proposal is still returned and submitted to consensus. If fee distribution is incorrect due to a bug, the proposal proceeds with potentially lost or over-allocated satoshis.

```rust
if !fee_dist.verify(data.subsidy_sats, data.tx_fees_sats) {
    warn!(  // Should this be an error?
        expected = data.subsidy_sats + data.tx_fees_sats,
        actual = fee_dist.total(),
        "Fee distribution verification failed - small rounding difference"
    );
}
```

**Suggested fix**: If the mismatch exceeds 1 satoshi, return an error. The comment says "small rounding difference" but if integer arithmetic is correct (as the code claims), there should be no rounding difference at all.

### H-03: Solo Mode Hardcoded Dust Threshold Instead of Config Value

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, line 595
**Category**: Configuration Issue
**Impact**: Solo mode uses a hardcoded `546` for the dust threshold check instead of `self.config.dust_threshold_sats`. If the dust threshold is changed in configuration, pool mode will use the new value but solo mode will still use 546.

```rust
if solo_miner_amount >= 546 {  // Hardcoded, should use self.config.dust_threshold_sats
```

**Suggested fix**: Replace `546` with `self.config.dust_threshold_sats`.

### H-04: Bidirectional Fee Adjustment Uncapped for Increases

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/template.rs`, lines 838-863
**Category**: Loss-of-Fund Scenario / Logic Error
**Impact**: When fees increase due to RBF, the comment explicitly says "add extra to block finder -- uncapped". This means if fees dramatically increase (e.g., a high-fee RBF transaction arrives), the entire surplus goes to the block finder's node. There is no cap or sanity check on the extra amount. While a final sanity check exists at line 876, an extremely large fee increase could disproportionately benefit the block finder at the expense of other pool participants who also submitted shares during the round.

```rust
// FEES INCREASED (RBF): add extra to block finder -- uncapped
let extra = available_fees - original_fees;
```

**Suggested fix**: Add a cap on the maximum fee increase that can be absorbed without re-proposal. For example, cap at 2x the original fees.

### H-05: Hardcoded RPC Credentials in Test Scripts

**File**: `/home/defenwycke/dev/projects/ghost/scripts/test-deployment.sh`, line 34 (and ~20 other locations)
**Category**: Security Issue / Configuration Issue
**Impact**: The signet RPC password `ghost_signet_rpc_2024` is hardcoded in multiple scripts and committed to the repository. While this is for a signet test environment, the pattern of committing credentials to version control is dangerous. If these scripts are adapted for mainnet deployment, credentials could be exposed.

```bash
BTCLI="/opt/ghost/bin/ghost-cli -signet -datadir=/var/lib/bitcoin -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 ..."
```

**Suggested fix**: Read credentials from environment variables or a config file excluded from version control. The checkpoint scripts (`scripts/checkpoint/`) already demonstrate the correct pattern of reading from config files.

### H-06: Node Payout Address Failure Is Silent for Non-Block-Finder Nodes

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, lines 901-912
**Category**: Loss-of-Fund Scenario
**Impact**: When a node (not the block finder) has no payout address, their share is silently converted to dust and redistributed to the top node. While this is documented as intentional, it means a misconfigured node loses all node rewards indefinitely with only a `debug!()` log. The H-FUND-1 fix properly errors for the block finder, but other nodes silently lose funds.

```rust
if address.is_empty() {
    dust_total = dust_total.saturating_add(amount);
    allocated_total = allocated_total.saturating_add(amount);
    debug!(  // Only debug level!
        node_id = %hex::encode(&node_id[..8]),
        amount,
        "Node has no payout address - adding to dust pool"
    );
    continue;
}
```

**Suggested fix**: Log at `warn!()` level at minimum, and consider adding an API endpoint or dashboard indicator so node operators can see if their payout address is missing.

### H-07: Security Audit Job Uses continue-on-error

**File**: `/home/defenwycke/dev/projects/ghost/.github/workflows/ci.yml`, line 93
**Category**: Security Issue
**Impact**: The `cargo audit` security audit job has `continue-on-error: true`, meaning known vulnerabilities in dependencies will not fail CI. This effectively makes the security audit decorative rather than enforceable.

```yaml
audit:
    name: Security Audit
    runs-on: ubuntu-latest
    continue-on-error: true  # Don't fail CI on audit warnings
```

**Suggested fix**: Remove `continue-on-error: true`. If there are known advisory exceptions, use `cargo audit --ignore RUSTSEC-XXXX` for specific advisories.

---

## MEDIUM Severity

### M-01: debug_assert_eq Used for Fund Accounting Invariants

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, lines 957-964; `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/treasury.rs`, lines 248-257
**Category**: Logic Error / Loss-of-Fund Scenario
**Impact**: Critical fund accounting invariants (e.g., `allocated_total + rounding_remainder == total_sats` and `treasury_amount + node_reward_pool == pool_fee`) are enforced with `debug_assert_eq!()`, which is stripped from release builds. In production, if these invariants are violated, the code will silently proceed with incorrect payout amounts.

**Suggested fix**: Replace `debug_assert_eq!()` with explicit runtime checks that return errors when invariants are violated. The payout code already has overflow checks with proper error returns -- these accounting invariants deserve the same treatment.

### M-02: Template Processor .expect() on take_block_submitted_rx

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/template.rs`, line 448
**Category**: Error Handling
**Impact**: `take_block_submitted_rx()` calls `.expect("block_submitted_rx already taken")` which will panic if called twice. While this is documented as only being called once at startup, there is no compile-time enforcement. A refactor that accidentally calls it twice would crash the node.

**Suggested fix**: Return `Option<mpsc::UnboundedReceiver<BlockSubmittedInfo>>` instead of panicking.

### M-03: Share Work Values Use f64 in Tolerance Tracking

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/round.rs`, lines 126-148
**Category**: Logic Error
**Impact**: The `MinerToleranceTracker` uses `f64` for `total_work_credited` and `cumulative_tolerance_exploited`. The main payout arithmetic was carefully converted to integer (u128), but the tolerance tracking still uses floating point. For miners with very many shares, floating point accumulation errors could cause the 1% threshold check to produce incorrect results.

**Suggested fix**: Use integer arithmetic consistent with the payout calculation path.

### M-04: Payout Proposal Not Validated Against Total Coinbase Value

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, lines 521-556
**Category**: Loss-of-Fund Scenario
**Impact**: The payout proposal is created and submitted to consensus without verifying that `miner_payouts_total + node_payouts_total + treasury_amount == subsidy + tx_fees`. The individual components are calculated correctly, but there is no final cross-check summing all PayoutEntry amounts against the expected total. The `fee_dist.verify()` check on line 538 only checks the FeeDistribution struct, not the actual PayoutEntry amounts after dust redistribution and top-node dust absorption.

**Suggested fix**: Add a final validation that sums all PayoutEntry.amount values plus treasury_amount and verifies it equals subsidy + tx_fees.

### M-05: Rate Limiter persist_to_file Has No HMAC Authentication

**File**: `/home/defenwycke/dev/projects/ghost/crates/ghost-consensus/src/vote_handler.rs`, lines 292-298
**Category**: Security Issue
**Impact**: While there is an `AuthenticatedRateLimiterState` struct with HMAC (line 106), the `persist_to_file()` method at line 296 calls `self.to_persisted()` which returns the plain `PersistedRateLimiterState` without HMAC wrapping. An attacker with file system access could modify the persisted rate limiter state to reset their rate limit counters.

**Suggested fix**: Use the `AuthenticatedRateLimiterState` wrapper with HMAC when persisting to file.

### M-06: Miner Payout Address Can Be Overwritten By Remote Share Proofs

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/share_handler.rs`, lines 148-158
**Category**: Security Issue
**Impact**: When processing remote share proofs, the payout address from the proof is stored via `db.update_miner_address()`. A malicious node could broadcast share proofs with a legitimate miner's ID but substitute their own payout address. Since the most recent `update_miner_address` call wins, the attacker's address would be used for the miner's payout.

```rust
if let Some(ref addr) = payout_address {
    if !addr.is_empty() {
        if let Err(e) = self.db.update_miner_address(&miner_hex, addr) {
```

**Suggested fix**: Only update a miner's payout address from locally-received Stratum connections, not from P2P share proofs. Or verify the share proof is signed by the receiving node and that the address matches what was locally configured.

### M-07: Stale Proposal Detection Threshold May Be Too Loose

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/template.rs`, lines 771-783
**Category**: Logic Error
**Impact**: Stale proposals are detected only when `prop.subsidy > total_value`. This only catches proposals from a future halving epoch (where subsidy was higher). It does NOT catch proposals from a past halving epoch where subsidy was lower, or proposals where the block height doesn't match the current chain tip. A proposal from height 100,000 could be used at height 200,000 if the subsidy hasn't changed.

**Suggested fix**: Also check that the proposal's block_height is within a reasonable range of the current template height.

### M-08: Deprecated DECAY_SCHEDULE (f64) Still Present Alongside DECAY_SCHEDULE_BPS

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/treasury.rs`, lines 24-31
**Category**: Dead Code / Configuration Issue
**Impact**: The f64 `DECAY_SCHEDULE` array and `get_fee_split()` method are marked as deprecated but still present. While `DECAY_SCHEDULE_BPS` is used for actual calculations, the deprecated code could be accidentally used by future developers, reintroducing floating point precision issues.

**Suggested fix**: Remove the deprecated f64 versions or make them `pub(crate)` with clear deprecation warnings in documentation.

---

## LOW Severity

### L-01: Clippy Allow Rules May Mask Real Issues

**File**: `/home/defenwycke/dev/projects/ghost/.github/workflows/ci.yml`, line 38
**Category**: Configuration Issue
**Impact**: The CI clippy configuration allows 7 specific lint categories. While some (like `clone_on_copy`) are reasonable, `needless_borrows_for_generic_args` and `useless_vec` can mask real performance issues. The blanket allows may hide new instances of genuine problems.

### L-02: Template Work States HashMap Unbounded Growth

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/template.rs`, line 322
**Category**: Resource Issue
**Impact**: `work_states: RwLock<HashMap<u64, WorkState>>` stores work states by template_id. While old entries are presumably cleaned up, there is no explicit maximum size or eviction policy visible in the struct definition. Under sustained operation, this could grow unbounded.

**Suggested fix**: Add an eviction policy (e.g., keep last N states, or evict entries older than X minutes).

### L-03: `serde_json::to_vec(&msg).unwrap()` in Share Handler

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/share_handler.rs`, lines 247, 278
**Category**: Error Handling
**Impact**: These are in test code (`#[cfg(test)]`), so the impact is limited to test reliability. However, the pattern of using `.unwrap()` on serialization could mask test failures.

### L-04: Registry DB Uses libc::umask (Process-Wide Side Effect)

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-registry/src/db.rs`, lines 135-147; `/home/defenwycke/dev/projects/ghost/crates/ghost-storage/src/database.rs`, lines 57-71
**Category**: Race Condition
**Impact**: Both the registry and main database use `unsafe { libc::umask() }` to set restrictive file permissions. The umask is process-global, so in a multi-threaded context, another thread creating a file between the `umask()` call and the RAII guard drop would inherit the wrong permissions. The code documents this with RAII guards, but the window still exists. The ghost-storage code has a proper RAII `UmaskGuard`, but the registry DB code at line 135 uses a manual restore pattern.

### L-05: Verification Routes Use unsafe for statvfs Without libc Error Handling

**File**: `/home/defenwycke/dev/projects/ghost/crates/ghost-verification/src/routes.rs`, lines 110-117
**Category**: Error Handling
**Impact**: The unsafe `libc::statvfs` calls are properly documented with SAFETY comments and the result is checked. However, if `libc::statvfs` returns `-1`, the code silently returns `0.0` for disk usage rather than indicating an error to the caller. The verification system would report 0% disk usage, which could affect health checks.

### L-06: TODO in ghost-light-wallet-cli

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-light-wallet-cli/src/main.rs`, line 598
**Category**: TODO/FIXME Marker
**Impact**: `// TODO: Pass max_k to wallet.refresh_balance() when API supports it` -- This suggests the balance refresh may not limit scan key count, which could be a performance issue with many keys.

### L-07: SV2 Apps Submodule Contains Multiple TODOs

**File**: Various files under `/home/defenwycke/dev/projects/ghost/sv2-apps/`
**Category**: TODO/FIXME Marker
**Impact**: The SRI pool fork contains multiple `TODO` comments including:
- `sv2-apps/stratum-apps/src/rpc/mini_rpc_client.rs:1` - Entire file is a TODO
- `sv2-apps/pool-apps/jd-server/src/lib/job_declarator/mod.rs:92` - `TODO this should be computed for each new template so that fees are included`
- `sv2-apps/pool-apps/jd-server/src/lib/job_declarator/mod.rs:312` - `todo!()` macro (will panic at runtime)

The `todo!()` at line 312 is particularly concerning as it will crash the JD server if a `PushSolution` message is received.

### L-08: Panic in SV1 Connection Handler

**File**: `/home/defenwycke/dev/projects/ghost/sv2-apps/stratum-apps/src/network_helpers/sv1_connection.rs`, lines 191, 210
**Category**: Error Handling
**Impact**: `panic!("Unexpected message type")` in production network code. If an unexpected message type is received from a miner, the entire connection handler panics instead of gracefully rejecting the message.

---

## INFO Severity

### I-01: Extensive Prior Audit Trail

The codebase contains a comprehensive audit trail with well-documented security fix references (H-FUND-1, H-FUND-2, CRIT-MINE-1, H-MINE-3, M-5, M-15, M-28, PO4-M1, PO4-M2, etc.). This indicates multiple prior security reviews have been conducted and fixes properly implemented. The code quality in the core payout and consensus paths is notably high.

### I-02: Lock Ordering Documentation

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/template.rs`, lines 28-50
The template processor documents lock ordering rules (HIGH-POOL-4) to prevent deadlocks. This is good practice but relies on developer discipline -- there is no compile-time enforcement.

### I-03: Payout Rounding Strategy Well-Documented

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/payout.rs`, lines 997-1023
The decision to give rounding remainders to the top capability node is extensively documented with economic analysis. This is good engineering practice.

### I-04: Integer Arithmetic Correctly Used for Financial Calculations

The codebase has been carefully migrated from floating-point to integer arithmetic for all financial calculations (treasury decay, miner payouts, node payouts). The use of u128 for intermediate calculations and basis points for percentage calculations is appropriate and well-implemented.

### I-05: Fuzz Targets Exist

The project includes fuzz targets in `/home/defenwycke/dev/projects/ghost/fuzz/fuzz_targets/` for validation, stratum username parsing, message envelopes, and stratum RPC. This is good security practice.

### I-06: DEPRECATED DECAY_SCHEDULE Still Referenced in Tests

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/treasury.rs`, lines 386-394
Tests still validate the deprecated f64 DECAY_SCHEDULE values. These tests should be updated to only test the BPS versions.

### I-07: Coinbase Tag Written to Plaintext File

**File**: `/home/defenwycke/dev/projects/ghost/bins/ghost-pool/src/main.rs`, lines 849-852
The coinbase tag is written to `data_dir/coinbase_tag` for the SRI pool service to read. While the tag itself is not sensitive, this file has no access control beyond the directory permissions.

---

## Additional Findings: P2P Networking & Noise Protocol

### C-05: NoiseKeypair Private Key Not Zeroized on Drop

**File**: `crates/ghost-consensus/src/noise.rs`, lines 111-117
**Category**: Security Issue
**Impact**: The `NoiseKeypair` struct holds the X25519 static private key as a raw `[u8; 32]`. It does not implement `Drop`, `Zeroize`, or `ZeroizeOnDrop`. The struct also derives `Clone`, creating additional copies in memory. When dropped, the 32-byte private key remains in memory until the allocator reuses that region. An attacker with memory read access (core dump, swap, cold boot) can recover the node's persistent identity key, enabling impersonation across all 8 mesh ports.

**Suggested fix**: Add `zeroize` dependency and derive `ZeroizeOnDrop`. Remove `Clone` derive. Follow the pattern in `ghost-keys` which properly uses `ZeroizingSecretBytes`.

### H-08: Noise Keypair File Written World-Readable (NoiseManager Path)

**File**: `crates/ghost-consensus/src/noise.rs`, line 509
**Category**: Security Issue
**Impact**: When `NoiseManager::new()` generates and saves a new keypair, `std::fs::write()` is called without `set_permissions()`. The file inherits default umask (typically `0o644`), making the X25519 private key world-readable. Note: the `mesh.rs:1052-1064` code path DOES set `0o600` permissions — the two paths are inconsistent.

**Suggested fix**: Set `0o600` permissions after writing in `NoiseManager`, matching the `mesh.rs` pattern. Better: use the RAII `UmaskGuard` pattern from `ghost-storage`.

### H-09: DNS Resolution Failure Allows SSRF Bypass in Verification

**File**: `crates/ghost-verification/src/client.rs`, lines 441-452
**Category**: Security Issue
**Impact**: In `resolve_and_check_host()`, when DNS resolution fails (`to_socket_addrs()` returns `Err`), the function returns `Ok(())`, allowing the HTTP request to proceed. An attacker controlling DNS could cause resolution failure in the pre-check while the actual HTTP client resolves to an internal IP (127.0.0.1, cloud metadata, etc.).

**Suggested fix**: Return `Err` when DNS resolution fails, blocking the request.

---

## Additional Findings: Template Construction & Block Submission

### H-10: Skipped Transaction in Block Assembly Produces Invalid Block

**File**: `bins/ghost-pool/src/template.rs`, lines 2534-2544
**Category**: Logic Error
**Impact**: When assembling a block for submission, if a transaction's hex data fails to decode, the code logs an error and `continue`s. The block header's merkle root was computed over the full set including that txid, so the submitted block will have a merkle root mismatch and be rejected by Bitcoin Core (`bad-txnmrklroot`). Same pattern at lines 2714-2726.

**Suggested fix**: Abort block submission if any transaction fails to decode rather than submitting an invalid block.

### H-11: Missing Coinbase Verification When commitment_snapshot Is None

**File**: `bins/ghost-pool/src/template.rs`, lines 2687-2689
**Category**: Security Issue
**Impact**: When `work.commitment_snapshot` is `None`, coinbase verification is skipped entirely. An operator running a modified node could exploit this by disrupting BFT consensus (preventing any payout approval), then submitting blocks with arbitrary coinbase outputs.

**Suggested fix**: Either require a commitment (fail submission if none exists) or verify against the fallback address directly.

### H-12: Block Version Upper Bound Rejects BIP320 Version Rolling

**File**: `bins/ghost-pool/src/template.rs`, line 2500
**Category**: Logic Error
**Impact**: Block version validation rejects versions above `0x3FFFFFFF`. BIP320 version rolling can produce versions exceeding this if miners set bit 29.

**Suggested fix**: Validate only the base version bits, or allow any version Bitcoin Core consensus accepts.

---

## Additional Findings: Consensus Voting

### H-13: No Minimum Voter Count After invalidate_voter()

**File**: `crates/ghost-consensus/src/voting.rs`
**Category**: Security Issue
**Impact**: `VotingSession` enforces a minimum of 7 voters at creation, but `invalidate_voter()` can remove voters after creation (e.g., equivocation bans). If enough voters are invalidated, the remaining count drops below BFT minimum. With 4 voters remaining, only 3 are needed (67%), meaning a single attacker controlling 3 nodes can approve arbitrary payouts.

**Suggested fix**: Check remaining voter count after invalidation; refuse to invalidate if it would drop below minimum, or suspend the session.

### M-09: Proposal Allows Zero Miner Payouts (claimed_total << actual_total)

**File**: `bins/ghost-pool/src/payout_validator.rs`, lines 177-182
**Category**: Security Issue
**Impact**: `validate_basic_sanity()` checks that `claimed_total` doesn't exceed `actual_total` but doesn't enforce a minimum. A malicious proposer could create a proposal with all amounts at 0 (except treasury), distributing no funds to miners.

**Suggested fix**: Verify that `total_distributed` is within a reasonable percentage of `available` (e.g., at least 90%).

---

## Additional Findings: Verification System

### M-10: verify_all_capabilities() Skips GhostPay Challenge Nonce

**File**: `crates/ghost-verification/src/client.rs`, line 785
**Category**: Security Issue
**Impact**: The convenience method `verify_all_capabilities()` passes `None` for the challenge nonce, allowing precomputed responses. The primary path in `task.rs` correctly uses random nonces, but any caller using this convenience method gets weaker verification.

**Suggested fix**: Remove the convenience method or require a nonce parameter.

### M-11: TOCTOU Race in Noise Keypair File Permissions (Mesh Path)

**File**: `crates/ghost-consensus/src/mesh.rs`, lines 1052-1064
**Category**: Race Condition
**Impact**: Keypair file is written with default umask (world-readable), then permissions are tightened to `0o600`. Between these operations, a local attacker could read the private key.

**Suggested fix**: Set process umask to `0o077` before writing (use `UmaskGuard` from ghost-storage), or use `OpenOptions` with mode.

### M-12: Wraith Session Registry Loses State on Restart

**File**: `crates/wraith-protocol/src/session.rs`, lines 39-52
**Category**: Security Issue
**Impact**: `SessionRegistry` is in-memory only. On process restart, all session tracking is lost, allowing replay of sessions active before the restart within the session timeout window.

**Suggested fix**: Implement the `PersistentSessionRegistry` trait that is defined but not implemented.

---

## Additional Findings: Stratum / Connection Management

### M-13: allow_connection() TOCTOU Between Check and Registration

**File**: `bins/ghost-pool/src/connection.rs`, lines 179-228
**Category**: Race Condition
**Impact**: `allow_connection()` and `connection_opened()` are separate calls that acquire and release locks independently. Between check and registration, concurrent connections from the same IP could exceed the per-IP limit.

**Suggested fix**: Combine the check-and-register into a single atomic operation.

---

## Summary by Category

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| Loss-of-Fund Scenarios | 2 | 4 | 2 | 0 | 0 |
| Security Issues | 3 | 5 | 5 | 0 | 0 |
| Error Handling | 1 | 0 | 1 | 3 | 0 |
| Race Conditions | 0 | 0 | 2 | 1 | 0 |
| Logic Errors | 0 | 3 | 2 | 0 | 0 |
| Configuration Issues | 0 | 2 | 1 | 1 | 0 |
| Dead Code | 0 | 0 | 1 | 0 | 1 |
| TODO/FIXME Markers | 0 | 0 | 0 | 3 | 0 |
| **Totals** | **5** | **13** | **13** | **8** | **7** |

---

## Priority Recommendations

1. **Immediate** (before mainnet): C-01, C-02, C-03, C-04, C-05, H-01, H-02, H-08, H-09, H-11
2. **Soon** (before significant hashrate): H-04, H-06, H-10, H-12, H-13, M-01, M-04, M-06, M-09
3. **Planned** (next development cycle): Remaining Medium and Low issues
4. **Track** (no immediate action): Info items for awareness

---

## Methodology

This audit was conducted through static analysis of all Rust source files in the repository, excluding build artifacts in `target/`. Three parallel review passes covered:

**Pass 1**: Mining, payout calculation, consensus voting, template construction, block submission
**Pass 2**: Cryptography (ghost-keys, ghost-locks, ghost-mpc), P2P networking (Noise, ZMQ mesh), privacy (wraith-protocol), verification system, database/storage
**Pass 3**: Cross-cutting concerns, CI/CD, deployment scripts, configuration, error handling patterns

Techniques:
1. Manual code review of all critical paths (payout, coinbase, consensus, P2P)
2. Pattern-based search for vulnerability signatures (`.unwrap()`, `unsafe`, `panic!`, `TODO`, hardcoded credentials, `danger_accept_invalid_certs`, `assume_checked`, `NetworkUnchecked`)
3. Cross-referencing security fix annotations (H-*, CRIT-*, M-*, etc.) to verify completeness
4. Comparison of parallel code paths (pool vs solo mode, mesh.rs vs noise.rs) for inconsistencies
5. Review of CI/CD configuration and deployment scripts
6. Zeroization and secret handling verification across all crates
