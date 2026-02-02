# Payout System Fix Plan

## Executive Summary

This plan addresses two issues:
1. **Missing `is_block` trigger** - SRI webhook sends `is_block: true` but ghost-pool ignores it, so payout proposals are never created for SRI-mined blocks
2. **Fee distribution logic** - Current implementation differs from intended design (per ECONOMICS.md)

---

## Intended Fee Distribution (from ECONOMICS.md)

### Block Reward Structure

```
Block Reward = Subsidy + TX Fees

TX Fees (100%):
└── Node operator who built the block

Subsidy Distribution:
├── Pool Fee (1% of subsidy)
│   ├── Treasury Allocation (variable, starts at 0.5%)
│   └── Node Reward Pool (variable, starts at 0.5%)
└── Miner Pool (99% of subsidy)
    └── Top 200 miners proportional to work
```

### Treasury Decay Mechanism

Once treasury reaches **21 BTC threshold**, allocation decays over 5 years:

| Phase | Treasury Rate | Node Rate | Total Pool Fee |
|-------|---------------|-----------|----------------|
| Pre-threshold | 0.5% | 0.5% | 1.0% |
| Year 1 | 0.4% | 0.6% | 1.0% |
| Year 2 | 0.3% | 0.7% | 1.0% |
| Year 3 | 0.2% | 0.8% | 1.0% |
| Year 4 | 0.1% | 0.9% | 1.0% |
| Year 5+ | 0.0% | 1.0% | 1.0% |

### Example (3.125 BTC Block, Pre-threshold)

```
Subsidy:           312,500,000 sats (3.125 BTC)
TX Fees:            10,000,000 sats (0.1 BTC)

Pool Fee (1%):       3,125,000 sats
├── Treasury:        1,562,500 sats (0.5%)
└── Node Rewards:    1,562,500 sats (0.5%)

Miner Pool (99%): 309,375,000 sats

Coinbase Outputs:
├── Node Operator:   10,000,000 sats (TX fees)
├── Treasury:         1,562,500 sats
├── Top 100 Nodes:    1,562,500 sats (divided by 5-4-3-2-1 shares)
└── Top 200 Miners: 309,375,000 sats (divided by work)
```

### Example (Year 3 of Decay)

```
Pool Fee (1%):       3,125,000 sats
├── Treasury:          625,000 sats (0.2%)
└── Node Rewards:    2,500,000 sats (0.8%)
```

---

## Current Implementation (BROKEN)

### payout.rs:108-127

```rust
// CURRENT (WRONG):
let total_available = subsidy_sats + tx_fees_sats;  // Includes TX fees
let pool_fee = total_available * 0.01;               // 1% of EVERYTHING
let distributable = total_available - pool_fee;
let miner_pool = distributable / 2;                  // 49.5% to miners
let node_pool = distributable - miner_pool;          // 49.5% to nodes
let treasury_amount = pool_fee;                      // ALL to treasury
```

**Problems:**
1. TX fees mixed with subsidy (should go 100% to block builder)
2. Pool fee taken from total (should be subsidy only)
3. Treasury gets full 1% (should be 0.5% with decay)
4. No treasury decay mechanism
5. Miners/nodes split 50/50 (should be 99%/0.5%)

---

## Issue 1: Missing is_block → Payout Trigger

### Problem
When SRI Pool finds a block, it sends webhook with `is_block: true`, but:
1. `ShareNotification` struct lacks `is_block` field
2. `record_share_batch()` ignores `ShareData.is_block`
3. `RoundEvent::BlockFound` is never emitted
4. No payout proposal is created

### Files to Modify

#### 1. `crates/ghost-verification/src/server.rs`

**Add `is_block` to ShareNotification:**
```rust
pub struct ShareNotification {
    pub miner_id: String,
    pub work: f64,
    pub share_hash: String,
    pub job_id: u32,
    pub timestamp: u64,
    pub is_block: bool,  // NEW FIELD
}
```

**Add block found callback type:**
```rust
pub type BlockFoundFn = Arc<dyn Fn(BlockFoundNotification) -> GhostResult<()> + Send + Sync>;

pub struct BlockFoundNotification {
    pub share_hash: [u8; 32],
    pub miner_id: String,
    pub share_work: f64,
    pub timestamp: u64,
}
```

**Modify `record_share_batch()` to handle is_block:**
```rust
pub fn record_share_batch(&self, batch: ShareBatch) -> GhostResult<usize> {
    let mut recorded = 0;
    for share in batch.shares {
        let notification = ShareNotification {
            miner_id: share.downstream_id.to_string(),
            work: share.share_work,
            share_hash: share.share_hash.clone(),
            job_id: share.job_id,
            timestamp: share.timestamp_ms / 1000,
            is_block: share.is_block,  // Pass through
        };

        if let Err(e) = self.record_share(notification.clone()) {
            tracing::warn!(error = %e, "Failed to record share from batch");
        } else {
            recorded += 1;
        }

        // NEW: Trigger block found if this share found a block
        if share.is_block {
            if let Some(ref block_found_fn) = self.block_found_fn {
                let block_notification = BlockFoundNotification {
                    share_hash: parse_share_hash(&share.share_hash),
                    miner_id: share.downstream_id.to_string(),
                    share_work: share.share_work,
                    timestamp: share.timestamp_ms / 1000,
                };
                if let Err(e) = block_found_fn(block_notification) {
                    tracing::error!(error = %e, "Failed to handle block found");
                }
            }
        }
    }
    Ok(recorded)
}
```

**Add block found callback setter:**
```rust
pub fn with_block_found_handler<F>(mut self, handler: F) -> Self
where
    F: Fn(BlockFoundNotification) -> GhostResult<()> + Send + Sync + 'static,
{
    self.block_found_fn = Some(Arc::new(handler));
    self
}
```

#### 2. `bins/ghost-pool/src/main.rs`

**Configure block found handler on verification_state:**
```rust
// After configuring share_recorder, add block_found_handler
let rm_for_block = Arc::clone(&round_manager);
let tp_for_block = Arc::clone(&template_processor);
let payout_for_block = Arc::clone(&payout_handler);
let identity_for_block = Arc::clone(&identity);

verification_state = verification_state.with_block_found_handler(move |notification| {
    let round_id = rm_for_block.current_round_id();

    info!(
        round = round_id,
        hash = %hex::encode(&notification.share_hash[..8]),
        miner = %notification.miner_id,
        "Block found via SRI webhook - creating payout proposal"
    );

    // Get distribution data from round manager
    let miner_work = rm_for_block.get_miner_work(round_id);
    let node_shares = rm_for_block.get_node_shares(round_id);

    // Get block info from template processor
    let (subsidy, fees, height) = tp_for_block.get_current_block_info();

    // Create block found data
    let block_data = BlockFoundData {
        round_id,
        block_hash: notification.share_hash,
        block_height: height,
        winning_miner_id: notification.miner_id,
        winning_node_id: identity_for_block.node_id(),  // This node received the share
        subsidy_sats: subsidy,
        tx_fees_sats: fees,
        miner_work,
        node_shares,
    };

    // Submit for consensus
    payout_for_block.handle_block_found(block_data)?;
    Ok(())
});
```

---

## Issue 2: Fee Distribution Logic Fix

### New Module: Treasury Decay Calculator

#### Create `bins/ghost-pool/src/treasury.rs`

```rust
//! Treasury decay calculator per ECONOMICS.md
//!
//! Once treasury reaches 21 BTC, allocation decays over 5 years:
//! - Pre-threshold: 0.5% treasury, 0.5% nodes
//! - Year 1: 0.4% treasury, 0.6% nodes
//! - Year 2: 0.3% treasury, 0.7% nodes
//! - Year 3: 0.2% treasury, 0.8% nodes
//! - Year 4: 0.1% treasury, 0.9% nodes
//! - Year 5+: 0.0% treasury, 1.0% nodes

use chrono::{DateTime, Utc};

/// Treasury threshold in satoshis (21 BTC)
pub const TREASURY_THRESHOLD_SATS: u64 = 21_0000_0000 * 100_000_000;

/// Total pool fee as fraction of subsidy
pub const POOL_FEE_PERCENT: f64 = 0.01; // 1%

/// Decay rates by year (treasury_rate, node_rate)
const DECAY_SCHEDULE: [(f64, f64); 6] = [
    (0.5, 0.5),  // Pre-threshold / Year 0
    (0.4, 0.6),  // Year 1
    (0.3, 0.7),  // Year 2
    (0.2, 0.8),  // Year 3
    (0.1, 0.9),  // Year 4
    (0.0, 1.0),  // Year 5+
];

/// Treasury state for decay calculation
#[derive(Debug, Clone)]
pub struct TreasuryState {
    /// Current treasury balance in satoshis
    pub balance_sats: u64,
    /// Timestamp when threshold was reached (None if not yet reached)
    pub threshold_reached_at: Option<DateTime<Utc>>,
}

impl TreasuryState {
    pub fn new() -> Self {
        Self {
            balance_sats: 0,
            threshold_reached_at: None,
        }
    }

    /// Update balance and check threshold
    pub fn add_funds(&mut self, amount: u64) {
        self.balance_sats = self.balance_sats.saturating_add(amount);

        // Check if we just crossed threshold
        if self.threshold_reached_at.is_none() && self.balance_sats >= TREASURY_THRESHOLD_SATS {
            self.threshold_reached_at = Some(Utc::now());
            tracing::info!(
                balance = self.balance_sats,
                threshold = TREASURY_THRESHOLD_SATS,
                "Treasury threshold reached - decay begins"
            );
        }
    }

    /// Calculate years since threshold was reached
    fn years_since_threshold(&self) -> u32 {
        match self.threshold_reached_at {
            None => 0,
            Some(threshold_time) => {
                let elapsed = Utc::now().signed_duration_since(threshold_time);
                let days = elapsed.num_days().max(0) as u32;
                days / 365  // Approximate years
            }
        }
    }

    /// Get current fee split rates (treasury_rate, node_rate)
    /// Both rates are fractions of the 1% pool fee
    pub fn get_fee_split(&self) -> (f64, f64) {
        if self.threshold_reached_at.is_none() {
            return DECAY_SCHEDULE[0]; // Pre-threshold
        }

        let years = self.years_since_threshold() as usize;
        let index = (years + 1).min(DECAY_SCHEDULE.len() - 1);
        DECAY_SCHEDULE[index]
    }
}

/// Calculate fee distribution for a block
pub struct FeeDistribution {
    pub tx_fees_to_block_finder: u64,
    pub treasury_amount: u64,
    pub node_reward_pool: u64,
    pub miner_pool: u64,
}

impl FeeDistribution {
    pub fn calculate(
        subsidy_sats: u64,
        tx_fees_sats: u64,
        treasury_state: &TreasuryState,
    ) -> Self {
        // TX fees go 100% to block finder
        let tx_fees_to_block_finder = tx_fees_sats;

        // Pool fee is 1% of subsidy only
        let pool_fee = (subsidy_sats as f64 * POOL_FEE_PERCENT) as u64;

        // Split pool fee between treasury and nodes based on decay
        let (treasury_rate, node_rate) = treasury_state.get_fee_split();
        let treasury_amount = (pool_fee as f64 * treasury_rate) as u64;
        let node_reward_pool = pool_fee.saturating_sub(treasury_amount);

        // Miner pool is 99% of subsidy
        let miner_pool = subsidy_sats.saturating_sub(pool_fee);

        Self {
            tx_fees_to_block_finder,
            treasury_amount,
            node_reward_pool,
            miner_pool,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_threshold_split() {
        let state = TreasuryState::new();
        let (treasury, node) = state.get_fee_split();
        assert_eq!(treasury, 0.5);
        assert_eq!(node, 0.5);
    }

    #[test]
    fn test_fee_distribution() {
        let state = TreasuryState::new();
        let dist = FeeDistribution::calculate(
            312_500_000,  // 3.125 BTC subsidy
            10_000_000,   // 0.1 BTC fees
            &state,
        );

        assert_eq!(dist.tx_fees_to_block_finder, 10_000_000);
        assert_eq!(dist.treasury_amount, 1_562_500);    // 0.5% of subsidy
        assert_eq!(dist.node_reward_pool, 1_562_500);   // 0.5% of subsidy
        assert_eq!(dist.miner_pool, 309_375_000);       // 99% of subsidy
    }
}
```

### Files to Modify

#### 1. `bins/ghost-pool/src/payout.rs`

**Update BlockFoundData to include winning_node_id:**
```rust
pub struct BlockFoundData {
    pub round_id: RoundId,
    pub block_hash: [u8; 32],
    pub block_height: u64,
    pub winning_miner_id: String,
    pub winning_node_id: NodeId,  // NEW: Node that received block-finding share
    pub subsidy_sats: u64,
    pub tx_fees_sats: u64,
    pub miner_work: Vec<(String, f64)>,
    pub node_shares: Vec<(NodeId, i32)>,
}
```

**Update PayoutConfig:**
```rust
pub struct PayoutConfig {
    pub dust_threshold_sats: u64,
    pub max_miner_outputs: usize,
    pub max_node_outputs: usize,
    pub treasury_address: Vec<u8>,
    // Removed pool_fee_percent - now in treasury.rs
}
```

**Rewrite create_proposal() with correct fee distribution:**
```rust
pub fn create_proposal(&self, data: BlockFoundData) -> GhostResult<PayoutProposal> {
    let now = chrono::Utc::now().timestamp() as u64;

    // === CORRECT FEE DISTRIBUTION (per ECONOMICS.md) ===

    // Calculate fee distribution with treasury decay
    let treasury_state = self.db.get_treasury_state()?;
    let fees = FeeDistribution::calculate(
        data.subsidy_sats,
        data.tx_fees_sats,
        &treasury_state,
    );

    // 1. TX Fees go 100% to the node that built the block
    let block_finder_tx_fee_payout = if fees.tx_fees_to_block_finder > self.config.dust_threshold_sats {
        let node_address = self.db.get_node_payout_address(&data.winning_node_id)?
            .ok_or_else(|| GhostError::Internal("Block finder node has no payout address".into()))?;

        Some(PayoutEntry {
            address: node_address,
            amount: fees.tx_fees_to_block_finder,
            recipient_id: data.winning_node_id,
            payout_type: PayoutType::TxFees,
        })
    } else {
        None
    };

    // 2. Calculate miner payouts (99% of subsidy, proportional to work, top 200)
    let miner_payouts = self.calculate_miner_payouts(&data.miner_work, fees.miner_pool)?;

    // 3. Calculate node payouts (node_reward_pool, proportional to 5-4-3-2-1 shares, top 100)
    let mut node_payouts = self.calculate_node_payouts(&data.node_shares, fees.node_reward_pool)?;

    // 4. Add block finder's TX fee payout
    if let Some(tx_fee_payout) = block_finder_tx_fee_payout {
        // Check if block finder is already in node_payouts
        if let Some(existing) = node_payouts.iter_mut()
            .find(|p| p.recipient_id == tx_fee_payout.recipient_id) {
            // Add TX fees to their existing node reward
            existing.amount = existing.amount.saturating_add(tx_fee_payout.amount);
        } else {
            // Block finder not in top 100, but still gets TX fees
            node_payouts.push(tx_fee_payout);
        }
    }

    // 5. Update treasury balance (for decay tracking)
    if fees.treasury_amount > 0 {
        self.db.add_treasury_funds(fees.treasury_amount)?;
    }

    let proposal = PayoutProposal {
        proposal_hash: [0u8; 32],
        round_id: data.round_id,
        block_hash: data.block_hash,
        block_height: data.block_height,
        proposer: self.identity.node_id(),
        miner_payouts,
        node_payouts,
        treasury_amount: fees.treasury_amount,
        tx_fees: data.tx_fees_sats,
        subsidy: data.subsidy_sats,
        timestamp: now,
    };

    let (treasury_rate, node_rate) = treasury_state.get_fee_split();
    info!(
        round_id = data.round_id,
        height = data.block_height,
        miner_count = proposal.miner_payouts.len(),
        node_count = proposal.node_payouts.len(),
        treasury = fees.treasury_amount,
        node_pool = fees.node_reward_pool,
        miner_pool = fees.miner_pool,
        tx_fees_to_finder = fees.tx_fees_to_block_finder,
        treasury_rate = %format!("{:.1}%", treasury_rate * 100.0),
        node_rate = %format!("{:.1}%", node_rate * 100.0),
        "Created payout proposal"
    );

    Ok(proposal)
}
```

---

## Summary of Changes

### New Files

| File | Purpose |
|------|---------|
| `bins/ghost-pool/src/treasury.rs` | Treasury decay calculator, fee distribution logic |

### Modified Files

| File | Changes |
|------|---------|
| `crates/ghost-verification/src/server.rs` | Add `is_block` to ShareNotification, add `BlockFoundNotification`, add `with_block_found_handler()` |
| `bins/ghost-pool/src/payout.rs` | Add `winning_node_id` to BlockFoundData, use `FeeDistribution` for correct splits |
| `bins/ghost-pool/src/main.rs` | Configure block_found_handler, pass treasury_state |
| `bins/ghost-pool/src/lib.rs` | Export treasury module |
| `crates/ghost-storage/src/lib.rs` | Add treasury state persistence methods |

### Database Schema Addition

```sql
-- Treasury state for decay tracking
CREATE TABLE IF NOT EXISTS treasury_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton
    balance_sats INTEGER NOT NULL DEFAULT 0,
    threshold_reached_at TEXT,  -- ISO8601 timestamp, NULL if not reached
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Initialize singleton row
INSERT OR IGNORE INTO treasury_state (id, balance_sats) VALUES (1, 0);
```

### Fee Distribution Change

| Component | Current (WRONG) | New (Correct) |
|-----------|-----------------|---------------|
| TX Fees | Split with miners/nodes | 100% to block finder node |
| Pool Fee Base | subsidy + fees | subsidy only |
| Treasury | 1% of total | 0.5% → 0% (decaying) |
| Node Pool | 49.5% of total | 0.5% → 1% (decaying) |
| Miner Pool | 49.5% of total | 99% of subsidy |

### Treasury Decay Schedule

| Phase | Treasury | Nodes | Condition |
|-------|----------|-------|-----------|
| Pre-threshold | 0.5% | 0.5% | balance < 21 BTC |
| Year 1 | 0.4% | 0.6% | 0-1 years after threshold |
| Year 2 | 0.3% | 0.7% | 1-2 years |
| Year 3 | 0.2% | 0.8% | 2-3 years |
| Year 4 | 0.1% | 0.9% | 3-4 years |
| Year 5+ | 0.0% | 1.0% | 4+ years |

### Payout Limits (unchanged)

- Top 200 miners by work
- Top 100 nodes by capability shares (5-4-3-2-1)
- Dust threshold: 546 sats
- Max coinbase outputs: 302 (1 treasury + 1 tx_fees + 100 nodes + 200 miners)

---

## Implementation Order

1. **Phase 1: Treasury Module**
   - Create `bins/ghost-pool/src/treasury.rs`
   - Add database schema and methods
   - Unit tests for decay calculation

2. **Phase 2: is_block Trigger**
   - Add `is_block` to ShareNotification
   - Add `BlockFoundNotification` and handler
   - Wire up in main.rs

3. **Phase 3: Fee Distribution Fix**
   - Update `BlockFoundData` with `winning_node_id`
   - Rewrite `create_proposal()` to use `FeeDistribution`
   - Update treasury balance on each block

4. **Phase 4: Integration Testing**
   - Update webhook integration tests
   - Test full flow on signet VMs
   - Verify coinbase outputs

---

## Testing Plan

### Unit Tests

```rust
// treasury.rs tests
#[test] fn test_pre_threshold_split()
#[test] fn test_year_1_decay()
#[test] fn test_year_5_full_decay()
#[test] fn test_fee_distribution_math()

// payout.rs tests
#[test] fn test_tx_fees_to_block_finder()
#[test] fn test_miner_pool_99_percent()
#[test] fn test_node_pool_with_decay()
```

### Integration Tests

- `share_webhook_integration.rs`: Verify is_block triggers payout
- New test: Verify fee distribution matches ECONOMICS.md spec
- New test: Verify treasury decay over simulated time

### VM Testing

1. Deploy to signet VMs
2. Mine blocks, verify payout proposals created
3. Verify consensus voting occurs across 4 nodes
4. Verify coinbase outputs match proposal
5. Check treasury balance accumulates correctly

---

## Open Questions (RESOLVED)

1. ~~**Pool fee base**~~ → 1% of SUBSIDY only (per ECONOMICS.md)
2. ~~**Treasury split**~~ → Decays from 0.5% to 0% over 5 years after 21 BTC threshold
3. **Block finder not in top 100** → Still gets TX fees (separate output)
4. **TX fees below dust** → Skip payout (balance could accumulate in ledger, future enhancement)
