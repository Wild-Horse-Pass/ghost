//! Jump affordability assessment for Ghost Locks.
//!
//! Ghost Locks have a `JumpSchedule` that tracks WHEN to jump but is blind to
//! WHETHER the lock can AFFORD to jump. Mining costs for Wraith sessions eat
//! into lock value. After enough jumps, a lock erodes below the cost threshold
//! and the user is stuck with stale keys — defeating quantum safety.
//!
//! This module provides affordability checks that take pre-calculated mining
//! costs as parameters (since `ghost-locks` does not depend on `wraith-protocol`).

/// Minimum settlement amount in satoshis.
/// Duplicated from ghost-reconciliation to avoid cross-crate dependency.
const MIN_SETTLEMENT_SATS: u64 = 10_000;

/// Number of remaining jumps considered "comfortable" (no action needed).
const COMFORTABLE_JUMP_THRESHOLD: u32 = 3;

/// How many jumps a lock can afford before its value is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpAffordability {
    /// 3+ jumps remaining — no concern.
    Comfortable,
    /// 1-2 jumps remaining — plan to reconcile soon.
    Low,
    /// Cannot afford another jump while keeping MIN_SETTLEMENT_SATS reserve.
    Critical,
    /// Below MIN_SETTLEMENT_SATS — funds stranded, cannot settle or jump.
    Unrecoverable,
}

/// What action a lock should take given its current affordability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedAction {
    /// Jump when schedule says to.
    ContinueNormal,
    /// Jump now, but plan to reconcile soon.
    JumpButPlanReconcile,
    /// Skip jump, reconcile to L1 immediately.
    ReconcileNow,
    /// Cannot afford any action — wait for lower fees.
    Stranded,
}

/// Pre-calculated cost estimates from the caller.
///
/// The caller (typically wraith-protocol or a higher-level orchestrator)
/// provides these estimates based on current network conditions.
pub struct CostEstimates {
    /// Estimated cost per user for a Wraith jump session.
    /// From `WraithTransactionBuilder::estimate_mining_cost_per_user()`.
    pub jump_cost_sats: u64,
    /// Estimated batch mining fee share for L1 reconciliation.
    pub reconcile_cost_sats: u64,
}

/// Assess how many jumps a lock can afford.
///
/// Returns the affordability level based on the lock's value and estimated
/// jump cost. The lock must retain at least `MIN_SETTLEMENT_SATS` after all
/// jumps to be able to reconcile to L1.
pub fn assess_affordability(lock_value_sats: u64, estimated_jump_cost: u64) -> JumpAffordability {
    if lock_value_sats < MIN_SETTLEMENT_SATS {
        return JumpAffordability::Unrecoverable;
    }

    let remaining = remaining_jumps_estimate(lock_value_sats, estimated_jump_cost);

    if remaining == 0 {
        JumpAffordability::Critical
    } else if remaining < COMFORTABLE_JUMP_THRESHOLD {
        JumpAffordability::Low
    } else {
        JumpAffordability::Comfortable
    }
}

/// Estimate how many jumps a lock can afford.
///
/// Uses conservative floor division: `(lock_value - MIN_SETTLEMENT_SATS) / jump_cost`.
/// Returns 0 if the lock cannot afford even one jump while retaining the minimum
/// settlement reserve.
pub fn remaining_jumps_estimate(lock_value_sats: u64, estimated_jump_cost: u64) -> u32 {
    if lock_value_sats < MIN_SETTLEMENT_SATS || estimated_jump_cost == 0 {
        return 0;
    }

    let available = lock_value_sats - MIN_SETTLEMENT_SATS;
    // Safe: estimated_jump_cost != 0 checked above
    (available / estimated_jump_cost) as u32
}

/// Determine what action a lock should take based on affordability and costs.
///
/// Maps affordability level + reconciliation cost into a concrete recommendation.
pub fn recommended_action(lock_value_sats: u64, costs: &CostEstimates) -> RecommendedAction {
    let affordability = assess_affordability(lock_value_sats, costs.jump_cost_sats);

    match affordability {
        JumpAffordability::Unrecoverable => RecommendedAction::Stranded,
        JumpAffordability::Critical => {
            // Can't afford a jump. Can we at least reconcile?
            if lock_value_sats >= MIN_SETTLEMENT_SATS + costs.reconcile_cost_sats {
                RecommendedAction::ReconcileNow
            } else if lock_value_sats >= MIN_SETTLEMENT_SATS {
                // Can reconcile but won't have much left after costs
                RecommendedAction::ReconcileNow
            } else {
                RecommendedAction::Stranded
            }
        }
        JumpAffordability::Low => RecommendedAction::JumpButPlanReconcile,
        JumpAffordability::Comfortable => RecommendedAction::ContinueNormal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comfortable_affordability() {
        // 1M sats, 10K jump cost → (1M - 10K) / 10K = 99 jumps → Comfortable
        assert_eq!(
            assess_affordability(1_000_000, 10_000),
            JumpAffordability::Comfortable
        );
        assert_eq!(remaining_jumps_estimate(1_000_000, 10_000), 99);
    }

    #[test]
    fn test_low_affordability() {
        // 30K sats, 10K jump cost → (30K - 10K) / 10K = 2 jumps → Low
        assert_eq!(
            assess_affordability(30_000, 10_000),
            JumpAffordability::Low
        );
        assert_eq!(remaining_jumps_estimate(30_000, 10_000), 2);

        // 20K sats, 10K jump cost → (20K - 10K) / 10K = 1 jump → Low
        assert_eq!(
            assess_affordability(20_000, 10_000),
            JumpAffordability::Low
        );
        assert_eq!(remaining_jumps_estimate(20_000, 10_000), 1);
    }

    #[test]
    fn test_critical_affordability() {
        // Exactly at MIN_SETTLEMENT_SATS → 0 jumps → Critical
        assert_eq!(
            assess_affordability(10_000, 10_000),
            JumpAffordability::Critical
        );
        assert_eq!(remaining_jumps_estimate(10_000, 10_000), 0);

        // 15K sats, 10K jump cost → (15K - 10K) / 10K = 0 jumps → Critical
        assert_eq!(
            assess_affordability(15_000, 10_000),
            JumpAffordability::Critical
        );
        assert_eq!(remaining_jumps_estimate(15_000, 10_000), 0);
    }

    #[test]
    fn test_unrecoverable_affordability() {
        // Below MIN_SETTLEMENT_SATS → Unrecoverable
        assert_eq!(
            assess_affordability(9_999, 10_000),
            JumpAffordability::Unrecoverable
        );
        assert_eq!(remaining_jumps_estimate(9_999, 10_000), 0);

        assert_eq!(
            assess_affordability(0, 10_000),
            JumpAffordability::Unrecoverable
        );
    }

    #[test]
    fn test_zero_jump_cost() {
        // Zero jump cost → 0 remaining jumps (avoid division by zero)
        assert_eq!(remaining_jumps_estimate(1_000_000, 0), 0);
        // assess_affordability with 0 cost → Critical (0 remaining jumps)
        assert_eq!(
            assess_affordability(1_000_000, 0),
            JumpAffordability::Critical
        );
    }

    #[test]
    fn test_recommended_action_continue_normal() {
        let costs = CostEstimates {
            jump_cost_sats: 10_000,
            reconcile_cost_sats: 5_000,
        };
        assert_eq!(
            recommended_action(1_000_000, &costs),
            RecommendedAction::ContinueNormal
        );
    }

    #[test]
    fn test_recommended_action_jump_but_plan_reconcile() {
        let costs = CostEstimates {
            jump_cost_sats: 10_000,
            reconcile_cost_sats: 5_000,
        };
        // 20K sats → 1 jump remaining → Low → JumpButPlanReconcile
        assert_eq!(
            recommended_action(20_000, &costs),
            RecommendedAction::JumpButPlanReconcile
        );
    }

    #[test]
    fn test_recommended_action_reconcile_now() {
        let costs = CostEstimates {
            jump_cost_sats: 10_000,
            reconcile_cost_sats: 5_000,
        };
        // 10K sats → 0 jumps → Critical, but >= MIN_SETTLEMENT → ReconcileNow
        assert_eq!(
            recommended_action(10_000, &costs),
            RecommendedAction::ReconcileNow
        );
    }

    #[test]
    fn test_recommended_action_stranded() {
        let costs = CostEstimates {
            jump_cost_sats: 10_000,
            reconcile_cost_sats: 5_000,
        };
        // Below MIN_SETTLEMENT_SATS → Stranded
        assert_eq!(
            recommended_action(9_999, &costs),
            RecommendedAction::Stranded
        );
    }

    #[test]
    fn test_denomination_sizes_at_typical_fees() {
        // Typical wraith jump cost ~ 10K sats
        let jump_cost = 10_000u64;

        // Small = 1M sats → 99 jumps → Comfortable
        assert_eq!(
            assess_affordability(1_000_000, jump_cost),
            JumpAffordability::Comfortable
        );

        // Medium = 10M sats → 999 jumps → Comfortable
        assert_eq!(
            assess_affordability(10_000_000, jump_cost),
            JumpAffordability::Comfortable
        );

        // Large = 100M sats → 9999 jumps → Comfortable
        assert_eq!(
            assess_affordability(100_000_000, jump_cost),
            JumpAffordability::Comfortable
        );

        // Micro = 10K sats = MIN_SETTLEMENT_SATS → 0 jumps → Critical
        assert_eq!(
            assess_affordability(10_000, jump_cost),
            JumpAffordability::Critical
        );
    }

    #[test]
    fn test_boundary_between_low_and_comfortable() {
        let jump_cost = 10_000u64;

        // 3 jumps remaining = threshold → Comfortable
        // (3 * 10K) + 10K = 40K sats
        assert_eq!(remaining_jumps_estimate(40_000, jump_cost), 3);
        assert_eq!(
            assess_affordability(40_000, jump_cost),
            JumpAffordability::Comfortable
        );

        // 2 jumps remaining → Low
        assert_eq!(remaining_jumps_estimate(39_999, jump_cost), 2);
        assert_eq!(
            assess_affordability(39_999, jump_cost),
            JumpAffordability::Low
        );
    }
}
