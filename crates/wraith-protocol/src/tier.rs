//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: tier.rs                                                                                                        |
//|======================================================================================================================|

//! Participant tiers for Wraith sessions
//!
//! Tiers are designed around Bitcoin L1 transaction constraints:
//! - Maximum transaction size: ~100KB (we target 80KB for safety)
//! - Input cost: ~57.5 vbytes per P2TR input
//! - Output cost: ~43 vbytes per P2TR output
//!
//! With variable input amounts, multiple outputs per participant are needed
//! for denomination mixing to prevent amount correlation attacks.
//!
//! Trade-off: More participants = larger anonymity set, but fewer outputs per user.
//! Tiers are organized by balance range to optimize this trade-off.

use serde::{Deserialize, Serialize};

/// Maximum transaction size budget in vbytes (10% margin under 100KB standard limit)
///
/// Phase 2 is the binding constraint: OPP×58 + 43 vbytes per user > Phase 1's 58 + OPP×43.
/// 90K provides sufficient headroom for all tiers in both phases.
pub const MAX_TX_VBYTES: usize = 90_000;

/// Network maturity mode for participant minimums
///
/// Early networks cannot meet the full participant minimums (160-400).
/// WraithMode allows scaling participant requirements as the network grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum WraithMode {
    /// Bootstrap phase: 10 participants for all tiers (early network)
    #[default]
    Bootstrap,
    /// Growth phase: 15-50 participants scaled per tier
    Growth,
    /// Mature phase: full participant minimums (160-400)
    Mature,
}

impl WraithMode {
    /// Get the mode name
    pub fn name(&self) -> &'static str {
        match self {
            WraithMode::Bootstrap => "Bootstrap",
            WraithMode::Growth => "Growth",
            WraithMode::Mature => "Mature",
        }
    }
}

impl std::fmt::Display for WraithMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// vbytes per P2TR input
pub const VBYTES_PER_INPUT: usize = 58; // Rounded up from 57.5

/// vbytes per P2TR output
pub const VBYTES_PER_OUTPUT: usize = 43;

/// Participant tier for Wraith mixing sessions
///
/// Tiers are organized by balance range. Smaller balances get more participants
/// (larger anonymity set) with fewer outputs. Larger balances get more outputs
/// for denomination mixing but fewer participants.
///
/// All tiers are designed to fit within 90KB vbyte budget for both Phase 1 and Phase 2.
/// Phase 2 is the binding constraint (OPP inputs per participant × 58 vB).
///
/// OPP values are chosen so all denominations {100K, 1M, 10M, 100M} divide evenly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ParticipantTier {
    /// 0.001-0.01 BTC: 500 participants, 2 outputs each
    Micro,
    /// 0.01-0.1 BTC: 320 participants, 4 outputs each
    Small,
    /// 0.1-1 BTC: 260 participants, 5 outputs each
    #[default]
    Medium,
    /// 1-10 BTC: 250 participants, 5 outputs each
    Standard,
    /// 10-50 BTC: 170 participants, 8 outputs each
    Large,
    /// 50+ BTC: 140 participants, 10 outputs each
    Whale,
}

impl ParticipantTier {
    /// Get the minimum number of participants for this tier
    pub fn min_participants(&self) -> usize {
        match self {
            ParticipantTier::Micro => 500,
            ParticipantTier::Small => 320,
            ParticipantTier::Medium => 260,
            ParticipantTier::Standard => 250,
            ParticipantTier::Large => 170,
            ParticipantTier::Whale => 140,
        }
    }

    /// Get the maximum participants (10% over minimum for flexibility)
    pub fn max_participants(&self) -> usize {
        (self.min_participants() * 11) / 10
    }

    /// Get the number of outputs per participant for this tier
    ///
    /// OPP values {2,4,5,5,8,10} all divide denominations {100K, 1M, 10M, 100M} evenly.
    pub fn outputs_per_participant(&self) -> usize {
        match self {
            ParticipantTier::Micro => 2,
            ParticipantTier::Small => 4,
            ParticipantTier::Medium => 5,
            ParticipantTier::Standard => 5,
            ParticipantTier::Large => 8,
            ParticipantTier::Whale => 10,
        }
    }

    /// Get the balance range for this tier in satoshis (min, max)
    pub fn balance_range_sats(&self) -> (u64, u64) {
        match self {
            ParticipantTier::Micro => (100_000, 1_000_000), // 0.001-0.01 BTC
            ParticipantTier::Small => (1_000_000, 10_000_000), // 0.01-0.1 BTC
            ParticipantTier::Medium => (10_000_000, 100_000_000), // 0.1-1 BTC
            ParticipantTier::Standard => (100_000_000, 1_000_000_000), // 1-10 BTC
            ParticipantTier::Large => (1_000_000_000, 5_000_000_000), // 10-50 BTC
            ParticipantTier::Whale => (5_000_000_000, u64::MAX), // 50+ BTC
        }
    }

    /// Select the appropriate tier based on user's balance
    pub fn for_balance(sats: u64) -> Self {
        match sats {
            0..=999_999 => ParticipantTier::Micro,
            1_000_000..=9_999_999 => ParticipantTier::Small,
            10_000_000..=99_999_999 => ParticipantTier::Medium,
            100_000_000..=999_999_999 => ParticipantTier::Standard,
            1_000_000_000..=4_999_999_999 => ParticipantTier::Large,
            _ => ParticipantTier::Whale,
        }
    }

    /// Get the tier name
    pub fn name(&self) -> &'static str {
        match self {
            ParticipantTier::Micro => "Micro",
            ParticipantTier::Small => "Small",
            ParticipantTier::Medium => "Medium",
            ParticipantTier::Standard => "Standard",
            ParticipantTier::Large => "Large",
            ParticipantTier::Whale => "Whale",
        }
    }

    /// Get the tier description
    pub fn description(&self) -> &'static str {
        match self {
            ParticipantTier::Micro => "Micro balance (0.001-0.01 BTC): 500 participants, 2 outputs",
            ParticipantTier::Small => "Small balance (0.01-0.1 BTC): 320 participants, 4 outputs",
            ParticipantTier::Medium => "Medium balance (0.1-1 BTC): 260 participants, 5 outputs",
            ParticipantTier::Standard => "Standard balance (1-10 BTC): 250 participants, 5 outputs",
            ParticipantTier::Large => "Large balance (10-50 BTC): 170 participants, 8 outputs",
            ParticipantTier::Whale => "Whale balance (50+ BTC): 140 participants, 10 outputs",
        }
    }

    /// Get the expected wait time in approximate hours
    ///
    /// Wait time depends on how quickly the tier fills up.
    /// Smaller balances are more common, so Micro/Small fill faster.
    pub fn expected_wait_hours(&self) -> u32 {
        match self {
            ParticipantTier::Micro => 2,
            ParticipantTier::Small => 4,
            ParticipantTier::Medium => 8,
            ParticipantTier::Standard => 24,
            ParticipantTier::Large => 48,
            ParticipantTier::Whale => 168, // 1 week
        }
    }

    /// Estimate Phase 1 (split) transaction size in vbytes
    ///
    /// Phase 1: N inputs (1 per participant) → N×OPP outputs
    /// Per user: 58 vB input + OPP×43 vB outputs
    pub fn estimated_phase1_vbytes(&self) -> usize {
        let n = self.min_participants();
        let opp = self.outputs_per_participant();
        (n * VBYTES_PER_INPUT) + (n * opp * VBYTES_PER_OUTPUT)
    }

    /// Estimate Phase 2 (merge) transaction size in vbytes
    ///
    /// Phase 2: N×OPP inputs → N outputs (1 per participant)
    /// Per user: OPP×58 vB inputs + 43 vB output
    pub fn estimated_phase2_vbytes(&self) -> usize {
        let n = self.min_participants();
        let opp = self.outputs_per_participant();
        (n * opp * VBYTES_PER_INPUT) + (n * VBYTES_PER_OUTPUT)
    }

    /// Calculate the estimated transaction size in vbytes (max of Phase 1 and Phase 2)
    pub fn estimated_tx_vbytes(&self) -> usize {
        self.estimated_phase1_vbytes().max(self.estimated_phase2_vbytes())
    }

    /// Get all tiers
    pub fn all() -> &'static [ParticipantTier] {
        &[
            ParticipantTier::Micro,
            ParticipantTier::Small,
            ParticipantTier::Medium,
            ParticipantTier::Standard,
            ParticipantTier::Large,
            ParticipantTier::Whale,
        ]
    }

    /// Check if participant count meets minimum
    pub fn meets_minimum(&self, count: usize) -> bool {
        count >= self.min_participants()
    }

    /// Calculate fill percentage
    pub fn fill_percentage(&self, count: usize) -> f64 {
        (count as f64 / self.min_participants() as f64 * 100.0).min(100.0)
    }

    /// Get minimum participants for a specific network mode
    pub fn min_participants_for_mode(&self, mode: WraithMode) -> usize {
        match mode {
            WraithMode::Bootstrap => 10,
            WraithMode::Growth => match self {
                ParticipantTier::Whale => 15,
                ParticipantTier::Large => 20,
                ParticipantTier::Standard => 25,
                ParticipantTier::Medium => 30,
                ParticipantTier::Small => 40,
                ParticipantTier::Micro => 50,
            },
            WraithMode::Mature => self.min_participants(),
        }
    }

    /// Get maximum participants for a specific network mode (10% over minimum)
    pub fn max_participants_for_mode(&self, mode: WraithMode) -> usize {
        (self.min_participants_for_mode(mode) * 11) / 10
    }

    /// Check if participant count meets minimum for mode
    pub fn meets_minimum_for_mode(&self, count: usize, mode: WraithMode) -> bool {
        count >= self.min_participants_for_mode(mode)
    }

    /// Calculate fill percentage for mode
    pub fn fill_percentage_for_mode(&self, count: usize, mode: WraithMode) -> f64 {
        (count as f64 / self.min_participants_for_mode(mode) as f64 * 100.0).min(100.0)
    }

    /// Estimate tx vbytes for a specific mode's participant count (max of Phase 1 and Phase 2)
    pub fn estimated_tx_vbytes_for_mode(&self, mode: WraithMode) -> usize {
        let n = self.min_participants_for_mode(mode);
        let opp = self.outputs_per_participant();
        let phase1 = (n * VBYTES_PER_INPUT) + (n * opp * VBYTES_PER_OUTPUT);
        let phase2 = (n * opp * VBYTES_PER_INPUT) + (n * VBYTES_PER_OUTPUT);
        phase1.max(phase2)
    }

    /// Validate that this tier's transaction fits within size limits
    pub fn validate_tx_size(&self) -> bool {
        self.estimated_tx_vbytes() <= MAX_TX_VBYTES
    }
}

impl std::fmt::Display for ParticipantTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ---------------------------------------------------------------------------
// LITE TIERS — single-round atomic CoinJoin (Wraith Lite v1, see DESIGN_LITE.md)
// ---------------------------------------------------------------------------
//
// These coexist with `ParticipantTier` during the v1 refactor. Once every
// caller has migrated, the legacy two-phase types above are deleted in a
// single subtractive commit and `LiteTier` is renamed to the canonical
// `Tier`. Until then, both compile side-by-side.
//
// Differences from `ParticipantTier`:
//   * 1 output per participant (no OPP), so transactions are dramatically
//     smaller and there's no two-phase fee-pad bookkeeping.
//   * 4 tiers instead of 6, named after their fixed denominations.
//   * 5–100 participants per round, not 140–500. Filling at this scale is
//     practical even on launch day; the larger numbers only worked on paper.
//   * `WraithMode` (Bootstrap/Growth/Mature) is gone — the floor of 5 is
//     viable from network launch.
//   * Carries the bond + service-fee rates directly on the tier so callers
//     don't have to thread them separately.

/// Service-fee rate as basis points (50 bps = 0.5%). Applied to total round
/// notional value. Fee output goes to the coordinator pool's fee address.
pub const LITE_SERVICE_FEE_BPS: u32 = 50;

/// Bond rate as basis points (50 bps = 0.5%). Escrowed in ghost-pay L2 at
/// session.bond(); refunded on completion or no-show during Filling; slashed
/// on no-sign during Signing.
pub const LITE_BOND_BPS: u32 = 50;

/// How long a `Filling` session stays open after `min_participants` is
/// reached, waiting for more arrivals up to `max_participants`. Default
/// 5 minutes — long enough for a realistic real-time fill, short enough that
/// users don't lose patience.
pub const LITE_FILL_WINDOW_SECS: u64 = 300;

/// A Wraith Lite tier — denomination-named, single-round atomic.
///
/// Each variant binds:
///   * a fixed mixed-output denomination (the equal-output value participants
///     receive after the round),
///   * `min_participants` (5 universally — round won't start below this),
///   * `max_participants` (tier-specific cap so the on-chain tx stays small),
///   * shared service-fee + bond rates (`LITE_SERVICE_FEE_BPS`, `LITE_BOND_BPS`).
///
/// Users select a tier by the denomination they want their post-mix outputs
/// to be. A user with 0.5 BTC who wants a single 0.1 BTC mixed output picks
/// `Denom10mSats` (the rest comes back as change in the same tx).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum LiteTier {
    /// 100,000 sats per mixed output (~$60 at $60k BTC). Fast-fill, high traffic.
    #[default]
    Denom100kSats,
    /// 1,000,000 sats per mixed output (~$600).
    Denom1mSats,
    /// 10,000,000 sats per mixed output (~$6,000).
    Denom10mSats,
    /// 100,000,000 sats per mixed output (~$60,000). Whale tier.
    Denom100mSats,
}

impl LiteTier {
    /// The single-output denomination this tier mixes to (in satoshis).
    pub const fn denomination_sats(&self) -> u64 {
        match self {
            LiteTier::Denom100kSats => 100_000,
            LiteTier::Denom1mSats => 1_000_000,
            LiteTier::Denom10mSats => 10_000_000,
            LiteTier::Denom100mSats => 100_000_000,
        }
    }

    /// Stable string identifier — what the wallet sends in `find_or_create`
    /// and what shows up in IPC envelopes / logs / config files.
    pub const fn id(&self) -> &'static str {
        match self {
            LiteTier::Denom100kSats => "100k_sats",
            LiteTier::Denom1mSats => "1m_sats",
            LiteTier::Denom10mSats => "10m_sats",
            LiteTier::Denom100mSats => "100m_sats",
        }
    }

    /// Parse a tier id back to its enum (the `find_or_create` reverse of
    /// `id()`). Returns `None` for unknown ids — callers surface that as a
    /// typed error to the wallet, never panic.
    pub fn from_id(s: &str) -> Option<Self> {
        match s {
            "100k_sats" => Some(LiteTier::Denom100kSats),
            "1m_sats" => Some(LiteTier::Denom1mSats),
            "10m_sats" => Some(LiteTier::Denom10mSats),
            "100m_sats" => Some(LiteTier::Denom100mSats),
            _ => None,
        }
    }

    /// Minimum participants required for a round to broadcast. 5 across all
    /// tiers — Whirlpool's number, well-tested for fill rate vs. anonymity
    /// set in the real world.
    pub const fn min_participants(&self) -> usize {
        5
    }

    /// Per-tier participant cap. Larger tiers allow more participants
    /// because they're rarer (so a tx with 100 participants is acceptable
    /// for the 0.1 BTC tier where rounds happen less frequently).
    pub const fn max_participants(&self) -> usize {
        match self {
            LiteTier::Denom100kSats => 20,
            LiteTier::Denom1mSats => 30,
            LiteTier::Denom10mSats => 50,
            LiteTier::Denom100mSats => 100,
        }
    }

    /// Per-participant bond escrowed in ghost-pay L2 at registration.
    /// Refunded on round completion; slashed on no-sign during Signing.
    pub const fn bond_sats(&self) -> u64 {
        // bond = denomination * BPS / 10_000
        (self.denomination_sats() * LITE_BOND_BPS as u64) / 10_000
    }

    /// Per-participant service fee included in the round transaction.
    /// Funds the coordinator pool operator.
    pub const fn service_fee_sats(&self) -> u64 {
        (self.denomination_sats() * LITE_SERVICE_FEE_BPS as u64) / 10_000
    }

    /// Worst-case round transaction size in vbytes — used to sanity-check
    /// every tier still fits inside Bitcoin's 100 KB standardness limit.
    /// Conservatively assumes every participant has a change output.
    pub const fn estimated_tx_vbytes(&self) -> usize {
        let n = self.max_participants();
        // n inputs (one per participant)
        // + n mixed outputs (one per participant)
        // + n change outputs (worst case: every input is larger than denom + fee_share)
        // + 1 fee output (to coordinator)
        (n * VBYTES_PER_INPUT) + (n * VBYTES_PER_OUTPUT) + (n * VBYTES_PER_OUTPUT) + VBYTES_PER_OUTPUT
    }

    /// All four tiers, in ascending denomination order.
    pub const fn all() -> &'static [LiteTier] {
        &[
            LiteTier::Denom100kSats,
            LiteTier::Denom1mSats,
            LiteTier::Denom10mSats,
            LiteTier::Denom100mSats,
        ]
    }

    /// Suggest a tier for a user's available balance. Picks the largest
    /// tier where `denomination + service_fee + bond ≤ balance`. Returns
    /// `None` if the user can't afford even the smallest tier.
    ///
    /// Note: this is suggestion only — the wallet may pick any tier the
    /// user has the balance for, including downsizing to a smaller tier
    /// for faster fill or upgrading via remix queue.
    pub fn suggest_for_balance(sats: u64) -> Option<Self> {
        for tier in Self::all().iter().rev() {
            let needed = tier.denomination_sats()
                + tier.service_fee_sats()
                + tier.bond_sats();
            if sats >= needed {
                return Some(*tier);
            }
        }
        None
    }
}

impl std::fmt::Display for LiteTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_participants() {
        assert_eq!(ParticipantTier::Micro.min_participants(), 500);
        assert_eq!(ParticipantTier::Small.min_participants(), 320);
        assert_eq!(ParticipantTier::Medium.min_participants(), 260);
        assert_eq!(ParticipantTier::Standard.min_participants(), 250);
        assert_eq!(ParticipantTier::Large.min_participants(), 170);
        assert_eq!(ParticipantTier::Whale.min_participants(), 140);
    }

    #[test]
    fn test_outputs_per_participant() {
        assert_eq!(ParticipantTier::Micro.outputs_per_participant(), 2);
        assert_eq!(ParticipantTier::Small.outputs_per_participant(), 4);
        assert_eq!(ParticipantTier::Medium.outputs_per_participant(), 5);
        assert_eq!(ParticipantTier::Standard.outputs_per_participant(), 5);
        assert_eq!(ParticipantTier::Large.outputs_per_participant(), 8);
        assert_eq!(ParticipantTier::Whale.outputs_per_participant(), 10);
    }

    #[test]
    fn test_all_tiers_fit_in_90kb() {
        for tier in ParticipantTier::all() {
            let vbytes = tier.estimated_tx_vbytes();
            assert!(
                vbytes <= MAX_TX_VBYTES,
                "Tier {:?} exceeds 90KB: {} vbytes (Phase1={}, Phase2={})",
                tier,
                vbytes,
                tier.estimated_phase1_vbytes(),
                tier.estimated_phase2_vbytes(),
            );
        }
    }

    #[test]
    fn test_phase2_is_binding_constraint() {
        // Phase 2 should be larger than Phase 1 for all tiers (it has more inputs)
        for tier in ParticipantTier::all() {
            assert!(
                tier.estimated_phase2_vbytes() >= tier.estimated_phase1_vbytes(),
                "Tier {:?}: Phase 2 ({}) should be >= Phase 1 ({})",
                tier,
                tier.estimated_phase2_vbytes(),
                tier.estimated_phase1_vbytes(),
            );
        }
    }

    #[test]
    fn test_tier_tx_sizes() {
        // Verify all tiers fit within 90KB budget (MAX_TX_VBYTES)
        for tier in ParticipantTier::all() {
            let size = tier.estimated_tx_vbytes();
            assert!(
                size <= MAX_TX_VBYTES,
                "{:?} tx size {} exceeds max {}",
                tier,
                size,
                MAX_TX_VBYTES
            );
        }

        // Phase 2 vbytes (binding constraint): N×OPP×58 + N×43
        // Micro: 500×2×58 + 500×43 = 79,500
        // Small: 320×4×58 + 320×43 = 88,000
        // Medium: 260×5×58 + 260×43 = 86,580
        // Standard: 250×5×58 + 250×43 = 83,250
        // Large: 170×8×58 + 170×43 = 86,190
        // Whale: 140×10×58 + 140×43 = 87,220
        assert_eq!(ParticipantTier::Micro.estimated_phase2_vbytes(), 79_500);
        assert_eq!(ParticipantTier::Small.estimated_phase2_vbytes(), 88_000);
        assert_eq!(ParticipantTier::Medium.estimated_phase2_vbytes(), 86_580);
        assert_eq!(ParticipantTier::Standard.estimated_phase2_vbytes(), 83_250);
        assert_eq!(ParticipantTier::Large.estimated_phase2_vbytes(), 86_190);
        assert_eq!(ParticipantTier::Whale.estimated_phase2_vbytes(), 87_220);

        // Phase 1 vbytes: N×58 + N×OPP×43
        assert_eq!(ParticipantTier::Micro.estimated_phase1_vbytes(), 72_000);
        assert_eq!(ParticipantTier::Small.estimated_phase1_vbytes(), 73_600);
    }

    #[test]
    fn test_tier_selection_by_balance() {
        // Micro: 0.001-0.01 BTC (100k-1M sats)
        assert_eq!(
            ParticipantTier::for_balance(100_000),
            ParticipantTier::Micro
        );
        assert_eq!(
            ParticipantTier::for_balance(500_000),
            ParticipantTier::Micro
        );

        // Small: 0.01-0.1 BTC (1M-10M sats)
        assert_eq!(
            ParticipantTier::for_balance(1_000_000),
            ParticipantTier::Small
        );
        assert_eq!(
            ParticipantTier::for_balance(5_000_000),
            ParticipantTier::Small
        );

        // Medium: 0.1-1 BTC (10M-100M sats)
        assert_eq!(
            ParticipantTier::for_balance(10_000_000),
            ParticipantTier::Medium
        );
        assert_eq!(
            ParticipantTier::for_balance(50_000_000),
            ParticipantTier::Medium
        );

        // Standard: 1-10 BTC (100M-1B sats)
        assert_eq!(
            ParticipantTier::for_balance(100_000_000),
            ParticipantTier::Standard
        );
        assert_eq!(
            ParticipantTier::for_balance(500_000_000),
            ParticipantTier::Standard
        );

        // Large: 10-50 BTC (1B-5B sats)
        assert_eq!(
            ParticipantTier::for_balance(1_000_000_000),
            ParticipantTier::Large
        );
        assert_eq!(
            ParticipantTier::for_balance(3_000_000_000),
            ParticipantTier::Large
        );

        // Whale: 50+ BTC (5B+ sats)
        assert_eq!(
            ParticipantTier::for_balance(5_000_000_000),
            ParticipantTier::Whale
        );
        assert_eq!(
            ParticipantTier::for_balance(100_000_000_000),
            ParticipantTier::Whale
        );
    }

    #[test]
    fn test_minimum_anonymity_set() {
        // All tiers must have at least 140 participants (Whale minimum)
        for tier in ParticipantTier::all() {
            assert!(
                tier.min_participants() >= 140,
                "Tier {:?} has fewer than 140 participants",
                tier
            );
        }
    }

    #[test]
    fn test_meets_minimum() {
        assert!(ParticipantTier::Micro.meets_minimum(500));
        assert!(!ParticipantTier::Micro.meets_minimum(499));
        assert!(ParticipantTier::Whale.meets_minimum(140));
        assert!(!ParticipantTier::Whale.meets_minimum(139));
    }

    #[test]
    fn test_fill_percentage() {
        assert!((ParticipantTier::Micro.fill_percentage(250) - 50.0).abs() < 0.1);
        assert!((ParticipantTier::Micro.fill_percentage(500) - 100.0).abs() < 0.1);
        // Capped at 100%
        assert!((ParticipantTier::Micro.fill_percentage(600) - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_max_participants() {
        // 10% over minimum
        assert_eq!(ParticipantTier::Micro.max_participants(), 550);
        assert_eq!(ParticipantTier::Whale.max_participants(), 154);
    }

    #[test]
    fn test_bootstrap_mode_all_tiers_minimum_10() {
        for tier in ParticipantTier::all() {
            assert_eq!(
                tier.min_participants_for_mode(WraithMode::Bootstrap),
                10,
                "Bootstrap mode should be 10 for {:?}",
                tier
            );
        }
    }

    #[test]
    fn test_growth_mode_scaled() {
        assert_eq!(
            ParticipantTier::Whale.min_participants_for_mode(WraithMode::Growth),
            15
        );
        assert_eq!(
            ParticipantTier::Large.min_participants_for_mode(WraithMode::Growth),
            20
        );
        assert_eq!(
            ParticipantTier::Standard.min_participants_for_mode(WraithMode::Growth),
            25
        );
        assert_eq!(
            ParticipantTier::Medium.min_participants_for_mode(WraithMode::Growth),
            30
        );
        assert_eq!(
            ParticipantTier::Small.min_participants_for_mode(WraithMode::Growth),
            40
        );
        assert_eq!(
            ParticipantTier::Micro.min_participants_for_mode(WraithMode::Growth),
            50
        );
    }

    #[test]
    fn test_mature_matches_original() {
        for tier in ParticipantTier::all() {
            assert_eq!(
                tier.min_participants_for_mode(WraithMode::Mature),
                tier.min_participants(),
                "Mature mode should match original for {:?}",
                tier
            );
        }
    }

    #[test]
    fn test_bootstrap_tx_sizes_within_limit() {
        // 10 participants must fit in 90KB for any tier
        for tier in ParticipantTier::all() {
            let vbytes = tier.estimated_tx_vbytes_for_mode(WraithMode::Bootstrap);
            assert!(
                vbytes <= MAX_TX_VBYTES,
                "Bootstrap {:?} tx size {} exceeds max {}",
                tier,
                vbytes,
                MAX_TX_VBYTES
            );
        }
        // Whale (OPP=10): Phase2 = 10×10×58 + 10×43 = 5800+430 = 6,230 (binding)
        assert_eq!(
            ParticipantTier::Whale.estimated_tx_vbytes_for_mode(WraithMode::Bootstrap),
            6_230
        );
    }

    #[test]
    fn test_mode_aware_meets_minimum() {
        // Bootstrap: 10 is enough for any tier
        assert!(ParticipantTier::Whale.meets_minimum_for_mode(10, WraithMode::Bootstrap));
        assert!(!ParticipantTier::Whale.meets_minimum_for_mode(9, WraithMode::Bootstrap));

        // Growth: Whale needs 15
        assert!(ParticipantTier::Whale.meets_minimum_for_mode(15, WraithMode::Growth));
        assert!(!ParticipantTier::Whale.meets_minimum_for_mode(14, WraithMode::Growth));

        // Mature: Whale needs 140
        assert!(ParticipantTier::Whale.meets_minimum_for_mode(140, WraithMode::Mature));
        assert!(!ParticipantTier::Whale.meets_minimum_for_mode(139, WraithMode::Mature));
    }

    #[test]
    fn test_mode_aware_fill_percentage() {
        // Bootstrap: 5 of 10 = 50%
        let pct = ParticipantTier::Medium.fill_percentage_for_mode(5, WraithMode::Bootstrap);
        assert!((pct - 50.0).abs() < 0.1);

        // Bootstrap: 10 of 10 = 100%
        let pct = ParticipantTier::Medium.fill_percentage_for_mode(10, WraithMode::Bootstrap);
        assert!((pct - 100.0).abs() < 0.1);

        // Capped at 100%
        let pct = ParticipantTier::Medium.fill_percentage_for_mode(20, WraithMode::Bootstrap);
        assert!((pct - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_mode_aware_max_participants() {
        // Bootstrap: 10 * 11/10 = 11
        assert_eq!(
            ParticipantTier::Medium.max_participants_for_mode(WraithMode::Bootstrap),
            11
        );
        // Growth: Whale 15 * 11/10 = 16
        assert_eq!(
            ParticipantTier::Whale.max_participants_for_mode(WraithMode::Growth),
            16
        );
    }

    // -----------------------------------------------------------------------
    // Lite tier tests — locks the v1 spec (DESIGN_LITE.md §8 tier table)
    // -----------------------------------------------------------------------

    #[test]
    fn lite_tier_ids_are_canonical() {
        // Wallet wire format depends on these strings being stable.
        assert_eq!(LiteTier::Denom100kSats.id(), "100k_sats");
        assert_eq!(LiteTier::Denom1mSats.id(), "1m_sats");
        assert_eq!(LiteTier::Denom10mSats.id(), "10m_sats");
        assert_eq!(LiteTier::Denom100mSats.id(), "100m_sats");
    }

    #[test]
    fn lite_tier_id_round_trips() {
        for tier in LiteTier::all() {
            let id = tier.id();
            assert_eq!(LiteTier::from_id(id), Some(*tier));
        }
        assert_eq!(LiteTier::from_id("not_a_tier"), None);
        assert_eq!(LiteTier::from_id(""), None);
    }

    #[test]
    fn lite_tier_denominations_are_powers_of_ten() {
        // Spec invariant — each tier is exactly 10x the previous, so
        // remix-queue downgrade math (1 × 1m → 10 × 100k) works without
        // remainder.
        assert_eq!(LiteTier::Denom100kSats.denomination_sats(), 100_000);
        assert_eq!(LiteTier::Denom1mSats.denomination_sats(), 1_000_000);
        assert_eq!(LiteTier::Denom10mSats.denomination_sats(), 10_000_000);
        assert_eq!(LiteTier::Denom100mSats.denomination_sats(), 100_000_000);
    }

    #[test]
    fn lite_tier_fees_and_bonds_match_spec() {
        // 0.5% service fee + 0.5% bond, applied per-tier.
        for tier in LiteTier::all() {
            let denom = tier.denomination_sats();
            assert_eq!(tier.service_fee_sats(), denom / 200, "tier {tier} fee");
            assert_eq!(tier.bond_sats(), denom / 200, "tier {tier} bond");
        }
        // Concrete:
        assert_eq!(LiteTier::Denom100kSats.bond_sats(), 500);
        assert_eq!(LiteTier::Denom1mSats.bond_sats(), 5_000);
        assert_eq!(LiteTier::Denom10mSats.bond_sats(), 50_000);
        assert_eq!(LiteTier::Denom100mSats.bond_sats(), 500_000);
    }

    #[test]
    fn lite_tier_min_participants_is_five() {
        for tier in LiteTier::all() {
            assert_eq!(tier.min_participants(), 5, "tier {tier} min");
        }
    }

    #[test]
    fn lite_tier_max_participants_match_spec() {
        // From DESIGN_LITE.md §8 tier table.
        assert_eq!(LiteTier::Denom100kSats.max_participants(), 20);
        assert_eq!(LiteTier::Denom1mSats.max_participants(), 30);
        assert_eq!(LiteTier::Denom10mSats.max_participants(), 50);
        assert_eq!(LiteTier::Denom100mSats.max_participants(), 100);
    }

    #[test]
    fn lite_tier_tx_size_fits_standardness() {
        // Every tier at maximum fill must fit comfortably in Bitcoin's
        // 100KB standardness limit. Largest is Denom100mSats with 100
        // participants, ~14.4KB worst-case.
        for tier in LiteTier::all() {
            let vb = tier.estimated_tx_vbytes();
            assert!(
                vb <= MAX_TX_VBYTES,
                "tier {tier}: {vb} vbytes exceeds {MAX_TX_VBYTES}"
            );
        }
        // The 100m tier's worst-case sanity-check (100 inputs + 100 mixed +
        // 100 change + 1 fee = 301 io-units × ~50 vB ≈ 14.4 KB).
        let big = LiteTier::Denom100mSats.estimated_tx_vbytes();
        assert!(
            (14_000..=15_000).contains(&big),
            "100m tier tx size ({big}) outside expected ~14.4KB band"
        );
    }

    #[test]
    fn lite_tier_suggestion_picks_largest_affordable() {
        // Just enough for the smallest tier: denom + fee + bond.
        let smallest_total = LiteTier::Denom100kSats.denomination_sats()
            + LiteTier::Denom100kSats.service_fee_sats()
            + LiteTier::Denom100kSats.bond_sats();
        assert_eq!(
            LiteTier::suggest_for_balance(smallest_total),
            Some(LiteTier::Denom100kSats)
        );
        // One sat short of the smallest → None.
        assert_eq!(LiteTier::suggest_for_balance(smallest_total - 1), None);
        // 1 BTC exactly. denom (100m) + fee (500k) + bond (500k) = 101m sats.
        // 100m sats is short by 1m sats. So we expect the 10m tier.
        assert_eq!(
            LiteTier::suggest_for_balance(100_000_000),
            Some(LiteTier::Denom10mSats)
        );
        // 1.01+ BTC → 100m tier.
        assert_eq!(
            LiteTier::suggest_for_balance(101_000_000),
            Some(LiteTier::Denom100mSats)
        );
    }

    #[test]
    fn lite_tier_default_is_smallest() {
        // Default tier is the smallest — fastest fill, lowest commitment.
        // Wallet code that uses LiteTier::default() lands users in the
        // tier most likely to fill on launch day.
        assert_eq!(LiteTier::default(), LiteTier::Denom100kSats);
    }

    #[test]
    fn lite_constants_match_spec() {
        // 50 bps = 0.5%, 5 minute fill window — these are wallet-visible,
        // pin them so a future "let's tune the rate" change has to
        // explicitly update the test.
        assert_eq!(LITE_SERVICE_FEE_BPS, 50);
        assert_eq!(LITE_BOND_BPS, 50);
        assert_eq!(LITE_FILL_WINDOW_SECS, 300);
    }
}
