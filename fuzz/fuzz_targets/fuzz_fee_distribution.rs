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
//| FILE: fuzz_fee_distribution.rs                                                                                       |
//|======================================================================================================================|

//! Fuzz target for treasury fee distribution arithmetic
//!
//! Tests that fee distribution never panics and maintains invariants:
//! - treasury_amount + node_pool == total_fee_pool
//! - sum of node payouts == node_pool (accounting for dust reclamation)
//! - no individual payout exceeds total pool
//! - no satoshis are lost

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use chrono::{DateTime, TimeZone, Utc};
use ghost_reconciliation::fee_distribution::{
    distribute_to_nodes, L2FeeDistribution, TreasuryState,
};

#[derive(Arbitrary, Debug)]
struct FuzzFeeInput {
    total_fee_pool: u64,
    treasury_balance: u64,
    threshold_timestamp: Option<i64>,
    reference_timestamp: i64,
    nodes: Vec<(u8, u8, i32)>, // (node_id_byte, addr_byte, shares)
}

fuzz_target!(|input: FuzzFeeInput| {
    // Build treasury state
    let threshold_at = input.threshold_timestamp.and_then(|ts| {
        // Clamp to valid range to avoid chrono panics
        let clamped = ts.clamp(-8_000_000_000, 8_000_000_000);
        Utc.timestamp_opt(clamped, 0).single()
    });
    let treasury = TreasuryState::from_stored(input.treasury_balance, threshold_at);

    // Reference time — clamp to valid range
    let ref_ts = input.reference_timestamp.clamp(-8_000_000_000, 8_000_000_000);
    let reference_time: DateTime<Utc> = match Utc.timestamp_opt(ref_ts, 0).single() {
        Some(t) => t,
        None => return,
    };

    // Treasury methods must not panic
    let _ = treasury.threshold_reached();
    let _ = treasury.years_since_threshold(reference_time);
    let (t_bps, n_bps) = treasury.get_fee_split_bps(reference_time);

    // Fee split must sum to 10000 bps
    assert_eq!(t_bps + n_bps, 10000, "fee split must sum to 10000 bps");

    let _ = treasury.decay_year(reference_time);

    // Build node list (cap to 20 nodes)
    let nodes: Vec<(String, String, i32)> = input.nodes
        .iter()
        .take(20)
        .map(|(id, addr, shares)| {
            (format!("node_{id}"), format!("addr_{addr}"), *shares)
        })
        .collect();

    // Calculate full distribution — must not panic
    let dist = L2FeeDistribution::calculate(
        input.total_fee_pool,
        &treasury,
        reference_time,
        &nodes,
    );

    // Invariant: treasury + node_pool == total
    assert_eq!(
        dist.treasury_amount + dist.node_pool, dist.total_fee_pool,
        "treasury + node_pool must equal total_fee_pool"
    );

    // Invariant: sum of node payouts == node_pool
    let payout_sum: u64 = dist.node_payouts.iter().map(|(_, _, amt)| amt).sum();
    if !dist.node_payouts.is_empty() {
        assert_eq!(payout_sum, dist.node_pool,
            "sum of node payouts must equal node_pool");
    }

    // Invariant: no individual payout exceeds total
    for (_, _, amt) in &dist.node_payouts {
        assert!(*amt <= dist.total_fee_pool,
            "individual payout must not exceed total fee pool");
    }

    // Also fuzz distribute_to_nodes directly
    let payouts = distribute_to_nodes(input.total_fee_pool, &nodes);
    let direct_sum: u64 = payouts.iter().map(|(_, _, amt)| amt).sum();
    assert!(direct_sum <= input.total_fee_pool,
        "direct distribution must not exceed pool");
});
