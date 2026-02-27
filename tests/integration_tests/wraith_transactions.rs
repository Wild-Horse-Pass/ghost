//! Category 23: Wraith Transaction Tests (30 tests, 700-729)
//!
//! Integration tests for wraith-protocol transaction building:
//! - Denomination math (700-709)
//! - Transaction builder split/merge (710-719)
//! - Encrypted OP_RETURN markers (720-724)
//! - Phase execution lifecycle (725-729)

use std::str::FromStr;

use bitcoin::{Address, Network, ScriptBuf, Txid};
use wraith_protocol::{
    generate_encrypted_marker_v3, verify_encrypted_marker_v3, Phase, PhaseExecution, PhaseState,
    SessionType, WraithDenomination, WraithInput, WraithTransactionBuilder,
};

// =============================================================================
// HELPERS
// =============================================================================

/// Create a dummy txid for test inputs.
fn test_txid() -> Txid {
    Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap()
}

/// Generate a P2TR address on Signet for testing.
///
/// `seed_byte` must be non-zero (valid secret key).
fn signet_p2tr_address(seed_byte: u8) -> String {
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::SecretKey;

    let secp = Secp256k1::new();
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = if seed_byte == 0 { 1 } else { seed_byte };
    key_bytes[31] = seed_byte.wrapping_add(1); // ensure uniqueness
    let sk = SecretKey::from_slice(&key_bytes).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let xonly = pk.x_only_public_key().0;
    Address::p2tr(&secp, xonly, None, Network::Signet).to_string()
}

/// Build a WraithInput with the given amount and participant_id.
fn make_input(amount: u64, participant_id: u32) -> WraithInput {
    WraithInput {
        txid: test_txid(),
        vout: participant_id,
        amount,
        script_pubkey: ScriptBuf::new(),
        participant_id,
    }
}

/// Generate `opp` unique Signet P2TR addresses for one participant.
fn address_set_for_participant(participant_idx: u8, opp: usize) -> Vec<String> {
    (0..opp)
        .map(|i| {
            // Use a unique seed per (participant, index) combination
            let seed = (participant_idx as u16 * 11 + i as u16 + 1) as u8;
            signet_p2tr_address(seed)
        })
        .collect()
}

// =============================================================================
// DENOMINATION MATH TESTS (700-709)
// =============================================================================

#[test]
fn test_700_all_denominations_output_sats() {
    assert_eq!(WraithDenomination::Micro.output_sats(), 100_000);
    assert_eq!(WraithDenomination::Small.output_sats(), 1_000_000);
    assert_eq!(WraithDenomination::Medium.output_sats(), 10_000_000);
    assert_eq!(WraithDenomination::Large.output_sats(), 100_000_000);
}

#[test]
fn test_701_fixed_service_fees() {
    assert_eq!(WraithDenomination::Micro.service_fee(), 500);
    assert_eq!(WraithDenomination::Small.service_fee(), 2_000);
    assert_eq!(WraithDenomination::Medium.service_fee(), 5_000);
    assert_eq!(WraithDenomination::Large.service_fee(), 10_000);
}

#[test]
fn test_702_min_input_equals_output_plus_service_fee() {
    for denom in WraithDenomination::all() {
        assert_eq!(
            denom.min_input_sats(),
            denom.output_sats() + denom.service_fee(),
            "min_input_sats mismatch for {:?}",
            denom
        );
    }
}

#[test]
fn test_703_intermediate_sats_equals_output_div_opp() {
    // All OPPs {2,4,5,8,10} must divide all denominations evenly (M-23)
    let opps = [2, 4, 5, 8, 10];
    for denom in WraithDenomination::all() {
        for &opp in &opps {
            assert_eq!(
                denom.intermediate_sats(opp),
                denom.output_sats() / opp as u64,
                "intermediate_sats mismatch for {:?} with OPP {}",
                denom, opp
            );
        }
    }
}

#[test]
fn test_704_intermediate_sats_identical_across_calls() {
    // All intermediate amounts must be identical for privacy — no variance allowed.
    // Variable amounts would create a correlation vector for chain analysis.
    for denom in WraithDenomination::all() {
        let expected = denom.intermediate_sats(4);
        for _ in 0..100 {
            assert_eq!(
                denom.intermediate_sats(4),
                expected,
                "{:?}: intermediate_sats must return identical values on every call",
                denom
            );
        }
    }
}

#[test]
fn test_705_from_output_sats_roundtrip() {
    for denom in WraithDenomination::all() {
        let sats = denom.output_sats();
        let recovered = WraithDenomination::from_output_sats(sats);
        assert_eq!(
            recovered,
            Some(*denom),
            "from_output_sats({}) should return {:?}",
            sats,
            denom
        );
    }
}

#[test]
fn test_706_from_output_sats_invalid_returns_none() {
    assert_eq!(WraithDenomination::from_output_sats(999), None);
    assert_eq!(WraithDenomination::from_output_sats(0), None);
    assert_eq!(WraithDenomination::from_output_sats(500_000), None);
    assert_eq!(WraithDenomination::from_output_sats(u64::MAX), None);
}

#[test]
fn test_707_largest_fitting_boundary_values() {
    // Below Micro min_input_sats (100_500) -> None
    assert_eq!(WraithDenomination::largest_fitting(100_499), None);

    // Exactly at Micro boundary -> Micro
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Micro.min_input_sats()),
        Some(WraithDenomination::Micro)
    );

    // Between Micro and Small -> Micro
    assert_eq!(
        WraithDenomination::largest_fitting(500_000),
        Some(WraithDenomination::Micro)
    );

    // Exactly at Small boundary -> Small
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Small.min_input_sats()),
        Some(WraithDenomination::Small)
    );

    // Exactly at Medium boundary -> Medium
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Medium.min_input_sats()),
        Some(WraithDenomination::Medium)
    );

    // Exactly at Large boundary -> Large
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Large.min_input_sats()),
        Some(WraithDenomination::Large)
    );

    // Way above Large -> Large
    assert_eq!(
        WraithDenomination::largest_fitting(1_000_000_000),
        Some(WraithDenomination::Large)
    );
}

#[test]
fn test_708_short_code_roundtrip() {
    let expected_codes = [
        (WraithDenomination::Micro, "MI"),
        (WraithDenomination::Small, "SM"),
        (WraithDenomination::Medium, "MD"),
        (WraithDenomination::Large, "LG"),
    ];

    for (denom, code) in &expected_codes {
        assert_eq!(denom.short_code(), *code);
        assert_eq!(
            WraithDenomination::from_short_code(code),
            Some(*denom),
            "from_short_code({}) should return {:?}",
            code,
            denom
        );
    }
}

#[test]
fn test_709_from_short_code_invalid_returns_none() {
    assert_eq!(WraithDenomination::from_short_code("XX"), None);
    assert_eq!(WraithDenomination::from_short_code(""), None);
    assert_eq!(WraithDenomination::from_short_code("mi"), None); // case sensitive
    assert_eq!(WraithDenomination::from_short_code("MICRO"), None);
}

// =============================================================================
// TRANSACTION BUILDER TESTS (710-719)
// =============================================================================

#[test]
fn test_710_new_builder_zero_participants() {
    let builder = WraithTransactionBuilder::new(
        "session-710".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        4,
        SessionType::Mix,
    );

    assert_eq!(builder.participant_count(), 0);
    assert_eq!(builder.session_id, "session-710");
}

#[test]
fn test_711_add_input_sufficient_amount_succeeds() {
    let mut builder = WraithTransactionBuilder::new(
        "session-711".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        4,
        SessionType::Mix,
    );

    let result = builder.add_input(make_input(WraithDenomination::Small.min_input_sats(), 0));
    assert!(result.is_ok());
    assert_eq!(builder.participant_count(), 1);

    // Amount above minimum also accepted
    let result = builder.add_input(make_input(
        WraithDenomination::Small.min_input_sats() + 50_000,
        1,
    ));
    assert!(result.is_ok());
    assert_eq!(builder.participant_count(), 2);
}

#[test]
fn test_712_input_below_denomination_rejected() {
    let mut builder = WraithTransactionBuilder::new(
        "session-712".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        4,
        SessionType::Mix,
    );

    // One sat below the required input amount
    let result = builder.add_input(make_input(WraithDenomination::Small.min_input_sats() - 1, 0));
    assert!(result.is_err());
    assert_eq!(builder.participant_count(), 0);
}

#[test]
fn test_713_split_tx_output_count() {
    // Split: N participants -> OPP*N intermediate outputs + 1 OP_RETURN marker
    const OPP: usize = 4; // Small denomination OPP
    let n = 3;
    let mut builder = WraithTransactionBuilder::new(
        "session-713".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        OPP,
        SessionType::Mix,
    );

    for p in 0..n {
        // Provide enough to cover intermediates + fee headroom
        builder
            .add_input(make_input(
                WraithDenomination::Small.min_input_sats() + 100_000,
                p as u32,
            ))
            .unwrap();
    }

    let addresses: Vec<Vec<String>> = (0..n)
        .map(|p| address_set_for_participant(p as u8, OPP))
        .collect();

    let split_tx = builder.build_split_transaction(&addresses).unwrap();
    let expected_outputs = n * OPP + 1; // +1 for OP_RETURN
    assert_eq!(
        split_tx.transaction.output.len(),
        expected_outputs,
        "Split tx should have OPP*N + 1 outputs, got {}",
        split_tx.transaction.output.len()
    );
}

#[test]
fn test_714_split_tx_participant_count_matches() {
    const OPP: usize = 2; // Micro denomination OPP
    let n = 2;
    let mut builder = WraithTransactionBuilder::new(
        "session-714".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
        OPP,
        SessionType::Mix,
    );

    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.min_input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    let addresses: Vec<Vec<String>> = (0..n)
        .map(|p| address_set_for_participant(p as u8 + 100, OPP))
        .collect();

    let split_tx = builder.build_split_transaction(&addresses).unwrap();
    assert_eq!(split_tx.participant_count, n);
}

#[test]
fn test_715_split_tx_intermediate_count() {
    const OPP: usize = 2; // Micro denomination OPP
    let n = 4;
    let mut builder = WraithTransactionBuilder::new(
        "session-715".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
        OPP,
        SessionType::Mix,
    );

    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.min_input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    let addresses: Vec<Vec<String>> = (0..n)
        .map(|p| address_set_for_participant(p as u8 + 50, OPP))
        .collect();

    let split_tx = builder.build_split_transaction(&addresses).unwrap();
    assert_eq!(split_tx.intermediate_count, n * OPP);
}

#[test]
fn test_716_build_split_no_inputs_error() {
    let builder = WraithTransactionBuilder::new(
        "session-716".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        4,
        SessionType::Mix,
    );

    let result = builder.build_split_transaction(&[]);
    assert!(result.is_err(), "Build split with no inputs should fail");
}

#[test]
fn test_717_split_wrong_address_set_count_error() {
    const OPP: usize = 4; // Small denomination OPP
    let mut builder = WraithTransactionBuilder::new(
        "session-717".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        OPP,
        SessionType::Mix,
    );

    // Add 2 participants
    for p in 0..2 {
        builder
            .add_input(make_input(
                WraithDenomination::Small.min_input_sats() + 100_000,
                p,
            ))
            .unwrap();
    }

    // Provide only 1 address set (need 2)
    let addresses = vec![address_set_for_participant(1, OPP)];
    let result = builder.build_split_transaction(&addresses);
    assert!(result.is_err(), "Mismatched address set count should fail");

    // Provide 3 address sets (need 2)
    let addresses = vec![
        address_set_for_participant(1, OPP),
        address_set_for_participant(2, OPP),
        address_set_for_participant(3, OPP),
    ];
    let result = builder.build_split_transaction(&addresses);
    assert!(result.is_err(), "Too many address sets should also fail");
}

#[test]
fn test_718_merge_tx_output_count() {
    // Merge: N participants -> N final outputs + 1 OP_RETURN
    const OPP: usize = 2; // Micro denomination OPP
    let n = 3usize;
    let mut builder = WraithTransactionBuilder::new(
        "session-718".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
        OPP,
        SessionType::Mix,
    );

    // We still need at least one input registered in the builder for session context,
    // but merge uses intermediate_inputs directly. Add a dummy input per participant.
    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.min_input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    // Intermediates carry a fee pad for Phase 2 mining cost (same as real split tx)
    let base_intermediate = WraithDenomination::Micro.intermediate_sats(OPP);
    let fee_pad = 1_000u64; // ~1000 sats/intermediate covers merge mining at 10 sat/vB
    let intermediate_amount = base_intermediate + fee_pad;

    // Build intermediate inputs: each participant has OPP inputs
    let intermediate_inputs: Vec<Vec<WraithInput>> = (0..n)
        .map(|p| {
            (0..OPP)
                .map(|i| WraithInput {
                    txid: test_txid(),
                    vout: (p * OPP + i) as u32,
                    amount: intermediate_amount,
                    script_pubkey: ScriptBuf::new(),
                    participant_id: p as u32,
                })
                .collect()
        })
        .collect();

    let final_addresses: Vec<String> = (0..n).map(|p| signet_p2tr_address((p + 1) as u8)).collect();

    let merge_tx = builder
        .build_merge_transaction(&intermediate_inputs, &final_addresses)
        .unwrap();

    let expected_outputs = n + 1; // N finals + OP_RETURN
    assert_eq!(
        merge_tx.transaction.output.len(),
        expected_outputs,
        "Merge tx should have N + 1 outputs, got {}",
        merge_tx.transaction.output.len()
    );
}

#[test]
fn test_719_merge_tx_consumes_all_intermediate_inputs() {
    const OPP: usize = 2; // Micro denomination OPP
    let n = 2usize;
    let mut builder = WraithTransactionBuilder::new(
        "session-719".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
        OPP,
        SessionType::Mix,
    );

    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.min_input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    // Intermediates carry a fee pad for Phase 2 mining cost
    let base_intermediate = WraithDenomination::Micro.intermediate_sats(OPP);
    let fee_pad = 1_000u64;
    let intermediate_amount = base_intermediate + fee_pad;

    let intermediate_inputs: Vec<Vec<WraithInput>> = (0..n)
        .map(|p| {
            (0..OPP)
                .map(|i| WraithInput {
                    txid: test_txid(),
                    vout: (p * OPP + i) as u32,
                    amount: intermediate_amount,
                    script_pubkey: ScriptBuf::new(),
                    participant_id: p as u32,
                })
                .collect()
        })
        .collect();

    let final_addresses: Vec<String> = (0..n)
        .map(|p| signet_p2tr_address((p + 200) as u8))
        .collect();

    let merge_tx = builder
        .build_merge_transaction(&intermediate_inputs, &final_addresses)
        .unwrap();

    // All OPP*N intermediate inputs should appear as transaction inputs
    let expected_input_count = n * OPP;
    assert_eq!(
        merge_tx.transaction.input.len(),
        expected_input_count,
        "Merge tx should consume all OPP*N intermediate inputs"
    );
}

// =============================================================================
// ENCRYPTED MARKER TESTS (720-724)
// =============================================================================

#[test]
fn test_720_v3_marker_is_exactly_32_bytes() {
    let session_id = [0xABu8; 32];
    let marker = generate_encrypted_marker_v3(1, &session_id, 250);
    assert_eq!(
        marker.len(),
        32,
        "v3 marker must be exactly 32 bytes — no plaintext leak"
    );
}

#[test]
fn test_721_v3_verify_marker_roundtrip() {
    let session_id = [0x42u8; 32];
    let count = 250u16;

    let marker_p1 = generate_encrypted_marker_v3(1, &session_id, count);
    let result = verify_encrypted_marker_v3(&marker_p1, &session_id, 400);
    assert_eq!(
        result,
        Some((1, count)),
        "Phase 1 v3 marker should verify with correct count"
    );

    let marker_p2 = generate_encrypted_marker_v3(2, &session_id, count);
    let result = verify_encrypted_marker_v3(&marker_p2, &session_id, 400);
    assert_eq!(
        result,
        Some((2, count)),
        "Phase 2 v3 marker should verify with correct count"
    );
}

#[test]
fn test_722_v3_different_sessions_and_counts_produce_different_markers() {
    let session_a = [0x01u8; 32];
    let session_b = [0x02u8; 32];

    // Different sessions, same count
    let marker_a = generate_encrypted_marker_v3(1, &session_a, 250);
    let marker_b = generate_encrypted_marker_v3(1, &session_b, 250);
    assert_ne!(
        marker_a, marker_b,
        "Different sessions must produce different markers"
    );

    // Same session, different counts
    let marker_c = generate_encrypted_marker_v3(1, &session_a, 100);
    assert_ne!(
        marker_a, marker_c,
        "Different counts must produce different markers"
    );

    // Cross-verify: wrong session fails
    assert_eq!(verify_encrypted_marker_v3(&marker_a, &session_b, 400), None);
}

#[test]
fn test_723_v3_phase1_vs_phase2_different_markers() {
    let session_id = [0xFFu8; 32];
    let count = 250u16;

    let marker_p1 = generate_encrypted_marker_v3(1, &session_id, count);
    let marker_p2 = generate_encrypted_marker_v3(2, &session_id, count);

    assert_ne!(marker_p1, marker_p2, "Phase 1 and Phase 2 must differ");

    // Each verifies to its own phase
    let r1 = verify_encrypted_marker_v3(&marker_p1, &session_id, 400);
    assert_eq!(r1, Some((1, count)));
    let r2 = verify_encrypted_marker_v3(&marker_p2, &session_id, 400);
    assert_eq!(r2, Some((2, count)));
}

// =============================================================================
// PHASE EXECUTION TESTS (725-729)
// =============================================================================

#[test]
fn test_725_phase_split_ratios() {
    assert_eq!(Phase::Split.input_ratio(), 1);
    assert_eq!(Phase::Split.output_ratio(), 10);

    // For 5 participants: 5 inputs, 50 outputs
    assert_eq!(Phase::Split.inputs_for_participants(5), 5);
    assert_eq!(Phase::Split.outputs_for_participants(5), 50);
}

#[test]
fn test_726_phase_merge_ratios() {
    assert_eq!(Phase::Merge.input_ratio(), 10);
    assert_eq!(Phase::Merge.output_ratio(), 1);

    // For 5 participants: 50 inputs, 5 outputs
    assert_eq!(Phase::Merge.inputs_for_participants(5), 50);
    assert_eq!(Phase::Merge.outputs_for_participants(5), 5);
}

#[test]
fn test_727_phase_execution_full_lifecycle() {
    let mut exec = PhaseExecution::new(Phase::Split, 3);

    // Initial: Pending
    assert_eq!(exec.state(), PhaseState::Pending);

    // Start -> CollectingSignatures
    exec.start();
    assert_eq!(exec.state(), PhaseState::CollectingSignatures);

    // Add 2/3 signatures -> still CollectingSignatures
    exec.add_signature();
    exec.add_signature();
    assert_eq!(exec.state(), PhaseState::CollectingSignatures);
    assert!(!exec.has_all_signatures());

    // Add 3rd signature -> Ready
    exec.add_signature();
    assert_eq!(exec.state(), PhaseState::Ready);
    assert!(exec.has_all_signatures());

    // Broadcast -> Broadcasting
    exec.broadcast("abc123def456".to_string());
    assert_eq!(exec.state(), PhaseState::Broadcasting);
    assert_eq!(exec.txid(), Some("abc123def456"));

    // Confirm -> Confirmed
    exec.confirm(850_000);
    assert_eq!(exec.state(), PhaseState::Confirmed);
    assert_eq!(exec.confirmed_height(), Some(850_000));
}

#[test]
fn test_728_signature_progress_tracking() {
    let mut exec = PhaseExecution::new(Phase::Merge, 4);

    // 0/4 = 0%
    assert!((exec.signature_progress() - 0.0).abs() < f64::EPSILON);

    exec.start();

    // 1/4 = 25%
    exec.add_signature();
    assert!((exec.signature_progress() - 25.0).abs() < f64::EPSILON);

    // 2/4 = 50%
    exec.add_signature();
    assert!((exec.signature_progress() - 50.0).abs() < f64::EPSILON);

    // 3/4 = 75%
    exec.add_signature();
    assert!((exec.signature_progress() - 75.0).abs() < f64::EPSILON);

    // 4/4 = 100%
    exec.add_signature();
    assert!((exec.signature_progress() - 100.0).abs() < f64::EPSILON);

    // Edge case: 0 participants = 100% by convention
    let zero_exec = PhaseExecution::new(Phase::Split, 0);
    assert!((zero_exec.signature_progress() - 100.0).abs() < f64::EPSILON);
}

#[test]
fn test_729_update_depth_and_deep_confirmed() {
    let mut exec = PhaseExecution::new(Phase::Split, 1);

    // Before confirmation: no depth
    assert_eq!(exec.confirmation_depth(), 0);
    assert!(!exec.is_deep_confirmed(6));

    // Drive through lifecycle to Confirmed
    exec.start();
    exec.add_signature();
    exec.broadcast("txid729".to_string());
    exec.confirm(100);

    // Just confirmed: depth 0
    assert_eq!(exec.first_confirmed_height(), Some(100));
    assert_eq!(exec.confirmation_depth(), 0);
    assert!(!exec.is_deep_confirmed(6));
    assert!(exec.is_deep_confirmed(0)); // depth 0 >= 0

    // Advance to block 103 -> depth 3
    exec.update_depth(103);
    assert_eq!(exec.confirmation_depth(), 3);
    assert!(!exec.is_deep_confirmed(6));
    assert!(exec.is_deep_confirmed(3));

    // Advance to block 106 -> depth 6 (standard confirmation threshold)
    exec.update_depth(106);
    assert_eq!(exec.confirmation_depth(), 6);
    assert!(exec.is_deep_confirmed(6));

    // Advance further -> depth keeps increasing
    exec.update_depth(200);
    assert_eq!(exec.confirmation_depth(), 100);
    assert!(exec.is_deep_confirmed(6));

    // update_depth before confirm has no effect on a fresh execution
    let mut fresh = PhaseExecution::new(Phase::Merge, 1);
    fresh.update_depth(999);
    assert_eq!(fresh.confirmation_depth(), 0);
}
