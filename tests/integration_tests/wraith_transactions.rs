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
    check_legacy_marker, generate_encrypted_marker, verify_encrypted_marker, Phase,
    PhaseExecution, PhaseState, WraithDenomination, WraithInput, WraithTransactionBuilder,
    FEE_PERCENTAGE, SPLIT_RATIO, WRAITH_PHASE1_MARKER, WRAITH_PHASE2_MARKER,
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

/// Generate `SPLIT_RATIO` (10) unique Signet P2TR addresses for one participant.
fn address_set_for_participant(participant_idx: u8) -> Vec<String> {
    (0..SPLIT_RATIO)
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
    assert_eq!(WraithDenomination::Micro.output_sats(), 10_000);
    assert_eq!(WraithDenomination::Small.output_sats(), 1_000_000);
    assert_eq!(WraithDenomination::Medium.output_sats(), 10_000_000);
    assert_eq!(WraithDenomination::Large.output_sats(), 100_000_000);
}

#[test]
fn test_701_fee_sats_one_percent_of_output() {
    for denom in WraithDenomination::all() {
        let expected_fee = (denom.output_sats() as f64 * FEE_PERCENTAGE) as u64;
        assert_eq!(
            denom.fee_sats(),
            expected_fee,
            "Fee mismatch for {:?}: expected {}, got {}",
            denom,
            expected_fee,
            denom.fee_sats()
        );
    }
}

#[test]
fn test_702_input_sats_equals_output_plus_fee() {
    for denom in WraithDenomination::all() {
        assert_eq!(
            denom.input_sats(),
            denom.output_sats() + denom.fee_sats(),
            "input_sats mismatch for {:?}",
            denom
        );
    }
}

#[test]
fn test_703_intermediate_sats_equals_output_div_split_ratio() {
    for denom in WraithDenomination::all() {
        assert_eq!(
            denom.intermediate_sats(),
            denom.output_sats() / SPLIT_RATIO as u64,
            "intermediate_sats mismatch for {:?}",
            denom
        );
    }
}

#[test]
fn test_704_intermediate_sats_randomized_within_five_percent() {
    // Sample 100 times for each denomination and verify range
    for denom in WraithDenomination::all() {
        let base = denom.intermediate_sats();
        let variance = base / 20; // 5%
        let min_expected = base.saturating_sub(variance);
        let max_expected = base + variance;

        for _ in 0..100 {
            let randomized = denom.intermediate_sats_randomized();
            assert!(
                randomized >= min_expected && randomized <= max_expected,
                "{:?}: randomized {} not in range [{}, {}] (base={})",
                denom,
                randomized,
                min_expected,
                max_expected,
                base
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
    // Below Micro input_sats (10_100) -> None
    assert_eq!(WraithDenomination::largest_fitting(10_099), None);

    // Exactly at Micro boundary -> Micro
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Micro.input_sats()),
        Some(WraithDenomination::Micro)
    );

    // Between Micro and Small -> Micro
    assert_eq!(
        WraithDenomination::largest_fitting(500_000),
        Some(WraithDenomination::Micro)
    );

    // Exactly at Small boundary -> Small
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Small.input_sats()),
        Some(WraithDenomination::Small)
    );

    // Exactly at Medium boundary -> Medium
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Medium.input_sats()),
        Some(WraithDenomination::Medium)
    );

    // Exactly at Large boundary -> Large
    assert_eq!(
        WraithDenomination::largest_fitting(WraithDenomination::Large.input_sats()),
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
    );

    let result = builder.add_input(make_input(
        WraithDenomination::Small.input_sats(),
        0,
    ));
    assert!(result.is_ok());
    assert_eq!(builder.participant_count(), 1);

    // Amount above minimum also accepted
    let result = builder.add_input(make_input(
        WraithDenomination::Small.input_sats() + 50_000,
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
    );

    // One sat below the required input amount
    let result = builder.add_input(make_input(
        WraithDenomination::Small.input_sats() - 1,
        0,
    ));
    assert!(result.is_err());
    assert_eq!(builder.participant_count(), 0);
}

#[test]
fn test_713_split_tx_output_count() {
    // Split: N participants -> 10*N intermediate outputs + 1 OP_RETURN marker
    let n = 3;
    let mut builder = WraithTransactionBuilder::new(
        "session-713".to_string(),
        WraithDenomination::Small,
        Network::Signet,
    );

    for p in 0..n {
        // Provide enough to cover intermediates + fee headroom
        builder
            .add_input(make_input(
                WraithDenomination::Small.input_sats() + 100_000,
                p as u32,
            ))
            .unwrap();
    }

    let addresses: Vec<Vec<String>> = (0..n)
        .map(|p| address_set_for_participant(p as u8))
        .collect();

    let split_tx = builder.build_split_transaction(&addresses).unwrap();
    let expected_outputs = n * SPLIT_RATIO + 1; // +1 for OP_RETURN
    assert_eq!(
        split_tx.transaction.output.len(),
        expected_outputs,
        "Split tx should have 10*N + 1 outputs, got {}",
        split_tx.transaction.output.len()
    );
}

#[test]
fn test_714_split_tx_participant_count_matches() {
    let n = 2;
    let mut builder = WraithTransactionBuilder::new(
        "session-714".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
    );

    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    let addresses: Vec<Vec<String>> = (0..n)
        .map(|p| address_set_for_participant(p as u8 + 100))
        .collect();

    let split_tx = builder.build_split_transaction(&addresses).unwrap();
    assert_eq!(split_tx.participant_count, n);
}

#[test]
fn test_715_split_tx_intermediate_count() {
    let n = 4;
    let mut builder = WraithTransactionBuilder::new(
        "session-715".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
    );

    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    let addresses: Vec<Vec<String>> = (0..n)
        .map(|p| address_set_for_participant(p as u8 + 50))
        .collect();

    let split_tx = builder.build_split_transaction(&addresses).unwrap();
    assert_eq!(split_tx.intermediate_count, n * SPLIT_RATIO);
}

#[test]
fn test_716_build_split_no_inputs_error() {
    let builder = WraithTransactionBuilder::new(
        "session-716".to_string(),
        WraithDenomination::Small,
        Network::Signet,
    );

    let result = builder.build_split_transaction(&[]);
    assert!(result.is_err(), "Build split with no inputs should fail");
}

#[test]
fn test_717_split_wrong_address_set_count_error() {
    let mut builder = WraithTransactionBuilder::new(
        "session-717".to_string(),
        WraithDenomination::Small,
        Network::Signet,
    );

    // Add 2 participants
    for p in 0..2 {
        builder
            .add_input(make_input(
                WraithDenomination::Small.input_sats() + 100_000,
                p,
            ))
            .unwrap();
    }

    // Provide only 1 address set (need 2)
    let addresses = vec![address_set_for_participant(1)];
    let result = builder.build_split_transaction(&addresses);
    assert!(
        result.is_err(),
        "Mismatched address set count should fail"
    );

    // Provide 3 address sets (need 2)
    let addresses = vec![
        address_set_for_participant(1),
        address_set_for_participant(2),
        address_set_for_participant(3),
    ];
    let result = builder.build_split_transaction(&addresses);
    assert!(
        result.is_err(),
        "Too many address sets should also fail"
    );
}

#[test]
fn test_718_merge_tx_output_count() {
    // Merge: N participants -> N final outputs + 1 OP_RETURN
    let n = 3usize;
    let mut builder = WraithTransactionBuilder::new(
        "session-718".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
    );

    // We still need at least one input registered in the builder for session context,
    // but merge uses intermediate_inputs directly. Add a dummy input per participant.
    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    let intermediate_amount = WraithDenomination::Micro.intermediate_sats();

    // Build intermediate inputs: each participant has SPLIT_RATIO inputs
    let intermediate_inputs: Vec<Vec<WraithInput>> = (0..n)
        .map(|p| {
            (0..SPLIT_RATIO)
                .map(|i| WraithInput {
                    txid: test_txid(),
                    vout: (p * SPLIT_RATIO + i) as u32,
                    amount: intermediate_amount,
                    script_pubkey: ScriptBuf::new(),
                    participant_id: p as u32,
                })
                .collect()
        })
        .collect();

    let final_addresses: Vec<String> = (0..n)
        .map(|p| signet_p2tr_address((p + 1) as u8))
        .collect();

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
    let n = 2usize;
    let mut builder = WraithTransactionBuilder::new(
        "session-719".to_string(),
        WraithDenomination::Micro,
        Network::Signet,
    );

    for p in 0..n {
        builder
            .add_input(make_input(
                WraithDenomination::Micro.input_sats() + 10_000,
                p as u32,
            ))
            .unwrap();
    }

    let intermediate_amount = WraithDenomination::Micro.intermediate_sats();

    let intermediate_inputs: Vec<Vec<WraithInput>> = (0..n)
        .map(|p| {
            (0..SPLIT_RATIO)
                .map(|i| WraithInput {
                    txid: test_txid(),
                    vout: (p * SPLIT_RATIO + i) as u32,
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

    // All 10*N intermediate inputs should appear as transaction inputs
    let expected_input_count = n * SPLIT_RATIO;
    assert_eq!(
        merge_tx.transaction.input.len(),
        expected_input_count,
        "Merge tx should consume all 10*N intermediate inputs"
    );
}

// =============================================================================
// ENCRYPTED MARKER TESTS (720-724)
// =============================================================================

#[test]
fn test_720_generate_encrypted_marker_returns_32_bytes() {
    let session_id = [0xABu8; 32];
    let marker = generate_encrypted_marker(1, &session_id);
    assert_eq!(marker.len(), 32);
}

#[test]
fn test_721_verify_encrypted_marker_roundtrip() {
    let session_id = [0x42u8; 32];

    let marker_phase1 = generate_encrypted_marker(1, &session_id);
    assert_eq!(
        verify_encrypted_marker(&marker_phase1, &session_id),
        Some(1),
        "Phase 1 marker should verify as phase 1"
    );

    let marker_phase2 = generate_encrypted_marker(2, &session_id);
    assert_eq!(
        verify_encrypted_marker(&marker_phase2, &session_id),
        Some(2),
        "Phase 2 marker should verify as phase 2"
    );
}

#[test]
fn test_722_different_session_ids_produce_different_markers() {
    let session_a = [0x01u8; 32];
    let session_b = [0x02u8; 32];

    let marker_a = generate_encrypted_marker(1, &session_a);
    let marker_b = generate_encrypted_marker(1, &session_b);

    assert_ne!(
        marker_a, marker_b,
        "Different session IDs must produce different markers"
    );

    // Cross-verify: marker from session A should not verify with session B
    assert_eq!(verify_encrypted_marker(&marker_a, &session_b), None);
    assert_eq!(verify_encrypted_marker(&marker_b, &session_a), None);
}

#[test]
fn test_723_phase1_vs_phase2_different_markers_same_session() {
    let session_id = [0xFFu8; 32];

    let marker_p1 = generate_encrypted_marker(1, &session_id);
    let marker_p2 = generate_encrypted_marker(2, &session_id);

    assert_ne!(
        marker_p1, marker_p2,
        "Phase 1 and Phase 2 markers must differ for the same session"
    );

    // Each verifies to its own phase
    assert_eq!(verify_encrypted_marker(&marker_p1, &session_id), Some(1));
    assert_eq!(verify_encrypted_marker(&marker_p2, &session_id), Some(2));
}

#[test]
fn test_724_check_legacy_marker() {
    assert_eq!(check_legacy_marker(WRAITH_PHASE1_MARKER), Some(1));
    assert_eq!(check_legacy_marker(WRAITH_PHASE2_MARKER), Some(2));
    assert_eq!(check_legacy_marker(b"WR1"), Some(1));
    assert_eq!(check_legacy_marker(b"WR2"), Some(2));
    assert_eq!(check_legacy_marker(b"WR3"), None);
    assert_eq!(check_legacy_marker(b""), None);
    assert_eq!(check_legacy_marker(b"WRAITH"), None);
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
