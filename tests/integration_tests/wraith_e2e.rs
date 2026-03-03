//! Category 30: Wraith End-to-End Session Tests (15 tests, 890-904)
//!
//! Integration tests exercising the full WraithCoordinator lifecycle:
//! - Full Mix and Jump sessions (890-899)
//! - Jump Lock lifecycle, scheduling, and state machine (900-904)

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Network, ScriptBuf, Txid};
use ghost_locks::{
    Denomination, GhostLock, JumpRiskTier, LockState, StateTransition, TimelockTier,
};
use wraith_protocol::{
    BlindingContext, ParticipantTier, ReputationTracker, SessionConfig, SessionState, SessionType,
    UnblindedToken, WraithCoordinator, WraithDenomination, WraithInput, WraithSession,
};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Number of participants for Bootstrap mode (minimum required)
const N: usize = 10;

/// Fake txid string for broadcast functions
const FAKE_TXID: &str = "0000000000000000000000000000000000000000000000000000000000000001";

// =============================================================================
// HELPERS
// =============================================================================

/// Create a dummy txid for test inputs.
fn test_txid() -> Txid {
    Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap()
}

/// Generate a valid x-only public key as 32-byte Vec (for blind signature token messages).
///
/// `seed_byte` must produce a valid secp256k1 secret key.
fn xonly_pubkey_bytes(seed_byte: u8) -> Vec<u8> {
    let secp = Secp256k1::new();
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = if seed_byte == 0 { 1 } else { seed_byte };
    key_bytes[31] = seed_byte.wrapping_add(1);
    let sk = SecretKey::from_slice(&key_bytes).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let (xonly, _) = pk.x_only_public_key();
    xonly.serialize().to_vec()
}

/// Generate a P2WPKH address on Signet for final outputs.
///
/// P2WPKH is required because P2TR addresses are rejected for quantum safety.
fn signet_p2wpkh_address(seed_byte: u8) -> String {
    let secp = Secp256k1::new();
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = if seed_byte == 0 { 1 } else { seed_byte };
    key_bytes[31] = seed_byte.wrapping_add(1);
    let sk = SecretKey::from_slice(&key_bytes).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let mut compressed = [0u8; 33];
    compressed.copy_from_slice(&pk.serialize());
    let cpk = bitcoin::CompressedPublicKey::from_slice(&compressed).unwrap();
    bitcoin::Address::p2wpkh(&cpk, Network::Signet).to_string()
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

/// Drive the full blind signature flow for one participant through the coordinator.
///
/// Returns `outputs_per_participant()` unblinded tokens with valid x-only pubkey messages.
/// `seed_start` controls unique key material per participant to avoid collisions.
fn blind_sign_for_participant(
    coordinator: &mut WraithCoordinator,
    ghost_id: &str,
    seed_start: u8,
) -> Vec<UnblindedToken> {
    let coordinator_pubkey = *coordinator.coordinator_public_key();
    let key_id = *coordinator.coordinator_key_id();
    let opp = coordinator.outputs_per_participant();

    // Step 1: Request nonces
    let nonces = coordinator.request_nonces(ghost_id).unwrap();
    assert_eq!(nonces.len(), opp);

    // Step 2: Create blinding contexts and challenges
    let mut contexts = Vec::with_capacity(opp);
    let mut challenges = Vec::with_capacity(opp);
    for (i, nonce) in nonces.iter().enumerate() {
        let message = xonly_pubkey_bytes(seed_start.wrapping_add(i as u8));
        let ctx = BlindingContext::new(message, &coordinator_pubkey, nonce).unwrap();
        let challenge = ctx.create_blinded_challenge().unwrap();
        contexts.push(ctx);
        challenges.push(challenge);
    }

    // Step 3: Submit challenges and get responses
    let responses = coordinator
        .submit_blinded_challenges(ghost_id, challenges)
        .unwrap();
    assert_eq!(responses.len(), opp);

    // Step 4: Unblind each response
    contexts
        .iter()
        .zip(responses.iter())
        .map(|(ctx, resp)| ctx.unblind(resp, key_id).unwrap())
        .collect()
}

/// Run a complete Wraith coordinator session from creation to completion.
///
/// Returns the coordinator after `confirm_phase2` with state == Completed.
fn run_full_session(
    tier: ParticipantTier,
    denom: WraithDenomination,
    session_type: SessionType,
) -> WraithCoordinator {
    let mut coord = WraithCoordinator::new(tier, denom, Network::Signet, session_type)
        .unwrap()
        .without_utxo_required_for_registration()
        .with_broadcaster(|_| Ok(FAKE_TXID.to_string()));

    let opp = coord.outputs_per_participant();

    // Determine input amount based on session type
    // Include generous fee headroom for mining costs (split + merge phases)
    let input_amount = match session_type {
        SessionType::Mix => denom.min_input_sats() + 100_000,
        SessionType::Jump => denom.output_sats() + 100_000, // no service fee for Jump
    };

    // Register N participants
    let ghost_ids: Vec<String> = (0..N).map(|i| format!("ghost_{}", i)).collect();
    for gid in &ghost_ids {
        coord.register_participant(gid.clone()).unwrap();
    }
    assert_eq!(coord.participant_count(), N);

    // Transition to collecting inputs
    coord.start_collecting().unwrap();
    assert_eq!(coord.state(), SessionState::CollectingInputs);

    // Submit inputs
    for (i, gid) in ghost_ids.iter().enumerate() {
        coord
            .submit_input(gid, make_input(input_amount, i as u32))
            .unwrap();
    }

    // Blind signature flow + anonymous token submission for each participant
    for (i, gid) in ghost_ids.iter().enumerate() {
        // Each participant gets unique seed range for x-only pubkeys
        let seed_start = ((i + 1) * (opp + 1)) as u8;
        let tokens = blind_sign_for_participant(&mut coord, gid, seed_start);
        assert_eq!(tokens.len(), opp);

        // Submit tokens anonymously with a unique P2WPKH final address
        let final_addr = signet_p2wpkh_address(200u8.wrapping_add(i as u8));
        coord
            .submit_tokens_with_address_anonymous(tokens, final_addr)
            .unwrap();
    }

    assert!(coord.ready_for_phase1());
    assert_eq!(coord.anonymous_batch_count(), N);

    // Build Phase 1 (split)
    let split_tx = coord.build_phase1().unwrap();
    let expected_outputs = N * opp + 1; // OPP per participant + OP_RETURN
    assert_eq!(split_tx.transaction.output.len(), expected_outputs);
    assert_eq!(split_tx.participant_count, N);
    assert_eq!(split_tx.intermediate_count, N * opp);

    // Add Phase 1 signatures
    for (i, gid) in ghost_ids.iter().enumerate() {
        let all_signed = coord.add_phase1_signature(gid).unwrap();
        if i < N - 1 {
            assert!(!all_signed);
        } else {
            assert!(all_signed);
        }
    }

    // Broadcast Phase 1
    let txid_str = coord.broadcast_phase1(FAKE_TXID).unwrap();
    assert_eq!(txid_str, FAKE_TXID);

    // Confirm Phase 1
    coord.confirm_phase1(100).unwrap();
    assert!(coord.ready_for_phase2());

    // Build Phase 2 (merge)
    let merge_tx = coord.build_phase2().unwrap();
    let expected_merge_outputs = N + 1; // N final outputs + OP_RETURN
    assert_eq!(merge_tx.transaction.output.len(), expected_merge_outputs);
    assert_eq!(merge_tx.participant_count, N);

    // Add Phase 2 signatures
    for (i, gid) in ghost_ids.iter().enumerate() {
        let all_signed = coord.add_phase2_signature(gid).unwrap();
        if i < N - 1 {
            assert!(!all_signed);
        } else {
            assert!(all_signed);
        }
    }

    // Broadcast Phase 2
    coord.broadcast_phase2(FAKE_TXID).unwrap();

    // Confirm Phase 2
    coord.confirm_phase2(101).unwrap();

    coord
}

// Helper: deterministic secret keys for Ghost Lock creation
fn lock_secret() -> SecretKey {
    SecretKey::from_slice(&[1u8; 32]).unwrap()
}

fn recovery_secret() -> SecretKey {
    SecretKey::from_slice(&[2u8; 32]).unwrap()
}

fn alt_lock_secret() -> SecretKey {
    SecretKey::from_slice(&[3u8; 32]).unwrap()
}

fn alt_recovery_secret() -> SecretKey {
    SecretKey::from_slice(&[4u8; 32]).unwrap()
}

// =============================================================================
// TEST 890: Full Mix session — 10 participants, Small denomination, complete lifecycle
// =============================================================================

#[test]
fn test_890_full_mix_session_lifecycle() {
    let coord = run_full_session(
        ParticipantTier::Small,
        WraithDenomination::Small,
        SessionType::Mix,
    );

    // Session should be in Completed state
    assert_eq!(coord.state(), SessionState::Completed);

    // Phase 1 and Phase 2 transactions should exist
    assert!(coord.phase1_transaction().is_some());
    assert!(coord.phase2_transaction().is_some());
}

// =============================================================================
// TEST 891: Full Jump session — 10 participants, zero service fee
// =============================================================================

#[test]
fn test_891_full_jump_session_lifecycle() {
    let coord = run_full_session(
        ParticipantTier::Small,
        WraithDenomination::Small,
        SessionType::Jump,
    );

    assert_eq!(coord.state(), SessionState::Completed);
    assert!(coord.phase1_transaction().is_some());
    assert!(coord.phase2_transaction().is_some());
}

// =============================================================================
// TEST 892: Mix vs Jump fee difference
// =============================================================================

#[test]
fn test_892_mix_and_jump_same_l1_minimum() {
    // Service fee moved to L2 — both Mix and Jump require output_sats at L1
    let mix_min = WraithDenomination::Small.min_input_sats();
    let jump_min = WraithDenomination::Small.output_sats();

    assert_eq!(
        mix_min, jump_min,
        "Mix and Jump L1 minimums should be equal (fee is L2)"
    );

    // Service fee still exists for L2 accounting
    assert!(WraithDenomination::Small.service_fee() > 0);

    // Both builders accept output_sats as sufficient input
    use wraith_protocol::WraithTransactionBuilder;
    let opp = ParticipantTier::Small.outputs_per_participant();

    let mut mix_builder = WraithTransactionBuilder::new(
        "mix-892".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        opp,
        SessionType::Mix,
    );

    let mut jump_builder = WraithTransactionBuilder::new(
        "jump-892".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        opp,
        SessionType::Jump,
    );

    let amount = WraithDenomination::Small.output_sats();

    assert!(jump_builder.add_input(make_input(amount, 0)).is_ok());
    assert!(mix_builder.add_input(make_input(amount, 0)).is_ok());
}

// =============================================================================
// TEST 893: Anonymous token submission breaks identity linkage
// =============================================================================

#[test]
fn test_893_anonymous_token_submission_unlinkable() {
    let mut coord = WraithCoordinator::new(
        ParticipantTier::Small,
        WraithDenomination::Small,
        Network::Signet,
        SessionType::Mix,
    )
    .unwrap()
    .without_utxo_required_for_registration()
    .with_broadcaster(|_| Ok(FAKE_TXID.to_string()));

    let opp = coord.outputs_per_participant();
    let input_amount = WraithDenomination::Small.min_input_sats() + 7_000;

    // Register and set up N participants
    let ghost_ids: Vec<String> = (0..N).map(|i| format!("ghost_{}", i)).collect();
    for gid in &ghost_ids {
        coord.register_participant(gid.clone()).unwrap();
    }
    coord.start_collecting().unwrap();
    for (i, gid) in ghost_ids.iter().enumerate() {
        coord
            .submit_input(gid, make_input(input_amount, i as u32))
            .unwrap();
    }

    // Collect all tokens first (identified step)
    let all_tokens: Vec<Vec<UnblindedToken>> = ghost_ids
        .iter()
        .enumerate()
        .map(|(i, gid)| {
            let seed_start = ((i + 1) * (opp + 1)) as u8;
            blind_sign_for_participant(&mut coord, gid, seed_start)
        })
        .collect();

    // Submit anonymously in REVERSE order (participant N-1 first, 0 last)
    for (rev_i, tokens) in all_tokens.into_iter().rev().enumerate() {
        let final_addr = signet_p2wpkh_address(100u8.wrapping_add(rev_i as u8));
        coord
            .submit_tokens_with_address_anonymous(tokens, final_addr)
            .unwrap();
    }

    // Verify all batches received
    assert_eq!(coord.anonymous_batch_count(), N);
    assert_eq!(coord.anonymous_token_count(), N * opp);
    assert!(coord.ready_for_phase1());

    // Build Phase 1 succeeds — coordinator cannot know submission order
    let split_tx = coord.build_phase1().unwrap();
    assert_eq!(split_tx.participant_count, N);
}

// =============================================================================
// TEST 894: Phase 1 split transaction structure validation
// =============================================================================

#[test]
fn test_894_phase1_split_transaction_structure() {
    let mut coord = WraithCoordinator::new(
        ParticipantTier::Small,
        WraithDenomination::Small,
        Network::Signet,
        SessionType::Mix,
    )
    .unwrap()
    .without_utxo_required_for_registration()
    .with_broadcaster(|_| Ok(FAKE_TXID.to_string()));

    let opp = coord.outputs_per_participant();
    let denom = WraithDenomination::Small;
    let input_amount = denom.min_input_sats() + 7_000;

    // Set up full session through to Phase 1 build
    let ghost_ids: Vec<String> = (0..N).map(|i| format!("ghost_{}", i)).collect();
    for gid in &ghost_ids {
        coord.register_participant(gid.clone()).unwrap();
    }
    coord.start_collecting().unwrap();
    for (i, gid) in ghost_ids.iter().enumerate() {
        coord
            .submit_input(gid, make_input(input_amount, i as u32))
            .unwrap();
    }
    for (i, gid) in ghost_ids.iter().enumerate() {
        let seed_start = ((i + 1) * (opp + 1)) as u8;
        let tokens = blind_sign_for_participant(&mut coord, gid, seed_start);
        let final_addr = signet_p2wpkh_address(150u8.wrapping_add(i as u8));
        coord
            .submit_tokens_with_address_anonymous(tokens, final_addr)
            .unwrap();
    }

    let split_tx = coord.build_phase1().unwrap();

    // Validate structure
    assert_eq!(split_tx.participant_count, N);
    assert_eq!(split_tx.intermediate_count, N * opp);

    let outputs = &split_tx.transaction.output;
    let expected_output_count = N * opp + 1; // intermediates + OP_RETURN
    assert_eq!(outputs.len(), expected_output_count);

    // Last output should be OP_RETURN (zero value)
    let op_return = &outputs[outputs.len() - 1];
    assert_eq!(
        op_return.value.to_sat(),
        0,
        "OP_RETURN output must have zero value"
    );
    assert!(
        op_return.script_pubkey.is_op_return(),
        "Last output must be OP_RETURN"
    );

    // OP_RETURN data should be exactly 32 bytes (v3 encrypted marker)
    // Script format: OP_RETURN (0x6a) + PUSH32 (0x20) + 32 bytes = 34 byte script
    let op_return_bytes = op_return.script_pubkey.as_bytes();
    assert_eq!(
        op_return_bytes.len(),
        34,
        "OP_RETURN script should be 34 bytes (OP_RETURN + PUSH32 + 32 data)"
    );

    // All intermediate outputs should have identical amounts per OPP group
    let intermediate_sats = denom.intermediate_sats(opp);
    // Intermediates include Phase 2 fee padding, so they may be slightly above intermediate_sats
    for output in &outputs[..outputs.len() - 1] {
        let value = output.value.to_sat();
        assert!(
            value >= intermediate_sats,
            "Intermediate output {} should be >= {} (intermediate_sats for OPP {})",
            value,
            intermediate_sats,
            opp
        );
    }
}

// =============================================================================
// TEST 895: Phase 2 merge transaction structure validation
// =============================================================================

#[test]
fn test_895_phase2_merge_transaction_structure() {
    let coord = run_full_session(
        ParticipantTier::Small,
        WraithDenomination::Small,
        SessionType::Mix,
    );

    let merge_tx = coord.phase2_transaction().unwrap();

    // Validate structure
    assert_eq!(merge_tx.participant_count, N);

    let opp = ParticipantTier::Small.outputs_per_participant();

    // Inputs: N * OPP intermediates
    assert_eq!(merge_tx.transaction.input.len(), N * opp);

    // Outputs: N final outputs + 1 OP_RETURN
    assert_eq!(merge_tx.transaction.output.len(), N + 1);

    // Last output should be OP_RETURN
    let op_return = &merge_tx.transaction.output[merge_tx.transaction.output.len() - 1];
    assert_eq!(op_return.value.to_sat(), 0);
    assert!(op_return.script_pubkey.is_op_return());

    // Final outputs should each carry the denomination's output value (minus mining cost)
    let denom_output = WraithDenomination::Small.output_sats();
    for output in &merge_tx.transaction.output[..N] {
        let value = output.value.to_sat();
        // Mining cost is deducted, so final output <= denomination output
        assert!(
            value <= denom_output && value > 0,
            "Final output {} should be positive and <= {} (denom output)",
            value,
            denom_output
        );
    }
}

// =============================================================================
// TEST 896: All 6 tiers complete a full session
// =============================================================================

#[test]
fn test_896_all_tiers_complete_full_session() {
    for tier in ParticipantTier::all() {
        let opp = tier.outputs_per_participant();
        let coord = run_full_session(*tier, WraithDenomination::Small, SessionType::Mix);

        assert_eq!(
            coord.state(),
            SessionState::Completed,
            "Session should complete for tier {:?}",
            tier
        );
        assert_eq!(
            coord.outputs_per_participant(),
            opp,
            "OPP should match for tier {:?}",
            tier
        );

        // Verify Phase 1 intermediate count matches tier's OPP
        let split_tx = coord.phase1_transaction().unwrap();
        assert_eq!(
            split_tx.intermediate_count,
            N * opp,
            "Intermediate count should be N * OPP for tier {:?}",
            tier
        );
    }
}

// =============================================================================
// TEST 897: Reputation tracker records successful completion
// =============================================================================

#[test]
fn test_897_reputation_tracker_records_success() {
    let tracker = Arc::new(parking_lot::RwLock::new(ReputationTracker::new()));

    let mut coord = WraithCoordinator::new(
        ParticipantTier::Small,
        WraithDenomination::Small,
        Network::Signet,
        SessionType::Mix,
    )
    .unwrap()
    .without_utxo_required_for_registration()
    .with_broadcaster(|_| Ok(FAKE_TXID.to_string()))
    .with_reputation(tracker.clone());

    let opp = coord.outputs_per_participant();
    let input_amount = WraithDenomination::Small.min_input_sats() + 100_000;

    let ghost_ids: Vec<String> = (0..N).map(|i| format!("ghost_{}", i)).collect();
    for gid in &ghost_ids {
        coord.register_participant(gid.clone()).unwrap();
    }
    coord.start_collecting().unwrap();
    for (i, gid) in ghost_ids.iter().enumerate() {
        coord
            .submit_input(gid, make_input(input_amount, i as u32))
            .unwrap();
    }
    for (i, gid) in ghost_ids.iter().enumerate() {
        let seed_start = ((i + 1) * (opp + 1)) as u8;
        let tokens = blind_sign_for_participant(&mut coord, gid, seed_start);
        let final_addr = signet_p2wpkh_address(50u8.wrapping_add(i as u8));
        coord
            .submit_tokens_with_address_anonymous(tokens, final_addr)
            .unwrap();
    }
    coord.build_phase1().unwrap();
    for gid in &ghost_ids {
        coord.add_phase1_signature(gid).unwrap();
    }
    coord.broadcast_phase1(FAKE_TXID).unwrap();
    coord.confirm_phase1(100).unwrap();
    coord.build_phase2().unwrap();
    for gid in &ghost_ids {
        coord.add_phase2_signature(gid).unwrap();
    }
    coord.broadcast_phase2(FAKE_TXID).unwrap();

    // confirm_phase2 triggers record_success for all participants (WR-M3)
    coord.confirm_phase2(101).unwrap();
    assert_eq!(coord.state(), SessionState::Completed);

    // After successful completion, all participants should still be allowed
    let t = tracker.read();
    for gid in &ghost_ids {
        assert!(
            t.is_allowed(gid),
            "Participant {} should be allowed after successful session",
            gid
        );
        assert!(
            !t.is_banned(gid),
            "Participant {} should not be banned after success",
            gid
        );
    }

    // Verify no bans at all
    assert!(
        t.get_banned().is_empty(),
        "No participants should be banned after successful session"
    );
}

// =============================================================================
// TEST 898: Session timeout handling
// =============================================================================

#[test]
fn test_898_session_timeout_handling() {
    // Use WraithSession directly with a very short timeout (1 second)
    // NOTE: start_collecting() resets timeout to state-specific values,
    // so we test the WaitingForParticipants phase timeout instead.
    let config = SessionConfig::with_timeout(1);
    let mut session = WraithSession::with_config(
        ParticipantTier::Small,
        WraithDenomination::Small,
        config,
    );

    // Session starts in WaitingForParticipants with 1-second timeout
    assert_eq!(session.state(), SessionState::WaitingForParticipants);
    assert!(!session.is_timed_out(), "Should not be timed out immediately");

    // Wait for timeout to expire
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Session should now be timed out
    assert!(
        session.is_timed_out(),
        "Session should be timed out after 2 seconds with 1-second timeout"
    );

    // Transition to refunded (no participants joined in time)
    let result = session.refund();
    assert!(result.is_ok());
    assert_eq!(session.state(), SessionState::Refunded);
    assert!(session.state().is_terminal());

    // Cannot refund again (already terminal)
    assert!(session.refund().is_err());
}

// =============================================================================
// TEST 899: Duplicate token replay rejected
// =============================================================================

#[test]
fn test_899_duplicate_token_replay_rejected() {
    let mut coord = WraithCoordinator::new(
        ParticipantTier::Small,
        WraithDenomination::Small,
        Network::Signet,
        SessionType::Mix,
    )
    .unwrap()
    .without_utxo_required_for_registration()
    .with_broadcaster(|_| Ok(FAKE_TXID.to_string()));

    let opp = coord.outputs_per_participant();
    let input_amount = WraithDenomination::Small.min_input_sats() + 5_000;

    let ghost_ids: Vec<String> = (0..N).map(|i| format!("ghost_{}", i)).collect();
    for gid in &ghost_ids {
        coord.register_participant(gid.clone()).unwrap();
    }
    coord.start_collecting().unwrap();
    for (i, gid) in ghost_ids.iter().enumerate() {
        coord
            .submit_input(gid, make_input(input_amount, i as u32))
            .unwrap();
    }

    // Get tokens for the first participant
    let tokens = blind_sign_for_participant(&mut coord, &ghost_ids[0], 10);
    assert_eq!(tokens.len(), opp);

    // First submission succeeds
    let final_addr_1 = signet_p2wpkh_address(250);
    coord
        .submit_tokens_with_address_anonymous(tokens.clone(), final_addr_1)
        .unwrap();

    // Second submission with SAME tokens should fail (replay prevention)
    let final_addr_2 = signet_p2wpkh_address(251);
    let result = coord.submit_tokens_with_address_anonymous(tokens, final_addr_2);
    assert!(
        result.is_err(),
        "Duplicate token submission must be rejected"
    );
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("replay") || err_msg.contains("Replay") || err_msg.contains("already"),
        "Error should mention replay: {}",
        err_msg
    );
}

// =============================================================================
// TEST 900: Jump Lock full lifecycle — schedule → needs_jump → execute → new lock
// =============================================================================

#[test]
fn test_900_jump_lock_full_lifecycle() {
    let secp = Secp256k1::new();
    let creation_height = 800_000u32;

    // 1. Create a GhostLock with Large denomination
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        creation_height,
    )
    .unwrap();
    assert_eq!(lock.state(), LockState::Active);
    assert_eq!(lock.denomination(), Denomination::Large);

    // 2. Inspect jump schedule
    let schedule = lock.jump_schedule();
    assert_eq!(schedule.tier, JumpRiskTier::High); // Large = 1 BTC >= High threshold
    assert_eq!(schedule.jumps_completed, 0);
    assert_eq!(schedule.creation_height, creation_height);

    // Deadline should be within High tier range
    let min_deadline = creation_height + JumpRiskTier::High.min_rotation_blocks();
    let max_deadline = creation_height + JumpRiskTier::High.max_rotation_blocks();
    assert!(schedule.deadline_height >= min_deadline);
    assert!(schedule.deadline_height <= max_deadline);

    // 3. Not due for jump yet
    assert!(!lock.needs_jump(creation_height));
    assert!(!schedule.needs_jump(creation_height));

    // 4. At deadline, jump is due
    let deadline = schedule.deadline_height;
    assert!(schedule.needs_jump(deadline));
    assert!(lock.needs_jump(deadline));

    // 5. Urgency progresses from 0 to ~0.5 to 1.0
    let urgency_start = schedule.urgency(creation_height);
    assert!(urgency_start < 0.01, "Urgency at creation should be ~0.0");

    let midpoint = creation_height + (deadline - creation_height) / 2;
    let urgency_mid = schedule.urgency(midpoint);
    assert!(
        (urgency_mid - 0.5).abs() < 0.1,
        "Urgency at midpoint should be ~0.5, got {}",
        urgency_mid
    );

    let urgency_deadline = schedule.urgency(deadline);
    assert!(
        (urgency_deadline - 1.0).abs() < 0.01,
        "Urgency at deadline should be ~1.0"
    );

    // 6. Execute jump: Active → Jumping → Spent (old lock)
    let mut old_lock = lock;
    old_lock
        .transition(StateTransition::StartJump)
        .expect("Active → Jumping should succeed");
    assert_eq!(old_lock.state(), LockState::Jumping);

    old_lock
        .transition(StateTransition::CompleteJump)
        .expect("Jumping → Spent should succeed");
    assert_eq!(old_lock.state(), LockState::Spent);

    // 7. Create new lock at deadline height with fresh keys
    let new_lock = GhostLock::new(
        &secp,
        &alt_lock_secret(),
        &alt_recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        deadline,
    )
    .unwrap();
    assert_eq!(new_lock.state(), LockState::Active);
    assert_eq!(new_lock.creation_height(), deadline);

    // 8. Create schedule.after_jump() to track jumps_completed
    let new_schedule = old_lock.jump_schedule().after_jump(deadline);
    assert_eq!(new_schedule.jumps_completed, 1);
    assert_eq!(new_schedule.creation_height, deadline);

    // 9. New schedule has a fresh random deadline in the correct range
    let new_min = deadline + JumpRiskTier::High.min_rotation_blocks();
    let new_max = deadline + JumpRiskTier::High.max_rotation_blocks();
    assert!(new_schedule.deadline_height >= new_min);
    assert!(new_schedule.deadline_height <= new_max);

    // 10. New lock starts Active
    assert_eq!(new_lock.state(), LockState::Active);
}

// =============================================================================
// TEST 901: Jump Lock risk tiers match denomination thresholds
// =============================================================================

#[test]
fn test_901_jump_lock_risk_tiers_match_denominations() {
    // Low tier: < 0.1 BTC (10M sats)
    assert_eq!(
        JumpRiskTier::from_denomination(Denomination::Micro),
        JumpRiskTier::Low,
        "Micro (10K sats) should be Low"
    );
    assert_eq!(
        JumpRiskTier::from_denomination(Denomination::Tiny),
        JumpRiskTier::Low,
        "Tiny (100K sats) should be Low"
    );
    assert_eq!(
        JumpRiskTier::from_denomination(Denomination::Small),
        JumpRiskTier::Low,
        "Small (1M sats) should be Low"
    );

    // Medium tier: 0.1 BTC (10M sats)
    assert_eq!(
        JumpRiskTier::from_denomination(Denomination::Medium),
        JumpRiskTier::Medium,
        "Medium (10M sats) should be Medium"
    );

    // High tier: >= 1 BTC (100M sats)
    assert_eq!(
        JumpRiskTier::from_denomination(Denomination::Large),
        JumpRiskTier::High,
        "Large (100M sats) should be High"
    );
    assert_eq!(
        JumpRiskTier::from_denomination(Denomination::XL),
        JumpRiskTier::High,
        "XL (1B sats) should be High"
    );

    // Verify rotation day ranges
    assert_eq!(JumpRiskTier::Low.rotation_days_range(), (30, 60));
    assert_eq!(JumpRiskTier::Medium.rotation_days_range(), (14, 30));
    assert_eq!(JumpRiskTier::High.rotation_days_range(), (7, 14));
}

// =============================================================================
// TEST 902: Jump Lock state machine transitions
// =============================================================================

#[test]
fn test_902_jump_lock_state_machine_transitions() {
    let secp = Secp256k1::new();

    // Valid: Active → StartJump → Jumping
    let mut lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();
    assert!(lock.transition(StateTransition::StartJump).is_ok());
    assert_eq!(lock.state(), LockState::Jumping);

    // Valid: Jumping → CompleteJump → Spent
    assert!(lock.transition(StateTransition::CompleteJump).is_ok());
    assert_eq!(lock.state(), LockState::Spent);

    // Invalid: Jumping → StartJump (can't start jump while already jumping)
    let mut lock2 = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();
    lock2.transition(StateTransition::StartJump).unwrap(); // → Jumping
    assert!(
        lock2.transition(StateTransition::StartJump).is_err(),
        "StartJump from Jumping should fail"
    );

    // Invalid: Spent → StartJump (terminal state)
    assert!(
        lock.transition(StateTransition::StartJump).is_err(),
        "StartJump from Spent should fail"
    );

    // Invalid: InMix → StartJump (can't jump while mixing)
    let mut lock3 = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();
    lock3.transition(StateTransition::EnterMix).unwrap(); // → InMix
    assert_eq!(lock3.state(), LockState::InMix);
    assert!(
        lock3.transition(StateTransition::StartJump).is_err(),
        "StartJump from InMix should fail"
    );
}

// =============================================================================
// TEST 903: Jump Lock warning threshold
// =============================================================================

#[test]
fn test_903_jump_lock_warning_threshold() {
    let secp = Secp256k1::new();
    let creation = 800_000u32;

    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        creation,
    )
    .unwrap();

    let schedule = lock.jump_schedule();
    let deadline = schedule.deadline_height;
    let warning_blocks = schedule.tier.warning_threshold_blocks();

    // Far from deadline: should NOT warn
    assert!(
        !lock.should_warn_jump(creation),
        "Should not warn at creation"
    );
    assert!(
        !schedule.should_warn(creation),
        "Schedule should not warn at creation"
    );

    // Just before warning threshold: should NOT warn
    let before_warning = deadline - warning_blocks - 1;
    if before_warning > creation {
        assert!(
            !schedule.should_warn(before_warning),
            "Should not warn before threshold"
        );
    }

    // Within warning threshold (1 block into warning zone): SHOULD warn
    let in_warning = deadline - warning_blocks + 1;
    if in_warning > creation && in_warning < deadline {
        assert!(
            schedule.should_warn(in_warning),
            "Should warn within threshold at height {}",
            in_warning
        );
    }

    // AT deadline: needs_jump takes over, should_warn is false
    assert!(
        !schedule.should_warn(deadline),
        "should_warn should be false AT deadline (needs_jump takes over)"
    );

    // Past deadline: should_warn is false, needs_jump is true
    assert!(
        !schedule.should_warn(deadline + 100),
        "should_warn should be false past deadline"
    );
    assert!(schedule.needs_jump(deadline));
}

// =============================================================================
// TEST 904: Multiple consecutive jumps
// =============================================================================

#[test]
fn test_904_multiple_consecutive_jumps() {
    let secp = Secp256k1::new();
    let initial_height = 800_000u32;

    // Create initial lock + schedule
    let mut lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        initial_height,
    )
    .unwrap();

    let mut schedule = lock.jump_schedule().clone();
    let mut deadlines = Vec::new();
    let mut current_height;

    // Keys for successive locks (alternate between two pairs)
    let key_pairs = [
        (lock_secret(), recovery_secret()),
        (alt_lock_secret(), alt_recovery_secret()),
    ];

    for jump_num in 0..5u32 {
        assert_eq!(schedule.jumps_completed, jump_num);

        // Record this deadline
        let deadline = schedule.deadline_height;
        deadlines.push(deadline);

        // Deadline should be within tier range from current creation height
        let min = schedule.creation_height + JumpRiskTier::High.min_rotation_blocks();
        let max = schedule.creation_height + JumpRiskTier::High.max_rotation_blocks();
        assert!(
            deadline >= min && deadline <= max,
            "Jump {} deadline {} not in [{}, {}]",
            jump_num,
            deadline,
            min,
            max
        );

        // Advance to deadline
        current_height = deadline;

        // Execute jump on old lock
        lock.transition(StateTransition::StartJump).unwrap();
        assert_eq!(lock.state(), LockState::Jumping);
        lock.transition(StateTransition::CompleteJump).unwrap();
        assert_eq!(lock.state(), LockState::Spent);

        // Update schedule
        schedule = schedule.after_jump(current_height);

        // Create new lock at the deadline height
        let (ref lk, ref rk) = key_pairs[(jump_num as usize + 1) % 2];
        lock = GhostLock::new(
            &secp,
            lk,
            rk,
            Denomination::Large,
            TimelockTier::Standard,
            current_height,
        )
        .unwrap();
        assert_eq!(lock.state(), LockState::Active);
    }

    // After 5 jumps: jumps_completed should be 5
    assert_eq!(schedule.jumps_completed, 5);

    // All 5 deadlines should be different (CSPRNG randomization)
    let unique_deadlines: HashSet<u32> = deadlines.iter().copied().collect();
    assert_eq!(
        unique_deadlines.len(),
        5,
        "All 5 deadlines should be unique (CSPRNG randomization): {:?}",
        deadlines
    );

    // Each deadline should be strictly greater than the previous (ascending)
    for i in 1..deadlines.len() {
        assert!(
            deadlines[i] > deadlines[i - 1],
            "Deadlines must be strictly ascending: {} > {}",
            deadlines[i],
            deadlines[i - 1]
        );
    }
}

// =============================================================================
// TEST 905: Jump affordability by denomination at typical fees
// =============================================================================

#[test]
fn test_905_jump_affordability_by_denomination() {
    use ghost_locks::JumpAffordability;
    use wraith_protocol::WraithTransactionBuilder;

    let secp = Secp256k1::new();

    // Get a realistic mining cost estimate using WraithTransactionBuilder
    let opp = wraith_protocol::ParticipantTier::Small.outputs_per_participant();
    let builder = WraithTransactionBuilder::new(
        "affordability-905".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        opp,
        SessionType::Jump,
    );
    let jump_cost = builder.estimate_mining_cost_per_user(N);

    // Small (1M sats) should be Comfortable
    let lock_small = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();
    assert_eq!(
        lock_small.jump_affordability(jump_cost),
        JumpAffordability::Comfortable,
        "Small (1M sats) should be Comfortable with jump cost {}",
        jump_cost
    );

    // Medium (10M sats) should be Comfortable
    let lock_medium = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Medium,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();
    assert_eq!(
        lock_medium.jump_affordability(jump_cost),
        JumpAffordability::Comfortable,
        "Medium (10M sats) should be Comfortable"
    );

    // Large (100M sats) should be Comfortable
    let lock_large = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();
    assert_eq!(
        lock_large.jump_affordability(jump_cost),
        JumpAffordability::Comfortable,
        "Large (100M sats) should be Comfortable"
    );
}

// =============================================================================
// TEST 906: Recommended action integrates with wraith costs
// =============================================================================

#[test]
fn test_906_recommended_action_with_wraith_costs() {
    use ghost_locks::{CostEstimates, RecommendedAction};
    use wraith_protocol::WraithTransactionBuilder;

    let secp = Secp256k1::new();

    // Get real mining cost estimate
    let opp = wraith_protocol::ParticipantTier::Small.outputs_per_participant();
    let builder = WraithTransactionBuilder::new(
        "action-906".to_string(),
        WraithDenomination::Small,
        Network::Signet,
        opp,
        SessionType::Jump,
    );
    let jump_cost = builder.estimate_mining_cost_per_user(N);

    let costs = CostEstimates {
        jump_cost_sats: jump_cost,
        reconcile_cost_sats: jump_cost / 2, // Reconciliation is typically cheaper
    };

    // Large lock should get ContinueNormal
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();

    assert_eq!(
        lock.recommended_action(&costs),
        RecommendedAction::ContinueNormal,
        "Large lock should get ContinueNormal with realistic costs"
    );
}

// =============================================================================
// TEST 907: Micro denomination is at risk
// =============================================================================

#[test]
fn test_907_micro_denomination_at_risk() {
    use ghost_locks::JumpAffordability;

    let secp = Secp256k1::new();

    // Micro = 10K sats = MIN_SETTLEMENT_SATS
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Micro,
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();

    assert_eq!(lock.sats(), 10_000);

    // With ANY nonzero jump cost, Micro should be Critical
    assert_eq!(
        lock.jump_affordability(1),
        JumpAffordability::Critical,
        "Micro (10K sats) should be Critical with any nonzero jump cost"
    );
    assert_eq!(
        lock.jump_affordability(1_000),
        JumpAffordability::Critical,
        "Micro should be Critical with 1K jump cost"
    );
    assert!(!lock.can_afford_jump(1), "Micro should not afford any jump");
    assert_eq!(lock.remaining_jumps_estimate(1_000), 0);
}

// =============================================================================
// TEST 908: Remaining jumps estimate consistency
// =============================================================================

#[test]
fn test_908_remaining_jumps_estimate_consistency() {
    use ghost_locks::remaining_jumps_estimate;

    // Manual calculation: 1M sats lock, 10K jump cost, 10K min settlement
    // available = 1_000_000 - 10_000 = 990_000
    // jumps = 990_000 / 10_000 = 99
    assert_eq!(remaining_jumps_estimate(1_000_000, 10_000), 99);

    // 100K sats, 10K cost → (100K - 10K) / 10K = 9
    assert_eq!(remaining_jumps_estimate(100_000, 10_000), 9);

    // 10K sats (exactly min), 10K cost → 0
    assert_eq!(remaining_jumps_estimate(10_000, 10_000), 0);

    // Verify via GhostLock method
    let secp = Secp256k1::new();
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small, // 1M sats
        TimelockTier::Standard,
        800_000,
    )
    .unwrap();

    assert_eq!(lock.remaining_jumps_estimate(10_000), 99);
    assert_eq!(
        lock.remaining_jumps_estimate(10_000),
        remaining_jumps_estimate(lock.sats(), 10_000),
        "GhostLock method should match free function"
    );
}
