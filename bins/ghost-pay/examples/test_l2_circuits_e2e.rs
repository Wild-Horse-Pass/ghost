//! End-to-end tests: Consolidation, Unshield, and Cross-Circuit Double-Spend
//!
//! Tests the full L2 circuit pipeline against running ghost-pay + ghost-pool services.
//! Covers all 3 ZK circuits (NoteSpend, Consolidation, Unshield) and cross-circuit
//! nullifier protection.
//!
//! Usage:
//!   # Fast mode (random trusted setup, depth 4, no MPC params):
//!   cargo run -p ghost-pay --example test_l2_circuits_e2e -- \
//!     --ghost-pay-url http://127.0.0.1:8800 \
//!     --api-secret <secret> --fast
//!
//!   # With MPC params (production depth 20):
//!   cargo run -p ghost-pay --example test_l2_circuits_e2e -- \
//!     --ghost-pay-url http://127.0.0.1:8800 \
//!     --api-secret <secret> \
//!     --params-dir /path/to/mpc_params

use std::io::BufReader;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bellperson::groth16::Parameters;
use blstrs::Bls12;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use ghost_zkp::{
    ConsolidationInputNote, ConsolidationWitness, GhostConsolidateProver,
    GhostConsolidateVerifier, GhostNoteProver, GhostNoteSpendWitness, GhostNoteVerifier,
    GhostUnshieldProver, GhostUnshieldVerifier, UnshieldWitness,
};

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let api_url =
        get_arg(&args, "--ghost-pay-url").unwrap_or_else(|| "http://127.0.0.1:8800".to_string());
    let api_secret = get_arg(&args, "--api-secret").expect("--api-secret required");
    let params_dir = get_arg(&args, "--params-dir");
    let fast = args.iter().any(|a| a == "--fast");
    let tree_depth: usize = if fast { 4 } else { 20 };

    let use_mpc = params_dir.is_some();

    println!("=== Ghost Pay L2 Circuits E2E Test ===");
    println!("API: {}", api_url);
    if use_mpc {
        println!("Mode: MPC params (depth {})", tree_depth);
        println!("Params dir: {}", params_dir.as_deref().unwrap());
    } else {
        println!(
            "Mode: {}",
            if fast {
                "fast (depth 4)"
            } else {
                "production (depth 20)"
            }
        );
    }
    println!();

    // ========================================================================
    // Load or generate Groth16 params for all 3 circuits
    // ========================================================================

    println!("[setup] Loading/generating params for 3 circuits...");
    let setup_start = Instant::now();

    let (consolidate_prover, consolidate_verifier) = load_consolidation_params(
        params_dir.as_deref(),
        tree_depth,
    );
    let (unshield_prover, unshield_verifier) = load_unshield_params(
        params_dir.as_deref(),
        tree_depth,
    );
    let (note_prover, note_verifier) = load_note_spend_params(
        params_dir.as_deref(),
        tree_depth,
    );

    println!(
        "[setup] All 3 circuits ready in {:?}",
        setup_start.elapsed()
    );
    println!();

    // ========================================================================
    // Test 1: Consolidation E2E (4 notes → 1)
    // ========================================================================

    println!("╔══════════════════════════════════════════════╗");
    println!("║  Test 1: Consolidation E2E (4 notes → 1)    ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // [1/7] Shield 4 notes
    println!("[1/7] Shielding 4 notes (1000, 2000, 3000, 4000 sats)...");
    let spending_key_1 = deterministic_blinding(15);
    let owner_1 = [0x10u8; 32];
    let amounts_1: [u64; 4] = [1000, 2000, 3000, 4000];
    let blindings_1: [[u8; 32]; 4] = [
        deterministic_blinding(10),
        deterministic_blinding(11),
        deterministic_blinding(12),
        deterministic_blinding(13),
    ];

    let mut indices_1 = Vec::new();
    for (i, (&amount, blinding)) in amounts_1.iter().zip(&blindings_1).enumerate() {
        let resp = shield_balance(&api_url, &api_secret, amount, blinding, &owner_1);
        let idx = resp["note_index"]
            .as_u64()
            .expect("shield response should have note_index");
        println!("  Note {} ({} sats) at index {}", i, amount, idx);
        indices_1.push(idx);
    }

    // [2/7] Fetch Merkle proofs for all 4
    println!("[2/7] Fetching Merkle proofs for all 4 notes...");
    let mut siblings_1 = Vec::new();
    let mut proof_root_1 = String::new();
    for (i, &idx) in indices_1.iter().enumerate() {
        let (sibs, root) = get_merkle_proof(&api_url, idx);
        if i == 0 {
            proof_root_1 = root.clone();
        } else {
            assert_eq!(
                root, proof_root_1,
                "Root mismatch between note {} and note 0 — concurrent tree update?",
                i
            );
        }
        println!("  Note {} (idx {}): {} siblings", i, idx, sibs.len());
        siblings_1.push(sibs);
    }
    println!("  Tree root: {}...", &proof_root_1[..16]);

    // [3/7] Build ConsolidationWitness and generate proof
    println!("[3/7] Generating Consolidation Groth16 proof...");
    let output_blinding_1 = deterministic_blinding(14);
    let inputs_1: Vec<ConsolidationInputNote> = (0..4)
        .map(|i| ConsolidationInputNote {
            value: amounts_1[i],
            blinding: blindings_1[i],
            index: indices_1[i],
            epoch: 0,
            merkle_siblings: siblings_1[i].clone(),
        })
        .collect();

    let witness_1 = ConsolidationWitness {
        spending_key: spending_key_1,
        inputs: inputs_1,
        output_blinding: output_blinding_1,
    };

    let start = Instant::now();
    let proof_1 = consolidate_prover
        .prove(&witness_1)
        .expect("Consolidation proof generation failed");
    let prove_time_1 = start.elapsed();
    println!(
        "  Proof generated in {:?} (size: {} bytes, real: {})",
        prove_time_1,
        proof_1.proof.len(),
        proof_1.is_real_proof()
    );

    // [4/7] Local verification
    println!("[4/7] Local verification...");
    let local_valid_1 = consolidate_verifier
        .verify(&proof_1)
        .expect("Local consolidation verification error");
    println!(
        "  Local verification: {}",
        if local_valid_1 { "PASS" } else { "FAIL" }
    );
    assert!(local_valid_1, "Local consolidation proof verification failed!");

    // [5/7] Capture tree state baseline, then submit
    let (_, note_count_before_1, null_count_before_1) = get_tree_state(&api_url);
    println!(
        "[5/7] Submitting consolidation (tree: {} notes, {} nullifiers)...",
        note_count_before_1, null_count_before_1
    );

    let nullifiers_hex_1: Vec<String> = proof_1
        .public_inputs
        .nullifiers
        .iter()
        .map(hex::encode)
        .collect();

    let body_1 = serde_json::json!({
        "proof_hex": hex::encode(&proof_1.proof),
        "commitment_root": hex::encode(proof_1.public_inputs.commitment_root),
        "nullifiers": nullifiers_hex_1,
        "output_commitment": hex::encode(proof_1.public_inputs.output_commitment),
        "encrypted_output": null,
        "epoch": 0,
    });

    let result_1 = http_post_authed(
        &format!("{}/api/v1/confidential/consolidate", api_url),
        &api_secret,
        &body_1,
    );
    let consolidation_id = result_1
        .get("consolidation_id")
        .and_then(|v| v.as_str())
        .expect("Server should return consolidation_id");
    let output_index_1 = result_1
        .get("output_index")
        .and_then(|v| v.as_u64())
        .expect("Server should return output_index");
    println!("  Consolidation ID: {}", consolidation_id);
    println!("  Output note at index {}", output_index_1);

    // [6/7] Double-spend check
    println!("[6/7] Verifying double-spend rejection...");
    let (status_ds_1, _) = http_post_authed_raw(
        &format!("{}/api/v1/confidential/consolidate", api_url),
        &api_secret,
        &body_1,
    );
    if status_ds_1 == 409 {
        println!("  Double-spend correctly rejected (409 Conflict)");
    } else {
        panic!(
            "Expected 409 for consolidation double-spend, got {}",
            status_ds_1
        );
    }

    // [7/7] Tree state check
    println!("[7/7] Verifying tree state...");
    let (_, note_count_after_1, null_count_after_1) = get_tree_state(&api_url);
    let note_delta_1 = note_count_after_1 - note_count_before_1;
    let null_delta_1 = null_count_after_1 - null_count_before_1;
    println!(
        "  note_count: {} → {} (delta: {}, expected: 1)",
        note_count_before_1, note_count_after_1, note_delta_1
    );
    println!(
        "  nullifier_count: {} → {} (delta: {}, expected: 4)",
        null_count_before_1, null_count_after_1, null_delta_1
    );
    assert_eq!(note_delta_1, 1, "Consolidation should add exactly 1 output note");
    assert_eq!(null_delta_1, 4, "Consolidation should spend exactly 4 nullifiers");

    println!();
    println!("  ✓ Test 1: Consolidation E2E PASSED (prove: {:?})", prove_time_1);
    println!();

    // ========================================================================
    // Test 2: Unshield E2E (full withdrawal)
    // ========================================================================

    println!("╔══════════════════════════════════════════════╗");
    println!("║  Test 2: Unshield E2E (full withdrawal)      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // [1/6] Shield 1 note
    println!("[1/6] Shielding 1 note (5000 sats)...");
    let spending_key_2 = deterministic_blinding(21);
    let blinding_2 = deterministic_blinding(20);
    let owner_2 = [0x20u8; 32];
    let amount_2: u64 = 5000;

    let resp_2 = shield_balance(&api_url, &api_secret, amount_2, &blinding_2, &owner_2);
    let index_2 = resp_2["note_index"]
        .as_u64()
        .expect("shield response should have note_index");
    println!("  Note at index {} (5000 sats)", index_2);

    // [2/6] Fetch Merkle proof
    println!("[2/6] Fetching Merkle proof...");
    let (siblings_2, root_2) = get_merkle_proof(&api_url, index_2);
    println!(
        "  {} siblings, root: {}...",
        siblings_2.len(),
        &root_2[..16]
    );

    // [3/6] Generate Unshield proof
    println!("[3/6] Generating Unshield Groth16 proof...");
    let witness_2 = UnshieldWitness {
        spending_key: spending_key_2,
        note_value: amount_2,
        note_blinding: blinding_2,
        note_index: index_2,
        epoch: 0,
        merkle_siblings: siblings_2,
    };

    let start = Instant::now();
    let proof_2 = unshield_prover
        .prove(&witness_2)
        .expect("Unshield proof generation failed");
    let prove_time_2 = start.elapsed();
    println!(
        "  Proof generated in {:?} (size: {} bytes, real: {})",
        prove_time_2,
        proof_2.proof.len(),
        proof_2.is_real_proof()
    );

    let local_valid_2 = unshield_verifier
        .verify(&proof_2)
        .expect("Local unshield verification error");
    println!(
        "  Local verification: {}",
        if local_valid_2 { "PASS" } else { "FAIL" }
    );
    assert!(local_valid_2, "Local unshield proof verification failed!");

    // [4/6] Capture tree state, then submit
    let (_, note_count_before_2, null_count_before_2) = get_tree_state(&api_url);
    println!(
        "[4/6] Submitting unshield (tree: {} notes, {} nullifiers)...",
        note_count_before_2, null_count_before_2
    );

    let body_2 = serde_json::json!({
        "proof_hex": hex::encode(&proof_2.proof),
        "commitment_root": hex::encode(proof_2.public_inputs.commitment_root),
        "nullifier": hex::encode(proof_2.public_inputs.nullifier),
        "withdrawal_amount_sats": proof_2.public_inputs.withdrawal_amount,
        "destination_address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    });

    let result_2 = http_post_authed(
        &format!("{}/api/v1/confidential/unshield", api_url),
        &api_secret,
        &body_2,
    );
    let unshield_id = result_2
        .get("unshield_id")
        .and_then(|v| v.as_str())
        .expect("Server should return unshield_id");
    println!("  Unshield ID: {}", unshield_id);
    println!(
        "  Withdrawal: {} sats",
        result_2
            .get("withdrawal_amount_sats")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    );

    // [5/6] Double-spend check
    println!("[5/6] Verifying double-spend rejection...");
    let (status_ds_2, _) = http_post_authed_raw(
        &format!("{}/api/v1/confidential/unshield", api_url),
        &api_secret,
        &body_2,
    );
    if status_ds_2 == 409 {
        println!("  Double-spend correctly rejected (409 Conflict)");
    } else {
        panic!(
            "Expected 409 for unshield double-spend, got {}",
            status_ds_2
        );
    }

    // [6/6] Tree state check
    println!("[6/6] Verifying tree state...");
    let (_, note_count_after_2, null_count_after_2) = get_tree_state(&api_url);
    let note_delta_2 = note_count_after_2 - note_count_before_2;
    let null_delta_2 = null_count_after_2 - null_count_before_2;
    println!(
        "  note_count: {} → {} (delta: {}, expected: 0)",
        note_count_before_2, note_count_after_2, note_delta_2
    );
    println!(
        "  nullifier_count: {} → {} (delta: {}, expected: 1)",
        null_count_before_2, null_count_after_2, null_delta_2
    );
    assert_eq!(note_delta_2, 0, "Unshield should NOT add any notes");
    assert_eq!(null_delta_2, 1, "Unshield should spend exactly 1 nullifier");

    println!();
    println!("  ✓ Test 2: Unshield E2E PASSED (prove: {:?})", prove_time_2);
    println!();

    // ========================================================================
    // Test 3: Cross-Circuit Double-Spend
    // ========================================================================

    println!("╔══════════════════════════════════════════════╗");
    println!("║  Test 3: Cross-Circuit Double-Spend          ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // [1/5] Shield 1 note
    println!("[1/5] Shielding 1 note (6000 sats)...");
    let spending_key_3 = deterministic_blinding(31);
    let blinding_3 = deterministic_blinding(30);
    let owner_3 = [0x30u8; 32];
    let amount_3: u64 = 6000;

    let resp_3 = shield_balance(&api_url, &api_secret, amount_3, &blinding_3, &owner_3);
    let index_3 = resp_3["note_index"]
        .as_u64()
        .expect("shield response should have note_index");
    println!("  Note at index {} (6000 sats)", index_3);

    // [2/5] Fetch Merkle proof and generate NoteSpend
    println!("[2/5] Fetching Merkle proof and generating NoteSpend proof...");
    let (siblings_3, _root_3) = get_merkle_proof(&api_url, index_3);

    let transfer_amount_3: u64 = 2000;
    let change_blinding_3 = deterministic_blinding(32);
    let recipient_blinding_3 = deterministic_blinding(33);

    let witness_3 = GhostNoteSpendWitness {
        spending_key: spending_key_3,
        note_value: amount_3,
        note_blinding: blinding_3,
        note_index: index_3,
        epoch: 0,
        merkle_siblings: siblings_3,
        amount: transfer_amount_3,
        change_blinding: change_blinding_3,
        recipient_blinding: recipient_blinding_3,
    };

    let start = Instant::now();
    let proof_3 = note_prover
        .prove(&witness_3)
        .expect("NoteSpend proof generation failed");
    let prove_time_3 = start.elapsed();
    println!(
        "  NoteSpend proof in {:?} (real: {})",
        prove_time_3,
        proof_3.is_real_proof()
    );

    let local_valid_3 = note_verifier
        .verify(&proof_3)
        .expect("Local NoteSpend verification error");
    assert!(local_valid_3, "Local NoteSpend proof verification failed!");

    let spent_nullifier = hex::encode(proof_3.public_inputs.nullifier);
    println!("  Nullifier: {}...", &spent_nullifier[..16]);

    // [3/5] Submit NoteSpend transfer → expect 200
    println!("[3/5] Submitting NoteSpend transfer...");
    let recipient_owner_3 = [0x31u8; 32];

    let tree_state_3: serde_json::Value = http_get(&format!(
        "{}/api/v1/confidential/tree",
        api_url
    ));
    let recipient_index_3 = tree_state_3["next_index"]
        .as_u64()
        .expect("tree state should have next_index");

    let body_3 = serde_json::json!({
        "proof_hex": hex::encode(&proof_3.proof),
        "commitment_root": hex::encode(proof_3.public_inputs.commitment_root),
        "nullifier": &spent_nullifier,
        "change_commitment": hex::encode(proof_3.public_inputs.change_commitment),
        "recipient_commitment": hex::encode(proof_3.public_inputs.recipient_commitment),
        "sender_index": index_3,
        "recipient_index": recipient_index_3,
        "recipient_owner_pubkey": hex::encode(recipient_owner_3),
        "epoch": 0,
    });

    let (status_ns, body_ns) = http_post_authed_raw(
        &format!("{}/api/v1/confidential/transfer", api_url),
        &api_secret,
        &body_3,
    );
    if status_ns != 200 {
        panic!(
            "NoteSpend transfer failed with HTTP {}: {}",
            status_ns, body_ns
        );
    }
    let result_ns: serde_json::Value = serde_json::from_str(&body_ns)
        .expect("NoteSpend response should be valid JSON");
    let transfer_id = result_ns
        .get("transfer_id")
        .and_then(|v| v.as_str())
        .expect("Server should return transfer_id");
    println!("  NoteSpend accepted (200): transfer_id={}", transfer_id);

    // [4/5] Attempt consolidation with the spent nullifier → expect 409
    println!("[4/5] Attempting consolidation with spent nullifier...");
    let (current_root, _, _) = get_tree_state(&api_url);

    // Dummy nullifiers for the other 3 slots (unused, definitely not spent)
    let dummy_null_1 = hex::encode(deterministic_blinding(40));
    let dummy_null_2 = hex::encode(deterministic_blinding(41));
    let dummy_null_3 = hex::encode(deterministic_blinding(42));

    let body_cross_consolidate = serde_json::json!({
        "proof_hex": hex::encode([0u8; 192]),
        "commitment_root": &current_root,
        "nullifiers": [&spent_nullifier, &dummy_null_1, &dummy_null_2, &dummy_null_3],
        "output_commitment": hex::encode([0u8; 32]),
        "encrypted_output": null,
        "epoch": 0,
    });

    let (status_xc, body_xc) = http_post_authed_raw(
        &format!("{}/api/v1/confidential/consolidate", api_url),
        &api_secret,
        &body_cross_consolidate,
    );
    if status_xc == 409 {
        println!("  Consolidation correctly rejected (409) — cross-circuit nullifier protection works");
    } else {
        panic!(
            "Expected 409 for cross-circuit consolidation, got {}: {}",
            status_xc, body_xc
        );
    }

    // [5/5] Attempt unshield with the spent nullifier → expect 409
    println!("[5/5] Attempting unshield with spent nullifier...");

    let body_cross_unshield = serde_json::json!({
        "proof_hex": hex::encode([0u8; 192]),
        "commitment_root": &current_root,
        "nullifier": &spent_nullifier,
        "withdrawal_amount_sats": amount_3,
        "destination_address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    });

    let (status_xu, body_xu) = http_post_authed_raw(
        &format!("{}/api/v1/confidential/unshield", api_url),
        &api_secret,
        &body_cross_unshield,
    );
    if status_xu == 409 {
        println!(
            "  Unshield correctly rejected (409) — cross-circuit nullifier protection works"
        );
    } else {
        panic!(
            "Expected 409 for cross-circuit unshield, got {}: {}",
            status_xu, body_xu
        );
    }

    println!();
    println!("  ✓ Test 3: Cross-Circuit Double-Spend PASSED");
    println!();

    // ========================================================================
    // Summary
    // ========================================================================

    println!("╔══════════════════════════════════════════════╗");
    println!("║  ALL 3 TESTS PASSED                         ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("  ✓ Test 1: Consolidation E2E (4→1) — shield, prove ({:?}), submit(200), double-spend(409), tree check", prove_time_1);
    println!("  ✓ Test 2: Unshield E2E — shield, prove ({:?}), submit(200), double-spend(409), tree check", prove_time_2);
    println!(
        "  ✓ Test 3: Cross-circuit double-spend — NoteSpend(200), Consolidate(409), Unshield(409)"
    );
    println!();
    println!("  Tree depth: {}", tree_depth);
    println!("  Params: {}", if use_mpc { "MPC" } else { "test" });
}

// ============================================================================
// Param loading
// ============================================================================

fn load_consolidation_params(
    params_dir: Option<&str>,
    tree_depth: usize,
) -> (GhostConsolidateProver, GhostConsolidateVerifier) {
    if let Some(dir) = params_dir {
        let path = format!("{}/payout_params_current.bin", dir);
        println!("  [consolidation] Loading MPC params from {}...", path);
        let start = Instant::now();
        let file = std::fs::File::open(&path).expect("Failed to open consolidation params");
        let reader = BufReader::new(file);
        let params =
            Parameters::<Bls12>::read(reader, false).expect("Failed to deserialize consolidation params");
        let prover = GhostConsolidateProver::new_with_params(Arc::new(params), tree_depth);
        let verifier = GhostConsolidateVerifier::for_prover(&prover);
        println!(
            "  [consolidation] Loaded in {:?} (has_params={})",
            start.elapsed(),
            prover.has_groth16_params()
        );
        (prover, verifier)
    } else {
        println!("  [consolidation] Generating test params (depth {})...", tree_depth);
        let start = Instant::now();
        let prover = GhostConsolidateProver::new_with_setup(tree_depth)
            .expect("Failed to setup consolidation prover");
        let verifier = GhostConsolidateVerifier::for_prover(&prover);
        println!("  [consolidation] Setup in {:?}", start.elapsed());
        (prover, verifier)
    }
}

fn load_unshield_params(
    params_dir: Option<&str>,
    tree_depth: usize,
) -> (GhostUnshieldProver, GhostUnshieldVerifier) {
    if let Some(dir) = params_dir {
        let path = format!("{}/unshield_params_current.bin", dir);
        println!("  [unshield] Loading MPC params from {}...", path);
        let start = Instant::now();
        let file = std::fs::File::open(&path).expect("Failed to open unshield params");
        let reader = BufReader::new(file);
        let params =
            Parameters::<Bls12>::read(reader, false).expect("Failed to deserialize unshield params");
        let prover = GhostUnshieldProver::new_with_params(Arc::new(params), tree_depth);
        let verifier = GhostUnshieldVerifier::for_prover(&prover);
        println!(
            "  [unshield] Loaded in {:?} (has_params={})",
            start.elapsed(),
            prover.has_groth16_params()
        );
        (prover, verifier)
    } else {
        println!("  [unshield] Generating test params (depth {})...", tree_depth);
        let start = Instant::now();
        let prover = GhostUnshieldProver::new_with_setup(tree_depth)
            .expect("Failed to setup unshield prover");
        let verifier = GhostUnshieldVerifier::for_prover(&prover);
        println!("  [unshield] Setup in {:?}", start.elapsed());
        (prover, verifier)
    }
}

fn load_note_spend_params(
    params_dir: Option<&str>,
    tree_depth: usize,
) -> (GhostNoteProver, GhostNoteVerifier) {
    if let Some(dir) = params_dir {
        let path = format!("{}/note_spend_params_current.bin", dir);
        println!("  [note_spend] Loading MPC params from {}...", path);
        let start = Instant::now();
        let file = std::fs::File::open(&path).expect("Failed to open note_spend params");
        let reader = BufReader::new(file);
        let params =
            Parameters::<Bls12>::read(reader, false).expect("Failed to deserialize note_spend params");
        let prover = GhostNoteProver::new_with_params(Arc::new(params), tree_depth);
        let verifier = GhostNoteVerifier::for_prover(&prover);
        println!(
            "  [note_spend] Loaded in {:?} (has_params={})",
            start.elapsed(),
            prover.has_groth16_params()
        );
        (prover, verifier)
    } else {
        println!("  [note_spend] Generating test params (depth {})...", tree_depth);
        let start = Instant::now();
        let prover = GhostNoteProver::new_with_setup(tree_depth)
            .expect("Failed to setup note_spend prover");
        let verifier = GhostNoteVerifier::for_prover(&prover);
        println!("  [note_spend] Setup in {:?}", start.elapsed());
        (prover, verifier)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn deterministic_blinding(seed: u8) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-l2-e2e-v1");
    hasher.update([seed]);
    let hash: [u8; 32] = hasher.finalize().into();
    let mut result = hash;
    result[31] &= 0x3F; // Ensure valid BLS12-381 scalar
    result
}

fn shield_balance(
    api_url: &str,
    api_secret: &str,
    amount_sats: u64,
    blinding: &[u8; 32],
    owner_pubkey: &[u8; 32],
) -> serde_json::Value {
    let body = serde_json::json!({
        "amount_sats": amount_sats,
        "blinding_hex": hex::encode(blinding),
        "owner_pubkey": hex::encode(owner_pubkey),
    });
    http_post_authed(
        &format!("{}/api/v1/confidential/shield", api_url),
        api_secret,
        &body,
    )
}

fn get_merkle_proof(api_url: &str, note_index: u64) -> (Vec<[u8; 32]>, String) {
    let resp: serde_json::Value = http_get(&format!(
        "{}/api/v1/confidential/proof/{}",
        api_url, note_index
    ));

    let siblings: Vec<[u8; 32]> = resp["siblings"]
        .as_array()
        .expect("proof response should have siblings array")
        .iter()
        .map(|s| {
            let hex_str = s.as_str().expect("sibling should be hex string");
            let bytes = hex::decode(hex_str).expect("sibling should be valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();

    let root = resp["tree_root"]
        .as_str()
        .expect("proof response should have tree_root")
        .to_string();

    (siblings, root)
}

fn get_tree_state(api_url: &str) -> (String, u64, u64) {
    let state: serde_json::Value =
        http_get(&format!("{}/api/v1/confidential/tree", api_url));
    let root = state["root"].as_str().unwrap_or("unknown").to_string();
    let note_count = state["note_count"].as_u64().unwrap_or(0);
    let nullifier_count = state["nullifier_count"].as_u64().unwrap_or(0);
    (root, note_count, nullifier_count)
}

fn http_get(url: &str) -> serde_json::Value {
    let output = std::process::Command::new("curl")
        .args(["-s", url])
        .output()
        .expect("curl failed");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        serde_json::json!({"error": "Failed to parse response"})
    })
}

fn compute_hmac(secret: &str, timestamp: &str, body: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn http_post_authed(url: &str, secret: &str, body: &serde_json::Value) -> serde_json::Value {
    let (status, response) = http_post_authed_raw(url, secret, body);
    if status != 200 {
        eprintln!("WARNING: HTTP {} from {}: {}", status, url, response);
    }
    serde_json::from_str(&response).unwrap_or_else(|e| {
        panic!("Invalid JSON from {}: {} — Response: {}", url, e, response);
    })
}

/// Returns (status_code, body_string)
fn http_post_authed_raw(
    url: &str,
    secret: &str,
    body: &serde_json::Value,
) -> (u16, String) {
    let body_str = serde_json::to_string(body).unwrap();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let signature = compute_hmac(secret, &timestamp, &body_str);

    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-o", "/dev/stderr",
            "-w", "%{http_code}",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-H", &format!("X-Ghost-Timestamp: {}", timestamp),
            "-H", &format!("X-Ghost-Signature: {}", signature),
            "-d", &body_str,
            url,
        ])
        .output()
        .expect("curl failed");

    let status_str = String::from_utf8_lossy(&output.stdout);
    let status: u16 = status_str.trim().parse().unwrap_or(0);
    let body_response = String::from_utf8_lossy(&output.stderr).to_string();

    (status, body_response)
}
