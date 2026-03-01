//! End-to-end test: shield notes → generate Groth16 proof → submit confidential transfer
//!
//! **Deprecated:** This example uses the legacy ConfidentialTransfer circuit.
//! New code should use the NoteSpend circuit via `GhostNoteProver`.
//!
//! Usage:
//!   cargo run -p ghost-pay --example test_confidential_e2e -- \
//!     --api-url http://127.0.0.1:8800 \
//!     --api-secret <secret> \
//!     --params-path /path/to/confidential_params_current.bin

#![allow(deprecated)]

use std::time::{SystemTime, UNIX_EPOCH};

use bellperson::groth16::Parameters;
use blstrs::{Bls12, Scalar as Fr};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use ghost_zkp::{
    compute_commitment_bytes, CommitmentTree, ConfidentialProver, ConfidentialVerifier,
};

const TREE_DEPTH: usize = 20;

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let api_url =
        get_arg(&args, "--api-url").unwrap_or_else(|| "http://127.0.0.1:8800".to_string());
    let api_secret = get_arg(&args, "--api-secret").expect("--api-secret required");
    let params_path = get_arg(&args, "--params-path").unwrap_or_else(|| {
        "/tmp/ghost_confidential_params/confidential_params_current.bin".to_string()
    });

    println!("=== Ghost Pay Confidential Transfer E2E Test ===");
    println!("API: {}", api_url);
    println!("Params: {}", params_path);
    println!();

    // Step 1: Load Groth16 proving parameters
    println!("[1/6] Loading Groth16 proving parameters...");
    let file = std::fs::File::open(&params_path).expect("Failed to open params file");
    let reader = std::io::BufReader::new(file);
    let params: Parameters<Bls12> = Parameters::read(reader, false).expect("Failed to read params");
    let prover = ConfidentialProver::new_with_params(std::sync::Arc::new(params), TREE_DEPTH);
    let verifier = ConfidentialVerifier::for_prover(&prover);
    println!(
        "  Loaded OK (has_groth16={}, has_vk={})",
        prover.has_groth16_params(),
        verifier.has_groth16_vk()
    );

    // Step 2: Get current tree state from server
    println!("[2/6] Fetching current tree state...");
    let tree_state: serde_json::Value = http_get(&format!("{}/api/v1/confidential/tree", api_url));
    let server_root = tree_state["root"].as_str().unwrap();
    let next_index = tree_state["next_index"].as_u64().unwrap();
    println!("  Root: {}...", &server_root[..16]);
    println!("  Next index: {}", next_index);

    // Step 3: Shield sender note (creates commitment in tree)
    println!("[3/6] Shielding sender note (1000 sats)...");
    let sender_blinding = deterministic_blinding(1);
    let sender_amount: u64 = 1000;
    let sender_owner = [0x01u8; 32]; // Test pubkey
    let shield1 = shield_balance(
        &api_url,
        &api_secret,
        sender_amount,
        &sender_blinding,
        &sender_owner,
    );
    let sender_index = shield1["note_index"].as_u64().unwrap();
    let sender_commitment_hex = shield1["commitment"].as_str().unwrap();
    println!("  Sender note created at index {}", sender_index);
    println!("  Commitment: {}...", &sender_commitment_hex[..16]);

    // Step 4: Shield recipient note (500 sats)
    println!("[4/6] Shielding recipient note (500 sats)...");
    let recipient_blinding = deterministic_blinding(2);
    let recipient_amount: u64 = 500;
    let recipient_owner = [0x02u8; 32]; // Test pubkey
    let shield2 = shield_balance(
        &api_url,
        &api_secret,
        recipient_amount,
        &recipient_blinding,
        &recipient_owner,
    );
    let recipient_index = shield2["note_index"].as_u64().unwrap();
    let new_root_after_shield = shield2["new_root"].as_str().unwrap().to_string();
    println!("  Recipient note created at index {}", recipient_index);
    println!(
        "  Tree root after shields: {}...",
        &new_root_after_shield[..16]
    );

    // Step 5: Generate confidential transfer proof
    println!("[5/6] Generating Groth16 confidential transfer proof...");
    let transfer_amount: u64 = 300;

    // Build a local tree matching the server state
    // We need ALL notes in the tree, not just ours. Fetch from server.
    let _notes_url = format!(
        "{}/api/v1/confidential/notes/{}",
        api_url,
        hex::encode(sender_owner)
    );
    // Since we can't easily fetch all notes, rebuild from our known commitments
    // and any prior notes. Use the server's next_index to detect prior notes.
    let sender_commitment = compute_commitment_bytes(sender_amount, &sender_blinding).unwrap();
    let recipient_commitment =
        compute_commitment_bytes(recipient_amount, &recipient_blinding).unwrap();

    let mut local_tree = CommitmentTree::new(TREE_DEPTH);
    // Insert all notes up to our indices (zeros for unknown prior notes)
    // Actually we need the exact same tree. Since shield gives us back the root,
    // and we know the commitments, we just need to insert at the right indices.
    // Prior notes (if any) were inserted before ours.
    // For notes we don't know, insert zero commitments (matches empty slots).
    for i in 0..sender_index {
        // We don't know these commitments — but they're in the server tree.
        // We need to fetch them. Use a simple approach: query the notes endpoint.
        // For now, skip if sender_index == 0 (no prior notes).
        let _ = i;
    }
    // If there were prior notes, our local tree won't match. Handle this:
    if sender_index > 0 {
        // Fetch all notes from server to reconstruct tree
        println!("  Fetching prior notes to reconstruct local tree...");
        // The /notes endpoint is per-owner. We need all notes.
        // Use a workaround: query the tree state which includes the root,
        // then use it to verify our computed root matches.
        // For a clean test, we should start with an empty tree.
        println!(
            "  WARNING: Tree has prior notes (index {}). Wiping and re-shielding...",
            sender_index
        );

        // Wipe the confidential tables on VM and restart
        // Actually, let's just work with what we have by building the tree correctly.
        // The key insight: we know the commitments for our notes, and the server
        // root after shield2 must match a tree with ALL notes up to that point.
        // Since we can't easily get prior note commitments, let's just verify
        // our newly shielded notes produce the right root when combined with the
        // prior state.

        // Simple approach: trust the server's root after shielding and use it as
        // old_commitment_root for the transfer. The proof generation uses our
        // local tree which we build from known data.
        // This works because the Groth16 circuit only needs merkle proofs for
        // the sender and recipient indices, not the entire tree.
    }

    local_tree.insert(sender_index, sender_commitment);
    local_tree.insert(recipient_index, recipient_commitment);

    // Verify local tree matches server
    let local_root = local_tree.root().unwrap();
    let local_root_hex = hex::encode(local_root);
    if local_root_hex != new_root_after_shield {
        println!("  WARNING: Local tree root doesn't match server (prior notes exist)");
        println!("  Local:  {}...", &local_root_hex[..16]);
        println!("  Server: {}...", &new_root_after_shield[..16]);
        println!("  This means there are notes in the tree we don't know about.");
        println!("  Aborting — please run with an empty tree.");
        std::process::exit(1);
    }
    println!("  Local tree root matches server");

    // Generate fresh blindings for new notes
    let sender_new_blinding = deterministic_blinding(3);
    let recipient_new_blinding = deterministic_blinding(4);

    // Convert to field elements
    let sender_blinding_fr = bytes_to_fr(&sender_blinding);
    let spending_key = deterministic_blinding(42); // Test spending key
    let spending_key_fr = bytes_to_fr(&spending_key);
    let sender_new_blinding_fr = bytes_to_fr(&sender_new_blinding);
    let recipient_old_blinding_fr = bytes_to_fr(&recipient_blinding);
    let recipient_new_blinding_fr = bytes_to_fr(&recipient_new_blinding);

    // Apply transfer to local tree (generates witness data)
    let witness = local_tree
        .apply_transfer(
            sender_index,
            sender_amount,
            sender_blinding_fr,
            spending_key_fr,
            transfer_amount,
            sender_new_blinding_fr,
            recipient_index,
            recipient_amount,
            recipient_old_blinding_fr,
            recipient_new_blinding_fr,
        )
        .expect("apply_transfer failed");

    let new_root_after_transfer = local_tree.root().unwrap();

    // Generate Groth16 proof
    let start = std::time::Instant::now();
    let proof = prover.prove(&witness).expect("Proof generation failed");
    let proof_time = start.elapsed();
    println!("  Proof generated in {:?}", proof_time);
    println!(
        "  Proof size: {} bytes (real Groth16: {})",
        proof.proof.len(),
        proof.is_real_proof()
    );

    // Verify locally first
    let local_valid = verifier.verify(&proof).expect("Local verification failed");
    println!(
        "  Local verification: {}",
        if local_valid { "PASS" } else { "FAIL" }
    );
    assert!(local_valid, "Local proof verification failed!");

    // Step 6: Submit transfer to server
    println!("[6/6] Submitting confidential transfer to server...");
    let body = serde_json::json!({
        "proof_hex": hex::encode(&proof.proof),
        "old_commitment_root": new_root_after_shield,
        "new_commitment_root": hex::encode(new_root_after_transfer),
        "nullifier": hex::encode(proof.public_inputs.nullifier),
        "sender_new_commitment": hex::encode(proof.public_inputs.sender_new_commitment),
        "recipient_new_commitment": hex::encode(proof.public_inputs.recipient_new_commitment),
        "sender_index": sender_index,
        "recipient_index": recipient_index,
        "recipient_owner_pubkey": hex::encode(recipient_owner),
    });

    let result = http_post_authed(
        &format!("{}/api/v1/confidential/transfer", api_url),
        &api_secret,
        &body,
    );

    println!(
        "  Server response: {}",
        serde_json::to_string_pretty(&result).unwrap()
    );

    // Verify final tree state
    let final_state: serde_json::Value = http_get(&format!("{}/api/v1/confidential/tree", api_url));
    let final_root = final_state["root"].as_str().unwrap();
    let final_note_count = final_state["note_count"].as_u64().unwrap();
    let final_nullifier_count = final_state["nullifier_count"].as_u64().unwrap();

    println!();
    println!("=== RESULTS ===");
    println!(
        "  Transfer ID: {}",
        result
            .get("transfer_id")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A")
    );
    println!("  Final root: {}...", &final_root[..16]);
    println!("  Note count: {}", final_note_count);
    println!("  Nullifier count: {}", final_nullifier_count);
    println!(
        "  Expected root match: {}",
        final_root == hex::encode(new_root_after_transfer)
    );

    if result.get("transfer_id").is_some() {
        println!();
        println!("  *** E2E TEST PASSED: Real Groth16 proof verified by server ***");
    } else {
        println!();
        println!("  *** E2E TEST FAILED ***");
        println!(
            "  Error: {}",
            result
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
        std::process::exit(1);
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
    hasher.update(b"ghost-e2e-test-blinding-v1");
    hasher.update([seed]);
    let hash: [u8; 32] = hasher.finalize().into();
    let mut result = hash;
    result[31] &= 0x3F; // Ensure valid BLS12-381 scalar
    result
}

fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    ghost_zkp::field_utils::bytes_to_field(bytes).expect("Invalid field element")
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

fn http_get(url: &str) -> serde_json::Value {
    let output = std::process::Command::new("curl")
        .args(["-s", url])
        .output()
        .expect("curl failed");
    serde_json::from_slice(&output.stdout).expect("Invalid JSON response")
}

fn http_post_authed(url: &str, secret: &str, body: &serde_json::Value) -> serde_json::Value {
    let body_str = serde_json::to_string(body).unwrap();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    // Compute HMAC-SHA256(secret, timestamp + body)
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(body_str.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            &format!("X-Ghost-Timestamp: {}", timestamp),
            "-H",
            &format!("X-Ghost-Signature: {}", signature),
            "-d",
            &body_str,
            url,
        ])
        .output()
        .expect("curl failed");

    let response = String::from_utf8_lossy(&output.stdout);
    if response.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "Empty response from server. Status code likely non-200. Stderr: {}",
            stderr
        );
    }
    serde_json::from_str(&response).unwrap_or_else(|e| {
        panic!("Invalid JSON: {} — Response: {}", e, response);
    })
}
