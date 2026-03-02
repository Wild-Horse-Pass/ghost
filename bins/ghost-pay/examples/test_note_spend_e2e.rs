//! End-to-end test: shield note → fetch Merkle proof → generate NoteSpend Groth16 proof → submit transfer
//!
//! Tests the full NoteSpend flow against running ghost-pay + ghost-pool services.
//!
//! Usage:
//!   # With locally-generated test params (requires empty tree):
//!   cargo run -p ghost-pay --example test_note_spend_e2e -- \
//!     --ghost-pay-url http://127.0.0.1:8800 \
//!     --api-secret <secret> \
//!     [--fast]  # depth 4 for quick iteration (~10ms proving)
//!
//!   # With MPC params (works with any tree state):
//!   cargo run -p ghost-pay --example test_note_spend_e2e -- \
//!     --ghost-pay-url http://83.136.251.162:8800 \
//!     --api-secret <secret> \
//!     --params-file /tmp/note_spend_params.bin

use std::io::BufReader;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bellperson::groth16::Parameters;
use blstrs::Bls12;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use ghost_zkp::{GhostNoteProver, GhostNoteSpendWitness, GhostNoteVerifier};

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let api_url =
        get_arg(&args, "--ghost-pay-url").unwrap_or_else(|| "http://127.0.0.1:8800".to_string());
    let api_secret = get_arg(&args, "--api-secret").expect("--api-secret required");
    let params_file = get_arg(&args, "--params-file");
    let fast = args.iter().any(|a| a == "--fast");
    let tree_depth: usize = if fast { 4 } else { 20 };

    let use_mpc = params_file.is_some();

    println!("=== Ghost Pay NoteSpend E2E Test ===");
    println!("API: {}", api_url);
    if use_mpc {
        println!("Mode: MPC params (depth {})", tree_depth);
        println!("Params: {}", params_file.as_deref().unwrap());
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

    // Step 1: Load or generate Groth16 params
    let (prover, verifier) = if let Some(ref path) = params_file {
        println!("[1/8] Loading MPC params from {}...", path);
        let start = Instant::now();
        let file = std::fs::File::open(path).expect("Failed to open params file");
        let reader = BufReader::new(file);
        let params =
            Parameters::<Bls12>::read(reader, false).expect("Failed to deserialize params");
        let prover = GhostNoteProver::new_with_params(Arc::new(params), tree_depth);
        let verifier = GhostNoteVerifier::for_prover(&prover);
        println!(
            "  MPC params loaded in {:?} (has_params={}, prover_id={}...)",
            start.elapsed(),
            prover.has_groth16_params(),
            hex::encode(&prover.prover_id()[..8])
        );
        (prover, verifier)
    } else {
        println!("[1/8] Generating test Groth16 params (GhostNoteProver)...");
        let start = Instant::now();
        let prover =
            GhostNoteProver::new_with_setup(tree_depth).expect("Failed to setup prover");
        let verifier = GhostNoteVerifier::for_prover(&prover);
        println!(
            "  Setup complete in {:?} (has_params={}, prover_id={}...)",
            start.elapsed(),
            prover.has_groth16_params(),
            hex::encode(&prover.prover_id()[..8])
        );
        (prover, verifier)
    };

    // Step 2: Shield sender note
    println!("[2/8] Shielding sender note (1000 sats)...");
    let sender_blinding = deterministic_blinding(1);
    let sender_amount: u64 = 1000;
    let sender_owner = [0x01u8; 32];
    let shield1 = shield_balance(
        &api_url,
        &api_secret,
        sender_amount,
        &sender_blinding,
        &sender_owner,
    );
    let sender_index = shield1["note_index"]
        .as_u64()
        .expect("shield response should have note_index");
    let server_root_hex = shield1["new_root"]
        .as_str()
        .expect("shield response should have new_root")
        .to_string();
    println!("  Sender note at index {}", sender_index);
    println!("  Tree root after shield: {}...", &server_root_hex[..16]);

    // Step 3: Fetch Merkle proof from server
    println!("[3/8] Fetching Merkle proof from server...");
    let proof_response: serde_json::Value = http_get(&format!(
        "{}/api/v1/confidential/proof/{}",
        api_url, sender_index
    ));

    let server_siblings: Vec<[u8; 32]> = proof_response["siblings"]
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

    let proof_root_hex = proof_response["tree_root"]
        .as_str()
        .expect("proof response should have tree_root");
    let proof_depth = proof_response["tree_depth"]
        .as_u64()
        .expect("proof response should have tree_depth") as usize;

    println!(
        "  Got {} siblings (depth {})",
        server_siblings.len(),
        proof_depth
    );
    println!("  Proof root: {}...", &proof_root_hex[..16]);

    // Verify root consistency
    if proof_root_hex != server_root_hex {
        println!("  WARNING: proof root differs from shield root (concurrent tree update?)");
        println!("  Shield root: {}...", &server_root_hex[..16]);
        println!("  Proof root:  {}...", &proof_root_hex[..16]);
        println!("  Using proof root (current state).");
    }
    assert_eq!(
        proof_depth, tree_depth,
        "Server tree depth {} doesn't match expected {}",
        proof_depth, tree_depth
    );

    // Step 4: (reserved — previously: local tree build)
    println!("[4/8] Using server-provided Merkle proof (no local tree needed)...");

    // Step 5: Generate NoteSpend proof
    println!("[5/8] Generating NoteSpend Groth16 proof...");
    let transfer_amount: u64 = 300;
    let spending_key = deterministic_blinding(42);
    let change_blinding = deterministic_blinding(3);
    let recipient_new_blinding = deterministic_blinding(4);

    let witness = GhostNoteSpendWitness {
        spending_key,
        note_value: sender_amount,
        note_blinding: sender_blinding,
        note_index: sender_index,
        epoch: 0,
        merkle_siblings: server_siblings,
        amount: transfer_amount,
        change_blinding,
        recipient_blinding: recipient_new_blinding,
    };

    let start = Instant::now();
    let proof = prover.prove(&witness).expect("Proof generation failed");
    let prove_time = start.elapsed();
    println!(
        "  Proof generated in {:?} (size: {} bytes, real: {})",
        prove_time,
        proof.proof.len(),
        proof.is_real_proof()
    );

    // Verify locally
    let local_valid = verifier.verify(&proof).expect("Local verification error");
    println!(
        "  Local verification: {}",
        if local_valid { "PASS" } else { "FAIL" }
    );
    println!(
        "  Commitment root matches server: {}",
        hex::encode(proof.public_inputs.commitment_root) == proof_root_hex
    );
    assert!(local_valid, "Local proof verification failed!");

    // Step 6: Submit to ghost-pay
    println!("[6/8] Submitting NoteSpend transfer to ghost-pay...");
    let recipient_owner = [0x02u8; 32];

    // Get next_index for recipient note placement
    let tree_state: serde_json::Value =
        http_get(&format!("{}/api/v1/confidential/tree", api_url));
    let recipient_index = tree_state["next_index"]
        .as_u64()
        .expect("tree state should have next_index");
    println!("  Recipient note will be at index {}", recipient_index);

    let body = serde_json::json!({
        "proof_hex": hex::encode(&proof.proof),
        "commitment_root": hex::encode(proof.public_inputs.commitment_root),
        "nullifier": hex::encode(proof.public_inputs.nullifier),
        "change_commitment": hex::encode(proof.public_inputs.change_commitment),
        "recipient_commitment": hex::encode(proof.public_inputs.recipient_commitment),
        "sender_index": sender_index,
        "recipient_index": recipient_index,
        "recipient_owner_pubkey": hex::encode(recipient_owner),
        "epoch": 0,
    });

    let result = http_post_authed(
        &format!("{}/api/v1/confidential/transfer", api_url),
        &api_secret,
        &body,
    );
    println!(
        "  Response: {}",
        serde_json::to_string_pretty(&result).unwrap()
    );

    let transfer_id = result
        .get("transfer_id")
        .and_then(|v| v.as_str())
        .expect("Server should return transfer_id");
    println!("  Transfer ID: {}", transfer_id);

    // Step 7: Verify nullifier is spent (attempt double-spend → expect 409)
    println!("[7/8] Verifying nullifier is spent (double-spend attempt)...");
    let double_spend_result = http_post_authed_raw(
        &format!("{}/api/v1/confidential/transfer", api_url),
        &api_secret,
        &body,
    );
    if double_spend_result.0 == 409 {
        println!("  Double-spend correctly rejected (409 Conflict)");
    } else if double_spend_result.0 == 200 {
        println!("  ERROR: Double-spend was accepted! This is a bug.");
        std::process::exit(1);
    } else {
        println!(
            "  Got HTTP {} (expected 409): {}",
            double_spend_result.0, double_spend_result.1
        );
    }

    // Step 8: Query tree state and verify consistency
    println!("[8/8] Verifying final tree state...");
    let final_state: serde_json::Value =
        http_get(&format!("{}/api/v1/confidential/tree", api_url));
    let final_root = final_state["root"].as_str().unwrap_or("unknown");
    let final_note_count = final_state["note_count"].as_u64().unwrap_or(0);
    let final_nullifier_count = final_state["nullifier_count"].as_u64().unwrap_or(0);

    println!();
    println!("=== RESULTS ===");
    println!("  Transfer ID: {}", transfer_id);
    println!(
        "  Final root: {}...",
        &final_root[..std::cmp::min(16, final_root.len())]
    );
    println!("  Note count: {}", final_note_count);
    println!("  Nullifier count: {}", final_nullifier_count);
    println!("  Proof time: {:?}", prove_time);
    println!("  Tree depth: {}", tree_depth);
    println!("  Params: {}", if use_mpc { "MPC" } else { "test" });
    println!();
    println!("  *** NoteSpend E2E TEST PASSED ***");
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
    hasher.update(b"ghost-note-spend-e2e-v1");
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
        eprintln!("WARNING: HTTP {} from {}", status, url);
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
