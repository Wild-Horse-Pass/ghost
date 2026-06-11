//! End-to-end test: claim glyph → verify pending → duplicate rejection → simulate registration
//!
//! Tests the full GhostGlyph lifecycle against a running ghost-pay instance.
//!
//! Usage:
//!   # Basic (steps 1-7):
//!   cargo run -p ghost-pay --example test_glyph_e2e -- \
//!     --ghost-pay-url http://127.0.0.1:8800 \
//!     --api-secret <secret>
//!
//!   # Full with registration simulation (steps 1-9):
//!   cargo run -p ghost-pay --example test_glyph_e2e -- \
//!     --ghost-pay-url http://127.0.0.1:8800 \
//!     --api-secret <secret> \
//!     --db-path /path/to/ghost-pay.db
//!
//!   # Custom ghost ID:
//!   cargo run -p ghost-pay --example test_glyph_e2e -- \
//!     --ghost-pay-url http://127.0.0.1:8800 \
//!     --api-secret <secret> \
//!     --ghost-id ghost1custom_id

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use ghost_glyph::{GhostGlyph, GLYPH_SIZE, PALETTE_SIZE};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let api_url =
        get_arg(&args, "--ghost-pay-url").unwrap_or_else(|| "http://127.0.0.1:8800".to_string());
    let api_secret = get_arg(&args, "--api-secret").expect("--api-secret required");
    let db_path = get_arg(&args, "--db-path");
    let ghost_id =
        get_arg(&args, "--ghost-id").unwrap_or_else(|| format!("ghost1e2etest_{}", rand_hex(8)));

    let total_steps = if db_path.is_some() { 9 } else { 7 };

    println!("=== GhostGlyph E2E Test ===");
    println!("API: {}", api_url);
    println!("Ghost ID: {}", ghost_id);
    if let Some(ref p) = db_path {
        println!("DB path: {} (registration simulation enabled)", p);
    } else {
        println!("DB path: none (steps 8-9 skipped)");
    }
    println!();

    // Step 1: Generate test glyph
    println!("[1/{}] Generating test glyph...", total_steps);
    let mut pixels = [0u8; GLYPH_SIZE];
    let seed = deterministic_seed(&ghost_id);
    for i in 0..GLYPH_SIZE {
        pixels[i] = ((seed[i % 32] as usize + i) % PALETTE_SIZE) as u8;
    }
    let bitmap_hash = GhostGlyph::compute_bitmap_hash(&pixels);
    let commitment = GhostGlyph::compute_commitment(&pixels, ghost_id.as_bytes());
    let bitmap_hash_hex = hex::encode(bitmap_hash);
    println!(
        "  Pixels: {} bytes (palette range 0..{})",
        GLYPH_SIZE,
        PALETTE_SIZE - 1
    );
    println!("  Bitmap hash: {}...", &bitmap_hash_hex[..16]);
    println!("  Commitment: {}...", &hex::encode(commitment)[..16]);

    // Step 2: Check availability
    println!("[2/{}] Checking bitmap availability...", total_steps);
    let check_resp: serde_json::Value = http_get(&format!(
        "{}/api/v1/glyph/check/{}",
        api_url, bitmap_hash_hex
    ));
    let available = check_resp["available"]
        .as_bool()
        .expect("check response should have 'available' bool");
    println!("  Available: {}", available);
    assert!(available, "Bitmap should be available before claiming");

    // Step 3: Claim glyph
    println!("[3/{}] Claiming glyph...", total_steps);
    let claim_body = serde_json::json!({
        "ghost_id": ghost_id,
        "pixels": pixels.to_vec(),
    });
    let claim_resp = http_post_authed(
        &format!("{}/api/v1/glyph/claim", api_url),
        &api_secret,
        &claim_body,
    );
    let resp_commitment = claim_resp["commitment"]
        .as_str()
        .expect("claim response should have 'commitment'");
    let resp_bitmap_hash = claim_resp["bitmap_hash"]
        .as_str()
        .expect("claim response should have 'bitmap_hash'");
    let resp_status = claim_resp["status"]
        .as_str()
        .expect("claim response should have 'status'");
    println!("  Status: {}", resp_status);
    println!("  Commitment: {}...", &resp_commitment[..16]);
    assert_eq!(resp_status, "pending", "Claim status should be 'pending'");
    assert_eq!(
        resp_commitment,
        hex::encode(commitment),
        "Server commitment should match locally computed"
    );
    assert_eq!(
        resp_bitmap_hash, bitmap_hash_hex,
        "Server bitmap_hash should match locally computed"
    );

    // Step 4: Verify pending via GET
    println!("[4/{}] Verifying glyph is pending...", total_steps);
    let info_resp: serde_json::Value = http_get(&format!("{}/api/v1/glyph/{}", api_url, ghost_id));
    let info_status = info_resp["status"]
        .as_str()
        .expect("info response should have 'status'");
    let info_funding = &info_resp["funding_txid"];
    println!("  Status: {}", info_status);
    println!("  Funding txid: {}", info_funding);
    assert_eq!(info_status, "pending", "Glyph should still be pending");
    assert!(
        info_funding.is_null(),
        "funding_txid should be null before registration"
    );

    // Step 5: Bitmap taken
    println!("[5/{}] Verifying bitmap is now taken...", total_steps);
    let check_resp2: serde_json::Value = http_get(&format!(
        "{}/api/v1/glyph/check/{}",
        api_url, bitmap_hash_hex
    ));
    let available2 = check_resp2["available"]
        .as_bool()
        .expect("check response should have 'available' bool");
    println!("  Available: {}", available2);
    assert!(!available2, "Bitmap should no longer be available");

    // Step 6: Duplicate bitmap rejected
    println!(
        "[6/{}] Claiming same bitmap with different ghost_id (expect rejection)...",
        total_steps
    );
    let alt_ghost_id = format!("ghost1alt_{}", rand_hex(8));
    let dup_bitmap_body = serde_json::json!({
        "ghost_id": alt_ghost_id,
        "pixels": pixels.to_vec(),
    });
    let (dup_bitmap_status, dup_bitmap_resp) = http_post_authed_raw(
        &format!("{}/api/v1/glyph/claim", api_url),
        &api_secret,
        &dup_bitmap_body,
    );
    println!("  HTTP {}: {}", dup_bitmap_status, dup_bitmap_resp.trim());
    assert_eq!(
        dup_bitmap_status, 409,
        "Duplicate bitmap should be rejected with 409 Conflict"
    );

    // Step 7: Duplicate ghost_id rejected
    println!(
        "[7/{}] Claiming different bitmap with same ghost_id (expect rejection)...",
        total_steps
    );
    let mut alt_pixels = [0u8; GLYPH_SIZE];
    for i in 0..GLYPH_SIZE {
        alt_pixels[i] = ((pixels[i] as usize + 1) % PALETTE_SIZE) as u8;
    }
    let dup_id_body = serde_json::json!({
        "ghost_id": ghost_id,
        "pixels": alt_pixels.to_vec(),
    });
    let (dup_id_status, dup_id_resp) = http_post_authed_raw(
        &format!("{}/api/v1/glyph/claim", api_url),
        &api_secret,
        &dup_id_body,
    );
    println!("  HTTP {}: {}", dup_id_status, dup_id_resp.trim());
    assert_eq!(
        dup_id_status, 409,
        "Duplicate ghost_id should be rejected with 409 Conflict"
    );

    if let Some(ref path) = db_path {
        // Step 8: Simulate registration via direct DB
        println!(
            "[8/{}] Simulating registration via direct DB...",
            total_steps
        );
        let db = ghost_storage::Database::open(path).expect("Failed to open database");
        let fake_txid = format!("e2e_test_{}", rand_hex(16));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        db.complete_glyph_registration(&ghost_id, &fake_txid, now)
            .expect("complete_glyph_registration failed");
        println!("  Registered with txid: {}", fake_txid);
        println!("  Timestamp: {}", now);

        // Step 9: Verify registered via GET
        println!("[9/{}] Verifying glyph is registered...", total_steps);
        let reg_resp: serde_json::Value =
            http_get(&format!("{}/api/v1/glyph/{}", api_url, ghost_id));
        let reg_status = reg_resp["status"]
            .as_str()
            .expect("info response should have 'status'");
        let reg_txid = reg_resp["funding_txid"]
            .as_str()
            .expect("registered glyph should have funding_txid");
        let reg_at = reg_resp["registered_at"]
            .as_u64()
            .expect("registered glyph should have registered_at");
        println!("  Status: {}", reg_status);
        println!("  Funding txid: {}", reg_txid);
        println!("  Registered at: {}", reg_at);
        assert_eq!(reg_status, "registered", "Glyph should be registered");
        assert_eq!(reg_txid, fake_txid, "Funding txid should match");
    }

    println!();
    println!("=== RESULTS ===");
    println!("  Ghost ID: {}", ghost_id);
    println!("  Bitmap hash: {}...", &bitmap_hash_hex[..16]);
    println!("  Steps completed: {}/{}", total_steps, total_steps);
    println!();
    println!("  *** GhostGlyph E2E TEST PASSED ***");
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

fn deterministic_seed(input: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-glyph-e2e-v1");
    hasher.update(input.as_bytes());
    hasher.finalize().into()
}

fn rand_hex(bytes: usize) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-glyph-e2e-rand");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    hasher.update(now.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    hex::encode(&hash[..bytes])
}

fn compute_hmac(secret: &str, timestamp: &str, body: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn http_get(url: &str) -> serde_json::Value {
    let output = std::process::Command::new("curl")
        .args(["-s", url])
        .output()
        .expect("curl failed");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        let body = String::from_utf8_lossy(&output.stdout);
        panic!("Failed to parse JSON from GET {}: {}", url, body);
    })
}

fn http_post_authed(url: &str, secret: &str, body: &serde_json::Value) -> serde_json::Value {
    let (status, response) = http_post_authed_raw(url, secret, body);
    if status != 200 {
        panic!("HTTP {} from POST {}: {}", status, url, response);
    }
    serde_json::from_str(&response).unwrap_or_else(|e| {
        panic!("Invalid JSON from {}: {} — Response: {}", url, e, response);
    })
}

/// Returns (status_code, body_string)
fn http_post_authed_raw(url: &str, secret: &str, body: &serde_json::Value) -> (u16, String) {
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
            "-o",
            "/dev/stderr",
            "-w",
            "%{http_code}",
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

    let status_str = String::from_utf8_lossy(&output.stdout);
    let status: u16 = status_str.trim().parse().unwrap_or(0);
    let body_response = String::from_utf8_lossy(&output.stderr).to_string();

    (status, body_response)
}
