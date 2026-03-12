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
//| FILE: fuzz_l2_requests.rs                                                                                            |
//|======================================================================================================================|

//! Fuzz target for ghost-pay L2 API request deserialization
//!
//! The request structs are private to ghost-pay's main.rs, so we mirror
//! them here for fuzzing. Tests that none of the L2 endpoints' JSON
//! deserialization can panic on arbitrary input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

// Mirror of ghost-pay request structs (kept in sync manually)

#[derive(Debug, Deserialize)]
struct ConfidentialTransferRequest {
    proof_hex: String,
    commitment_root: String,
    nullifier: String,
    change_commitment: String,
    recipient_commitment: String,
    sender_index: u64,
    recipient_index: u64,
    recipient_owner_pubkey: String,
    epoch: u64,
    #[serde(default)]
    encrypted_change: String,
    #[serde(default)]
    encrypted_recipient: String,
}

#[derive(Debug, Deserialize)]
struct ConsolidateRequest {
    proof_hex: String,
    commitment_root: String,
    nullifiers: [String; 4],
    output_commitment: String,
    encrypted_output: String,
    epoch: u64,
}

#[derive(Debug, Deserialize)]
struct UnshieldRequest {
    proof_hex: String,
    commitment_root: String,
    nullifier: String,
    withdrawal_amount_sats: u64,
    destination_address: String,
}

#[derive(Debug, Deserialize)]
struct ShieldBalanceRequest {
    amount_sats: u64,
    blinding_hex: String,
    owner_pubkey: String,
    lock_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SendL2PaymentRequest {
    recipient: String,
    amount_sats: u64,
    #[serde(default)]
    memo: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WraithSubmitInputRequest {
    session_id: String,
    ghost_id: String,
    txid: String,
    vout: u32,
    amount: u64,
    script_pubkey: String,
}

#[derive(Debug, Deserialize)]
struct WraithRequestNoncesRequest {
    session_id: String,
    ghost_id: String,
}

#[derive(Debug, Deserialize)]
struct WraithSubmitBlindedRequest {
    session_id: String,
    ghost_id: String,
    blinded_address: String,
}

#[derive(Debug, Deserialize)]
struct WraithSubmitAnonymousRequest {
    session_id: String,
    address: String,
    token: String,
}

#[derive(Debug, Deserialize)]
struct CreateLockRequest {
    owner_pubkey: String,
    recovery_pubkey: String,
    capacity_sats: u64,
    #[serde(default)]
    timelock_tier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GlyphClaimRequest {
    ghost_id: String,
    #[serde(default)]
    display_name: Option<String>,
}

fuzz_target!(|data: &[u8]| {
    // L2 confidential transfer endpoints
    let _ = serde_json::from_slice::<ConfidentialTransferRequest>(data);
    let _ = serde_json::from_slice::<ConsolidateRequest>(data);
    let _ = serde_json::from_slice::<UnshieldRequest>(data);
    let _ = serde_json::from_slice::<ShieldBalanceRequest>(data);
    let _ = serde_json::from_slice::<SendL2PaymentRequest>(data);

    // Wraith protocol endpoints
    let _ = serde_json::from_slice::<WraithSubmitInputRequest>(data);
    let _ = serde_json::from_slice::<WraithRequestNoncesRequest>(data);
    let _ = serde_json::from_slice::<WraithSubmitBlindedRequest>(data);
    let _ = serde_json::from_slice::<WraithSubmitAnonymousRequest>(data);

    // Ghost Lock + Glyph
    let _ = serde_json::from_slice::<CreateLockRequest>(data);
    let _ = serde_json::from_slice::<GlyphClaimRequest>(data);
});
