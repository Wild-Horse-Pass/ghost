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
//| FILE: fuzz_wraith_blind.rs                                                                                           |
//|======================================================================================================================|

//! Fuzz target for Wraith Protocol blind signature operations
//!
//! Tests that blind signature creation, verification, and token validation
//! never panic on arbitrary inputs. Also exercises denomination parsing,
//! encrypted markers, and coordinator signer lifecycle.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use wraith_protocol::{
    BlindSignature, BlindedAddress, UnblindedToken,
    CoordinatorSigner, WraithDenomination, WraithMode,
    derive_phase_key, verify_encrypted_marker_v3,
};

#[derive(Arbitrary, Debug)]
struct FuzzWraithInput {
    // Denomination deserialization
    denom_json: Vec<u8>,
    mode_json: Vec<u8>,

    // Phase key derivation
    session_id: [u8; 32],
    phase: u8,

    // Encrypted marker verification
    marker_bytes: Vec<u8>,
    key_bytes: [u8; 32],

    // Blind signature types deserialization
    blind_sig_json: Vec<u8>,
    blinded_addr_json: Vec<u8>,
    unblinded_token_json: Vec<u8>,

    // Coordinator signer from arbitrary key
    signer_key: [u8; 32],
}

fuzz_target!(|input: FuzzWraithInput| {
    // Denomination deserialization — must not panic
    let _ = serde_json::from_slice::<WraithDenomination>(&input.denom_json);

    // Mode deserialization — must not panic
    let _ = serde_json::from_slice::<WraithMode>(&input.mode_json);

    // Phase key derivation — must not panic
    let _key = derive_phase_key(&input.session_id, input.phase);

    // Encrypted marker verification — must not panic
    let mut marker = [0u8; 32];
    let len = input.marker_bytes.len().min(32);
    marker[..len].copy_from_slice(&input.marker_bytes[..len]);
    let _ = verify_encrypted_marker_v3(&marker, &input.key_bytes, 1000);

    // Blind signature type deserialization — must not panic
    let _ = serde_json::from_slice::<BlindSignature>(&input.blind_sig_json);
    let _ = serde_json::from_slice::<BlindedAddress>(&input.blinded_addr_json);
    let _ = serde_json::from_slice::<UnblindedToken>(&input.unblinded_token_json);

    // CoordinatorSigner creation — must not panic (may fail on invalid key)
    if let Ok(signer) = CoordinatorSigner::from_bytes(&input.signer_key, &input.session_id) {
        // Token verification with arbitrary data — must not panic
        if let Ok(token) = serde_json::from_slice::<UnblindedToken>(&input.unblinded_token_json) {
            let _ = signer.verify_signature(&token);
        }
    }
});
