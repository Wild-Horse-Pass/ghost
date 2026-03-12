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
//| FILE: fuzz_ghost_locks.rs                                                                                            |
//|======================================================================================================================|

//! Fuzz target for Ghost Lock script construction and validation
//!
//! Tests that script builders and validators never panic on arbitrary inputs.
//! Ghost Locks use P2WSH for quantum safety — incorrect script construction
//! could lock funds permanently or defeat the timelock.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::blockdata::script::ScriptBuf;
use ghost_locks::{
    build_wsh_witness_script, build_p2wsh_script_pubkey, build_lock_script,
    build_normal_witness, build_recovery_witness, ghost_lock_id,
    is_p2wsh, is_p2tr, TimelockTier,
};

#[derive(Arbitrary, Debug)]
struct FuzzLockInput {
    lock_key_bytes: [u8; 32],
    recovery_key_bytes: [u8; 32],
    recovery_blocks: u32,
    capacity_sats: u64,
    creation_height: u32,
    signature_bytes: Vec<u8>,
    arbitrary_script: Vec<u8>,
    timelock_tier: u8,
}

fuzz_target!(|input: FuzzLockInput| {
    let secp = Secp256k1::new();

    // Generate valid pubkeys from the fuzzer's seed bytes (or skip if invalid)
    let lock_key = match SecretKey::from_slice(&input.lock_key_bytes) {
        Ok(sk) => PublicKey::from_secret_key(&secp, &sk),
        Err(_) => return,
    };
    let recovery_key = match SecretKey::from_slice(&input.recovery_key_bytes) {
        Ok(sk) => PublicKey::from_secret_key(&secp, &sk),
        Err(_) => return,
    };

    // Script construction with raw recovery_blocks — must not panic
    let witness_result = build_wsh_witness_script(
        &lock_key,
        &recovery_key,
        input.recovery_blocks,
    );

    if let Ok(witness_script) = &witness_result {
        // P2WSH wrapping — must not panic
        let p2wsh = build_p2wsh_script_pubkey(witness_script);

        // Valid witness scripts must produce valid P2WSH
        assert!(is_p2wsh(&p2wsh), "build_p2wsh must produce valid P2WSH");

        // Witness construction — must not panic
        let _ = build_normal_witness(&input.signature_bytes, witness_script);
        let _ = build_recovery_witness(&input.signature_bytes, witness_script);
    }

    // build_lock_script with TimelockTier — must not panic
    let tier = match input.timelock_tier % 3 {
        0 => TimelockTier::Short,
        1 => TimelockTier::Standard,
        _ => TimelockTier::Long,
    };
    let _ = build_lock_script(&lock_key, &recovery_key, input.creation_height, tier);

    // Lock ID derivation — must not panic
    let _ = ghost_lock_id(
        &lock_key,
        &recovery_key,
        input.creation_height,
        input.capacity_sats,
    );

    // Validate arbitrary scripts — must not panic
    let arb_script = ScriptBuf::from_bytes(input.arbitrary_script);
    let _ = is_p2wsh(&arb_script);
    let _ = is_p2tr(&arb_script);
});
