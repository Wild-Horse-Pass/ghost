// Allow common test-code patterns that clippy flags
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::let_and_return)]
#![allow(clippy::iter_nth_zero)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_repeat_n)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::needless_character_iteration)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::bool_assert_comparison)]

//! Category: Silent Payment v2 Tests
//!
//! Tests for counter-based k Silent Payment implementation:
//! - Position-independent address derivation
//! - Shuffle-safe scanning
//! - Recovery scanning
//! - Multi-output transactions

use bitcoin::secp256k1::Secp256k1;
use ghost_keys::{
    compute_tweak_v2, derive_payment_address_v2, GhostKeys, PaymentDetector, ScanConfig,
    DEFAULT_MAX_K, DOMAIN_SEPARATOR_V2, MAX_MAX_K,
};
use rand::rngs::OsRng;

// =============================================================================
// CORE DERIVATION TESTS
// =============================================================================

#[test]
fn test_sp2_001_tweak_uses_domain_separator() {
    let shared_secret = [0x42u8; 32];

    // Compute v2 tweak
    let tweak = compute_tweak_v2(&shared_secret, 0);

    // Manually compute expected value
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR_V2);
    hasher.update(&shared_secret);
    hasher.update(0u32.to_le_bytes());
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(tweak, expected);
}

#[test]
fn test_sp2_002_different_k_different_tweak() {
    let shared_secret = [0x42u8; 32];

    let tweak0 = compute_tweak_v2(&shared_secret, 0);
    let tweak1 = compute_tweak_v2(&shared_secret, 1);
    let tweak2 = compute_tweak_v2(&shared_secret, 2);
    let tweak1000 = compute_tweak_v2(&shared_secret, 1000);

    // All should be unique
    assert_ne!(tweak0, tweak1);
    assert_ne!(tweak1, tweak2);
    assert_ne!(tweak0, tweak1000);
}

#[test]
fn test_sp2_003_derive_address_deterministic() {
    let secp = Secp256k1::new();
    let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);
    let shared_secret = [0x42u8; 32];

    let (addr1, tweak1) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 0).unwrap();
    let (addr2, tweak2) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 0).unwrap();

    assert_eq!(addr1, addr2);
    assert_eq!(tweak1, tweak2);
}

#[test]
fn test_sp2_004_derive_address_different_k() {
    let secp = Secp256k1::new();
    let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);
    let shared_secret = [0x42u8; 32];

    let (addr0, _) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 0).unwrap();
    let (addr1, _) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 1).unwrap();
    let (addr2, _) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 2).unwrap();

    assert_ne!(addr0, addr1);
    assert_ne!(addr1, addr2);
    assert_ne!(addr0, addr2);
}

// =============================================================================
// GHOST ID DERIVATION TESTS
// =============================================================================

#[test]
fn test_sp2_010_ghost_id_derive_v2() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    let (addr, ephemeral) = ghost_id.derive_payment_address_v2(0).unwrap();

    // Address should be different from spend pubkey
    assert_ne!(addr, *keys.spend_pubkey());

    // Ephemeral should be valid
    assert_eq!(ephemeral.serialize().len(), 33);
}

#[test]
fn test_sp2_011_ghost_id_derive_multiple_k() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    // Derive addresses for k=0,1,2,3,4
    let addrs: Vec<_> = (0..5)
        .map(|k| ghost_id.derive_payment_address_v2(k).unwrap().0)
        .collect();

    // All should be unique
    for i in 0..addrs.len() {
        for j in (i + 1)..addrs.len() {
            assert_ne!(
                addrs[i], addrs[j],
                "k={} and k={} produced same address",
                i, j
            );
        }
    }
}

#[test]
fn test_sp2_012_detection_finds_payment() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    let (addr, ephemeral) = ghost_id.derive_payment_address_v2(0).unwrap();

    let result = keys.detect_payment_default(&ephemeral, &addr).unwrap();
    assert!(result.is_some());

    let (spend_key, k) = result.unwrap();
    assert_eq!(k, 0);
    assert_eq!(spend_key.secret_bytes().len(), 32);
}

#[test]
fn test_sp2_013_detection_finds_high_k() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    // Create ephemeral key
    let secp = Secp256k1::new();
    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Derive with k=7
    let (addr, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 7)
        .unwrap();

    // Default config (max_k=10) should find it
    let config = ScanConfig::default();
    let result = keys.detect_payment(&ephemeral, &addr, &config).unwrap();
    assert!(result.is_some());

    let (_, k) = result.unwrap();
    assert_eq!(k, 7);
}

// =============================================================================
// SCANNING TESTS - CRITICAL FOR WRAITH
// =============================================================================

#[test]
fn test_sp2_020_scan_single_output() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    let (addr, ephemeral, _) = ghost_id.derive_payment_address_v2_full(0).unwrap();

    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &[(addr, Some(100_000))]);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].k, 0);
    assert_eq!(found[0].output_index, 0);
    assert_eq!(found[0].amount, Some(100_000));
}

#[test]
fn test_sp2_021_scan_multiple_outputs_same_recipient() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    let secp = Secp256k1::new();
    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Create 3 outputs with k=0,1,2
    let (addr0, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
        .unwrap();
    let (addr1, _, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 1)
        .unwrap();
    let (addr2, _, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 2)
        .unwrap();

    let outputs = vec![
        (addr0, Some(50_000)),
        (addr1, Some(75_000)),
        (addr2, Some(100_000)),
    ];

    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &outputs);

    assert_eq!(found.len(), 3);
    assert!(found.iter().any(|p| p.k == 0 && p.amount == Some(50_000)));
    assert!(found.iter().any(|p| p.k == 1 && p.amount == Some(75_000)));
    assert!(found.iter().any(|p| p.k == 2 && p.amount == Some(100_000)));
}

#[test]
fn test_sp2_022_scan_shuffled_outputs_critical() {
    // THIS IS THE CRITICAL TEST FOR WRAITH PROTOCOL
    // Outputs are shuffled but detection must still work

    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    let secp = Secp256k1::new();
    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Create outputs with k=0,1,2
    let (addr0, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
        .unwrap();
    let (addr1, _, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 1)
        .unwrap();
    let (addr2, _, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 2)
        .unwrap();

    // SHUFFLE: Put them in random order (simulating Wraith shuffle)
    let shuffled_outputs = vec![
        (addr2, Some(100_000)), // k=2 is first in vec (output_index=0)
        (addr0, Some(50_000)),  // k=0 is second (output_index=1)
        (addr1, Some(75_000)),  // k=1 is third (output_index=2)
    ];

    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &shuffled_outputs);

    // All 3 should be found despite shuffle
    assert_eq!(found.len(), 3, "Should find all 3 outputs despite shuffle");

    // Verify k values are correct (independent of position)
    let k0_payment = found.iter().find(|p| p.k == 0).expect("Should find k=0");
    let k1_payment = found.iter().find(|p| p.k == 1).expect("Should find k=1");
    let k2_payment = found.iter().find(|p| p.k == 2).expect("Should find k=2");

    // Verify amounts match (proves we found the right outputs)
    assert_eq!(k0_payment.amount, Some(50_000));
    assert_eq!(k1_payment.amount, Some(75_000));
    assert_eq!(k2_payment.amount, Some(100_000));

    // Verify output_index is the position in vec (for spending)
    assert_eq!(k2_payment.output_index, 0); // k=2 was first in vec
    assert_eq!(k0_payment.output_index, 1); // k=0 was second
    assert_eq!(k1_payment.output_index, 2); // k=1 was third
}

#[test]
fn test_sp2_023_scan_with_random_outputs() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let secp = Secp256k1::new();

    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Our outputs
    let (our_addr0, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
        .unwrap();
    let (our_addr1, _, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 1)
        .unwrap();

    // Random outputs (not ours)
    let (_, random1) = secp.generate_keypair(&mut OsRng);
    let (_, random2) = secp.generate_keypair(&mut OsRng);
    let (_, random3) = secp.generate_keypair(&mut OsRng);

    // Mix ours with random
    let outputs = vec![
        (random1, Some(10_000)),
        (our_addr0, Some(50_000)),
        (random2, Some(20_000)),
        (our_addr1, Some(75_000)),
        (random3, Some(30_000)),
    ];

    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &outputs);

    // Should find exactly 2 (our outputs)
    assert_eq!(found.len(), 2);
    assert!(found.iter().any(|p| p.k == 0 && p.output_index == 1));
    assert!(found.iter().any(|p| p.k == 1 && p.output_index == 3));
}

// =============================================================================
// RECOVERY SCANNING TESTS
// =============================================================================

#[test]
fn test_sp2_030_default_max_k() {
    assert_eq!(DEFAULT_MAX_K, 10);
    assert_eq!(MAX_MAX_K, 10_000);
}

#[test]
fn test_sp2_031_scan_respects_max_k() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let secp = Secp256k1::new();

    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Create output with k=15 (higher than default max_k=10)
    let (addr15, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 15)
        .unwrap();

    let outputs = vec![(addr15, Some(100_000))];

    // Default detector (max_k=10) should NOT find it
    let detector_default = PaymentDetector::new(&keys);
    let found = detector_default.scan_transaction(&ephemeral, &outputs);
    assert!(found.is_empty(), "Default scanner should miss k=15");

    // Detector with max_k=20 SHOULD find it
    let detector_high = PaymentDetector::with_config(&keys, ScanConfig::new(20));
    let found = detector_high.scan_transaction(&ephemeral, &outputs);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].k, 15);
}

#[test]
fn test_sp2_032_recovery_scan_finds_missed() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let secp = Secp256k1::new();

    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Create output with k=500 (would be missed by default)
    let (addr500, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 500)
        .unwrap();

    let outputs = vec![(addr500, Some(1_000_000))];

    // Default scan misses it
    let detector_default = PaymentDetector::new(&keys);
    assert!(detector_default
        .scan_transaction(&ephemeral, &outputs)
        .is_empty());

    // Recovery scan finds it
    let detector_recovery = PaymentDetector::with_config(&keys, ScanConfig::recovery());
    let found = detector_recovery.scan_transaction(&ephemeral, &outputs);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].k, 500);
}

#[test]
fn test_sp2_033_deep_recovery_scan() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let secp = Secp256k1::new();

    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Create output with k=5000
    let (addr5000, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 5000)
        .unwrap();

    let outputs = vec![(addr5000, Some(1_000_000))];

    // Regular recovery (max_k=1000) misses it
    let detector_recovery = PaymentDetector::with_config(&keys, ScanConfig::recovery());
    assert!(detector_recovery
        .scan_transaction(&ephemeral, &outputs)
        .is_empty());

    // Deep recovery (max_k=10000) finds it
    let detector_deep = PaymentDetector::with_config(&keys, ScanConfig::deep_recovery());
    let found = detector_deep.scan_transaction(&ephemeral, &outputs);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].k, 5000);
}

// =============================================================================
// SCAN CONFIG TESTS
// =============================================================================

#[test]
fn test_sp2_040_config_clamps_values() {
    // Below minimum
    let config = ScanConfig::new(0);
    assert_eq!(config.max_k(), 1);

    // Above maximum
    let config = ScanConfig::new(100_000);
    assert_eq!(config.max_k(), MAX_MAX_K);

    // Normal value
    let config = ScanConfig::new(500);
    assert_eq!(config.max_k(), 500);
}

#[test]
fn test_sp2_041_config_presets() {
    let default = ScanConfig::default();
    let recovery = ScanConfig::recovery();
    let deep = ScanConfig::deep_recovery();

    assert_eq!(default.max_k(), DEFAULT_MAX_K);
    assert_eq!(recovery.max_k(), 1000);
    assert_eq!(deep.max_k(), MAX_MAX_K);
}

// =============================================================================
// MULTI-RECIPIENT TESTS
// =============================================================================

#[test]
fn test_sp2_050_multi_recipient_single_tx() {
    // Two recipients in same transaction
    let keys_alice = GhostKeys::generate();
    let keys_bob = GhostKeys::generate();

    let secp = Secp256k1::new();
    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Outputs to Alice (k=0) and Bob (k=0)
    let (alice_addr, ephemeral, _) = keys_alice
        .ghost_id()
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
        .unwrap();
    let (bob_addr, _, _) = keys_bob
        .ghost_id()
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
        .unwrap();

    let outputs = vec![(alice_addr, Some(100_000)), (bob_addr, Some(200_000))];

    // Alice should find her payment
    let detector_alice = PaymentDetector::new(&keys_alice);
    let found_alice = detector_alice.scan_transaction(&ephemeral, &outputs);
    assert_eq!(found_alice.len(), 1);
    assert_eq!(found_alice[0].amount, Some(100_000));
    assert_eq!(found_alice[0].output_index, 0);

    // Bob should find his payment
    let detector_bob = PaymentDetector::new(&keys_bob);
    let found_bob = detector_bob.scan_transaction(&ephemeral, &outputs);
    assert_eq!(found_bob.len(), 1);
    assert_eq!(found_bob[0].amount, Some(200_000));
    assert_eq!(found_bob[0].output_index, 1);
}

#[test]
fn test_sp2_051_miner_and_node_reward_same_recipient() {
    // Scenario: Miner and node reward both go to same address
    // They need different k values
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let secp = Secp256k1::new();

    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Miner reward (k=0)
    let (miner_addr, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
        .unwrap();

    // Node reward (k=1)
    let (node_addr, _, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 1)
        .unwrap();

    let outputs = vec![
        (miner_addr, Some(312_500_000)), // 3.125 BTC miner reward
        (node_addr, Some(100_000)),      // 0.001 BTC node reward
    ];

    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &outputs);

    // Should find both
    assert_eq!(found.len(), 2);
    assert!(found
        .iter()
        .any(|p| p.k == 0 && p.amount == Some(312_500_000)));
    assert!(found.iter().any(|p| p.k == 1 && p.amount == Some(100_000)));
}

// =============================================================================
// QUICK CHECK TESTS
// =============================================================================

#[test]
fn test_sp2_060_quick_check_k0() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();

    let (addr, ephemeral, _) = ghost_id.derive_payment_address_v2_full(0).unwrap();

    let detector = PaymentDetector::new(&keys);
    assert!(detector.quick_check(&ephemeral, &addr));
}

#[test]
fn test_sp2_061_quick_check_misses_high_k() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let secp = Secp256k1::new();

    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // k=5 should be missed by quick_check (only checks k=0)
    let (addr5, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 5)
        .unwrap();

    let detector = PaymentDetector::new(&keys);
    assert!(!detector.quick_check(&ephemeral, &addr5));

    // But full scan should find it
    let found = detector.scan_transaction(&ephemeral, &[(addr5, None)]);
    assert_eq!(found.len(), 1);
}

#[test]
fn test_sp2_062_quick_check_rejects_others() {
    let keys = GhostKeys::generate();
    let other_keys = GhostKeys::generate();

    let (addr, ephemeral, _) = other_keys
        .ghost_id()
        .derive_payment_address_v2_full(0)
        .unwrap();

    let detector = PaymentDetector::new(&keys);
    assert!(!detector.quick_check(&ephemeral, &addr));
}

// =============================================================================
// EDGE CASES
// =============================================================================

#[test]
fn test_sp2_070_empty_outputs() {
    let keys = GhostKeys::generate();
    let secp = Secp256k1::new();
    let (_, ephemeral) = secp.generate_keypair(&mut OsRng);

    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &[]);

    assert!(found.is_empty());
}

#[test]
fn test_sp2_071_all_random_outputs() {
    let keys = GhostKeys::generate();
    let secp = Secp256k1::new();

    let (_, ephemeral) = secp.generate_keypair(&mut OsRng);
    let (_, random1) = secp.generate_keypair(&mut OsRng);
    let (_, random2) = secp.generate_keypair(&mut OsRng);

    let outputs = vec![(random1, Some(100_000)), (random2, Some(200_000))];

    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &outputs);

    assert!(found.is_empty());
}

#[test]
fn test_sp2_072_max_k_boundary() {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let secp = Secp256k1::new();

    let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

    // Create at exactly max_k boundary
    let (addr_at_max, ephemeral, _) = ghost_id
        .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, DEFAULT_MAX_K)
        .unwrap();

    let outputs = vec![(addr_at_max, Some(100_000))];

    // Should find it (max_k is inclusive)
    let detector = PaymentDetector::new(&keys);
    let found = detector.scan_transaction(&ephemeral, &outputs);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].k, DEFAULT_MAX_K);
}
