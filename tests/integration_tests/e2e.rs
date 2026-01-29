//! End-to-End Tests for Bitcoin Ghost
//!
//! These tests verify complete workflows across the entire stack.
//! Run with: cargo test --test integration e2e
//!
//! Test Categories:
//! - Ghost Keys lifecycle
//! - Ghost Lock management
//! - GSP protocol messages
//! - BUDS classification
//! - Wraith session management
//!
//! Note: Light wallet tests require the ghost-light-wallet binary crate.
//! For real network tests, use the signet test scripts.

// ============================================================================
// Ghost Keys E2E Tests
// ============================================================================

mod ghost_keys {
    use ghost_keys::{GhostId, GhostKeys};

    #[test]
    fn test_key_generation() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Ghost ID should be valid
        assert!(!ghost_id.to_string().is_empty());
    }

    #[test]
    fn test_key_uniqueness() {
        // Each generation should produce unique keys
        let keys1 = GhostKeys::generate();
        let keys2 = GhostKeys::generate();

        // Different generations should have different IDs
        assert_ne!(keys1.ghost_id().to_string(), keys2.ghost_id().to_string());
    }

    #[test]
    fn test_key_export_roundtrip() {
        let keys = GhostKeys::generate();
        let (scan_secret, spend_secret) = keys.export_secrets();

        // Secrets should be 32 bytes
        assert_eq!(scan_secret.len(), 32);
        assert_eq!(spend_secret.len(), 32);
    }

    #[test]
    fn test_ghost_id_parsing() {
        let keys = GhostKeys::generate();
        let ghost_id_str = keys.ghost_id().to_string();

        // Should be able to parse back using decode
        let parsed = GhostId::decode(&ghost_id_str);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_pubkey_export() {
        let keys = GhostKeys::generate();

        // Export pubkeys
        let export = keys.export();

        // Should have valid hex-encoded pubkeys (66 hex chars = 33 bytes)
        assert_eq!(export.scan_pubkey_hex.len(), 66);
        assert_eq!(export.spend_pubkey_hex.len(), 66);
        assert!(!export.ghost_id.is_empty());
    }

    #[test]
    fn test_lock_derivation() {
        let keys = GhostKeys::generate();

        // Derive lock pubkey at different indices
        let pubkey1 = keys.derive_lock_pubkey(0);
        let pubkey2 = keys.derive_lock_pubkey(1);

        // Different indices should produce different pubkeys
        assert_ne!(pubkey1, pubkey2);

        // Pubkeys should be 33 bytes (compressed)
        assert_eq!(pubkey1.len(), 33);
        assert_eq!(pubkey2.len(), 33);
    }

    #[test]
    fn test_recovery_derivation() {
        let keys = GhostKeys::generate();

        // Derive recovery pubkeys
        let recovery1 = keys.derive_recovery_pubkey(0);
        let recovery2 = keys.derive_recovery_pubkey(1);

        // Different indices should produce different pubkeys
        assert_ne!(recovery1, recovery2);
    }
}

// ============================================================================
// Ghost Locks E2E Tests
// ============================================================================

mod ghost_locks_tests {
    use ::ghost_locks::{Denomination, GhostLock, TimelockTier};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_lock_denominations() {
        // Test all denominations have increasing values
        assert!(Denomination::Micro.sats() < Denomination::Tiny.sats());
        assert!(Denomination::Tiny.sats() < Denomination::Small.sats());
        assert!(Denomination::Small.sats() < Denomination::Medium.sats());
        assert!(Denomination::Medium.sats() < Denomination::Large.sats());
    }

    #[test]
    fn test_denomination_values() {
        // Test specific values
        assert_eq!(Denomination::Micro.sats(), 10_000);
        assert_eq!(Denomination::Tiny.sats(), 100_000);
    }

    #[test]
    fn test_denomination_from_sats() {
        // from_sats should return exact denomination
        let denom = Denomination::from_sats(10_000).unwrap();
        assert_eq!(denom.sats(), 10_000);

        // closest_for_amount should return appropriate denomination
        let closest = Denomination::closest_for_amount(15_000).unwrap();
        assert_eq!(closest, Denomination::Micro); // Closest to 10,000
    }

    #[test]
    fn test_timelock_tiers() {
        // Test all tiers (Short=6mo, Standard=1yr, Long=2yr)
        assert!(TimelockTier::Short.blocks() < TimelockTier::Standard.blocks());
        assert!(TimelockTier::Standard.blocks() < TimelockTier::Long.blocks());
    }

    #[test]
    fn test_timelock_display() {
        assert!(!TimelockTier::Standard.to_string().is_empty());
        assert!(!TimelockTier::Short.to_string().is_empty());
    }

    #[test]
    fn test_lock_creation() {
        let secp = Secp256k1::new();

        // Create test keys (deterministic for testing)
        let lock_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let recovery_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let denomination = Denomination::Tiny; // 100,000 sats
        let creation_height = 800_000;

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            denomination,
            TimelockTier::Standard,
            creation_height,
        );

        assert!(lock.is_ok());
        let lock = lock.unwrap();

        // Lock should have correct properties
        assert_eq!(lock.sats(), 100_000);
        assert_eq!(lock.denomination(), Denomination::Tiny);
        assert_eq!(lock.creation_height(), creation_height);
    }

    #[test]
    fn test_lock_multiple_denominations() {
        let secp = Secp256k1::new();
        let lock_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let recovery_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();

        for denom in [
            Denomination::Micro,
            Denomination::Tiny,
            Denomination::Small,
            Denomination::Medium,
        ] {
            let lock = GhostLock::new(
                &secp,
                &lock_secret,
                &recovery_secret,
                denom,
                TimelockTier::Standard,
                800_000,
            );
            assert!(lock.is_ok());
            assert_eq!(lock.unwrap().sats(), denom.sats());
        }
    }

    #[test]
    fn test_lock_different_timelocks() {
        let secp = Secp256k1::new();
        let lock_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let recovery_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();

        // Test all available timelock tiers
        for tier in [
            TimelockTier::Short,
            TimelockTier::Standard,
            TimelockTier::Long,
        ] {
            let lock = GhostLock::new(
                &secp,
                &lock_secret,
                &recovery_secret,
                Denomination::Tiny,
                tier,
                800_000,
            );
            assert!(lock.is_ok());
            assert_eq!(lock.unwrap().timelock_tier(), tier);
        }
    }

    #[test]
    fn test_lock_recovery_height() {
        let secp = Secp256k1::new();
        let lock_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let recovery_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let creation_height = 800_000;

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Tiny,
            TimelockTier::Standard,
            creation_height,
        )
        .unwrap();

        // Recovery height should be after creation
        assert!(lock.recovery_height() > creation_height);

        // Check blocks until recovery
        assert!(lock.blocks_until_recovery(creation_height) > 0);
        assert!(!lock.is_recovery_available(creation_height));
    }

    #[test]
    fn test_lock_id_uniqueness() {
        let secp = Secp256k1::new();
        let lock_secret1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let lock_secret2 = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let recovery_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let lock1 = GhostLock::new(
            &secp,
            &lock_secret1,
            &recovery_secret,
            Denomination::Tiny,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        let lock2 = GhostLock::new(
            &secp,
            &lock_secret2,
            &recovery_secret,
            Denomination::Tiny,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        // Different keys should produce different lock IDs
        assert_ne!(lock1.lock_id(), lock2.lock_id());
        assert_ne!(lock1.lock_id_hex(), lock2.lock_id_hex());
    }
}

// ============================================================================
// GSP Protocol E2E Tests
// ============================================================================

mod gsp_protocol {
    use ghost_gsp_proto::{
        ClientMessage, PaymentMode, PaymentStatus, ServerMessage, WalletId, WalletProof,
    };

    #[test]
    fn test_wallet_id_creation() {
        let pubkey = [1u8; 32];
        let wallet_id = WalletId::from_pubkey(&pubkey);

        assert!(wallet_id.is_valid());
        assert_eq!(wallet_id.as_str().len(), 32);
    }

    #[test]
    fn test_wallet_id_deterministic() {
        let pubkey = [42u8; 32];
        let id1 = WalletId::from_pubkey(&pubkey);
        let id2 = WalletId::from_pubkey(&pubkey);

        assert_eq!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn test_wallet_id_different_keys() {
        let id1 = WalletId::from_pubkey(&[1u8; 32]);
        let id2 = WalletId::from_pubkey(&[2u8; 32]);

        assert_ne!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn test_wallet_proof_creation() {
        let pubkey = [1u8; 32];
        let proof = WalletProof::new("register", &pubkey);

        assert!(proof.is_timestamp_valid());
        assert_eq!(proof.action(), Some("register"));
    }

    #[test]
    fn test_wallet_proof_different_actions() {
        let pubkey = [1u8; 32];

        for action in ["register", "session", "jump", "payment"] {
            let proof = WalletProof::new(action, &pubkey);
            assert_eq!(proof.action(), Some(action));
        }
    }

    #[test]
    fn test_client_message_serialization() {
        let messages = vec![
            ClientMessage::GetBalance,
            ClientMessage::GetUtxos {
                min_confirmations: 6,
            },
            ClientMessage::GetGhostLocks,
            ClientMessage::Ping { timestamp: Some(0) },
            ClientMessage::SubscribeBalance,
            ClientMessage::SubscribePayments,
            ClientMessage::SubscribeLocks,
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_server_message_serialization() {
        let responses = vec![
            ServerMessage::BalanceUpdate {
                confirmed: 1_000_000,
                unconfirmed: 50_000,
                locked: 100_000,
            },
            ServerMessage::Pong {
                timestamp: Some(1704067200),
                server_time: 1704067201,
            },
            ServerMessage::Error {
                code: "TEST".to_string(),
                message: "Test error".to_string(),
                request_id: None,
            },
            ServerMessage::Subscribed {
                subscription: "balance".to_string(),
            },
        ];

        for resp in responses {
            let json = serde_json::to_string(&resp).unwrap();
            let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_payment_status_lifecycle() {
        // Early stages can cancel
        assert!(PaymentStatus::Preparing.can_cancel());
        assert!(PaymentStatus::PendingSignature.can_cancel());
        assert!(PaymentStatus::Signed.can_cancel());

        // Later stages cannot
        assert!(!PaymentStatus::Broadcast.can_cancel());
        assert!(!PaymentStatus::Mempool.can_cancel());
        assert!(!PaymentStatus::Confirmed.can_cancel());

        // Terminal statuses
        assert!(PaymentStatus::Confirmed.is_terminal());
        assert!(PaymentStatus::Failed.is_terminal());
        assert!(PaymentStatus::Cancelled.is_terminal());
        assert!(PaymentStatus::Expired.is_terminal());
    }

    #[test]
    fn test_payment_mode_default() {
        assert_eq!(PaymentMode::default(), PaymentMode::GhostPay);
    }

    #[test]
    fn test_auth_requirements() {
        // These require auth
        assert!(ClientMessage::GetBalance.requires_auth());
        assert!(ClientMessage::GetUtxos {
            min_confirmations: 1
        }
        .requires_auth());
        assert!(ClientMessage::GetGhostLocks.requires_auth());
        assert!(ClientMessage::SubscribeBalance.requires_auth());

        // These don't
        assert!(!ClientMessage::Ping { timestamp: None }.requires_auth());
        assert!(!ClientMessage::Authenticate {
            token: "test".to_string()
        }
        .requires_auth());
    }
}

// ============================================================================
// BUDS Classification E2E Tests
// ============================================================================

mod buds_classification {
    use ghost_buds::{BudsClassifier, BudsTier};

    #[test]
    fn test_classifier_initialization() {
        let classifier = BudsClassifier::new();
        // Classifier should initialize without panicking
        let _ = classifier;
    }

    #[test]
    fn test_tier_ordering() {
        // T0 is most preferred, T3 is least
        assert!(BudsTier::T0.value() < BudsTier::T1.value());
        assert!(BudsTier::T1.value() < BudsTier::T2.value());
        assert!(BudsTier::T2.value() < BudsTier::T3.value());
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(BudsTier::T0.to_string(), "T0");
        assert_eq!(BudsTier::T1.to_string(), "T1");
        assert_eq!(BudsTier::T2.to_string(), "T2");
        assert_eq!(BudsTier::T3.to_string(), "T3");
    }

    #[test]
    fn test_tier_from_value() {
        assert_eq!(BudsTier::from_value(0), Some(BudsTier::T0));
        assert_eq!(BudsTier::from_value(1), Some(BudsTier::T1));
        assert_eq!(BudsTier::from_value(2), Some(BudsTier::T2));
        assert_eq!(BudsTier::from_value(3), Some(BudsTier::T3));
        assert_eq!(BudsTier::from_value(99), None); // Invalid value
    }
}

// ============================================================================
// Wraith Protocol E2E Tests
// ============================================================================

mod wraith_protocol {
    use wraith_protocol::{ParticipantTier, Phase, SessionState, WraithDenomination, WraithSession};

    #[test]
    fn test_session_creation() {
        let session = WraithSession::new(ParticipantTier::Small, WraithDenomination::Small);

        // Session ID should be valid (32 bytes = 64 hex chars)
        let session_id_hex = session.session_id_hex();
        assert_eq!(session_id_hex.len(), 64);
        assert!(session_id_hex.chars().all(|c| c.is_ascii_hexdigit()));

        // Initial state should be WaitingForParticipants
        assert_eq!(session.state(), SessionState::WaitingForParticipants);
    }

    #[test]
    fn test_session_id_uniqueness() {
        let session1 = WraithSession::new(ParticipantTier::Small, WraithDenomination::Small);
        let session2 = WraithSession::new(ParticipantTier::Small, WraithDenomination::Small);

        assert_ne!(session1.session_id_hex(), session2.session_id_hex());
    }

    #[test]
    fn test_session_denominations() {
        for denom in WraithDenomination::all() {
            let session = WraithSession::new(ParticipantTier::Small, *denom);
            assert_eq!(session.denomination(), denom);
        }
    }

    #[test]
    fn test_phase_ordering() {
        // Phases should proceed in order based on number
        assert!(Phase::Split.number() < Phase::Merge.number());
    }

    #[test]
    fn test_phase_display() {
        assert!(!Phase::Split.to_string().is_empty());
        assert!(!Phase::Merge.to_string().is_empty());
    }

    #[test]
    fn test_phase_input_output_ratios() {
        // Split: 1 input -> n outputs
        assert_eq!(Phase::Split.input_ratio(), 1);
        assert!(Phase::Split.output_ratio() > 1);

        // Merge: n inputs -> 1 output
        assert!(Phase::Merge.input_ratio() > 1);
        assert_eq!(Phase::Merge.output_ratio(), 1);
    }

    #[test]
    fn test_participant_tiers() {
        // Larger tiers should have higher minimum participants
        assert!(ParticipantTier::Small.min_participants() < ParticipantTier::Medium.min_participants());
        assert!(ParticipantTier::Medium.min_participants() < ParticipantTier::Large.min_participants());
    }
}

// ============================================================================
// Consensus E2E Tests
// ============================================================================

mod consensus {
    use ghost_common::VoteType;

    #[test]
    fn test_vote_types_serialization() {
        let votes = vec![
            VoteType::PayoutApproval,
            VoteType::ElderRevocation,
            VoteType::ShareAllocation,
        ];

        for vote in votes {
            let json = serde_json::to_string(&vote).unwrap();
            let parsed: VoteType = serde_json::from_str(&json).unwrap();
            assert_eq!(vote, parsed);
        }
    }

    #[test]
    fn test_bft_threshold_calculation() {
        // 67% threshold for BFT
        // For n nodes, need ceil(2n/3) votes

        fn required_votes(total: usize) -> usize {
            (total * 2 + 2) / 3 // Ceiling of 2/3
        }

        assert_eq!(required_votes(3), 2); // 2 out of 3
        assert_eq!(required_votes(4), 3); // 3 out of 4
        assert_eq!(required_votes(5), 4); // 4 out of 5
        assert_eq!(required_votes(6), 4); // 4 out of 6
        assert_eq!(required_votes(7), 5); // 5 out of 7
        assert_eq!(required_votes(10), 7); // 7 out of 10
    }

    #[test]
    fn test_quorum_scenarios() {
        fn has_quorum(votes: usize, total: usize) -> bool {
            votes >= (total * 2 + 2) / 3
        }

        // 3 node cluster
        assert!(!has_quorum(1, 3)); // 1/3 - no quorum
        assert!(has_quorum(2, 3)); // 2/3 - quorum!
        assert!(has_quorum(3, 3)); // 3/3 - quorum!

        // 5 node cluster
        assert!(!has_quorum(2, 5)); // 2/5 - no quorum
        assert!(!has_quorum(3, 5)); // 3/5 - no quorum
        assert!(has_quorum(4, 5)); // 4/5 - quorum!
        assert!(has_quorum(5, 5)); // 5/5 - quorum!
    }
}

// ============================================================================
// Full Stack Integration Tests
// ============================================================================

mod full_stack {
    use bitcoin::secp256k1::Secp256k1;

    /// Test that all major crates compile together
    #[test]
    fn test_crate_imports() {
        use ::ghost_buds::BudsTier;
        use ::ghost_common::VoteType;
        use ::ghost_gsp_proto::ClientMessage;
        use ::ghost_keys::GhostKeys;
        use ::ghost_locks::TimelockTier;
        use ::wraith_protocol::Phase;

        // If this compiles, all crates are compatible
        let _ = BudsTier::T0;
        let _ = VoteType::PayoutApproval;
        let _ = ClientMessage::GetBalance;
        let _ = GhostKeys::generate();
        let _ = TimelockTier::Standard;
        let _ = Phase::Split;
    }

    /// Test complete lock creation flow
    #[test]
    fn test_lock_creation_flow() {
        use ::ghost_keys::GhostKeys;
        use ::ghost_locks::{Denomination, GhostLock, TimelockTier};

        // 1. Generate keys
        let keys = GhostKeys::generate();

        // 2. Determine denomination for amount
        let amount = 100_000; // 0.001 BTC (Tiny denomination)
        let denomination = Denomination::from_sats(amount).unwrap();
        assert_eq!(denomination.sats(), amount);

        // 3. Create lock using derived secrets
        let secp = Secp256k1::new();
        let lock_secret = keys.derive_lock_secret(0).unwrap();
        let recovery_secret = keys.derive_recovery_secret(0).unwrap();

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            denomination,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        // 4. Lock should have correct value
        assert_eq!(lock.sats(), amount);

        // 5. Lock should have unique ID
        assert_eq!(lock.lock_id_hex().len(), 64); // 32 bytes = 64 hex chars
    }

    /// Test GSP authentication flow
    #[test]
    fn test_gsp_auth_flow() {
        use ::ghost_gsp_proto::{ClientMessage, ServerMessage, WalletId, WalletProof};

        // 1. Create a test pubkey (32 bytes for wallet ID)
        let test_pubkey: [u8; 32] = [42u8; 32];

        // 2. Create wallet ID
        let wallet_id = WalletId::from_pubkey(&test_pubkey);
        assert!(wallet_id.is_valid());

        // 3. Create wallet proof
        let proof = WalletProof::new("register", &test_pubkey);
        assert!(proof.is_timestamp_valid());

        // 4. Simulate auth message
        let auth_msg = ClientMessage::Authenticate {
            token: "test_token".to_string(),
        };
        let json = serde_json::to_string(&auth_msg).unwrap();
        assert!(json.contains("authenticate"));

        // 5. Simulate success response
        let success = ServerMessage::AuthResult {
            success: true,
            wallet_id: Some(wallet_id.as_str().to_string()),
            error: None,
        };
        let response_json = serde_json::to_string(&success).unwrap();
        assert!(response_json.contains("true"));
    }

    /// Test key derivation flow
    #[test]
    fn test_key_derivation_flow() {
        use ::ghost_keys::GhostKeys;

        // 1. Generate keys
        let keys = GhostKeys::generate();

        // 2. Get ghost ID
        let ghost_id = keys.ghost_id();
        let ghost_id_str = ghost_id.to_string();
        assert!(!ghost_id_str.is_empty());

        // 3. Derive lock pubkey
        let lock_pubkey = keys.derive_lock_pubkey(0);
        assert_eq!(lock_pubkey.len(), 33);

        // 4. Export public data (hex-encoded)
        let export = keys.export();
        assert_eq!(export.scan_pubkey_hex.len(), 66); // 33 bytes = 66 hex chars
        assert_eq!(export.spend_pubkey_hex.len(), 66);

        // 5. Export secrets (for backup)
        let (scan_secret, spend_secret) = keys.export_secrets();
        assert_eq!(scan_secret.len(), 32);
        assert_eq!(spend_secret.len(), 32);
    }

    /// Test GhostLock with GhostKeys integration
    #[test]
    fn test_ghost_keys_to_lock_integration() {
        use ::ghost_keys::GhostKeys;
        use ::ghost_locks::{Denomination, GhostLock, TimelockTier};

        let secp = Secp256k1::new();
        let keys = GhostKeys::generate();

        // Derive lock and recovery secrets from GhostKeys
        let lock_secret = keys.derive_lock_secret(0).unwrap();
        let recovery_secret = keys.derive_recovery_secret(0).unwrap();

        // Create lock
        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small, // 0.01 BTC
            TimelockTier::Standard,
            850_000,
        )
        .unwrap();

        // Verify lock properties
        assert_eq!(lock.sats(), 1_000_000);
        assert_eq!(lock.timelock_tier(), TimelockTier::Standard);
        assert!(!lock.is_recovery_available(850_000));
    }
}
