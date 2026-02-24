//! GSP Payment & Lock Message Integration Tests (820-849)
//!
//! Tests for payment messages, lock messages, lock state, instant payments,
//! reorg notifications, and full flow simulations in the ghost-gsp-proto crate.
//!
//! Run with: cargo test --test integration gsp_payment_messages

use ghost_gsp_proto::{
    ClientMessage, GhostLockStatus, JumpPriority, L2ReorgReason, LockStateChangeType,
    LockStateSnapshot, PaymentMode, PaymentStatus, ReorgLayer, ServerMessage, WalletProof,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a WalletProof with a valid structure for testing.
/// The signature is a dummy 64-byte hex string, not cryptographically valid,
/// but structurally correct for serialization round-trip tests.
fn make_test_proof(action: &str) -> WalletProof {
    let pubkey = [1u8; 32];
    let mut proof = WalletProof::new(action, &pubkey).expect("nonce generation failed");
    proof.signature = hex::encode([2u8; 64]);
    proof
}

/// Create a PreparedPayment for testing round-trips.
fn make_test_prepared_payment() -> ghost_gsp_proto::PreparedPayment {
    ghost_gsp_proto::PreparedPayment {
        payment_id: "pay-test-001".to_string(),
        mode: PaymentMode::GhostPay,
        recipient_address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
        original_recipient: "ghost1testrecipient".to_string(),
        amount_sats: 50_000,
        fee_sats: 500,
        total_sats: 50_500,
        sighash: hex::encode([0xab; 32]),
        signing_method: "schnorr".to_string(),
        expires_at: 1_900_000_000, // Far future timestamp for testing
        status: PaymentStatus::PendingSignature,
        inputs: vec![],
        outputs: vec![],
        memo: Some("test payment".to_string()),
        encrypted_metadata: None,
        ephemeral_pubkey: None,
    }
}

/// Create a LockStateSnapshot for testing.
fn make_test_snapshot() -> LockStateSnapshot {
    LockStateSnapshot {
        state: "Active".to_string(),
        balance_sats: 500_000,
        confirmations: 10,
        jump_urgency: 0.05,
        in_mempool: false,
        pending_l2_sats: 0,
        max_instant_sats: 100_000,
        current_height: 800_100,
    }
}

// ============================================================================
// Payment Messages (820-826)
// ============================================================================

mod payment_messages {
    use super::*;

    /// 820: ClientMessage::PreparePayment round-trips through JSON
    #[test]
    fn test_820_prepare_payment_roundtrip() {
        let proof = make_test_proof("payment");
        let msg = ClientMessage::PreparePayment {
            recipient: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            amount_sats: 100_000,
            mode: PaymentMode::GhostPay,
            proof,
            memo: Some("test memo".to_string()),
            encrypted_metadata: Some("dGVzdA==".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"prepare_payment\""));
        assert!(json.contains("\"amount_sats\":100000"));
        assert!(json.contains("\"memo\":\"test memo\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::PreparePayment {
                recipient,
                amount_sats,
                mode,
                memo,
                encrypted_metadata,
                ..
            } => {
                assert_eq!(recipient, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
                assert_eq!(amount_sats, 100_000);
                assert_eq!(mode, PaymentMode::GhostPay);
                assert_eq!(memo, Some("test memo".to_string()));
                assert_eq!(encrypted_metadata, Some("dGVzdA==".to_string()));
            }
            _ => panic!("Expected PreparePayment, got {:?}", parsed),
        }
    }

    /// 821: PaymentMode::GhostPay serializes as "ghostpay"
    #[test]
    fn test_821_payment_mode_ghostpay_serialization() {
        let mode = PaymentMode::GhostPay;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"ghostpay\"");

        let parsed: PaymentMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PaymentMode::GhostPay);
    }

    /// 822: PaymentMode::Wraith serializes as "wraith"
    #[test]
    fn test_822_payment_mode_wraith_serialization() {
        let mode = PaymentMode::Wraith;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"wraith\"");

        let parsed: PaymentMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PaymentMode::Wraith);

        // Also verify Confidential while we are here
        let mode_c = PaymentMode::Confidential;
        let json_c = serde_json::to_string(&mode_c).unwrap();
        assert_eq!(json_c, "\"confidential\"");
    }

    /// 823: ServerMessage::PaymentPrepared success round-trips
    #[test]
    fn test_823_payment_prepared_success_roundtrip() {
        let prepared = make_test_prepared_payment();
        let msg = ServerMessage::PaymentPrepared {
            success: true,
            payment: Some(prepared),
            error: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"payment_prepared\""));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"payment_id\":\"pay-test-001\""));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::PaymentPrepared {
                success,
                payment,
                error,
            } => {
                assert!(success);
                assert!(error.is_none());
                let p = payment.expect("payment should be present");
                assert_eq!(p.payment_id, "pay-test-001");
                assert_eq!(p.amount_sats, 50_000);
                assert_eq!(p.fee_sats, 500);
                assert_eq!(p.total_sats, 50_500);
                assert_eq!(p.mode, PaymentMode::GhostPay);
                assert_eq!(p.status, PaymentStatus::PendingSignature);
            }
            _ => panic!("Expected PaymentPrepared"),
        }
    }

    /// 824: ClientMessage::SubmitSignedPayment round-trips
    #[test]
    fn test_824_submit_signed_payment_roundtrip() {
        let msg = ClientMessage::SubmitSignedPayment {
            payment_id: "pay-test-002".to_string(),
            signature: hex::encode([0xaa; 64]),
            public_key: hex::encode([0xbb; 32]),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"submit_signed_payment\""));
        assert!(json.contains("\"payment_id\":\"pay-test-002\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::SubmitSignedPayment {
                payment_id,
                signature,
                public_key,
            } => {
                assert_eq!(payment_id, "pay-test-002");
                assert_eq!(signature, hex::encode([0xaa; 64]));
                assert_eq!(public_key, hex::encode([0xbb; 32]));
            }
            _ => panic!("Expected SubmitSignedPayment"),
        }
    }

    /// 825: ServerMessage::PaymentSubmitted success fields correct
    #[test]
    fn test_825_payment_submitted_success() {
        let msg = ServerMessage::PaymentSubmitted {
            success: true,
            payment_id: "pay-test-003".to_string(),
            txid: Some(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            ),
            error: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"payment_submitted\""));
        assert!(json.contains("\"success\":true"));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::PaymentSubmitted {
                success,
                payment_id,
                txid,
                error,
            } => {
                assert!(success);
                assert_eq!(payment_id, "pay-test-003");
                assert!(txid.is_some());
                assert_eq!(txid.unwrap().len(), 64);
                assert!(error.is_none());
            }
            _ => panic!("Expected PaymentSubmitted"),
        }
    }

    /// 826: ServerMessage::PaymentSubmitted failure with error field
    #[test]
    fn test_826_payment_submitted_failure() {
        let msg = ServerMessage::PaymentSubmitted {
            success: false,
            payment_id: "pay-test-004".to_string(),
            txid: None,
            error: Some("Insufficient funds".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::PaymentSubmitted {
                success,
                payment_id,
                txid,
                error,
            } => {
                assert!(!success);
                assert_eq!(payment_id, "pay-test-004");
                assert!(txid.is_none());
                assert_eq!(error.unwrap(), "Insufficient funds");
            }
            _ => panic!("Expected PaymentSubmitted"),
        }
    }
}

// ============================================================================
// Lock Messages (827-833)
// ============================================================================

mod lock_messages {
    use super::*;

    /// 827: ClientMessage::PrepareGhostLock round-trips
    #[test]
    fn test_827_prepare_ghost_lock_roundtrip() {
        let owner_pubkey = hex::encode([0x03; 32]);
        let msg = ClientMessage::PrepareGhostLock {
            owner_pubkey: owner_pubkey.clone(),
            capacity_sats: 1_000_000,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"prepare_ghost_lock\""));
        assert!(json.contains("\"capacity_sats\":1000000"));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::PrepareGhostLock {
                owner_pubkey: pk,
                capacity_sats,
            } => {
                assert_eq!(pk, owner_pubkey);
                assert_eq!(capacity_sats, 1_000_000);
            }
            _ => panic!("Expected PrepareGhostLock"),
        }
    }

    /// 828: ServerMessage::LockPrepared success fields correct
    #[test]
    fn test_828_lock_prepared_success() {
        let msg = ServerMessage::LockPrepared {
            success: true,
            lock_id: Some("lock-001".to_string()),
            funding_address: Some("bc1qfundingaddr".to_string()),
            required_sats: Some(1_000_546),
            error: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"lock_prepared\""));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::LockPrepared {
                success,
                lock_id,
                funding_address,
                required_sats,
                error,
            } => {
                assert!(success);
                assert_eq!(lock_id.unwrap(), "lock-001");
                assert_eq!(funding_address.unwrap(), "bc1qfundingaddr");
                assert_eq!(required_sats.unwrap(), 1_000_546);
                assert!(error.is_none());
            }
            _ => panic!("Expected LockPrepared"),
        }
    }

    /// 829: ServerMessage::LockPrepared failure with error
    #[test]
    fn test_829_lock_prepared_failure() {
        let msg = ServerMessage::LockPrepared {
            success: false,
            lock_id: None,
            funding_address: None,
            required_sats: None,
            error: Some("Capacity below dust limit".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::LockPrepared {
                success,
                lock_id,
                error,
                ..
            } => {
                assert!(!success);
                assert!(lock_id.is_none());
                assert_eq!(error.unwrap(), "Capacity below dust limit");
            }
            _ => panic!("Expected LockPrepared"),
        }
    }

    /// 830: ClientMessage::RequestJump round-trips
    #[test]
    fn test_830_request_jump_roundtrip() {
        let proof = make_test_proof("jump");
        let msg = ClientMessage::RequestJump {
            lock_id: "lock-002".to_string(),
            priority: "urgent".to_string(),
            target_address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            proof,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"request_jump\""));
        assert!(json.contains("\"priority\":\"urgent\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::RequestJump {
                lock_id,
                priority,
                target_address,
                ..
            } => {
                assert_eq!(lock_id, "lock-002");
                assert_eq!(priority, "urgent");
                assert_eq!(target_address, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
            }
            _ => panic!("Expected RequestJump"),
        }
    }

    /// 831: ServerMessage::JumpRequested round-trips
    #[test]
    fn test_831_jump_requested_roundtrip() {
        let msg = ServerMessage::JumpRequested {
            success: true,
            lock_id: "lock-002".to_string(),
            jump_txid: Some("ff".repeat(32)),
            error: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"jump_requested\""));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::JumpRequested {
                success,
                lock_id,
                jump_txid,
                error,
            } => {
                assert!(success);
                assert_eq!(lock_id, "lock-002");
                assert_eq!(jump_txid.unwrap(), "ff".repeat(32));
                assert!(error.is_none());
            }
            _ => panic!("Expected JumpRequested"),
        }
    }

    /// 832: All GhostLockStatus variants serialize/deserialize correctly
    #[test]
    fn test_832_ghost_lock_status_all_variants() {
        let variants = vec![
            (GhostLockStatus::Pending, "\"pending\""),
            (GhostLockStatus::Active, "\"active\""),
            (GhostLockStatus::InUse, "\"in_use\""),
            (GhostLockStatus::Jumping, "\"jumping\""),
            (GhostLockStatus::Spent, "\"spent\""),
            (GhostLockStatus::Recovering, "\"recovering\""),
            (GhostLockStatus::Recovered, "\"recovered\""),
            (GhostLockStatus::Invalid, "\"invalid\""),
            (GhostLockStatus::Unknown, "\"unknown\""),
        ];

        let mut seen_strings = std::collections::HashSet::new();
        for (status, expected_json) in &variants {
            let json = serde_json::to_string(status).unwrap();
            assert_eq!(
                &json, expected_json,
                "GhostLockStatus::{:?} should serialize to {}",
                status, expected_json
            );
            // Verify uniqueness
            assert!(
                seen_strings.insert(json.clone()),
                "Duplicate serialization for {:?}",
                status
            );
            // Round-trip
            let parsed: GhostLockStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, parsed);
        }
    }

    /// 833: All JumpPriority variants serialize/deserialize
    #[test]
    fn test_833_jump_priority_all_variants() {
        let variants = vec![
            (JumpPriority::Normal, "\"normal\""),
            (JumpPriority::High, "\"high\""),
            (JumpPriority::Urgent, "\"urgent\""),
        ];

        let mut seen_strings = std::collections::HashSet::new();
        for (priority, expected_json) in &variants {
            let json = serde_json::to_string(priority).unwrap();
            assert_eq!(&json, expected_json);
            assert!(seen_strings.insert(json.clone()));
            let parsed: JumpPriority = serde_json::from_str(&json).unwrap();
            assert_eq!(*priority, parsed);
        }

        // Verify default is Normal
        assert_eq!(JumpPriority::default(), JumpPriority::Normal);
    }
}

// ============================================================================
// Lock State & Instant Payments (834-839)
// ============================================================================

mod lock_state_and_instant {
    use super::*;

    /// 834: LockStateSnapshot round-trips through JSON
    #[test]
    fn test_834_lock_state_snapshot_roundtrip() {
        let snapshot = make_test_snapshot();

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("\"state\":\"Active\""));
        assert!(json.contains("\"balance_sats\":500000"));
        assert!(json.contains("\"confirmations\":10"));

        let parsed: LockStateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.state, "Active");
        assert_eq!(parsed.balance_sats, 500_000);
        assert_eq!(parsed.confirmations, 10);
        assert!((parsed.jump_urgency - 0.05).abs() < f32::EPSILON);
        assert!(!parsed.in_mempool);
        assert_eq!(parsed.pending_l2_sats, 0);
        assert_eq!(parsed.max_instant_sats, 100_000);
        assert_eq!(parsed.current_height, 800_100);
    }

    /// 835: All LockStateChangeType variants are distinct
    #[test]
    fn test_835_lock_state_change_type_all_distinct() {
        let variants = vec![
            LockStateChangeType::BalanceChange,
            LockStateChangeType::StateTransition,
            LockStateChangeType::Confirmation,
            LockStateChangeType::JumpUrgency,
            LockStateChangeType::MempoolChange,
            LockStateChangeType::PendingL2Change,
        ];

        let mut seen = std::collections::HashSet::new();
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert!(
                seen.insert(json.clone()),
                "Duplicate serialization: {} for {:?}",
                json,
                variant
            );
            // Round-trip
            let parsed: LockStateChangeType = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, parsed);
        }
        assert_eq!(seen.len(), 6, "Expected exactly 6 distinct variants");
    }

    /// 836: ClientMessage::CheckInstantCapability round-trips
    #[test]
    fn test_836_check_instant_capability_roundtrip() {
        let msg = ClientMessage::CheckInstantCapability {
            lock_id: "lock-instant-001".to_string(),
            amount_sats: 50_000,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"check_instant_capability\""));
        assert!(json.contains("\"lock_id\":\"lock-instant-001\""));
        assert!(json.contains("\"amount_sats\":50000"));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::CheckInstantCapability {
                lock_id,
                amount_sats,
            } => {
                assert_eq!(lock_id, "lock-instant-001");
                assert_eq!(amount_sats, 50_000);
            }
            _ => panic!("Expected CheckInstantCapability"),
        }
    }

    /// 837: ServerMessage::InstantCapabilityResult round-trips
    #[test]
    fn test_837_instant_capability_result_roundtrip() {
        let msg = ServerMessage::InstantCapabilityResult {
            lock_id: "lock-instant-001".to_string(),
            capable: true,
            max_instant_sats: 100_000,
            confidence: 0.95,
            valid_until_height: 800_200,
            conditions_met: 0b1111_1111,
            conditions_failed: 0b0000_0000,
            error: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"instant_capability_result\""));
        assert!(json.contains("\"capable\":true"));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::InstantCapabilityResult {
                lock_id,
                capable,
                max_instant_sats,
                confidence,
                valid_until_height,
                conditions_met,
                conditions_failed,
                error,
            } => {
                assert_eq!(lock_id, "lock-instant-001");
                assert!(capable);
                assert_eq!(max_instant_sats, 100_000);
                assert!((confidence - 0.95).abs() < f32::EPSILON);
                assert_eq!(valid_until_height, 800_200);
                assert_eq!(conditions_met, 0xFF);
                assert_eq!(conditions_failed, 0x00);
                assert!(error.is_none());
            }
            _ => panic!("Expected InstantCapabilityResult"),
        }
    }

    /// 838: ClientMessage::SubscribeLockState / UnsubscribeLockState round-trip
    #[test]
    fn test_838_subscribe_unsubscribe_lock_state() {
        // Subscribe
        let sub_msg = ClientMessage::SubscribeLockState {
            lock_id: "lock-sub-001".to_string(),
        };
        let sub_json = serde_json::to_string(&sub_msg).unwrap();
        assert!(sub_json.contains("\"type\":\"subscribe_lock_state\""));

        let sub_parsed: ClientMessage = serde_json::from_str(&sub_json).unwrap();
        match sub_parsed {
            ClientMessage::SubscribeLockState { lock_id } => {
                assert_eq!(lock_id, "lock-sub-001");
            }
            _ => panic!("Expected SubscribeLockState"),
        }

        // Unsubscribe
        let unsub_msg = ClientMessage::UnsubscribeLockState {
            lock_id: "lock-sub-001".to_string(),
        };
        let unsub_json = serde_json::to_string(&unsub_msg).unwrap();
        assert!(unsub_json.contains("\"type\":\"unsubscribe_lock_state\""));

        let unsub_parsed: ClientMessage = serde_json::from_str(&unsub_json).unwrap();
        match unsub_parsed {
            ClientMessage::UnsubscribeLockState { lock_id } => {
                assert_eq!(lock_id, "lock-sub-001");
            }
            _ => panic!("Expected UnsubscribeLockState"),
        }
    }

    /// 839: All PaymentStatus variants tested for is_terminal() / can_cancel()
    #[test]
    fn test_839_payment_status_terminal_and_cancellable() {
        // Terminal states: Confirmed, Failed, Cancelled, Expired
        assert!(PaymentStatus::Confirmed.is_terminal());
        assert!(PaymentStatus::Failed.is_terminal());
        assert!(PaymentStatus::Cancelled.is_terminal());
        assert!(PaymentStatus::Expired.is_terminal());

        // Non-terminal states
        assert!(!PaymentStatus::Preparing.is_terminal());
        assert!(!PaymentStatus::PendingSignature.is_terminal());
        assert!(!PaymentStatus::Signed.is_terminal());
        assert!(!PaymentStatus::Broadcast.is_terminal());
        assert!(!PaymentStatus::Mempool.is_terminal());

        // Cancellable states: Preparing, PendingSignature, Signed
        assert!(PaymentStatus::Preparing.can_cancel());
        assert!(PaymentStatus::PendingSignature.can_cancel());
        assert!(PaymentStatus::Signed.can_cancel());

        // Non-cancellable states
        assert!(!PaymentStatus::Broadcast.can_cancel());
        assert!(!PaymentStatus::Mempool.can_cancel());
        assert!(!PaymentStatus::Confirmed.can_cancel());
        assert!(!PaymentStatus::Failed.can_cancel());
        assert!(!PaymentStatus::Cancelled.can_cancel());
        assert!(!PaymentStatus::Expired.can_cancel());

        // Verify all statuses serialize uniquely
        let all_statuses = vec![
            PaymentStatus::Preparing,
            PaymentStatus::PendingSignature,
            PaymentStatus::Signed,
            PaymentStatus::Broadcast,
            PaymentStatus::Mempool,
            PaymentStatus::Confirmed,
            PaymentStatus::Failed,
            PaymentStatus::Cancelled,
            PaymentStatus::Expired,
        ];
        let mut seen = std::collections::HashSet::new();
        for status in &all_statuses {
            let json = serde_json::to_string(status).unwrap();
            assert!(seen.insert(json.clone()), "Duplicate: {}", json);
            let parsed: PaymentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, parsed);
        }
        assert_eq!(seen.len(), 9);
    }
}

// ============================================================================
// Reorg Messages (840-844)
// ============================================================================

mod reorg_messages {
    use super::*;

    /// 840: ServerMessage::L1ReorgDetected round-trips
    #[test]
    fn test_840_l1_reorg_detected_roundtrip() {
        let msg = ServerMessage::L1ReorgDetected {
            reorg_height: 800_050,
            depth: 3,
            old_tip: "aa".repeat(32),
            new_tip: "bb".repeat(32),
            affected_payments: vec!["pay-001".to_string(), "pay-002".to_string()],
            affected_locks: vec!["lock-001".to_string()],
            detected_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"l1_reorg_detected\""));
        assert!(json.contains("\"reorg_height\":800050"));
        assert!(json.contains("\"depth\":3"));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::L1ReorgDetected {
                reorg_height,
                depth,
                old_tip,
                new_tip,
                affected_payments,
                affected_locks,
                detected_at,
            } => {
                assert_eq!(reorg_height, 800_050);
                assert_eq!(depth, 3);
                assert_eq!(old_tip, "aa".repeat(32));
                assert_eq!(new_tip, "bb".repeat(32));
                assert_eq!(affected_payments.len(), 2);
                assert_eq!(affected_payments[0], "pay-001");
                assert_eq!(affected_locks.len(), 1);
                assert_eq!(detected_at, 1_700_000_000);
            }
            _ => panic!("Expected L1ReorgDetected"),
        }
    }

    /// 841: ServerMessage::L2ReorgDetected round-trips with all L2ReorgReason variants
    #[test]
    fn test_841_l2_reorg_detected_all_reasons() {
        let reasons = vec![
            (L2ReorgReason::ForkResolution, "\"fork_resolution\""),
            (L2ReorgReason::Equivocation, "\"equivocation\""),
            (L2ReorgReason::NetworkPartition, "\"network_partition\""),
            (L2ReorgReason::SnapshotRestore, "\"snapshot_restore\""),
            (L2ReorgReason::ManualRollback, "\"manual_rollback\""),
        ];

        for (reason, expected_json) in &reasons {
            // Verify standalone serialization
            let reason_json = serde_json::to_string(reason).unwrap();
            assert_eq!(
                &reason_json, expected_json,
                "L2ReorgReason::{:?} mismatch",
                reason
            );

            // Full message round-trip with this reason
            let msg = ServerMessage::L2ReorgDetected {
                reorg_height: 500,
                depth: 2,
                old_state_root: "cc".repeat(32),
                new_state_root: "dd".repeat(32),
                reason: *reason,
                affected_payments: vec!["pay-l2-001".to_string()],
                transfers_rolled_back: 5,
                detected_at: 1_700_001_000,
            };

            let json = serde_json::to_string(&msg).unwrap();
            assert!(json.contains("\"type\":\"l2_reorg_detected\""));

            let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
            match parsed {
                ServerMessage::L2ReorgDetected {
                    reorg_height,
                    depth,
                    reason: parsed_reason,
                    transfers_rolled_back,
                    ..
                } => {
                    assert_eq!(reorg_height, 500);
                    assert_eq!(depth, 2);
                    assert_eq!(parsed_reason, *reason);
                    assert_eq!(transfers_rolled_back, 5);
                }
                _ => panic!("Expected L2ReorgDetected for reason {:?}", reason),
            }
        }
    }

    /// 842: ServerMessage::PaymentReorged round-trips with both ReorgLayer::L1/L2
    #[test]
    fn test_842_payment_reorged_both_layers() {
        for layer in [ReorgLayer::L1, ReorgLayer::L2] {
            let msg = ServerMessage::PaymentReorged {
                payment_id: "pay-reorg-001".to_string(),
                layer,
                old_confirmations: 3,
                new_confirmations: 0,
                new_status: PaymentStatus::Mempool,
                reason: format!("{:?} chain reorg reverted confirmations", layer),
            };

            let json = serde_json::to_string(&msg).unwrap();
            assert!(json.contains("\"type\":\"payment_reorged\""));

            let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
            match parsed {
                ServerMessage::PaymentReorged {
                    payment_id,
                    layer: parsed_layer,
                    old_confirmations,
                    new_confirmations,
                    new_status,
                    ..
                } => {
                    assert_eq!(payment_id, "pay-reorg-001");
                    assert_eq!(parsed_layer, layer);
                    assert_eq!(old_confirmations, 3);
                    assert_eq!(new_confirmations, 0);
                    assert_eq!(new_status, PaymentStatus::Mempool);
                }
                _ => panic!("Expected PaymentReorged for layer {:?}", layer),
            }
        }

        // Also verify ReorgLayer serialization
        assert_eq!(serde_json::to_string(&ReorgLayer::L1).unwrap(), "\"l1\"");
        assert_eq!(serde_json::to_string(&ReorgLayer::L2).unwrap(), "\"l2\"");
    }

    /// 843: ServerMessage::LockReorged round-trips
    #[test]
    fn test_843_lock_reorged_roundtrip() {
        let msg = ServerMessage::LockReorged {
            lock_id: "lock-reorg-001".to_string(),
            layer: ReorgLayer::L1,
            old_state: "Active".to_string(),
            new_state: "Pending".to_string(),
            old_confirmations: 6,
            new_confirmations: 0,
            reason: "L1 reorg reverted lock funding confirmation".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"lock_reorged\""));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::LockReorged {
                lock_id,
                layer,
                old_state,
                new_state,
                old_confirmations,
                new_confirmations,
                reason,
            } => {
                assert_eq!(lock_id, "lock-reorg-001");
                assert_eq!(layer, ReorgLayer::L1);
                assert_eq!(old_state, "Active");
                assert_eq!(new_state, "Pending");
                assert_eq!(old_confirmations, 6);
                assert_eq!(new_confirmations, 0);
                assert!(reason.contains("reorg"));
            }
            _ => panic!("Expected LockReorged"),
        }
    }

    /// 844: ServerMessage::ReorgResolved round-trips
    #[test]
    fn test_844_reorg_resolved_roundtrip() {
        for layer in [ReorgLayer::L1, ReorgLayer::L2] {
            let tip = match layer {
                ReorgLayer::L1 => "ee".repeat(32),
                ReorgLayer::L2 => "ff".repeat(32),
            };

            let msg = ServerMessage::ReorgResolved {
                layer,
                height: 800_060,
                tip: tip.clone(),
                confirmations_since_reorg: 6,
            };

            let json = serde_json::to_string(&msg).unwrap();
            assert!(json.contains("\"type\":\"reorg_resolved\""));

            let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
            match parsed {
                ServerMessage::ReorgResolved {
                    layer: parsed_layer,
                    height,
                    tip: parsed_tip,
                    confirmations_since_reorg,
                } => {
                    assert_eq!(parsed_layer, layer);
                    assert_eq!(height, 800_060);
                    assert_eq!(parsed_tip, tip);
                    assert_eq!(confirmations_since_reorg, 6);
                }
                _ => panic!("Expected ReorgResolved for layer {:?}", layer),
            }
        }
    }
}

// ============================================================================
// Flow Simulations (845-849)
// ============================================================================

mod flow_simulations {
    use super::*;

    /// 845: Full payment flow: Auth -> PreparePayment -> PaymentPrepared -> Submit -> Submitted
    #[test]
    fn test_845_full_payment_flow() {
        // Step 1: Authenticate
        let auth_msg = ClientMessage::Authenticate {
            token: "eyJhbGciOiJIUzI1NiJ9.test.signature".to_string(),
        };
        let auth_json = serde_json::to_string(&auth_msg).unwrap();
        let _: ClientMessage = serde_json::from_str(&auth_json).unwrap();

        // Server responds with auth result
        let auth_result = ServerMessage::AuthResult {
            success: true,
            wallet_id: Some("abcdef1234567890abcdef1234567890".to_string()),
            error: None,
        };
        let auth_result_json = serde_json::to_string(&auth_result).unwrap();
        assert!(auth_result_json.contains("\"type\":\"auth_result\""));
        let _: ServerMessage = serde_json::from_str(&auth_result_json).unwrap();

        // Step 2: PreparePayment
        let proof = make_test_proof("payment");
        let prepare_msg = ClientMessage::PreparePayment {
            recipient: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            amount_sats: 75_000,
            mode: PaymentMode::GhostPay,
            proof,
            memo: Some("Coffee payment".to_string()),
            encrypted_metadata: None,
        };
        let prepare_json = serde_json::to_string(&prepare_msg).unwrap();
        assert!(prepare_json.contains("\"type\":\"prepare_payment\""));
        let _: ClientMessage = serde_json::from_str(&prepare_json).unwrap();

        // Step 3: Server responds with PaymentPrepared
        let prepared = make_test_prepared_payment();
        let payment_id = prepared.payment_id.clone();
        let prepared_msg = ServerMessage::PaymentPrepared {
            success: true,
            payment: Some(prepared),
            error: None,
        };
        let prepared_json = serde_json::to_string(&prepared_msg).unwrap();
        assert!(prepared_json.contains("\"type\":\"payment_prepared\""));
        let parsed_prepared: ServerMessage = serde_json::from_str(&prepared_json).unwrap();
        match &parsed_prepared {
            ServerMessage::PaymentPrepared { success, .. } => assert!(success),
            _ => panic!("Expected PaymentPrepared"),
        }

        // Step 4: Submit signed payment
        let submit_msg = ClientMessage::SubmitSignedPayment {
            payment_id: payment_id.clone(),
            signature: hex::encode([0x42; 64]),
            public_key: hex::encode([0x01; 32]),
        };
        let submit_json = serde_json::to_string(&submit_msg).unwrap();
        assert!(submit_json.contains("\"type\":\"submit_signed_payment\""));
        let _: ClientMessage = serde_json::from_str(&submit_json).unwrap();

        // Step 5: Server responds with PaymentSubmitted
        let submitted_msg = ServerMessage::PaymentSubmitted {
            success: true,
            payment_id: payment_id.clone(),
            txid: Some("aa".repeat(32)),
            error: None,
        };
        let submitted_json = serde_json::to_string(&submitted_msg).unwrap();
        assert!(submitted_json.contains("\"type\":\"payment_submitted\""));
        let parsed_submitted: ServerMessage = serde_json::from_str(&submitted_json).unwrap();
        match parsed_submitted {
            ServerMessage::PaymentSubmitted {
                success,
                payment_id: pid,
                txid,
                error,
            } => {
                assert!(success);
                assert_eq!(pid, payment_id);
                assert!(txid.is_some());
                assert!(error.is_none());
            }
            _ => panic!("Expected PaymentSubmitted"),
        }
    }

    /// 846: Full lock flow: Auth -> PrepareGhostLock -> LockPrepared -> ConfirmFunding -> LockConfirmed
    #[test]
    fn test_846_full_lock_flow() {
        // Step 1: Authenticate
        let auth_msg = ClientMessage::Authenticate {
            token: "jwt_session_token".to_string(),
        };
        let _ = serde_json::to_string(&auth_msg).unwrap();

        // Step 2: PrepareGhostLock
        let owner_pubkey = hex::encode([0x03; 32]);
        let prepare_lock = ClientMessage::PrepareGhostLock {
            owner_pubkey: owner_pubkey.clone(),
            capacity_sats: 500_000,
        };
        let prepare_json = serde_json::to_string(&prepare_lock).unwrap();
        assert!(prepare_json.contains("\"type\":\"prepare_ghost_lock\""));
        let _: ClientMessage = serde_json::from_str(&prepare_json).unwrap();

        // Step 3: Server responds with LockPrepared
        let lock_id = "lock-flow-001".to_string();
        let prepared_msg = ServerMessage::LockPrepared {
            success: true,
            lock_id: Some(lock_id.clone()),
            funding_address: Some("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()),
            required_sats: Some(500_546),
            error: None,
        };
        let prepared_json = serde_json::to_string(&prepared_msg).unwrap();
        let parsed_prepared: ServerMessage = serde_json::from_str(&prepared_json).unwrap();
        match &parsed_prepared {
            ServerMessage::LockPrepared {
                success,
                lock_id: lid,
                ..
            } => {
                assert!(success);
                assert_eq!(lid.as_deref(), Some("lock-flow-001"));
            }
            _ => panic!("Expected LockPrepared"),
        }

        // Step 4: ConfirmGhostLockFunding
        let funding_txid = "dd".repeat(32);
        let confirm_proof = make_test_proof("lock_confirm");
        let confirm_msg = ClientMessage::ConfirmGhostLockFunding {
            lock_id: lock_id.clone(),
            funding_txid: funding_txid.clone(),
            proof: confirm_proof,
        };
        let confirm_json = serde_json::to_string(&confirm_msg).unwrap();
        assert!(confirm_json.contains("\"type\":\"confirm_ghost_lock_funding\""));
        let _: ClientMessage = serde_json::from_str(&confirm_json).unwrap();

        // Step 5: Server responds with LockConfirmed
        let confirmed_msg = ServerMessage::LockConfirmed {
            lock_id: lock_id.clone(),
            txid: funding_txid.clone(),
            block_height: 800_100,
        };
        let confirmed_json = serde_json::to_string(&confirmed_msg).unwrap();
        assert!(confirmed_json.contains("\"type\":\"lock_confirmed\""));
        let parsed_confirmed: ServerMessage = serde_json::from_str(&confirmed_json).unwrap();
        match parsed_confirmed {
            ServerMessage::LockConfirmed {
                lock_id: lid,
                txid,
                block_height,
            } => {
                assert_eq!(lid, lock_id);
                assert_eq!(txid, funding_txid);
                assert_eq!(block_height, 800_100);
            }
            _ => panic!("Expected LockConfirmed"),
        }
    }

    /// 847: Full jump flow: Auth -> RequestJump -> JumpRequested
    #[test]
    fn test_847_full_jump_flow() {
        // Step 1: Authenticate
        let auth_msg = ClientMessage::Authenticate {
            token: "jwt_session_for_jump".to_string(),
        };
        let auth_json = serde_json::to_string(&auth_msg).unwrap();
        let _: ClientMessage = serde_json::from_str(&auth_json).unwrap();

        // Step 2: RequestJump
        let jump_proof = make_test_proof("jump");
        let lock_id = "lock-jump-001".to_string();
        let jump_msg = ClientMessage::RequestJump {
            lock_id: lock_id.clone(),
            priority: "high".to_string(),
            target_address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            proof: jump_proof,
        };
        let jump_json = serde_json::to_string(&jump_msg).unwrap();
        assert!(jump_json.contains("\"type\":\"request_jump\""));
        assert!(jump_json.contains("\"priority\":\"high\""));

        let parsed_jump: ClientMessage = serde_json::from_str(&jump_json).unwrap();
        match &parsed_jump {
            ClientMessage::RequestJump {
                lock_id: lid,
                priority,
                ..
            } => {
                assert_eq!(lid, &lock_id);
                assert_eq!(priority, "high");
            }
            _ => panic!("Expected RequestJump"),
        }

        // Step 3: Server responds with JumpRequested
        let jump_txid = "ee".repeat(32);
        let jump_result = ServerMessage::JumpRequested {
            success: true,
            lock_id: lock_id.clone(),
            jump_txid: Some(jump_txid.clone()),
            error: None,
        };
        let result_json = serde_json::to_string(&jump_result).unwrap();
        assert!(result_json.contains("\"type\":\"jump_requested\""));

        let parsed_result: ServerMessage = serde_json::from_str(&result_json).unwrap();
        match parsed_result {
            ServerMessage::JumpRequested {
                success,
                lock_id: lid,
                jump_txid: jtx,
                error,
            } => {
                assert!(success);
                assert_eq!(lid, lock_id);
                assert_eq!(jtx.unwrap(), jump_txid);
                assert!(error.is_none());
            }
            _ => panic!("Expected JumpRequested"),
        }
    }

    /// 848: WalletProof::new() for different actions all succeed and have correct action
    #[test]
    fn test_848_wallet_proof_actions() {
        let actions = ["register", "session", "jump", "payment"];
        let pubkey = [1u8; 32];

        for action in &actions {
            let proof = WalletProof::new(action, &pubkey).expect("nonce generation should succeed");

            // Verify the action is correctly embedded in the message
            assert_eq!(
                proof.action(),
                Some(*action),
                "Action mismatch for '{}'",
                action
            );

            // Verify message format: "ghost-{action}:{timestamp}:{nonce}"
            assert!(
                proof.message.starts_with(&format!("ghost-{}:", action)),
                "Message should start with 'ghost-{}:', got: {}",
                action,
                proof.message
            );

            // Verify nonce is 32 hex chars (16 bytes)
            assert_eq!(proof.nonce.len(), 32, "Nonce should be 32 hex chars");
            assert!(
                proof.nonce.chars().all(|c| c.is_ascii_hexdigit()),
                "Nonce should be valid hex"
            );

            // Verify public key is correctly set
            assert_eq!(proof.public_key, hex::encode(pubkey));

            // Verify timestamp is recent
            assert!(proof.is_timestamp_valid());
        }
    }

    /// 849: Two WalletProofs created rapidly have different nonces
    #[test]
    fn test_849_wallet_proof_unique_nonces() {
        let pubkey = [1u8; 32];

        // Create two proofs in rapid succession with the same parameters
        let proof1 = WalletProof::new("payment", &pubkey).expect("nonce generation should succeed");
        let proof2 = WalletProof::new("payment", &pubkey).expect("nonce generation should succeed");

        // Nonces MUST be different (CSPRNG guarantees this)
        assert_ne!(
            proof1.nonce, proof2.nonce,
            "Two proofs created rapidly must have different nonces (replay protection)"
        );

        // Messages must also be different (since nonces differ)
        assert_ne!(
            proof1.message, proof2.message,
            "Two proofs must have different messages"
        );

        // Verify both are structurally valid (with dummy signatures)
        let mut p1 = proof1;
        let mut p2 = proof2;
        p1.signature = hex::encode([0xaa; 64]);
        p2.signature = hex::encode([0xbb; 64]);
        assert!(p1.validate_structure().is_ok());
        assert!(p2.validate_structure().is_ok());
    }
}
