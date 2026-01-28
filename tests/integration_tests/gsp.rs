//! GSP (Ghost Service Provider) Integration Tests
//!
//! Tests for the GSP light wallet server functionality including:
//! - WebSocket protocol messages
//! - Authentication flow (WalletProof + JWT)
//! - Balance and UTXO queries
//! - Payment preparation and submission
//! - Ghost Lock management
//! - Subscriptions
//!
//! Run with: cargo test --test integration gsp

use ghost_gsp_proto::{
    ClientMessage, PaymentMode, PaymentStatus, ServerMessage, WalletId, WalletProof,
    validate_message,
};

// ============================================================================
// Protocol Validation Tests
// ============================================================================

mod protocol_validation {
    use super::*;

    #[test]
    fn test_client_message_get_balance_serialization() {
        let msg = ClientMessage::GetBalance;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"get_balance\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ClientMessage::GetBalance));
    }

    #[test]
    fn test_client_message_get_utxos_serialization() {
        let msg = ClientMessage::GetUtxos {
            min_confirmations: 6,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"get_utxos\""));
        assert!(json.contains("\"min_confirmations\":6"));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::GetUtxos { min_confirmations } => {
                assert_eq!(min_confirmations, 6);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_client_message_authenticate_serialization() {
        let msg = ClientMessage::Authenticate {
            token: "jwt_token_here".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"authenticate\""));
        assert!(json.contains("\"token\":\"jwt_token_here\""));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::Authenticate { token } => {
                assert_eq!(token, "jwt_token_here");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_client_message_ping_serialization() {
        let msg = ClientMessage::Ping {
            timestamp: Some(1704067200),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"ping\""));
        assert!(json.contains("\"timestamp\":1704067200"));
    }

    #[test]
    fn test_client_message_subscribe_serialization() {
        let msg = ClientMessage::SubscribeBalance;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"subscribe_balance\""));

        let msg2 = ClientMessage::SubscribePayments;
        let json2 = serde_json::to_string(&msg2).unwrap();
        assert!(json2.contains("\"type\":\"subscribe_payments\""));

        let msg3 = ClientMessage::SubscribeLocks;
        let json3 = serde_json::to_string(&msg3).unwrap();
        assert!(json3.contains("\"type\":\"subscribe_locks\""));
    }

    #[test]
    fn test_client_message_unsubscribe_serialization() {
        let msg = ClientMessage::Unsubscribe {
            subscription: "balance".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"unsubscribe\""));
        assert!(json.contains("\"subscription\":\"balance\""));
    }

    #[test]
    fn test_server_message_balance_update_serialization() {
        let msg = ServerMessage::BalanceUpdate {
            confirmed: 100_000,
            unconfirmed: 50_000,
            locked: 25_000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"balance_update\""));
        assert!(json.contains("\"confirmed\":100000"));
        assert!(json.contains("\"unconfirmed\":50000"));
        assert!(json.contains("\"locked\":25000"));
    }

    #[test]
    fn test_server_message_auth_result_serialization() {
        let msg = ServerMessage::AuthResult {
            success: true,
            wallet_id: Some("abc123def456".to_string()),
            error: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"auth_result\""));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"wallet_id\":\"abc123def456\""));
    }

    #[test]
    fn test_server_message_error_serialization() {
        let msg = ServerMessage::Error {
            code: "UNAUTHORIZED".to_string(),
            message: "Invalid token".to_string(),
            request_id: Some("req_123".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"error\""));
        assert!(json.contains("\"code\":\"UNAUTHORIZED\""));
        assert!(json.contains("\"message\":\"Invalid token\""));
    }

    #[test]
    fn test_server_message_pong_serialization() {
        let msg = ServerMessage::Pong {
            timestamp: Some(1704067200),
            server_time: 1704067201,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"pong\""));
        assert!(json.contains("\"timestamp\":1704067200"));
        assert!(json.contains("\"server_time\":1704067201"));
    }

    #[test]
    fn test_server_message_subscribed_serialization() {
        let msg = ServerMessage::Subscribed {
            subscription: "balance".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"subscribed\""));
        assert!(json.contains("\"subscription\":\"balance\""));
    }
}

// ============================================================================
// Message Validation Tests
// ============================================================================

mod message_validation {
    use super::*;

    #[test]
    fn test_validate_get_balance() {
        let msg = ClientMessage::GetBalance;
        let result = validate_message(&msg);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_get_utxos_valid() {
        let msg = ClientMessage::GetUtxos {
            min_confirmations: 1,
        };
        let result = validate_message(&msg);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_get_transactions_valid() {
        let msg = ClientMessage::GetTransactions {
            limit: 50,
            offset: 0,
        };
        let result = validate_message(&msg);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_get_transactions_limit_too_high() {
        let msg = ClientMessage::GetTransactions {
            limit: 1001,
            offset: 0,
        };
        let result = validate_message(&msg);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("Limit")));
    }

    #[test]
    fn test_validate_authenticate_valid() {
        let msg = ClientMessage::Authenticate {
            token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature".to_string(),
        };
        let result = validate_message(&msg);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_authenticate_empty_token() {
        let msg = ClientMessage::Authenticate {
            token: "".to_string(),
        };
        let result = validate_message(&msg);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("Token")));
    }
}

// ============================================================================
// Authentication Tests
// ============================================================================

mod authentication {
    use super::*;

    #[test]
    fn test_wallet_id_from_pubkey() {
        let pubkey = [0u8; 32];
        let id = WalletId::from_pubkey(&pubkey);
        assert!(id.is_valid());
        assert_eq!(id.as_str().len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_wallet_id_from_pubkey_deterministic() {
        let pubkey = [42u8; 32];
        let id1 = WalletId::from_pubkey(&pubkey);
        let id2 = WalletId::from_pubkey(&pubkey);
        assert_eq!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn test_wallet_id_different_pubkeys() {
        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];
        let id1 = WalletId::from_pubkey(&pubkey1);
        let id2 = WalletId::from_pubkey(&pubkey2);
        assert_ne!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn test_wallet_id_validation() {
        let valid_id = WalletId("0123456789abcdef0123456789abcdef".to_string());
        assert!(valid_id.is_valid());

        let invalid_short = WalletId("0123456789abcdef".to_string());
        assert!(!invalid_short.is_valid());

        let invalid_chars = WalletId("ghijklmnopqrstuv0123456789abcdef".to_string());
        assert!(!invalid_chars.is_valid());
    }

    #[test]
    fn test_wallet_proof_new() {
        let pubkey = [1u8; 32];
        let proof = WalletProof::new("register", &pubkey);

        assert!(proof.message.starts_with("ghost-register:"));
        assert_eq!(proof.nonce.len(), 32); // 16 bytes = 32 hex chars
        assert_eq!(proof.public_key.len(), 64); // 32 bytes = 64 hex chars
        assert!(proof.signature.is_empty()); // Not yet signed
    }

    #[test]
    fn test_wallet_proof_action() {
        let pubkey = [1u8; 32];

        let proof1 = WalletProof::new("register", &pubkey);
        assert_eq!(proof1.action(), Some("register"));

        let proof2 = WalletProof::new("session", &pubkey);
        assert_eq!(proof2.action(), Some("session"));

        let proof3 = WalletProof::new("jump", &pubkey);
        assert_eq!(proof3.action(), Some("jump"));
    }

    #[test]
    fn test_wallet_proof_timestamp_valid() {
        let pubkey = [1u8; 32];
        let proof = WalletProof::new("register", &pubkey);
        assert!(proof.is_timestamp_valid());
    }

    #[test]
    fn test_wallet_proof_message_bytes() {
        let pubkey = [1u8; 32];
        let proof = WalletProof::new("test", &pubkey);
        let bytes = proof.message_bytes();
        assert!(!bytes.is_empty());
        assert!(String::from_utf8(bytes).unwrap().starts_with("ghost-test:"));
    }

    #[test]
    fn test_wallet_proof_wallet_id() {
        let pubkey = [1u8; 32];
        let proof = WalletProof::new("register", &pubkey);
        let wallet_id = proof.wallet_id().unwrap();
        assert!(wallet_id.is_valid());
    }
}

// ============================================================================
// Payment Tests
// ============================================================================

mod payments {
    use super::*;

    #[test]
    fn test_payment_mode_serialization() {
        let ghostpay = PaymentMode::GhostPay;
        let json = serde_json::to_string(&ghostpay).unwrap();
        assert_eq!(json, "\"ghostpay\"");

        let wraith = PaymentMode::Wraith;
        let json2 = serde_json::to_string(&wraith).unwrap();
        assert_eq!(json2, "\"wraith\"");
    }

    #[test]
    fn test_payment_mode_deserialization() {
        let parsed: PaymentMode = serde_json::from_str("\"ghostpay\"").unwrap();
        assert_eq!(parsed, PaymentMode::GhostPay);

        let parsed2: PaymentMode = serde_json::from_str("\"wraith\"").unwrap();
        assert_eq!(parsed2, PaymentMode::Wraith);
    }

    #[test]
    fn test_payment_mode_default() {
        assert_eq!(PaymentMode::default(), PaymentMode::GhostPay);
    }

    #[test]
    fn test_payment_status_terminal() {
        assert!(PaymentStatus::Confirmed.is_terminal());
        assert!(PaymentStatus::Failed.is_terminal());
        assert!(PaymentStatus::Cancelled.is_terminal());
        assert!(PaymentStatus::Expired.is_terminal());

        assert!(!PaymentStatus::Preparing.is_terminal());
        assert!(!PaymentStatus::PendingSignature.is_terminal());
        assert!(!PaymentStatus::Signed.is_terminal());
        assert!(!PaymentStatus::Broadcast.is_terminal());
        assert!(!PaymentStatus::Mempool.is_terminal());
    }

    #[test]
    fn test_payment_status_can_cancel() {
        assert!(PaymentStatus::Preparing.can_cancel());
        assert!(PaymentStatus::PendingSignature.can_cancel());
        assert!(PaymentStatus::Signed.can_cancel());

        assert!(!PaymentStatus::Broadcast.can_cancel());
        assert!(!PaymentStatus::Mempool.can_cancel());
        assert!(!PaymentStatus::Confirmed.can_cancel());
        assert!(!PaymentStatus::Failed.can_cancel());
    }

    #[test]
    fn test_payment_status_display() {
        assert_eq!(format!("{}", PaymentStatus::Preparing), "preparing");
        assert_eq!(format!("{}", PaymentStatus::PendingSignature), "pending_signature");
        assert_eq!(format!("{}", PaymentStatus::Broadcast), "broadcast");
        assert_eq!(format!("{}", PaymentStatus::Confirmed), "confirmed");
    }
}

// ============================================================================
// Ghost Lock Tests
// ============================================================================

mod ghost_locks {
    use ghost_gsp_proto::{GhostLockStatus, JumpPriority};

    #[test]
    fn test_ghost_lock_status_display() {
        assert_eq!(format!("{}", GhostLockStatus::Pending), "pending");
        assert_eq!(format!("{}", GhostLockStatus::Active), "active");
        assert_eq!(format!("{}", GhostLockStatus::Jumping), "jumping");
        assert_eq!(format!("{}", GhostLockStatus::Recovering), "recovering");
        assert_eq!(format!("{}", GhostLockStatus::Recovered), "recovered");
    }

    #[test]
    fn test_jump_priority_default() {
        assert_eq!(JumpPriority::default(), JumpPriority::Normal);
    }

    #[test]
    fn test_jump_priority_display() {
        assert_eq!(format!("{}", JumpPriority::Normal), "normal");
        assert_eq!(format!("{}", JumpPriority::High), "high");
        assert_eq!(format!("{}", JumpPriority::Urgent), "urgent");
    }

    #[test]
    fn test_jump_priority_serialization() {
        let normal: JumpPriority = serde_json::from_str("\"normal\"").unwrap();
        assert_eq!(normal, JumpPriority::Normal);

        let high: JumpPriority = serde_json::from_str("\"high\"").unwrap();
        assert_eq!(high, JumpPriority::High);

        let urgent: JumpPriority = serde_json::from_str("\"urgent\"").unwrap();
        assert_eq!(urgent, JumpPriority::Urgent);
    }
}

// ============================================================================
// Message Authentication Requirements Tests
// ============================================================================

mod auth_requirements {
    use super::*;

    #[test]
    fn test_requires_auth_balance_queries() {
        assert!(ClientMessage::GetBalance.requires_auth());
        assert!(ClientMessage::GetUtxos { min_confirmations: 1 }.requires_auth());
        assert!(ClientMessage::GetGhostLocks.requires_auth());
        assert!(ClientMessage::GetTransactions { limit: 10, offset: 0 }.requires_auth());
    }

    #[test]
    fn test_requires_auth_subscriptions() {
        assert!(ClientMessage::SubscribeBalance.requires_auth());
        assert!(ClientMessage::SubscribePayments.requires_auth());
        assert!(ClientMessage::SubscribeLocks.requires_auth());
    }

    #[test]
    fn test_not_requires_auth() {
        assert!(!ClientMessage::Authenticate { token: "test".to_string() }.requires_auth());
        assert!(!ClientMessage::Ping { timestamp: None }.requires_auth());
        assert!(!ClientMessage::Unsubscribe { subscription: "balance".to_string() }.requires_auth());
    }
}

// ============================================================================
// WebSocket Message Flow Tests
// ============================================================================

mod message_flow {
    use super::*;

    /// Simulate a complete authentication flow
    #[test]
    fn test_auth_flow_simulation() {
        // Step 1: Client sends authenticate
        let client_auth = ClientMessage::Authenticate {
            token: "valid_jwt_token".to_string(),
        };
        let json = serde_json::to_string(&client_auth).unwrap();
        assert!(json.contains("authenticate"));

        // Step 2: Server responds with success
        let server_response = ServerMessage::AuthResult {
            success: true,
            wallet_id: Some("abc123def456".to_string()),
            error: None,
        };
        let response_json = serde_json::to_string(&server_response).unwrap();
        assert!(response_json.contains("auth_result"));
        assert!(response_json.contains("true"));
    }

    /// Simulate a balance query flow
    #[test]
    fn test_balance_query_flow_simulation() {
        // Client requests balance
        let request = ClientMessage::GetBalance;
        assert!(request.requires_auth());

        // Server responds with balance
        let response = ServerMessage::BalanceUpdate {
            confirmed: 1_000_000,
            unconfirmed: 50_000,
            locked: 100_000,
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();

        match parsed {
            ServerMessage::BalanceUpdate { confirmed, unconfirmed, locked } => {
                assert_eq!(confirmed, 1_000_000);
                assert_eq!(unconfirmed, 50_000);
                assert_eq!(locked, 100_000);
            }
            _ => panic!("Wrong response type"),
        }
    }

    /// Simulate a subscription flow
    #[test]
    fn test_subscription_flow_simulation() {
        // Client subscribes to balance updates
        let subscribe = ClientMessage::SubscribeBalance;
        assert!(subscribe.requires_auth());

        // Server confirms subscription
        let confirmed = ServerMessage::Subscribed {
            subscription: "balance".to_string(),
        };
        let json = serde_json::to_string(&confirmed).unwrap();
        assert!(json.contains("subscribed"));

        // Server pushes balance update
        let update = ServerMessage::BalanceUpdate {
            confirmed: 2_000_000,
            unconfirmed: 0,
            locked: 0,
        };
        let update_json = serde_json::to_string(&update).unwrap();
        assert!(update_json.contains("balance_update"));

        // Client unsubscribes
        let unsubscribe = ClientMessage::Unsubscribe {
            subscription: "balance".to_string(),
        };
        let _ = serde_json::to_string(&unsubscribe).unwrap();

        // Server confirms unsubscription
        let unsubscribed = ServerMessage::Unsubscribed {
            subscription: "balance".to_string(),
        };
        let unsub_json = serde_json::to_string(&unsubscribed).unwrap();
        assert!(unsub_json.contains("unsubscribed"));
    }

    /// Simulate a ping-pong flow
    #[test]
    fn test_ping_pong_flow_simulation() {
        let timestamp = 1704067200i64;

        // Client sends ping
        let ping = ClientMessage::Ping {
            timestamp: Some(timestamp),
        };
        let ping_json = serde_json::to_string(&ping).unwrap();
        assert!(ping_json.contains("ping"));

        // Server responds with pong
        let pong = ServerMessage::Pong {
            timestamp: Some(timestamp),
            server_time: timestamp + 1,
        };
        let pong_json = serde_json::to_string(&pong).unwrap();
        assert!(pong_json.contains("pong"));
        assert!(pong_json.contains(&timestamp.to_string()));
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_handling {
    use super::*;

    #[test]
    fn test_error_response_formats() {
        // Unauthorized error
        let unauthorized = ServerMessage::Error {
            code: "UNAUTHORIZED".to_string(),
            message: "Authentication required".to_string(),
            request_id: None,
        };
        let json = serde_json::to_string(&unauthorized).unwrap();
        assert!(json.contains("UNAUTHORIZED"));

        // Rate limit error
        let rate_limited = ServerMessage::Error {
            code: "RATE_LIMITED".to_string(),
            message: "Too many requests".to_string(),
            request_id: Some("req_abc123".to_string()),
        };
        let json2 = serde_json::to_string(&rate_limited).unwrap();
        assert!(json2.contains("RATE_LIMITED"));
        assert!(json2.contains("req_abc123"));

        // Invalid request error
        let invalid = ServerMessage::Error {
            code: "INVALID_REQUEST".to_string(),
            message: "Missing required field: amount".to_string(),
            request_id: None,
        };
        let json3 = serde_json::to_string(&invalid).unwrap();
        assert!(json3.contains("INVALID_REQUEST"));
    }

    #[test]
    fn test_auth_failure_response() {
        let auth_failed = ServerMessage::AuthResult {
            success: false,
            wallet_id: None,
            error: Some("Invalid or expired token".to_string()),
        };
        let json = serde_json::to_string(&auth_failed).unwrap();
        assert!(json.contains("false"));
        assert!(json.contains("Invalid or expired token"));
    }

    #[test]
    fn test_payment_failure_response() {
        let payment_failed = ServerMessage::PaymentSubmitted {
            success: false,
            payment_id: "pay_123".to_string(),
            txid: None,
            error: Some("Insufficient balance".to_string()),
        };
        let json = serde_json::to_string(&payment_failed).unwrap();
        assert!(json.contains("false"));
        assert!(json.contains("Insufficient balance"));
    }

    #[test]
    fn test_lock_failure_response() {
        let lock_failed = ServerMessage::LockPrepared {
            success: false,
            lock_id: None,
            funding_address: None,
            required_sats: None,
            error: Some("Amount below minimum lock size".to_string()),
        };
        let json = serde_json::to_string(&lock_failed).unwrap();
        assert!(json.contains("false"));
        assert!(json.contains("Amount below minimum lock size"));
    }

    #[test]
    fn test_jump_failure_response() {
        let jump_failed = ServerMessage::JumpRequested {
            success: false,
            lock_id: "lock_123".to_string(),
            jump_txid: None,
            error: Some("Lock not found or not owned by wallet".to_string()),
        };
        let json = serde_json::to_string(&jump_failed).unwrap();
        assert!(json.contains("false"));
        assert!(json.contains("Lock not found"));
    }
}
