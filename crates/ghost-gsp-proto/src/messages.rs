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
//| FILE: messages.rs                                                                                                    |
//|======================================================================================================================|

//! WebSocket message types for GSP Protocol
//!
//! Defines the bidirectional message format for client-server communication.

use serde::{Deserialize, Serialize};

use crate::auth::WalletProof;
use crate::lock::GhostLockInfo;
use crate::payment::{PaymentMode, PaymentStatus, PreparedPayment};

// Re-export instant types for convenience
pub use ghost_common::instant::{InstantCapability, InstantCondition, LockSnapshot};

/// Messages sent from Light Wallet client to GSP server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    // =========================================================================
    // Session Management
    // =========================================================================
    /// Authenticate with session token
    Authenticate {
        /// JWT session token
        token: String,
    },

    /// Ping to keep connection alive
    Ping {
        /// Optional timestamp for latency measurement
        timestamp: Option<i64>,
    },

    // =========================================================================
    // Balance & Queries
    // =========================================================================
    /// Request current balance
    GetBalance,

    /// Request UTXOs with minimum confirmations
    GetUtxos {
        /// Minimum confirmations required
        min_confirmations: u32,
    },

    /// Request all ghost locks for this wallet
    GetGhostLocks,

    /// Request transaction history
    GetTransactions {
        /// Maximum number of transactions to return
        limit: u32,
        /// Offset for pagination
        offset: u32,
    },

    // =========================================================================
    // Payments
    // =========================================================================
    /// Prepare a payment (requires WalletProof)
    PreparePayment {
        /// Recipient Ghost ID or Bitcoin address
        recipient: String,
        /// Amount in satoshis
        amount_sats: u64,
        /// Payment mode (ghostpay or wraith)
        mode: PaymentMode,
        /// Authentication proof
        proof: WalletProof,
    },

    /// Submit a signed payment
    SubmitSignedPayment {
        /// Payment ID from prepare_payment response
        payment_id: String,
        /// Schnorr signature (64 bytes hex)
        signature: String,
        /// Public key used for signing (32 bytes hex)
        public_key: String,
    },

    /// Get payment status
    GetPaymentStatus {
        /// Payment ID to query
        payment_id: String,
    },

    /// Cancel a pending payment
    CancelPayment {
        /// Payment ID to cancel
        payment_id: String,
        /// Authentication proof
        proof: WalletProof,
    },

    // =========================================================================
    // Ghost Locks
    // =========================================================================
    /// Prepare a new ghost lock
    PrepareGhostLock {
        /// Owner's public key (32 bytes hex)
        owner_pubkey: String,
        /// Lock capacity in satoshis
        capacity_sats: u64,
    },

    /// Confirm ghost lock funding
    ConfirmGhostLockFunding {
        /// Lock ID
        lock_id: String,
        /// Funding transaction ID
        funding_txid: String,
        /// Authentication proof
        proof: WalletProof,
    },

    /// Request emergency jump for a lock
    RequestJump {
        /// Lock ID to jump
        lock_id: String,
        /// Priority level (normal, high, urgent)
        priority: String,
        /// Target address for the jump
        target_address: String,
        /// Authentication proof
        proof: WalletProof,
    },

    // =========================================================================
    // Subscriptions
    // =========================================================================
    /// Subscribe to balance updates
    SubscribeBalance,

    /// Subscribe to payment notifications
    SubscribePayments,

    /// Subscribe to lock notifications
    SubscribeLocks,

    /// Unsubscribe from a subscription
    Unsubscribe {
        /// Subscription type to cancel
        subscription: String,
    },

    // =========================================================================
    // Instant Payments
    // =========================================================================
    /// Check if a lock is instant-capable for a payment amount
    CheckInstantCapability {
        /// Lock ID to check
        lock_id: String,
        /// Amount to pay (sats)
        amount_sats: u64,
    },

    /// Subscribe to real-time lock state updates
    SubscribeLockState {
        /// Lock ID to monitor
        lock_id: String,
    },

    /// Unsubscribe from lock state updates
    UnsubscribeLockState {
        /// Lock ID to stop monitoring
        lock_id: String,
    },

    /// Accept an instant payment as merchant
    AcceptInstantPayment {
        /// Sender's lock ID
        sender_lock_id: String,
        /// Payment amount (sats)
        amount_sats: u64,
        /// Merchant's authentication proof
        proof: WalletProof,
    },
}

/// Messages sent from GSP server to Light Wallet client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    // =========================================================================
    // Session Management
    // =========================================================================
    /// Authentication result
    AuthResult {
        /// Whether authentication succeeded
        success: bool,
        /// Wallet ID if successful
        wallet_id: Option<String>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Pong response to ping
    Pong {
        /// Echoed timestamp
        timestamp: Option<i64>,
        /// Server timestamp
        server_time: i64,
    },

    /// Generic error response
    Error {
        /// Error code
        code: String,
        /// Human-readable error message
        message: String,
        /// Related request ID if applicable
        request_id: Option<String>,
    },

    // =========================================================================
    // Balance & Query Responses
    // =========================================================================
    /// Balance update (response or push notification)
    BalanceUpdate {
        /// Confirmed balance in satoshis
        confirmed: u64,
        /// Unconfirmed balance in satoshis
        unconfirmed: u64,
        /// Amount locked in Ghost Locks
        locked: u64,
    },

    /// UTXO list response
    Utxos {
        /// List of UTXOs
        utxos: Vec<UtxoInfo>,
        /// Total value in satoshis
        total_sats: u64,
    },

    /// Ghost locks list response
    GhostLocks {
        /// List of ghost locks
        locks: Vec<GhostLockInfo>,
        /// Total locked value
        total_locked_sats: u64,
    },

    /// Transaction history response
    Transactions {
        /// List of transactions
        transactions: Vec<TransactionInfo>,
        /// Total count (for pagination)
        total_count: u32,
    },

    // =========================================================================
    // Payment Responses & Notifications
    // =========================================================================
    /// Payment preparation result
    PaymentPrepared {
        /// Whether preparation succeeded
        success: bool,
        /// Prepared payment details
        payment: Option<PreparedPayment>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Payment submission result
    PaymentSubmitted {
        /// Whether submission succeeded
        success: bool,
        /// Payment ID
        payment_id: String,
        /// Transaction ID if broadcast
        txid: Option<String>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Payment status response
    PaymentStatus {
        /// Payment ID
        payment_id: String,
        /// Current status
        status: PaymentStatus,
        /// Confirmations if confirmed
        confirmations: Option<u32>,
    },

    /// Payment received notification (push)
    PaymentReceived {
        /// Payment ID
        payment_id: String,
        /// Amount in satoshis
        amount_sats: u64,
        /// Sender Ghost ID if known
        sender: Option<String>,
        /// Transaction ID
        txid: String,
    },

    /// Payment confirmed notification (push)
    PaymentConfirmed {
        /// Payment ID
        payment_id: String,
        /// Number of confirmations
        confirmations: u32,
    },

    // =========================================================================
    // Ghost Lock Responses & Notifications
    // =========================================================================
    /// Lock preparation result
    LockPrepared {
        /// Whether preparation succeeded
        success: bool,
        /// Lock ID
        lock_id: Option<String>,
        /// Funding address
        funding_address: Option<String>,
        /// Required amount to fund
        required_sats: Option<u64>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Lock funding confirmed
    LockConfirmed {
        /// Lock ID
        lock_id: String,
        /// Funding transaction ID
        txid: String,
        /// Block height of confirmation
        block_height: u32,
    },

    /// Jump request result
    JumpRequested {
        /// Whether jump was initiated
        success: bool,
        /// Lock ID
        lock_id: String,
        /// Jump transaction ID if broadcast
        jump_txid: Option<String>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Lock state changed notification (push)
    LockStateChanged {
        /// Lock ID
        lock_id: String,
        /// Previous state
        old_state: String,
        /// New state
        new_state: String,
    },

    // =========================================================================
    // Subscription Confirmations
    // =========================================================================
    /// Subscription confirmed
    Subscribed {
        /// Subscription type
        subscription: String,
    },

    /// Unsubscription confirmed
    Unsubscribed {
        /// Subscription type
        subscription: String,
    },

    // =========================================================================
    // Instant Payment Responses & Notifications
    // =========================================================================
    /// Instant capability check result
    InstantCapabilityResult {
        /// Lock ID that was checked
        lock_id: String,
        /// Whether instant payment is possible
        capable: bool,
        /// Maximum instant payment amount (sats)
        max_instant_sats: u64,
        /// Confidence score (0.0 - 1.0)
        confidence: f32,
        /// Block height until this capability is valid
        valid_until_height: u64,
        /// Conditions that passed (as bitmap)
        conditions_met: u8,
        /// Conditions that failed (as bitmap)
        conditions_failed: u8,
        /// Error message if check failed
        error: Option<String>,
    },

    /// Lock state subscription confirmed
    LockStateSubscribed {
        /// Lock ID being monitored
        lock_id: String,
        /// Initial snapshot of lock state
        snapshot: LockStateSnapshot,
    },

    /// Lock state subscription cancelled
    LockStateUnsubscribed {
        /// Lock ID no longer monitored
        lock_id: String,
    },

    /// Real-time lock state update (push notification)
    LockStateUpdate {
        /// Lock ID
        lock_id: String,
        /// Updated snapshot
        snapshot: LockStateSnapshot,
        /// What changed
        change_type: LockStateChangeType,
        /// Timestamp
        timestamp: i64,
    },

    /// Instant payment accepted (merchant side)
    InstantPaymentAccepted {
        /// Payment ID (32 bytes hex)
        payment_id: String,
        /// Sender's lock ID
        sender_lock_id: String,
        /// Amount (sats)
        amount_sats: u64,
        /// Expected settlement block
        settlement_block: u64,
        /// Confidence at acceptance
        confidence: f32,
        /// Timestamp
        timestamp: i64,
    },

    /// Instant payment settled notification
    InstantPaymentSettled {
        /// Payment ID
        payment_id: String,
        /// Settlement block height
        settled_at_height: u64,
        /// Final status (confirmed/failed)
        success: bool,
    },
}

/// UTXO information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Number of confirmations
    pub confirmations: u32,
    /// Script type (p2tr, p2wpkh, etc.)
    pub script_type: String,
    /// Whether this UTXO is spendable
    pub spendable: bool,
}

/// Transaction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    /// Transaction ID
    pub txid: String,
    /// Block height (None if unconfirmed)
    pub block_height: Option<u32>,
    /// Timestamp (Unix seconds)
    pub timestamp: i64,
    /// Net amount change (positive for received, negative for sent)
    pub amount_sats: i64,
    /// Fee paid (if known)
    pub fee_sats: Option<u64>,
    /// Transaction type (send, receive, lock, jump, etc.)
    pub tx_type: String,
    /// Number of confirmations
    pub confirmations: u32,
    /// Optional memo/note
    pub memo: Option<String>,
}

/// Lock state snapshot for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockStateSnapshot {
    /// Current state (Active, Frozen, etc.)
    pub state: String,
    /// L2 balance in sats
    pub balance_sats: u64,
    /// Current confirmations
    pub confirmations: u32,
    /// Jump urgency (0.0 = fresh, 1.0 = needs rotation)
    pub jump_urgency: f32,
    /// Whether lock UTXO is in mempool
    pub in_mempool: bool,
    /// Pending L2 payment amount
    pub pending_l2_sats: u64,
    /// Maximum instant payment amount
    pub max_instant_sats: u64,
    /// Current block height
    pub current_height: u64,
}

/// Type of lock state change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStateChangeType {
    /// Balance changed (L2 payment)
    BalanceChange,
    /// Lock state transition (Active -> Frozen)
    StateTransition,
    /// Confirmation count increased
    Confirmation,
    /// Jump urgency changed
    JumpUrgency,
    /// Mempool status changed (L1 tx appeared/confirmed)
    MempoolChange,
    /// Pending L2 payment added/removed
    PendingL2Change,
}

impl ClientMessage {
    /// Check if this message requires authentication
    pub fn requires_auth(&self) -> bool {
        matches!(
            self,
            ClientMessage::GetBalance
                | ClientMessage::GetUtxos { .. }
                | ClientMessage::GetGhostLocks
                | ClientMessage::GetTransactions { .. }
                | ClientMessage::PreparePayment { .. }
                | ClientMessage::SubmitSignedPayment { .. }
                | ClientMessage::GetPaymentStatus { .. }
                | ClientMessage::CancelPayment { .. }
                | ClientMessage::PrepareGhostLock { .. }
                | ClientMessage::ConfirmGhostLockFunding { .. }
                | ClientMessage::RequestJump { .. }
                | ClientMessage::SubscribeBalance
                | ClientMessage::SubscribePayments
                | ClientMessage::SubscribeLocks
                | ClientMessage::CheckInstantCapability { .. }
                | ClientMessage::SubscribeLockState { .. }
                | ClientMessage::UnsubscribeLockState { .. }
                | ClientMessage::AcceptInstantPayment { .. }
        )
    }

    /// Check if this message includes a WalletProof
    pub fn has_proof(&self) -> bool {
        matches!(
            self,
            ClientMessage::PreparePayment { .. }
                | ClientMessage::CancelPayment { .. }
                | ClientMessage::ConfirmGhostLockFunding { .. }
                | ClientMessage::RequestJump { .. }
                | ClientMessage::AcceptInstantPayment { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_serialize() {
        let msg = ClientMessage::GetBalance;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"get_balance\""));

        let msg2 = ClientMessage::GetUtxos {
            min_confirmations: 6,
        };
        let json2 = serde_json::to_string(&msg2).unwrap();
        assert!(json2.contains("\"min_confirmations\":6"));
    }

    #[test]
    fn test_server_message_serialize() {
        let msg = ServerMessage::BalanceUpdate {
            confirmed: 100000,
            unconfirmed: 50000,
            locked: 25000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"balance_update\""));
        assert!(json.contains("\"confirmed\":100000"));
    }

    #[test]
    fn test_requires_auth() {
        assert!(ClientMessage::GetBalance.requires_auth());
        assert!(!ClientMessage::Ping { timestamp: None }.requires_auth());
    }

    #[test]
    fn test_utxo_info_serialize() {
        let utxo = UtxoInfo {
            txid: "abc123".to_string(),
            vout: 0,
            amount_sats: 100000,
            confirmations: 6,
            script_type: "p2tr".to_string(),
            spendable: true,
        };
        let json = serde_json::to_string(&utxo).unwrap();
        assert!(json.contains("\"txid\":\"abc123\""));
        assert!(json.contains("\"spendable\":true"));
    }

    #[test]
    fn test_instant_capability_request_serialize() {
        let msg = ClientMessage::CheckInstantCapability {
            lock_id: "lock123".to_string(),
            amount_sats: 50000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"check_instant_capability\""));
        assert!(json.contains("\"lock_id\":\"lock123\""));
        assert!(json.contains("\"amount_sats\":50000"));
    }

    #[test]
    fn test_instant_capability_result_serialize() {
        let msg = ServerMessage::InstantCapabilityResult {
            lock_id: "lock123".to_string(),
            capable: true,
            max_instant_sats: 100000,
            confidence: 0.95,
            valid_until_height: 800100,
            conditions_met: 0xFF,
            conditions_failed: 0x00,
            error: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"instant_capability_result\""));
        assert!(json.contains("\"capable\":true"));
        assert!(json.contains("\"confidence\":0.95"));
    }

    #[test]
    fn test_lock_state_update_serialize() {
        let snapshot = LockStateSnapshot {
            state: "Active".to_string(),
            balance_sats: 500000,
            confirmations: 10,
            jump_urgency: 0.05,
            in_mempool: false,
            pending_l2_sats: 0,
            max_instant_sats: 100000,
            current_height: 800100,
        };
        let msg = ServerMessage::LockStateUpdate {
            lock_id: "lock123".to_string(),
            snapshot,
            change_type: LockStateChangeType::BalanceChange,
            timestamp: 1700000000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"lock_state_update\""));
        assert!(json.contains("\"change_type\":\"balance_change\""));
    }

    #[test]
    fn test_instant_messages_require_auth() {
        assert!(ClientMessage::CheckInstantCapability {
            lock_id: "test".to_string(),
            amount_sats: 1000,
        }
        .requires_auth());

        assert!(ClientMessage::SubscribeLockState {
            lock_id: "test".to_string(),
        }
        .requires_auth());
    }
}
