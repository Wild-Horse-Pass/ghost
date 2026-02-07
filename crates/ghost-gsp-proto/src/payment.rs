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
//| FILE: payment.rs                                                                                                     |
//|======================================================================================================================|

//! Payment types for GSP Protocol
//!
//! Defines the payment preparation, signing, and submission flow.

use serde::{Deserialize, Serialize};

use crate::auth::WalletProof;

/// Payment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PaymentMode {
    /// Standard Ghost Pay payment (direct, fast)
    #[default]
    GhostPay,
    /// Wraith Protocol payment (mixing, more private)
    Wraith,
}

impl std::fmt::Display for PaymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentMode::GhostPay => write!(f, "ghostpay"),
            PaymentMode::Wraith => write!(f, "wraith"),
        }
    }
}

/// Payment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    /// Payment is being prepared
    Preparing,
    /// Payment is ready for signing
    PendingSignature,
    /// Payment has been signed, awaiting broadcast
    Signed,
    /// Payment has been broadcast to network
    Broadcast,
    /// Payment is in mempool
    Mempool,
    /// Payment has confirmations
    Confirmed,
    /// Payment failed
    Failed,
    /// Payment was cancelled
    Cancelled,
    /// Payment expired (timed out)
    Expired,
}

impl PaymentStatus {
    /// Check if payment is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            PaymentStatus::Confirmed
                | PaymentStatus::Failed
                | PaymentStatus::Cancelled
                | PaymentStatus::Expired
        )
    }

    /// Check if payment can be cancelled
    pub fn can_cancel(&self) -> bool {
        matches!(
            self,
            PaymentStatus::Preparing | PaymentStatus::PendingSignature | PaymentStatus::Signed
        )
    }
}

impl std::fmt::Display for PaymentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PaymentStatus::Preparing => "preparing",
            PaymentStatus::PendingSignature => "pending_signature",
            PaymentStatus::Signed => "signed",
            PaymentStatus::Broadcast => "broadcast",
            PaymentStatus::Mempool => "mempool",
            PaymentStatus::Confirmed => "confirmed",
            PaymentStatus::Failed => "failed",
            PaymentStatus::Cancelled => "cancelled",
            PaymentStatus::Expired => "expired",
        };
        write!(f, "{}", s)
    }
}

/// Request to prepare a payment (REST API)
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts sensitive fields (recipient, proof, encrypted_metadata).
#[derive(Clone, Serialize, Deserialize)]
pub struct PreparePaymentRequest {
    /// Recipient Ghost ID or Bitcoin address
    pub recipient: String,

    /// Amount in satoshis
    pub amount_sats: u64,

    /// Payment mode
    #[serde(default)]
    pub mode: PaymentMode,

    /// Authentication proof
    pub proof: WalletProof,

    /// Optional memo/note
    pub memo: Option<String>,

    /// Encrypted label metadata (80 bytes, base64 encoded)
    /// Contains sender's label index and optional memo, encrypted with ECDH shared secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<String>,
}

impl std::fmt::Debug for PreparePaymentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparePaymentRequest")
            .field("recipient", &"[REDACTED]")
            .field("amount_sats", &self.amount_sats)
            .field("mode", &self.mode)
            .field("proof", &self.proof)
            .field("memo", &self.memo)
            .field("encrypted_metadata", &self.encrypted_metadata.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Response for payment preparation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparePaymentResponse {
    /// Whether preparation succeeded
    pub success: bool,

    /// Prepared payment details
    pub payment: Option<PreparedPayment>,

    /// Error message if failed
    pub error: Option<String>,
}

/// A prepared payment ready for signing
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts sensitive fields (addresses, sighash, keys, metadata).
#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedPayment {
    /// Unique payment ID
    pub payment_id: String,

    /// Payment mode
    pub mode: PaymentMode,

    /// Recipient address (derived if Ghost ID)
    pub recipient_address: String,

    /// Original recipient (Ghost ID or address)
    pub original_recipient: String,

    /// Amount being sent (satoshis)
    pub amount_sats: u64,

    /// Estimated fee (satoshis)
    pub fee_sats: u64,

    /// Total amount needed (amount + fee)
    pub total_sats: u64,

    /// Message to sign (sighash)
    pub sighash: String,

    /// Required signing method
    pub signing_method: String,

    /// Expiry timestamp (Unix seconds)
    pub expires_at: i64,

    /// Current status
    pub status: PaymentStatus,

    /// Input UTXOs being used
    pub inputs: Vec<PaymentInput>,

    /// Output details
    pub outputs: Vec<PaymentOutput>,

    /// Optional memo
    pub memo: Option<String>,

    /// Encrypted label metadata (80 bytes, base64 encoded)
    /// Pass-through from request - server never decrypts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<String>,

    /// Ephemeral public key for metadata decryption (33 bytes hex)
    /// Recipient needs this + their scan key to derive shared secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_pubkey: Option<String>,
}

impl std::fmt::Debug for PreparedPayment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedPayment")
            .field("payment_id", &self.payment_id)
            .field("mode", &self.mode)
            .field("recipient_address", &"[REDACTED]")
            .field("original_recipient", &"[REDACTED]")
            .field("amount_sats", &self.amount_sats)
            .field("fee_sats", &self.fee_sats)
            .field("total_sats", &self.total_sats)
            .field("sighash", &"[REDACTED]")
            .field("signing_method", &self.signing_method)
            .field("expires_at", &self.expires_at)
            .field("status", &self.status)
            .field("inputs", &format!("[{} inputs]", self.inputs.len()))
            .field("outputs", &format!("[{} outputs]", self.outputs.len()))
            .field("memo", &self.memo)
            .field("encrypted_metadata", &self.encrypted_metadata.as_ref().map(|_| "[REDACTED]"))
            .field("ephemeral_pubkey", &self.ephemeral_pubkey.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl PreparedPayment {
    /// Check if payment has expired
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now >= self.expires_at
    }

    /// Get remaining time until expiry in seconds
    pub fn remaining_secs(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (self.expires_at - now).max(0)
    }

    /// Get sighash bytes for signing
    pub fn sighash_bytes(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.sighash)
    }
}

/// Input UTXO for a payment
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts the derivation_path field.
#[derive(Clone, Serialize, Deserialize)]
pub struct PaymentInput {
    /// Transaction ID
    pub txid: String,

    /// Output index
    pub vout: u32,

    /// Amount in satoshis
    pub amount_sats: u64,

    /// Script type (p2tr, p2wpkh, etc.)
    pub script_type: String,

    /// Derivation path for signing (if applicable)
    pub derivation_path: Option<String>,
}

impl std::fmt::Debug for PaymentInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentInput")
            .field("txid", &self.txid)
            .field("vout", &self.vout)
            .field("amount_sats", &self.amount_sats)
            .field("script_type", &self.script_type)
            .field("derivation_path", &self.derivation_path.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Output for a payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOutput {
    /// Output address
    pub address: String,

    /// Amount in satoshis
    pub amount_sats: u64,

    /// Whether this is the recipient output
    pub is_recipient: bool,

    /// Whether this is change
    pub is_change: bool,
}

/// Request to submit a signed payment
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts the signature and public_key fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct SubmitPaymentRequest {
    /// Payment ID from prepare_payment
    pub payment_id: String,

    /// Schnorr signature (64 bytes hex)
    pub signature: String,

    /// Public key used for signing (32 bytes hex)
    pub public_key: String,
}

impl std::fmt::Debug for SubmitPaymentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubmitPaymentRequest")
            .field("payment_id", &self.payment_id)
            .field("signature", &"[REDACTED]")
            .field("public_key", &"[REDACTED]")
            .finish()
    }
}

/// Response for payment submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPaymentResponse {
    /// Whether submission succeeded
    pub success: bool,

    /// Payment ID
    pub payment_id: String,

    /// Transaction ID if broadcast
    pub txid: Option<String>,

    /// Updated status
    pub status: PaymentStatus,

    /// Error message if failed
    pub error: Option<String>,
}

/// Payment receipt (for confirmed payments)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Payment ID
    pub payment_id: String,

    /// Transaction ID
    pub txid: String,

    /// Block height
    pub block_height: u32,

    /// Block hash
    pub block_hash: String,

    /// Confirmations
    pub confirmations: u32,

    /// Timestamp
    pub timestamp: i64,

    /// Amount sent
    pub amount_sats: u64,

    /// Fee paid
    pub fee_sats: u64,

    /// Recipient address
    pub recipient: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_mode_serialize() {
        let mode = PaymentMode::GhostPay;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"ghostpay\"");

        let parsed: PaymentMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PaymentMode::GhostPay);
    }

    #[test]
    fn test_payment_status_terminal() {
        assert!(PaymentStatus::Confirmed.is_terminal());
        assert!(PaymentStatus::Failed.is_terminal());
        assert!(!PaymentStatus::Preparing.is_terminal());
        assert!(!PaymentStatus::Broadcast.is_terminal());
    }

    #[test]
    fn test_payment_status_can_cancel() {
        assert!(PaymentStatus::Preparing.can_cancel());
        assert!(PaymentStatus::PendingSignature.can_cancel());
        assert!(!PaymentStatus::Broadcast.can_cancel());
        assert!(!PaymentStatus::Confirmed.can_cancel());
    }

    #[test]
    fn test_prepared_payment_expiry() {
        let payment = PreparedPayment {
            payment_id: "test".to_string(),
            mode: PaymentMode::GhostPay,
            recipient_address: "bc1q...".to_string(),
            original_recipient: "ghost1...".to_string(),
            amount_sats: 100000,
            fee_sats: 1000,
            total_sats: 101000,
            sighash: "abcd".to_string(),
            signing_method: "schnorr".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 600, // 10 minutes
            status: PaymentStatus::PendingSignature,
            inputs: vec![],
            outputs: vec![],
            memo: None,
            encrypted_metadata: None,
            ephemeral_pubkey: None,
        };

        assert!(!payment.is_expired());
        assert!(payment.remaining_secs() > 0);
    }

    #[test]
    fn test_prepared_payment_debug_redacts_sensitive_fields() {
        // M-INFO-1 TEST: Verify Debug implementation redacts sensitive data
        let payment = PreparedPayment {
            payment_id: "test_payment_id".to_string(),
            mode: PaymentMode::GhostPay,
            recipient_address: "bc1qsecretaddress".to_string(),
            original_recipient: "ghost1secretrecipient".to_string(),
            amount_sats: 100000,
            fee_sats: 1000,
            total_sats: 101000,
            sighash: "deadbeef1234567890".to_string(),
            signing_method: "schnorr".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 600,
            status: PaymentStatus::PendingSignature,
            inputs: vec![],
            outputs: vec![],
            memo: Some("test memo".to_string()),
            encrypted_metadata: Some("encrypted_secret_data".to_string()),
            ephemeral_pubkey: Some("ephemeral_key_hex".to_string()),
        };

        let debug_output = format!("{:?}", payment);

        // Ensure sensitive fields are redacted
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("bc1qsecretaddress"));
        assert!(!debug_output.contains("ghost1secretrecipient"));
        assert!(!debug_output.contains("deadbeef1234567890"));
        assert!(!debug_output.contains("encrypted_secret_data"));
        assert!(!debug_output.contains("ephemeral_key_hex"));
        // Non-sensitive fields should be visible
        assert!(debug_output.contains("test_payment_id"));
        assert!(debug_output.contains("100000"));
    }

    #[test]
    fn test_submit_payment_request_debug_redacts_signature() {
        // M-INFO-1 TEST: Verify Debug implementation redacts signature and public key
        let request = SubmitPaymentRequest {
            payment_id: "payment_123".to_string(),
            signature: "secret_signature_hex".to_string(),
            public_key: "secret_pubkey_hex".to_string(),
        };

        let debug_output = format!("{:?}", request);

        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("secret_signature_hex"));
        assert!(!debug_output.contains("secret_pubkey_hex"));
        assert!(debug_output.contains("payment_123"));
    }

    #[test]
    fn test_payment_input_debug_redacts_derivation_path() {
        // M-INFO-1 TEST: Verify Debug implementation redacts derivation path
        let input = PaymentInput {
            txid: "abc123".to_string(),
            vout: 0,
            amount_sats: 50000,
            script_type: "p2tr".to_string(),
            derivation_path: Some("m/352'/0'/0'/0/5".to_string()),
        };

        let debug_output = format!("{:?}", input);

        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("m/352'/0'/0'/0/5"));
        // Non-sensitive fields should be visible
        assert!(debug_output.contains("abc123"));
        assert!(debug_output.contains("50000"));
    }
}
