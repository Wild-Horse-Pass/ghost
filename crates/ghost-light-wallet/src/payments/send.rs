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
//| FILE: payments/send.rs                                                                                               |
//|======================================================================================================================|

//! Send payment operations

use tracing::info;

use ghost_gsp_proto::{ClientMessage, PaymentMode, PaymentStatus, PreparedPayment};

use crate::error::{LightWalletError, WalletResult};
use crate::gsp::GspClient;
use crate::keys::MasterKey;
use crate::signing;

/// Payment request from user
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// Recipient address or Ghost ID
    pub recipient: String,

    /// Amount in satoshis
    pub amount_sats: u64,

    /// Payment mode
    pub mode: PaymentMode,

    /// Optional memo
    pub memo: Option<String>,
}

impl PaymentRequest {
    /// Create a new Ghost Pay payment request
    pub fn ghost_pay(recipient: &str, amount_sats: u64) -> Self {
        Self {
            recipient: recipient.to_string(),
            amount_sats,
            mode: PaymentMode::GhostPay,
            memo: None,
        }
    }

    /// Create a new Wraith payment request
    pub fn wraith(recipient: &str, amount_sats: u64) -> Self {
        Self {
            recipient: recipient.to_string(),
            amount_sats,
            mode: PaymentMode::Wraith,
            memo: None,
        }
    }

    /// Add a memo
    pub fn with_memo(mut self, memo: &str) -> Self {
        self.memo = Some(memo.to_string());
        self
    }
}

/// Prepare a payment through the GSP
///
/// This requests the GSP to prepare a payment transaction.
/// The transaction must then be signed locally and submitted.
pub async fn prepare_payment(
    client: &GspClient,
    master_key: &MasterKey,
    request: &PaymentRequest,
) -> WalletResult<PreparedPayment> {
    // Validate recipient
    if request.recipient.is_empty() {
        return Err(LightWalletError::InvalidRecipient(
            "Recipient cannot be empty".to_string(),
        ));
    }

    // Validate amount
    if request.amount_sats == 0 {
        return Err(LightWalletError::InvalidAmount(
            "Amount must be greater than 0".to_string(),
        ));
    }

    // Dust limit check
    if request.amount_sats < 546 {
        return Err(LightWalletError::InvalidAmount(
            "Amount below dust limit (546 sats)".to_string(),
        ));
    }

    // Create wallet proof for authentication
    let proof = signing::create_wallet_proof(master_key, "prepare_payment")?;

    info!(
        recipient = request.recipient,
        amount = request.amount_sats,
        mode = ?request.mode,
        "Preparing payment"
    );

    // Send prepare request to GSP
    let msg = ClientMessage::PreparePayment {
        recipient: request.recipient.clone(),
        amount_sats: request.amount_sats,
        mode: request.mode,
        proof,
    };

    // In a real implementation, we'd send this and wait for response
    // For now, return a placeholder
    let _ = msg;
    let _ = client;

    // Placeholder - actual implementation would parse GSP response
    Ok(PreparedPayment {
        payment_id: "placeholder".to_string(),
        mode: request.mode,
        recipient_address: request.recipient.clone(),
        original_recipient: request.recipient.clone(),
        amount_sats: request.amount_sats,
        fee_sats: 1000, // Placeholder fee
        total_sats: request.amount_sats + 1000,
        sighash: String::new(),
        signing_method: "schnorr".to_string(),
        expires_at: chrono::Utc::now().timestamp() + 300,
        status: PaymentStatus::PendingSignature,
        inputs: vec![],
        outputs: vec![],
        memo: request.memo.clone(),
    })
}

/// Sign a prepared payment and submit to GSP
pub async fn sign_and_submit(
    client: &GspClient,
    master_key: &MasterKey,
    prepared: &PreparedPayment,
) -> WalletResult<String> {
    // Check expiration
    let now = chrono::Utc::now().timestamp();
    if now >= prepared.expires_at {
        return Err(LightWalletError::PaymentFailed(
            "Payment preparation expired".to_string(),
        ));
    }

    info!(
        payment_id = prepared.payment_id,
        "Signing and submitting payment"
    );

    // Sign the transaction using the sighash
    let sighash_bytes = prepared
        .sighash_bytes()
        .map_err(|e| LightWalletError::SigningFailed(format!("Invalid sighash: {}", e)))?;
    let signature = signing::sign_data(master_key, &sighash_bytes)?;

    // Get public key
    let public_key = master_key.auth_pubkey();

    // Submit to GSP (hex-encode signature and public key)
    let msg = ClientMessage::SubmitSignedPayment {
        payment_id: prepared.payment_id.clone(),
        signature: hex::encode(signature),
        public_key: hex::encode(public_key),
    };

    // In a real implementation, we'd send this and wait for confirmation
    let _ = msg;
    let _ = client;

    info!(payment_id = prepared.payment_id, "Payment submitted");

    Ok(prepared.payment_id.clone())
}

/// Estimate fee for a payment
pub fn estimate_fee(amount_sats: u64, mode: &PaymentMode) -> u64 {
    // Simple fee estimation
    // In production, this would query the GSP or use fee rate estimation
    match mode {
        PaymentMode::GhostPay => {
            // Ghost Pay typically has lower fees (off-chain)
            (amount_sats as f64 * 0.001).max(100.0) as u64
        }
        PaymentMode::Wraith => {
            // Wraith requires on-chain tx
            // Assume ~140 vbytes for simple tx
            140 * 10 // 10 sat/vbyte
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_request() {
        let req = PaymentRequest::ghost_pay("ghost1abc...", 100_000);
        assert_eq!(req.amount_sats, 100_000);
        assert!(matches!(req.mode, PaymentMode::GhostPay));
        assert!(req.memo.is_none());

        let req = req.with_memo("Test payment");
        assert_eq!(req.memo, Some("Test payment".to_string()));
    }

    #[test]
    fn test_fee_estimation() {
        let ghost_fee = estimate_fee(100_000, &PaymentMode::GhostPay);
        let wraith_fee = estimate_fee(100_000, &PaymentMode::Wraith);

        // Ghost Pay should be cheaper
        assert!(ghost_fee < wraith_fee);

        // Minimum fee
        let min_fee = estimate_fee(1000, &PaymentMode::GhostPay);
        assert!(min_fee >= 100);
    }
}
