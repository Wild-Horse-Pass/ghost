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
//| FILE: api/websocket.rs                                                                                               |
//|======================================================================================================================|

//! WebSocket API handler

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use tracing::{debug, error, info, warn};

use ghost_gsp_proto::{
    validate_message, ClientMessage, PaymentMode, PaymentStatus, PreparedPayment, ServerMessage,
    WalletId, WalletProof,
};

use crate::auth::verify_schnorr_proof;
use crate::error::GspError;
use crate::server::GspState;

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<GspState>>,
) -> impl IntoResponse {
    // Check connection limit
    if !state.can_accept_connection() {
        return ws
            .on_failed_upgrade(|_| {
                warn!("WebSocket connection rejected: max connections reached");
            })
            .on_upgrade(|_| async {});
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Connection state
struct ConnectionState {
    /// Authenticated wallet ID (None if not yet authenticated)
    wallet_id: Option<WalletId>,

    /// Active subscriptions
    subscriptions: Vec<String>,

    /// Lock state subscriptions (lock_id)
    lock_state_subscriptions: Vec<String>,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            wallet_id: None,
            subscriptions: Vec::new(),
            lock_state_subscriptions: Vec::new(),
        }
    }
}

/// Handle a WebSocket connection
async fn handle_socket(socket: WebSocket, state: Arc<GspState>) {
    state.add_connection();
    debug!("WebSocket connection established");

    let (mut sender, mut receiver) = socket.split();
    let mut conn_state = ConnectionState::default();

    // Main message loop
    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                error!("WebSocket receive error: {}", e);
                break;
            }
        };

        // Handle message
        let response = match handle_message(&state, &mut conn_state, msg).await {
            Ok(Some(resp)) => resp,
            Ok(None) => continue, // No response needed
            Err(e) => ServerMessage::Error {
                code: "ERROR".to_string(),
                message: e.to_string(),
                request_id: None,
            },
        };

        // Send response
        let json = match serde_json::to_string(&response) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to serialize response: {}", e);
                continue;
            }
        };

        if let Err(e) = sender.send(Message::Text(json)).await {
            error!("WebSocket send error: {}", e);
            break;
        }
    }

    // Cleanup
    if let Some(wallet_id) = &conn_state.wallet_id {
        state.subscriptions.unsubscribe_all(wallet_id);
    }
    state.remove_connection();
    debug!("WebSocket connection closed");
}

/// Handle a single WebSocket message
async fn handle_message(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    msg: Message,
) -> Result<Option<ServerMessage>, GspError> {
    let text = match msg {
        Message::Text(t) => t,
        Message::Binary(_) => {
            return Err(GspError::BadRequest(
                "Binary messages not supported".to_string(),
            ))
        }
        Message::Ping(_) | Message::Pong(_) => return Ok(None),
        Message::Close(_) => return Ok(None),
    };

    // Parse message
    let client_msg: ClientMessage = serde_json::from_str(&text)
        .map_err(|e| GspError::BadRequest(format!("Invalid JSON: {}", e)))?;

    // Validate message
    let validation = validate_message(&client_msg);
    if !validation.valid {
        return Err(GspError::BadRequest(validation.errors.join("; ")));
    }

    // Check authentication for protected messages
    if client_msg.requires_auth() && conn_state.wallet_id.is_none() {
        return Err(GspError::Unauthorized);
    }

    // Handle message
    match client_msg {
        ClientMessage::Authenticate { token } => {
            handle_authenticate(state, conn_state, &token).await
        }

        ClientMessage::Ping { timestamp } => Ok(Some(ServerMessage::Pong {
            timestamp,
            server_time: chrono::Utc::now().timestamp(),
        })),

        ClientMessage::GetBalance => handle_get_balance(state, conn_state).await,

        ClientMessage::GetUtxos { min_confirmations } => {
            handle_get_utxos(state, conn_state, min_confirmations).await
        }

        ClientMessage::GetGhostLocks => handle_get_ghost_locks(state, conn_state).await,

        ClientMessage::GetTransactions { limit, offset } => {
            handle_get_transactions(state, conn_state, limit, offset).await
        }

        ClientMessage::SubscribeBalance => handle_subscribe(state, conn_state, "balance").await,

        ClientMessage::SubscribePayments => handle_subscribe(state, conn_state, "payments").await,

        ClientMessage::SubscribeLocks => handle_subscribe(state, conn_state, "locks").await,

        ClientMessage::Unsubscribe { subscription } => {
            handle_unsubscribe(state, conn_state, &subscription).await
        }

        // Payment operations
        ClientMessage::PreparePayment {
            recipient,
            amount_sats,
            mode,
            proof,
        } => {
            handle_prepare_payment(state, conn_state, &recipient, amount_sats, &mode, &proof).await
        }

        ClientMessage::SubmitSignedPayment {
            payment_id,
            signature,
            public_key,
        } => {
            handle_submit_signed_payment(state, conn_state, &payment_id, &signature, &public_key)
                .await
        }

        ClientMessage::GetPaymentStatus { payment_id } => {
            handle_get_payment_status(state, conn_state, &payment_id).await
        }

        ClientMessage::CancelPayment { payment_id, proof } => {
            handle_cancel_payment(state, conn_state, &payment_id, &proof).await
        }

        // Ghost Lock operations
        ClientMessage::PrepareGhostLock {
            owner_pubkey,
            capacity_sats,
        } => handle_prepare_ghost_lock(state, conn_state, &owner_pubkey, capacity_sats).await,

        ClientMessage::ConfirmGhostLockFunding {
            lock_id,
            funding_txid,
            proof,
        } => {
            handle_confirm_ghost_lock_funding(state, conn_state, &lock_id, &funding_txid, &proof)
                .await
        }

        ClientMessage::RequestJump {
            lock_id,
            priority,
            target_address,
            proof,
        } => {
            handle_request_jump(
                state,
                conn_state,
                &lock_id,
                &priority,
                &target_address,
                &proof,
            )
            .await
        }

        // Instant Payment operations
        ClientMessage::CheckInstantCapability {
            lock_id,
            amount_sats,
        } => handle_check_instant_capability(state, conn_state, &lock_id, amount_sats).await,

        ClientMessage::SubscribeLockState { lock_id } => {
            handle_subscribe_lock_state(state, conn_state, &lock_id).await
        }

        ClientMessage::UnsubscribeLockState { lock_id } => {
            handle_unsubscribe_lock_state(state, conn_state, &lock_id).await
        }

        ClientMessage::AcceptInstantPayment {
            sender_lock_id,
            amount_sats,
            proof,
        } => {
            handle_accept_instant_payment(state, conn_state, &sender_lock_id, amount_sats, &proof)
                .await
        }
    }
}

/// Handle authenticate message
async fn handle_authenticate(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    token: &str,
) -> Result<Option<ServerMessage>, GspError> {
    match state.jwt.validate_token(token) {
        Ok(wallet_id) => {
            info!(wallet_id = %wallet_id, "WebSocket authenticated");
            conn_state.wallet_id = Some(wallet_id.clone());

            Ok(Some(ServerMessage::AuthResult {
                success: true,
                wallet_id: Some(wallet_id.to_string()),
                error: None,
            }))
        }
        Err(e) => Ok(Some(ServerMessage::AuthResult {
            success: false,
            wallet_id: None,
            error: Some(e.to_string()),
        })),
    }
}

/// Handle get_balance message
async fn handle_get_balance(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Query pay node for balance
    let balance = state.pay_node.get_balance(&wallet_id.to_string()).await?;

    Ok(Some(ServerMessage::BalanceUpdate {
        confirmed: balance.confirmed,
        unconfirmed: balance.unconfirmed,
        locked: balance.locked,
    }))
}

/// Handle get_utxos message
async fn handle_get_utxos(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    min_confirmations: u32,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Query pay node for UTXOs
    let utxos = state
        .pay_node
        .get_utxos(&wallet_id.to_string(), min_confirmations)
        .await?;

    let total_sats: u64 = utxos.iter().map(|u| u.amount_sats).sum();

    Ok(Some(ServerMessage::Utxos { utxos, total_sats }))
}

/// Handle get_ghost_locks message
async fn handle_get_ghost_locks(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Query pay node for locks
    let locks = state
        .pay_node
        .get_ghost_locks(&wallet_id.to_string())
        .await?;

    let total_locked_sats: u64 = locks.iter().map(|l| l.balance_sats).sum();

    Ok(Some(ServerMessage::GhostLocks {
        locks,
        total_locked_sats,
    }))
}

/// Handle get_transactions message
async fn handle_get_transactions(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    limit: u32,
    offset: u32,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Query pay node for transactions
    let (transactions, total_count) = state
        .pay_node
        .get_transactions(&wallet_id.to_string(), limit, offset)
        .await?;

    Ok(Some(ServerMessage::Transactions {
        transactions,
        total_count,
    }))
}

/// Handle subscription request
async fn handle_subscribe(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    subscription: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Add subscription
    state.subscriptions.subscribe(wallet_id, subscription);
    conn_state.subscriptions.push(subscription.to_string());

    Ok(Some(ServerMessage::Subscribed {
        subscription: subscription.to_string(),
    }))
}

/// Handle unsubscription request
async fn handle_unsubscribe(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    subscription: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Remove subscription
    state.subscriptions.unsubscribe(wallet_id, subscription);
    conn_state.subscriptions.retain(|s| s != subscription);

    Ok(Some(ServerMessage::Unsubscribed {
        subscription: subscription.to_string(),
    }))
}

/// Handle jump request for Ghost Locks
///
/// A jump allows early key rotation before the timelock expires,
/// moving funds from an existing lock to a new address.
async fn handle_request_jump(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    lock_id: &str,
    priority: &str,
    target_address: &str,
    proof: &WalletProof,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Validate proof structure first
    if let Err(e) = proof.validate_structure() {
        return Ok(Some(ServerMessage::JumpRequested {
            success: false,
            lock_id: lock_id.to_string(),
            jump_txid: None,
            error: Some(format!("Invalid proof structure: {}", e)),
        }));
    }

    // Check timestamp is within acceptable range
    if !proof.is_timestamp_valid() {
        return Ok(Some(ServerMessage::JumpRequested {
            success: false,
            lock_id: lock_id.to_string(),
            jump_txid: None,
            error: Some("Proof timestamp expired or too far in future".to_string()),
        }));
    }

    // Verify the Schnorr signature
    if let Err(e) = verify_schnorr_proof(proof) {
        return Ok(Some(ServerMessage::JumpRequested {
            success: false,
            lock_id: lock_id.to_string(),
            jump_txid: None,
            error: Some(format!("Invalid wallet proof signature: {}", e)),
        }));
    }

    // Verify proof matches authenticated wallet
    let proof_wallet_id = match proof.wallet_id() {
        Ok(id) => id,
        Err(e) => {
            return Ok(Some(ServerMessage::JumpRequested {
                success: false,
                lock_id: lock_id.to_string(),
                jump_txid: None,
                error: Some(format!("Invalid proof public key: {}", e)),
            }));
        }
    };

    if proof_wallet_id != *wallet_id {
        return Ok(Some(ServerMessage::JumpRequested {
            success: false,
            lock_id: lock_id.to_string(),
            jump_txid: None,
            error: Some("Wallet proof does not match authenticated session".to_string()),
        }));
    }

    info!(
        wallet_id = %wallet_id,
        lock_id = %lock_id,
        target = %target_address,
        priority = %priority,
        "Processing jump request"
    );

    // Request jump from pay node
    match state
        .pay_node
        .request_jump(lock_id, target_address, priority)
        .await
    {
        Ok(result) => {
            // Parse the response
            let jump_txid = result
                .get("txid")
                .and_then(|v| v.as_str())
                .map(String::from);
            let success = result
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let error = result
                .get("error")
                .and_then(|v| v.as_str())
                .map(String::from);

            Ok(Some(ServerMessage::JumpRequested {
                success,
                lock_id: lock_id.to_string(),
                jump_txid,
                error,
            }))
        }
        Err(e) => {
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                error = %e,
                "Jump request failed"
            );

            Ok(Some(ServerMessage::JumpRequested {
                success: false,
                lock_id: lock_id.to_string(),
                jump_txid: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Handle prepare payment request
///
/// Prepares a payment transaction for signing by the wallet.
async fn handle_prepare_payment(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    recipient: &str,
    amount_sats: u64,
    mode: &PaymentMode,
    proof: &WalletProof,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Validate proof structure
    if let Err(e) = proof.validate_structure() {
        return Ok(Some(ServerMessage::PaymentPrepared {
            success: false,
            payment: None,
            error: Some(format!("Invalid proof structure: {}", e)),
        }));
    }

    // Check timestamp
    if !proof.is_timestamp_valid() {
        return Ok(Some(ServerMessage::PaymentPrepared {
            success: false,
            payment: None,
            error: Some("Proof timestamp expired or too far in future".to_string()),
        }));
    }

    // Verify signature
    if let Err(e) = verify_schnorr_proof(proof) {
        return Ok(Some(ServerMessage::PaymentPrepared {
            success: false,
            payment: None,
            error: Some(format!("Invalid wallet proof signature: {}", e)),
        }));
    }

    // Verify proof matches authenticated wallet
    let proof_wallet_id = match proof.wallet_id() {
        Ok(id) => id,
        Err(e) => {
            return Ok(Some(ServerMessage::PaymentPrepared {
                success: false,
                payment: None,
                error: Some(format!("Invalid proof public key: {}", e)),
            }));
        }
    };

    if proof_wallet_id != *wallet_id {
        return Ok(Some(ServerMessage::PaymentPrepared {
            success: false,
            payment: None,
            error: Some("Wallet proof does not match authenticated session".to_string()),
        }));
    }

    info!(
        wallet_id = %wallet_id,
        recipient = %recipient,
        amount_sats = amount_sats,
        mode = ?mode,
        "Preparing payment"
    );

    // Prepare payment via pay node
    match state
        .pay_node
        .prepare_payment(&wallet_id.to_string(), recipient, amount_sats)
        .await
    {
        Ok(result) => {
            // Parse the response into PreparedPayment
            let payment_id = result
                .get("payment_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let fee_sats = result.get("fee_sats").and_then(|v| v.as_u64()).unwrap_or(0);
            let expires_at = result
                .get("expires_at")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let sighash = result
                .get("sighash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let recipient_address = result
                .get("recipient_address")
                .and_then(|v| v.as_str())
                .unwrap_or(recipient)
                .to_string();

            let payment = PreparedPayment {
                payment_id,
                mode: *mode,
                recipient_address,
                original_recipient: recipient.to_string(),
                amount_sats,
                fee_sats,
                total_sats: amount_sats + fee_sats,
                sighash,
                signing_method: "schnorr".to_string(),
                expires_at,
                status: PaymentStatus::PendingSignature,
                inputs: vec![],
                outputs: vec![],
                memo: None,
            };

            Ok(Some(ServerMessage::PaymentPrepared {
                success: true,
                payment: Some(payment),
                error: None,
            }))
        }
        Err(e) => {
            warn!(
                wallet_id = %wallet_id,
                error = %e,
                "Payment preparation failed"
            );

            Ok(Some(ServerMessage::PaymentPrepared {
                success: false,
                payment: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Handle submit signed payment
///
/// Submits a signed payment transaction for broadcast.
async fn handle_submit_signed_payment(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    payment_id: &str,
    signature: &str,
    public_key: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    info!(
        wallet_id = %wallet_id,
        payment_id = %payment_id,
        "Submitting signed payment"
    );

    // Submit payment via pay node
    match state
        .pay_node
        .submit_payment(payment_id, signature, public_key)
        .await
    {
        Ok(result) => {
            let success = result
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let txid = result
                .get("txid")
                .and_then(|v| v.as_str())
                .map(String::from);
            let error = result
                .get("error")
                .and_then(|v| v.as_str())
                .map(String::from);

            Ok(Some(ServerMessage::PaymentSubmitted {
                success,
                payment_id: payment_id.to_string(),
                txid,
                error,
            }))
        }
        Err(e) => {
            warn!(
                wallet_id = %wallet_id,
                payment_id = %payment_id,
                error = %e,
                "Payment submission failed"
            );

            Ok(Some(ServerMessage::PaymentSubmitted {
                success: false,
                payment_id: payment_id.to_string(),
                txid: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Handle get payment status
async fn handle_get_payment_status(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    payment_id: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    debug!(
        wallet_id = %wallet_id,
        payment_id = %payment_id,
        "Getting payment status"
    );

    // Get status from pay node
    match state.pay_node.get_payment_status(payment_id).await {
        Ok(result) => {
            let status_str = result
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let confirmations = result
                .get("confirmations")
                .and_then(|v| v.as_u64())
                .map(|c| c as u32);

            let status = match status_str {
                "preparing" => PaymentStatus::Preparing,
                "pending_signature" => PaymentStatus::PendingSignature,
                "signed" => PaymentStatus::Signed,
                "broadcast" => PaymentStatus::Broadcast,
                "mempool" => PaymentStatus::Mempool,
                "confirmed" => PaymentStatus::Confirmed,
                "failed" => PaymentStatus::Failed,
                "cancelled" => PaymentStatus::Cancelled,
                "expired" => PaymentStatus::Expired,
                _ => PaymentStatus::Preparing,
            };

            Ok(Some(ServerMessage::PaymentStatus {
                payment_id: payment_id.to_string(),
                status,
                confirmations,
            }))
        }
        Err(e) => {
            warn!(
                wallet_id = %wallet_id,
                payment_id = %payment_id,
                error = %e,
                "Failed to get payment status"
            );

            Err(e)
        }
    }
}

/// Handle cancel payment request
async fn handle_cancel_payment(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    payment_id: &str,
    proof: &WalletProof,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Validate proof structure
    if let Err(e) = proof.validate_structure() {
        return Ok(Some(ServerMessage::PaymentSubmitted {
            success: false,
            payment_id: payment_id.to_string(),
            txid: None,
            error: Some(format!("Invalid proof structure: {}", e)),
        }));
    }

    // Check timestamp
    if !proof.is_timestamp_valid() {
        return Ok(Some(ServerMessage::PaymentSubmitted {
            success: false,
            payment_id: payment_id.to_string(),
            txid: None,
            error: Some("Proof timestamp expired or too far in future".to_string()),
        }));
    }

    // Verify signature
    if let Err(e) = verify_schnorr_proof(proof) {
        return Ok(Some(ServerMessage::PaymentSubmitted {
            success: false,
            payment_id: payment_id.to_string(),
            txid: None,
            error: Some(format!("Invalid wallet proof signature: {}", e)),
        }));
    }

    // Verify proof matches authenticated wallet
    let proof_wallet_id = match proof.wallet_id() {
        Ok(id) => id,
        Err(e) => {
            return Ok(Some(ServerMessage::PaymentSubmitted {
                success: false,
                payment_id: payment_id.to_string(),
                txid: None,
                error: Some(format!("Invalid proof public key: {}", e)),
            }));
        }
    };

    if proof_wallet_id != *wallet_id {
        return Ok(Some(ServerMessage::PaymentSubmitted {
            success: false,
            payment_id: payment_id.to_string(),
            txid: None,
            error: Some("Wallet proof does not match authenticated session".to_string()),
        }));
    }

    info!(
        wallet_id = %wallet_id,
        payment_id = %payment_id,
        "Cancelling payment"
    );

    // Cancel payment via pay node
    match state.pay_node.cancel_payment(payment_id).await {
        Ok(success) => Ok(Some(ServerMessage::PaymentSubmitted {
            success,
            payment_id: payment_id.to_string(),
            txid: None,
            error: if success {
                None
            } else {
                Some("Failed to cancel payment".to_string())
            },
        })),
        Err(e) => {
            warn!(
                wallet_id = %wallet_id,
                payment_id = %payment_id,
                error = %e,
                "Payment cancellation failed"
            );

            Ok(Some(ServerMessage::PaymentSubmitted {
                success: false,
                payment_id: payment_id.to_string(),
                txid: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Handle prepare ghost lock request
///
/// Prepares a new Ghost Lock for the wallet.
async fn handle_prepare_ghost_lock(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    _owner_pubkey: &str,
    capacity_sats: u64,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    info!(
        wallet_id = %wallet_id,
        capacity_sats = capacity_sats,
        "Preparing ghost lock"
    );

    // Create lock via pay node
    match state
        .pay_node
        .create_lock(&wallet_id.to_string(), capacity_sats, None)
        .await
    {
        Ok(lock_info) => Ok(Some(ServerMessage::LockPrepared {
            success: true,
            lock_id: Some(lock_info.lock_id),
            funding_address: Some(lock_info.funding_address),
            required_sats: Some(capacity_sats),
            error: None,
        })),
        Err(e) => {
            warn!(
                wallet_id = %wallet_id,
                error = %e,
                "Ghost lock preparation failed"
            );

            Ok(Some(ServerMessage::LockPrepared {
                success: false,
                lock_id: None,
                funding_address: None,
                required_sats: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

/// Handle confirm ghost lock funding
///
/// Confirms that a Ghost Lock has been funded on-chain.
async fn handle_confirm_ghost_lock_funding(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    lock_id: &str,
    funding_txid: &str,
    proof: &WalletProof,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Validate proof structure
    if let Err(e) = proof.validate_structure() {
        return Ok(Some(ServerMessage::Error {
            code: "INVALID_PROOF".to_string(),
            message: format!("Invalid proof structure: {}", e),
            request_id: None,
        }));
    }

    // Check timestamp
    if !proof.is_timestamp_valid() {
        return Ok(Some(ServerMessage::Error {
            code: "EXPIRED_PROOF".to_string(),
            message: "Proof timestamp expired or too far in future".to_string(),
            request_id: None,
        }));
    }

    // Verify signature
    if let Err(e) = verify_schnorr_proof(proof) {
        return Ok(Some(ServerMessage::Error {
            code: "INVALID_SIGNATURE".to_string(),
            message: format!("Invalid wallet proof signature: {}", e),
            request_id: None,
        }));
    }

    // Verify proof matches authenticated wallet
    let proof_wallet_id = match proof.wallet_id() {
        Ok(id) => id,
        Err(e) => {
            return Ok(Some(ServerMessage::Error {
                code: "INVALID_PUBLIC_KEY".to_string(),
                message: format!("Invalid proof public key: {}", e),
                request_id: None,
            }));
        }
    };

    if proof_wallet_id != *wallet_id {
        return Ok(Some(ServerMessage::Error {
            code: "WALLET_MISMATCH".to_string(),
            message: "Wallet proof does not match authenticated session".to_string(),
            request_id: None,
        }));
    }

    info!(
        wallet_id = %wallet_id,
        lock_id = %lock_id,
        funding_txid = %funding_txid,
        "Confirming ghost lock funding"
    );

    // Confirm funding via pay node
    match state
        .pay_node
        .confirm_lock_funding(lock_id, funding_txid, 0)
        .await
    {
        Ok(result) => {
            let block_height = result
                .get("block_height")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            Ok(Some(ServerMessage::LockConfirmed {
                lock_id: lock_id.to_string(),
                txid: funding_txid.to_string(),
                block_height,
            }))
        }
        Err(e) => {
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                error = %e,
                "Ghost lock funding confirmation failed"
            );

            Ok(Some(ServerMessage::Error {
                code: "CONFIRMATION_FAILED".to_string(),
                message: e.to_string(),
                request_id: None,
            }))
        }
    }
}

// =============================================================================
// Instant Payment Handlers
// =============================================================================

/// Check instant payment capability for a lock
///
/// Evaluates whether a lock can accept instant (optimistic) payments.
async fn handle_check_instant_capability(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    lock_id: &str,
    amount_sats: u64,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    debug!(
        wallet_id = %wallet_id,
        lock_id = %lock_id,
        amount_sats = amount_sats,
        "Checking instant capability"
    );

    // Query lock state from pay node
    let lock_snapshot = match state.pay_node.get_lock_snapshot(lock_id).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            return Ok(Some(ServerMessage::InstantCapabilityResult {
                lock_id: lock_id.to_string(),
                capable: false,
                max_instant_sats: 0,
                confidence: 0.0,
                valid_until_height: 0,
                conditions_met: 0,
                conditions_failed: 0xFF, // All failed
                error: Some(format!("Failed to get lock state: {}", e)),
            }));
        }
    };

    // Get current block height
    let current_height = state.pay_node.get_current_height().await.unwrap_or(0);

    // Evaluate instant capability using common logic
    let capability = lock_snapshot.check_instant(amount_sats, current_height);

    Ok(Some(ServerMessage::InstantCapabilityResult {
        lock_id: lock_id.to_string(),
        capable: capability.capable,
        max_instant_sats: capability.max_instant_sats,
        confidence: capability.confidence,
        valid_until_height: capability.valid_until_height,
        conditions_met: capability.conditions_bitmap(),
        conditions_failed: capability
            .conditions_failed
            .iter()
            .fold(0u8, |acc, c| acc | c.bit_flag()),
        error: None,
    }))
}

/// Subscribe to real-time lock state updates
async fn handle_subscribe_lock_state(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    lock_id: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    info!(
        wallet_id = %wallet_id,
        lock_id = %lock_id,
        "Subscribing to lock state updates"
    );

    // Register subscription
    conn_state
        .lock_state_subscriptions
        .push(lock_id.to_string());
    state.subscriptions.subscribe_lock_state(wallet_id, lock_id);

    // Get current lock snapshot
    let snapshot = match state.pay_node.get_lock_state_snapshot(lock_id).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(Some(ServerMessage::Error {
                code: "LOCK_NOT_FOUND".to_string(),
                message: format!("Failed to get lock state: {}", e),
                request_id: None,
            }));
        }
    };

    Ok(Some(ServerMessage::LockStateSubscribed {
        lock_id: lock_id.to_string(),
        snapshot,
    }))
}

/// Unsubscribe from lock state updates
async fn handle_unsubscribe_lock_state(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    lock_id: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    debug!(
        wallet_id = %wallet_id,
        lock_id = %lock_id,
        "Unsubscribing from lock state updates"
    );

    // Remove subscription
    conn_state.lock_state_subscriptions.retain(|s| s != lock_id);
    state
        .subscriptions
        .unsubscribe_lock_state(wallet_id, lock_id);

    Ok(Some(ServerMessage::LockStateUnsubscribed {
        lock_id: lock_id.to_string(),
    }))
}

/// Accept an instant payment as a merchant
///
/// This allows merchants to show "Confirmed" immediately for small payments,
/// with actual settlement happening on the next virtual block.
async fn handle_accept_instant_payment(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    sender_lock_id: &str,
    amount_sats: u64,
    proof: &WalletProof,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Validate proof
    if let Err(e) = proof.validate_structure() {
        return Ok(Some(ServerMessage::Error {
            code: "INVALID_PROOF".to_string(),
            message: format!("Invalid proof structure: {}", e),
            request_id: None,
        }));
    }

    if !proof.is_timestamp_valid() {
        return Ok(Some(ServerMessage::Error {
            code: "EXPIRED_PROOF".to_string(),
            message: "Proof timestamp expired or too far in future".to_string(),
            request_id: None,
        }));
    }

    if let Err(e) = verify_schnorr_proof(proof) {
        return Ok(Some(ServerMessage::Error {
            code: "INVALID_SIGNATURE".to_string(),
            message: format!("Invalid wallet proof signature: {}", e),
            request_id: None,
        }));
    }

    // Verify proof matches authenticated wallet
    let proof_wallet_id = match proof.wallet_id() {
        Ok(id) => id,
        Err(e) => {
            return Ok(Some(ServerMessage::Error {
                code: "INVALID_PUBLIC_KEY".to_string(),
                message: format!("Invalid proof public key: {}", e),
                request_id: None,
            }));
        }
    };

    if proof_wallet_id != *wallet_id {
        return Ok(Some(ServerMessage::Error {
            code: "WALLET_MISMATCH".to_string(),
            message: "Wallet proof does not match authenticated session".to_string(),
            request_id: None,
        }));
    }

    info!(
        wallet_id = %wallet_id,
        sender_lock_id = %sender_lock_id,
        amount_sats = amount_sats,
        "Accepting instant payment"
    );

    // Check instant capability
    let lock_snapshot = match state.pay_node.get_lock_snapshot(sender_lock_id).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            return Ok(Some(ServerMessage::Error {
                code: "LOCK_NOT_FOUND".to_string(),
                message: format!("Failed to get sender lock state: {}", e),
                request_id: None,
            }));
        }
    };

    let current_height = state.pay_node.get_current_height().await.unwrap_or(0);
    let capability = lock_snapshot.check_instant(amount_sats, current_height);

    if !capability.capable {
        let failed_conditions: Vec<String> = capability
            .conditions_failed
            .iter()
            .map(|c| c.description().to_string())
            .collect();

        return Ok(Some(ServerMessage::Error {
            code: "NOT_INSTANT_CAPABLE".to_string(),
            message: format!(
                "Lock not instant-capable. Failed: {}",
                failed_conditions.join(", ")
            ),
            request_id: None,
        }));
    }

    if amount_sats > capability.max_instant_sats {
        return Ok(Some(ServerMessage::Error {
            code: "AMOUNT_EXCEEDS_LIMIT".to_string(),
            message: format!(
                "Amount {} exceeds instant limit {}",
                amount_sats, capability.max_instant_sats
            ),
            request_id: None,
        }));
    }

    // Generate payment ID
    let payment_id = generate_instant_payment_id(sender_lock_id, amount_sats, current_height);
    let settlement_block = current_height + 1;
    let timestamp = chrono::Utc::now().timestamp();

    // Record the instant payment acceptance (for later settlement verification)
    // In production, this would record to the database for reconciliation
    info!(
        payment_id = hex::encode(&payment_id),
        sender_lock_id = sender_lock_id,
        amount_sats = amount_sats,
        settlement_block = settlement_block,
        confidence = capability.confidence,
        "Instant payment accepted - show Confirmed"
    );

    Ok(Some(ServerMessage::InstantPaymentAccepted {
        payment_id: hex::encode(&payment_id),
        sender_lock_id: sender_lock_id.to_string(),
        amount_sats,
        settlement_block,
        confidence: capability.confidence,
        timestamp,
    }))
}

/// Generate a unique payment ID for instant payments
fn generate_instant_payment_id(lock_id: &str, amount: u64, height: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-instant-payment-v1");
    hasher.update(lock_id.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(
        &chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_le_bytes(),
    );
    hasher.finalize().into()
}
