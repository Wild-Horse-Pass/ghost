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
use std::time::{Duration, Instant};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use tracing::{debug, error, info, warn};

/// M-3: Ping timeout in seconds (30 seconds default)
/// Connections that don't respond to pings within this time will be closed.
const PING_TIMEOUT_SECS: u64 = 30;

/// M-3: Ping interval in seconds
/// How often to send pings to check client liveness.
const PING_INTERVAL_SECS: u64 = 15;

/// HIGH-2: Rate limit configuration for WebSocket messages
/// Maximum messages per second (sustained rate)
const RATE_LIMIT_MESSAGES_PER_SEC: u32 = 100;

/// HIGH-2: Rate limit bucket capacity (burst allowance)
/// Allows brief bursts up to 3x the sustained rate
const RATE_LIMIT_BUCKET_CAPACITY: u32 = 300;

/// HIGH-2: Token bucket refill interval in milliseconds
const RATE_LIMIT_REFILL_INTERVAL_MS: u64 = 10;

/// CRIT-DOS-1: Maximum number of lock state subscriptions per connection
/// This prevents memory exhaustion attacks where a malicious client subscribes
/// to thousands of locks.
const MAX_LOCK_SUBSCRIPTIONS: usize = 100;

use std::collections::HashSet;

use ghost_gsp_proto::{
    validate_message, ClientMessage, PaymentMode, PaymentStatus, PreparedPayment, ServerMessage,
    SignedInstantPayment, WalletId, WalletProof,
};

use crate::error::GspError;
use crate::server::GspState;

// =============================================================================
// HIGH-2 FIX: Token Bucket Rate Limiter
// =============================================================================

/// Token bucket rate limiter for per-connection rate limiting
///
/// HIGH-2 FIX: Prevents WebSocket message flooding attacks by limiting
/// the rate of messages each connection can process.
struct TokenBucket {
    /// Current number of tokens available
    tokens: u32,
    /// Maximum tokens (bucket capacity)
    capacity: u32,
    /// Tokens added per refill
    refill_rate: u32,
    /// Last time tokens were refilled
    last_refill: Instant,
    /// Time between refills
    refill_interval: Duration,
}

impl TokenBucket {
    /// Create a new token bucket with the specified capacity and refill rate
    fn new(capacity: u32, tokens_per_second: u32) -> Self {
        // Calculate how many tokens to add per refill interval
        // With 10ms intervals, we need tokens_per_second / 100 per interval
        let refill_rate = (tokens_per_second / 100).max(1);

        Self {
            tokens: capacity, // Start full
            capacity,
            refill_rate,
            last_refill: Instant::now(),
            refill_interval: Duration::from_millis(RATE_LIMIT_REFILL_INTERVAL_MS),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Calculate how many intervals have passed
        let intervals = (elapsed.as_millis() / self.refill_interval.as_millis()) as u32;

        if intervals > 0 {
            // Add tokens for each interval, capped at capacity
            let new_tokens = self.tokens.saturating_add(intervals * self.refill_rate);
            self.tokens = new_tokens.min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// QUANTUM SAFETY: Check if a Bitcoin address is quantum-safe
///
/// P2TR addresses (bc1p...) are quantum-vulnerable because they expose
/// the public key on-chain. This function rejects P2TR addresses.
fn validate_quantum_safe_address(address: &str) -> Result<(), GspError> {
    if address.starts_with("bc1p") || address.starts_with("tb1p") || address.starts_with("bcrt1p") {
        return Err(GspError::QuantumUnsafe);
    }
    Ok(())
}

/// Verify a wallet proof for WebSocket operations
///
/// This performs comprehensive verification:
/// 1. Structure validation
/// 2. Timestamp validation
/// 3. Schnorr signature verification
/// 4. Wallet ID derivation validation (pubkey -> wallet ID)
/// 5. Nonce replay protection (tracked in registry database)
///
/// Returns Ok(()) on success or a descriptive error message.
fn verify_websocket_proof(
    state: &Arc<GspState>,
    proof: &WalletProof,
    session_wallet_id: &WalletId,
) -> Result<(), String> {
    // Use the registry's comprehensive verification which includes:
    // - Signature verification
    // - Wallet ID derivation check
    // - Nonce replay protection
    state
        .registry
        .verify_proof_for_wallet(proof, session_wallet_id)
        .map_err(|e| e.to_string())
}

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<GspState>>,
) -> impl IntoResponse {
    // L-12: Atomically check and increment connection count
    // This eliminates the TOCTOU race condition that existed with separate
    // can_accept_connection() and add_connection() calls
    if !state.try_add_connection() {
        warn!("WebSocket connection rejected: max connections reached");
        return ws
            .on_failed_upgrade(|_| {
                // Connection was never added, nothing to clean up
            })
            .on_upgrade(|_| async {});
    }

    ws.on_upgrade(move |socket| handle_socket_with_connection(socket, state))
}

/// Connection state
struct ConnectionState {
    /// Authenticated wallet ID (None if not yet authenticated)
    wallet_id: Option<WalletId>,

    /// MED-DOS-2 FIX: Active subscriptions stored in HashSet to prevent duplicates
    /// Using HashSet eliminates duplicate subscription attacks where malicious clients
    /// repeatedly subscribe to the same topic to exhaust memory.
    subscriptions: HashSet<String>,

    /// MED-DOS-2 FIX: Lock state subscriptions stored in HashSet to prevent duplicates
    /// CRIT-DOS-1: Size is bounded by MAX_LOCK_SUBSCRIPTIONS
    lock_state_subscriptions: HashSet<String>,

    /// M-3: Last time we received any message from the client
    last_activity: Option<Instant>,

    /// HIGH-2: Per-connection rate limiter to prevent message flooding
    rate_limiter: TokenBucket,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            wallet_id: None,
            subscriptions: HashSet::new(),
            lock_state_subscriptions: HashSet::new(),
            last_activity: None,
            rate_limiter: TokenBucket::new(RATE_LIMIT_BUCKET_CAPACITY, RATE_LIMIT_MESSAGES_PER_SEC),
        }
    }
}

/// Handle a WebSocket connection (connection already counted via try_add_connection)
async fn handle_socket_with_connection(socket: WebSocket, state: Arc<GspState>) {
    // L-12: Connection was already added atomically in ws_handler via try_add_connection()
    debug!("WebSocket connection established");

    let (mut sender, mut receiver) = socket.split();
    let mut conn_state = ConnectionState {
        last_activity: Some(Instant::now()),
        ..Default::default()
    };

    // M-3: Ping interval timer
    let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Main message loop with M-3 ping/timeout
    loop {
        tokio::select! {
            // Handle incoming messages
            msg_result = receiver.next() => {
                let msg = match msg_result {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => {
                        error!("WebSocket receive error: {}", e);
                        break;
                    }
                    None => break, // Connection closed
                };

                // M-3: Update last activity time on any message
                conn_state.last_activity = Some(Instant::now());

                // HIGH-2 FIX: Check rate limit before processing message
                // This prevents message flooding attacks by limiting the rate
                // at which messages are processed per connection.
                if !conn_state.rate_limiter.try_consume() {
                    warn!("HIGH-2: Rate limit exceeded for connection, rejecting message");
                    let response = ServerMessage::Error {
                        code: "RATE_LIMIT_EXCEEDED".to_string(),
                        message: "Too many requests. Please slow down.".to_string(),
                        request_id: None,
                    };
                    let json = serde_json::to_string(&response).unwrap_or_default();
                    if sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                    continue;
                }

                // Handle message
                let response = match handle_message(&state, &mut conn_state, msg).await {
                    Ok(Some(resp)) => resp,
                    Ok(None) => continue, // No response needed (ping/pong handled by axum)
                    Err(e) => sanitize_websocket_error(e),
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

            // M-3: Periodic ping check and timeout enforcement
            _ = ping_interval.tick() => {
                // Check if connection has timed out
                if let Some(last_activity) = conn_state.last_activity {
                    if last_activity.elapsed() > Duration::from_secs(PING_TIMEOUT_SECS) {
                        warn!("M-3: WebSocket connection timed out (no activity for {}s)", PING_TIMEOUT_SECS);
                        break;
                    }
                }

                // Send a ping to check client liveness
                // Note: axum's WebSocket handles ping/pong automatically at the protocol level,
                // but we send an explicit ping to trigger activity
                if let Err(e) = sender.send(Message::Ping(vec![])).await {
                    debug!("Failed to send ping, connection likely closed: {}", e);
                    break;
                }
            }
        }
    }

    // M-8: Full cleanup on disconnect
    cleanup_connection_state(&state, &conn_state);
    state.remove_connection();
    debug!("WebSocket connection closed");
}

/// M-8: Clean up all connection state on disconnect
///
/// Ensures all subscriptions and resources are properly cleaned up
/// when a connection terminates (normally or abnormally).
fn cleanup_connection_state(state: &Arc<GspState>, conn_state: &ConnectionState) {
    // Clean up wallet-level subscriptions
    if let Some(wallet_id) = &conn_state.wallet_id {
        state.subscriptions.unsubscribe_all(wallet_id);
    }

    // M-8: Clean up lock state subscriptions
    // MED-DOS-2: Now iterating over HashSet instead of Vec
    if let Some(wallet_id) = &conn_state.wallet_id {
        for lock_id in &conn_state.lock_state_subscriptions {
            state
                .subscriptions
                .unsubscribe_lock_state(wallet_id, lock_id);
        }
    }

    debug!(
        "Cleaned up connection state: {} subscriptions, {} lock subscriptions",
        conn_state.subscriptions.len(),
        conn_state.lock_state_subscriptions.len()
    );
}

/// HIGH-3 FIX: Sanitize error messages before sending to clients
///
/// This function logs the full error details internally for debugging but
/// returns a sanitized error message to the client to prevent information
/// disclosure attacks. Internal implementation details, file paths, and
/// database errors are hidden from clients.
fn sanitize_websocket_error(error: GspError) -> ServerMessage {
    // Log full error internally for debugging
    error!(
        error_type = ?std::mem::discriminant(&error),
        full_error = %error,
        "HIGH-3: WebSocket error (full details logged, sanitized for client)"
    );

    // Map errors to safe client-facing messages
    let (code, message) = match &error {
        // Authentication errors - safe to expose these codes (common)
        GspError::Unauthorized => ("UNAUTHORIZED", "Authentication required"),
        GspError::SessionExpired => ("SESSION_EXPIRED", "Session has expired"),
        GspError::WalletNotRegistered => ("WALLET_NOT_REGISTERED", "Wallet not registered"),
        GspError::WalletAlreadyRegistered => {
            ("WALLET_ALREADY_REGISTERED", "Wallet already registered")
        }
        GspError::WalletIdMismatch => ("WALLET_ID_MISMATCH", "Wallet ID verification failed"),
        GspError::NonceReplay => ("NONCE_REPLAY", "Nonce has already been used"),
        GspError::RateLimitExceeded => ("RATE_LIMIT_EXCEEDED", "Rate limit exceeded"),

        // Validation errors - safe to give generic feedback
        GspError::BadRequest(_) => ("BAD_REQUEST", "Invalid request format"),
        GspError::NotFound(_) => ("NOT_FOUND", "Resource not found"),

        // Payment/Lock errors - use generic messages to avoid leaking payment state
        GspError::PaymentOwnershipMismatch => ("FORBIDDEN", "Access denied"),
        GspError::LockNotFound(_) => ("LOCK_NOT_FOUND", "Lock not found"),
        GspError::LockPending => ("LOCK_PENDING", "Lock is pending"),
        GspError::InsufficientConfirmations { .. } => {
            ("INSUFFICIENT_CONFIRMATIONS", "Insufficient confirmations")
        }
        GspError::QuantumUnsafe => (
            "QUANTUM_UNSAFE",
            "P2TR addresses are not supported. Use P2WPKH.",
        ),

        // Internal errors - NEVER expose details to clients
        GspError::Config(_) => ("INTERNAL_ERROR", "Internal server error"),
        GspError::InvalidBindAddress(_) => ("INTERNAL_ERROR", "Internal server error"),
        GspError::InsecureJwtSecret(_) => ("INTERNAL_ERROR", "Internal server error"),
        GspError::InvalidCredentials(_) => ("INVALID_CREDENTIALS", "Invalid credentials"),
        GspError::InvalidToken(_) => ("INVALID_TOKEN", "Invalid or expired token"),
        GspError::SignatureVerification(_) => ("SIGNATURE_FAILED", "Signature verification failed"),
        GspError::PayNodeUnavailable(_) => (
            "SERVICE_UNAVAILABLE",
            "Payment service temporarily unavailable",
        ),
        GspError::PayNodeError(_) => ("SERVICE_ERROR", "Payment service error"),
        GspError::Database(_) => ("INTERNAL_ERROR", "Internal server error"),
        GspError::Internal(_) => ("INTERNAL_ERROR", "Internal server error"),
        GspError::Protocol(_) => ("PROTOCOL_ERROR", "Invalid protocol message"),
    };

    ServerMessage::Error {
        code: code.to_string(),
        message: message.to_string(),
        request_id: None,
    }
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

        ClientMessage::SubscribeReorgs => handle_subscribe(state, conn_state, "reorgs").await,

        ClientMessage::UnsubscribeReorgs => handle_unsubscribe(state, conn_state, "reorgs").await,

        ClientMessage::Unsubscribe { subscription } => {
            handle_unsubscribe(state, conn_state, &subscription).await
        }

        // Payment operations
        ClientMessage::PreparePayment {
            recipient,
            amount_sats,
            mode,
            proof,
            memo,
            encrypted_metadata,
        } => {
            handle_prepare_payment(
                state,
                conn_state,
                &recipient,
                amount_sats,
                &mode,
                &proof,
                memo.as_deref(),
                encrypted_metadata.as_deref(),
            )
            .await
        }

        ClientMessage::SubmitSignedPayment {
            payment_id,
            signature,
            public_key,
        } => {
            handle_submit_signed_payment(state, conn_state, &payment_id, &signature, &public_key)
                .await
        }

        ClientMessage::GetPaymentStatus { payment_id, proof } => {
            handle_get_payment_status(state, conn_state, &payment_id, &proof).await
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
            signed_payment,
        } => {
            handle_accept_instant_payment(
                state,
                conn_state,
                &sender_lock_id,
                amount_sats,
                &proof,
                &signed_payment,
            )
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

    // MED-OVERFLOW-1 FIX: Use fold with saturating_add instead of sum
    let total_sats: u64 = utxos.iter().fold(0u64, |acc, u| acc.saturating_add(u.amount_sats));

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

    // MED-OVERFLOW-1 FIX: Use fold with saturating_add instead of sum
    let total_locked_sats: u64 = locks.iter().fold(0u64, |acc, l| acc.saturating_add(l.balance_sats));

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
///
/// MED-DOS-2 FIX: Uses HashSet to automatically prevent duplicate subscriptions.
/// Duplicate subscription requests are silently ignored (idempotent).
async fn handle_subscribe(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    subscription: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // MED-DOS-2 FIX: Add subscription (HashSet handles deduplication automatically)
    state.subscriptions.subscribe(wallet_id, subscription);
    conn_state.subscriptions.insert(subscription.to_string());

    Ok(Some(ServerMessage::Subscribed {
        subscription: subscription.to_string(),
    }))
}

/// Handle unsubscription request
///
/// MED-DOS-2 FIX: Uses HashSet.remove() for efficient unsubscription.
async fn handle_unsubscribe(
    state: &Arc<GspState>,
    conn_state: &mut ConnectionState,
    subscription: &str,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // MED-DOS-2 FIX: Remove subscription (HashSet provides O(1) removal)
    state.subscriptions.unsubscribe(wallet_id, subscription);
    conn_state.subscriptions.remove(subscription);

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

    // QUANTUM SAFETY: Reject P2TR target addresses
    if let Err(e) = validate_quantum_safe_address(target_address) {
        return Ok(Some(ServerMessage::JumpRequested {
            success: false,
            lock_id: lock_id.to_string(),
            jump_txid: None,
            error: Some(e.to_string()),
        }));
    }

    // Comprehensive proof verification:
    // - Structure and timestamp validation
    // - Schnorr signature verification
    // - Wallet ID derivation check (pubkey -> wallet ID)
    // - Nonce replay protection
    if let Err(e) = verify_websocket_proof(state, proof, wallet_id) {
        return Ok(Some(ServerMessage::JumpRequested {
            success: false,
            lock_id: lock_id.to_string(),
            jump_txid: None,
            error: Some(e),
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
#[allow(clippy::too_many_arguments)]
async fn handle_prepare_payment(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    recipient: &str,
    amount_sats: u64,
    mode: &PaymentMode,
    proof: &WalletProof,
    memo: Option<&str>,
    encrypted_metadata: Option<&str>,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // QUANTUM SAFETY: Reject P2TR recipient addresses
    if let Err(e) = validate_quantum_safe_address(recipient) {
        return Ok(Some(ServerMessage::PaymentPrepared {
            success: false,
            payment: None,
            error: Some(e.to_string()),
        }));
    }

    // Comprehensive proof verification:
    // - Structure and timestamp validation
    // - Schnorr signature verification
    // - Wallet ID derivation check (pubkey -> wallet ID)
    // - Nonce replay protection
    if let Err(e) = verify_websocket_proof(state, proof, wallet_id) {
        return Ok(Some(ServerMessage::PaymentPrepared {
            success: false,
            payment: None,
            error: Some(e),
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

            // Get ephemeral pubkey from the response if present
            let ephemeral_pubkey = result
                .get("ephemeral_pubkey")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // MED-OVERFLOW-1 FIX: Use saturating_add for total calculation
            let total_sats = amount_sats.saturating_add(fee_sats);

            let payment = PreparedPayment {
                payment_id,
                mode: *mode,
                recipient_address,
                original_recipient: recipient.to_string(),
                amount_sats,
                fee_sats,
                total_sats,
                sighash,
                signing_method: "schnorr".to_string(),
                expires_at,
                status: PaymentStatus::PendingSignature,
                inputs: vec![],
                outputs: vec![],
                memo: memo.map(|s| s.to_string()),
                encrypted_metadata: encrypted_metadata.map(|s| s.to_string()),
                ephemeral_pubkey,
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
///
/// H-9 Security: Verifies that the payment belongs to the authenticated wallet
/// before allowing signature submission. This prevents payment hijacking where
/// an attacker could submit signatures for payments they didn't create.
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

    // H-9/HIGH-AUTHZ-1: Verify payment belongs to this wallet before allowing submission
    // This prevents payment hijacking attacks where an attacker could submit
    // signatures for payments created by other wallets.
    // HIGH-AUTHZ-1: Pass wallet_id to enable server-side access control
    let payment = state.pay_node.get_payment(payment_id, &wallet_id.to_string()).await?;
    if payment.wallet_id != wallet_id.to_string() {
        warn!(
            wallet_id = %wallet_id,
            payment_id = %payment_id,
            payment_owner = %payment.wallet_id,
            "H-9/HIGH-AUTHZ-1: Payment ownership mismatch - rejecting signature submission"
        );
        return Err(GspError::PaymentOwnershipMismatch);
    }

    info!(
        wallet_id = %wallet_id,
        payment_id = %payment_id,
        "Submitting signed payment (ownership verified)"
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
///
/// H-1: Requires wallet proof for authorization to prevent information leakage.
/// HIGH-INFO-1 FIX: Verifies wallet owns payment before returning status with confirmations.
/// CRIT-RACE-2 FIX: Returns version field for optimistic locking.
async fn handle_get_payment_status(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    payment_id: &str,
    proof: &WalletProof,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // H-AUTH-1 FIX: Verify wallet proof before returning payment information
    // Return proper auth error, not a fake payment status that could confuse clients
    if let Err(e) = verify_websocket_proof(state, proof, wallet_id) {
        warn!(
            wallet_id = %wallet_id,
            payment_id = %payment_id,
            error = %e,
            "H-AUTH-1: Payment status request rejected due to proof verification failure"
        );
        return Ok(Some(ServerMessage::Error {
            code: "UNAUTHORIZED".to_string(),
            message: format!("Wallet proof verification failed: {}", e),
            request_id: None,
        }));
    }

    // HIGH-INFO-1 FIX: Verify wallet owns this payment before returning any details
    // This prevents information leakage where confirmations could reveal transaction status
    // to unauthorized parties who guess payment IDs.
    let payment = state.pay_node.get_payment(payment_id, &wallet_id.to_string()).await?;
    if payment.wallet_id != wallet_id.to_string() {
        warn!(
            wallet_id = %wallet_id,
            payment_id = %payment_id,
            payment_owner = %payment.wallet_id,
            "HIGH-INFO-1: Payment status request rejected - wallet does not own payment"
        );
        return Err(GspError::PaymentOwnershipMismatch);
    }

    debug!(
        wallet_id = %wallet_id,
        payment_id = %payment_id,
        "Getting payment status (ownership verified)"
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

            // CRIT-RACE-2 FIX: Extract version for optimistic locking
            // Clients must include this version when making state changes
            // to detect concurrent modifications.
            let _version = result
                .get("version")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

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
///
/// M-14 FIX: Returns PaymentCancelled message type instead of PaymentSubmitted
/// HIGH-AUTHZ-2 FIX: Verifies wallet owns payment before allowing cancellation.
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

    // Comprehensive proof verification:
    // - Structure and timestamp validation
    // - Schnorr signature verification
    // - Wallet ID derivation check (pubkey -> wallet ID)
    // - Nonce replay protection
    if let Err(e) = verify_websocket_proof(state, proof, wallet_id) {
        return Ok(Some(ServerMessage::PaymentCancelled {
            success: false,
            payment_id: payment_id.to_string(),
            error: Some(e),
        }));
    }

    // HIGH-AUTHZ-2 FIX: Verify wallet owns this payment before allowing cancellation
    // This prevents unauthorized cancellation of other users' payments.
    let payment = state.pay_node.get_payment(payment_id, &wallet_id.to_string()).await?;
    if payment.wallet_id != wallet_id.to_string() {
        warn!(
            wallet_id = %wallet_id,
            payment_id = %payment_id,
            payment_owner = %payment.wallet_id,
            "HIGH-AUTHZ-2: Cancel payment rejected - wallet does not own payment"
        );
        return Ok(Some(ServerMessage::PaymentCancelled {
            success: false,
            payment_id: payment_id.to_string(),
            error: Some("Payment does not belong to this wallet".to_string()),
        }));
    }

    info!(
        wallet_id = %wallet_id,
        payment_id = %payment_id,
        "Cancelling payment (ownership verified)"
    );

    // Cancel payment via pay node
    match state.pay_node.cancel_payment(payment_id).await {
        Ok(success) => Ok(Some(ServerMessage::PaymentCancelled {
            success,
            payment_id: payment_id.to_string(),
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

            Ok(Some(ServerMessage::PaymentCancelled {
                success: false,
                payment_id: payment_id.to_string(),
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

    // Comprehensive proof verification:
    // - Structure and timestamp validation
    // - Schnorr signature verification
    // - Wallet ID derivation check (pubkey -> wallet ID)
    // - Nonce replay protection
    if let Err(e) = verify_websocket_proof(state, proof, wallet_id) {
        return Ok(Some(ServerMessage::Error {
            code: "PROOF_VERIFICATION_FAILED".to_string(),
            message: e,
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
///
/// # H-4 Security Fix
/// Before querying capability info, we verify that the authenticated wallet
/// actually owns the lock. This prevents information disclosure about other
/// users' locks.
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

    // H-4 FIX: Verify the authenticated wallet owns this lock before returning capability info
    match state
        .pay_node
        .is_lock_owner(&wallet_id.to_string(), lock_id)
        .await
    {
        Ok(true) => {} // Wallet owns the lock, proceed
        Ok(false) => {
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                "H-4: Unauthorized attempt to check instant capability for lock owned by another wallet"
            );
            return Err(GspError::Unauthorized);
        }
        Err(e) => {
            // If we can't verify ownership, fail closed for security
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                error = %e,
                "H-4: Failed to verify lock ownership, denying access"
            );
            return Err(GspError::Unauthorized);
        }
    }

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
///
/// # H-3 Security Fix
/// Before allowing subscription, we verify that the authenticated wallet
/// actually owns the lock. This prevents users from subscribing to state
/// updates for locks they don't own.
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

    // CRIT-DOS-1 FIX: Check if connection has reached max lock subscriptions
    // This prevents memory exhaustion attacks where a malicious client subscribes
    // to thousands of locks.
    if conn_state.lock_state_subscriptions.len() >= MAX_LOCK_SUBSCRIPTIONS {
        warn!(
            wallet_id = %wallet_id,
            lock_id = %lock_id,
            current_count = conn_state.lock_state_subscriptions.len(),
            max_allowed = MAX_LOCK_SUBSCRIPTIONS,
            "CRIT-DOS-1: Lock subscription limit reached - rejecting subscription"
        );
        return Ok(Some(ServerMessage::Error {
            code: "SUBSCRIPTION_LIMIT_EXCEEDED".to_string(),
            message: format!("Maximum lock subscriptions ({}) reached", MAX_LOCK_SUBSCRIPTIONS),
            request_id: None,
        }));
    }

    // H-3 FIX: Verify the authenticated wallet owns this lock before allowing subscription
    match state
        .pay_node
        .is_lock_owner(&wallet_id.to_string(), lock_id)
        .await
    {
        Ok(true) => {} // Wallet owns the lock, proceed
        Ok(false) => {
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                "H-3: Unauthorized attempt to subscribe to lock state for lock owned by another wallet"
            );
            return Err(GspError::Unauthorized);
        }
        Err(e) => {
            // If we can't verify ownership, fail closed for security
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                error = %e,
                "H-3: Failed to verify lock ownership, denying subscription"
            );
            return Err(GspError::Unauthorized);
        }
    }

    // LOW FIX: Get lock snapshot BEFORE registering subscription
    // This ensures we don't leak subscriptions if the snapshot fetch fails
    let snapshot = match state.pay_node.get_lock_state_snapshot(lock_id).await {
        Ok(s) => s,
        Err(e) => {
            // LOW FIX: Return error without registering subscription
            return Ok(Some(ServerMessage::Error {
                code: "LOCK_NOT_FOUND".to_string(),
                message: format!("Failed to get lock state: {}", e),
                request_id: None,
            }));
        }
    };

    // LOW FIX: Only register subscription after successful snapshot retrieval
    // MED-DOS-2 FIX: Using HashSet for deduplication
    conn_state
        .lock_state_subscriptions
        .insert(lock_id.to_string());
    state.subscriptions.subscribe_lock_state(wallet_id, lock_id);

    Ok(Some(ServerMessage::LockStateSubscribed {
        lock_id: lock_id.to_string(),
        snapshot,
    }))
}

/// Unsubscribe from lock state updates
///
/// MED-DOS-2 FIX: Uses HashSet.remove() for efficient unsubscription.
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

    // MED-DOS-2 FIX: Remove subscription (HashSet provides O(1) removal)
    conn_state.lock_state_subscriptions.remove(lock_id);
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
///
/// M-9 Security: Before accepting, we MUST verify the SignedInstantPayment from the sender.
/// Without this, anyone could claim payments from any lock without authorization.
///
/// H-11 Security: Before accepting an instant payment, we MUST verify that
/// the sender's lock UTXO actually exists on L1 with sufficient confirmations.
/// This prevents attacks where:
/// - The lock was never funded
/// - The lock funding transaction was reorged out
/// - The lock was already spent in another transaction
/// - The lock is only in the mempool (could be double-spent)
async fn handle_accept_instant_payment(
    state: &Arc<GspState>,
    conn_state: &ConnectionState,
    sender_lock_id: &str,
    amount_sats: u64,
    proof: &WalletProof,
    signed_payment: &SignedInstantPayment,
) -> Result<Option<ServerMessage>, GspError> {
    let wallet_id = conn_state
        .wallet_id
        .as_ref()
        .ok_or(GspError::Unauthorized)?;

    // Comprehensive proof verification for MERCHANT:
    // - Structure and timestamp validation
    // - Schnorr signature verification
    // - Wallet ID derivation check (pubkey -> wallet ID)
    // - Nonce replay protection
    if let Err(e) = verify_websocket_proof(state, proof, wallet_id) {
        return Ok(Some(ServerMessage::Error {
            code: "PROOF_VERIFICATION_FAILED".to_string(),
            message: e,
            request_id: None,
        }));
    }

    // =========================================================================
    // M-9 FIX: Verify SignedInstantPayment from SENDER
    // =========================================================================
    // This is CRITICAL. Without verifying the sender's signature, a malicious
    // merchant could claim payments from locks they don't control. The sender
    // must prove they own the lock by signing the payment details.

    // M-9 Check 1: Verify sender_lock_id matches the signed payment
    if signed_payment.sender_lock_id != sender_lock_id {
        warn!(
            wallet_id = %wallet_id,
            expected_lock_id = %sender_lock_id,
            signed_lock_id = %signed_payment.sender_lock_id,
            "M-9 Security: Lock ID mismatch in signed payment"
        );
        return Ok(Some(ServerMessage::Error {
            code: "SIGNED_PAYMENT_INVALID".to_string(),
            message: "Signed payment lock ID does not match request".to_string(),
            request_id: None,
        }));
    }

    // M-9 Check 2: Verify amount matches
    if signed_payment.amount_sats != amount_sats {
        warn!(
            wallet_id = %wallet_id,
            expected_amount = amount_sats,
            signed_amount = signed_payment.amount_sats,
            "M-9 Security: Amount mismatch in signed payment"
        );
        return Ok(Some(ServerMessage::Error {
            code: "SIGNED_PAYMENT_INVALID".to_string(),
            message: "Signed payment amount does not match request".to_string(),
            request_id: None,
        }));
    }

    // M-9 Check 3: Verify recipient is the merchant's wallet
    // The signed payment's recipient should match the authenticated wallet
    let merchant_wallet_id_str = wallet_id.to_string();
    if signed_payment.recipient != merchant_wallet_id_str {
        warn!(
            wallet_id = %wallet_id,
            signed_recipient = %signed_payment.recipient,
            "M-9 Security: Recipient mismatch - payment not intended for this merchant"
        );
        return Ok(Some(ServerMessage::Error {
            code: "SIGNED_PAYMENT_INVALID".to_string(),
            message: "Signed payment recipient does not match this wallet".to_string(),
            request_id: None,
        }));
    }

    // M-9 Check 4: Verify the timestamp is recent (prevent replay of old payments)
    // M-12 FIX: Reduced from 5 minutes to 90 seconds to limit replay attack window
    let now_millis = chrono::Utc::now().timestamp_millis() as u64;
    const MAX_PAYMENT_AGE_MILLIS: u64 = 90 * 1000; // 90 seconds (M-12: tightened from 5 min)
    if signed_payment.timestamp + MAX_PAYMENT_AGE_MILLIS < now_millis {
        warn!(
            wallet_id = %wallet_id,
            payment_timestamp = signed_payment.timestamp,
            current_time = now_millis,
            "M-9 Security: Signed payment has expired"
        );
        return Ok(Some(ServerMessage::Error {
            code: "SIGNED_PAYMENT_EXPIRED".to_string(),
            message: "Signed payment has expired".to_string(),
            request_id: None,
        }));
    }

    // M-9 Check 5: Verify the BIP-340 Schnorr signature
    // The signature must be valid over the payment message using the sender's pubkey
    if let Err(e) = verify_instant_payment_signature(signed_payment) {
        warn!(
            wallet_id = %wallet_id,
            sender_lock_id = %sender_lock_id,
            error = %e,
            "M-9 Security: Sender signature verification failed"
        );
        return Ok(Some(ServerMessage::Error {
            code: "SIGNATURE_VERIFICATION_FAILED".to_string(),
            message: "Sender signature verification failed".to_string(),
            request_id: None,
        }));
    }

    info!(
        wallet_id = %wallet_id,
        sender_lock_id = %sender_lock_id,
        amount_sats = amount_sats,
        sender_pubkey = hex::encode(signed_payment.sender_pubkey),
        "M-9: Sender signature verified, processing instant payment acceptance"
    );
    // =========================================================================
    // End M-9 signature verification
    // =========================================================================

    info!(
        wallet_id = %wallet_id,
        sender_lock_id = %sender_lock_id,
        amount_sats = amount_sats,
        "Processing instant payment acceptance request"
    );

    // =========================================================================
    // H-11: Verify L1 UTXO state before accepting instant payment
    // =========================================================================
    // This is CRITICAL for instant payment security. We must verify the lock
    // actually exists on L1 (not just in our cached data) before showing
    // "Confirmed" to the merchant.

    // Minimum confirmations required for instant payment acceptance
    // 6 confirmations provides high confidence the lock won't be reorged
    const MIN_INSTANT_CONFIRMATIONS: u32 = 6;

    let utxo_state = state.pay_node.get_utxo_state(sender_lock_id).await?;

    // H-11 Check 1: Verify the lock UTXO exists on L1
    if !utxo_state.exists {
        warn!(
            wallet_id = %wallet_id,
            sender_lock_id = %sender_lock_id,
            "H-11 Security: Lock UTXO not found on L1 - rejecting instant payment"
        );
        return Err(GspError::LockNotFound(sender_lock_id.to_string()));
    }

    // H-11 Check 2: Reject if the lock is only in the mempool (unconfirmed)
    // Mempool transactions can be double-spent via RBF or simply dropped
    if utxo_state.in_mempool {
        warn!(
            wallet_id = %wallet_id,
            sender_lock_id = %sender_lock_id,
            "H-11 Security: Lock UTXO is pending in mempool - rejecting instant payment"
        );
        return Err(GspError::LockPending);
    }

    // H-11 Check 3: Require minimum confirmations for instant payment
    // This ensures the lock has deep enough confirmation to be safe from reorgs
    if utxo_state.confirmations < MIN_INSTANT_CONFIRMATIONS {
        warn!(
            wallet_id = %wallet_id,
            sender_lock_id = %sender_lock_id,
            confirmations = utxo_state.confirmations,
            required = MIN_INSTANT_CONFIRMATIONS,
            "H-11 Security: Lock has insufficient confirmations - rejecting instant payment"
        );
        return Err(GspError::InsufficientConfirmations {
            have: utxo_state.confirmations,
            need: MIN_INSTANT_CONFIRMATIONS,
        });
    }

    info!(
        wallet_id = %wallet_id,
        sender_lock_id = %sender_lock_id,
        confirmations = utxo_state.confirmations,
        "H-11: L1 UTXO verification passed, proceeding with instant capability check"
    );

    // =========================================================================
    // End H-11 L1 verification
    // =========================================================================

    // Check instant capability using cached snapshot (now safe to use after L1 verification)
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
    let payment_id = generate_instant_payment_id(sender_lock_id, amount_sats, current_height)?;
    let settlement_block = current_height + 1;
    let timestamp = chrono::Utc::now().timestamp();

    // =========================================================================
    // HIGH-RACE-1 FIX: Atomic check-and-insert to prevent double-acceptance
    // =========================================================================
    // This is CRITICAL. Without atomic insertion with UNIQUE constraint, the same
    // instant payment could be accepted multiple times (double-spend). We call
    // the pay node's accept_instant_payment endpoint which will atomically insert
    // into accepted_instant_payments table with UNIQUE constraint on
    // (sender_lock_id, payment_id, merchant_wallet_id) to ensure exactly-once semantics.

    let merchant_wallet_id_str = wallet_id.to_string();

    // Call pay node to atomically record the instant payment acceptance
    // The pay node will use a database UNIQUE constraint to prevent double-acceptance
    match state
        .pay_node
        .accept_instant_payment(
            &hex::encode(payment_id),
            sender_lock_id,
            &merchant_wallet_id_str,
            amount_sats,
            settlement_block,
            capability.confidence.into(),
            &signed_payment.sender_pubkey,
            &signed_payment.signature,
        )
        .await
    {
        Ok(_) => {
            // Successfully recorded - this is the FIRST acceptance
            info!(
                payment_id = hex::encode(payment_id),
                sender_lock_id = sender_lock_id,
                merchant_wallet_id = %wallet_id,
                amount_sats = amount_sats,
                settlement_block = settlement_block,
                confidence = capability.confidence,
                l1_confirmations = utxo_state.confirmations,
                "HIGH-RACE-1: Instant payment accepted (L1 verified, atomically recorded) - show Confirmed"
            );

            Ok(Some(ServerMessage::InstantPaymentAccepted {
                payment_id: hex::encode(payment_id),
                sender_lock_id: sender_lock_id.to_string(),
                amount_sats,
                settlement_block,
                confidence: capability.confidence,
                timestamp,
            }))
        }
        Err(e) if matches!(&e, GspError::PayNodeError(msg) if msg.contains("already accepted")) => {
            // Payment was already accepted (double-acceptance attempt blocked)
            warn!(
                payment_id = hex::encode(payment_id),
                sender_lock_id = sender_lock_id,
                merchant_wallet_id = %wallet_id,
                "HIGH-RACE-1: Instant payment double-acceptance PREVENTED by database constraint"
            );

            Ok(Some(ServerMessage::Error {
                code: "PAYMENT_ALREADY_ACCEPTED".to_string(),
                message: "This instant payment has already been accepted".to_string(),
                request_id: None,
            }))
        }
        Err(e) => {
            // Other error
            error!(
                payment_id = hex::encode(payment_id),
                error = %e,
                "Failed to record instant payment acceptance"
            );
            Err(e)
        }
    }
}

/// Generate a unique payment ID for instant payments
///
/// M-10/HIGH-CRYPTO-1 FIX: Uses 32 bytes of cryptographically secure random data from getrandom
/// instead of predictable timestamp. This prevents payment ID guessing attacks
/// where an attacker could predict future payment IDs and exploit timing windows.
///
/// HIGH-CRYPTO-1 FIX: Returns Result instead of panicking on getrandom failure.
fn generate_instant_payment_id(lock_id: &str, amount: u64, height: u64) -> Result<[u8; 32], GspError> {
    use sha2::{Digest, Sha256};

    // M-10/HIGH-CRYPTO-1 FIX: Use cryptographically secure random bytes
    // Return error instead of panic if randomness fails
    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes).map_err(|e| {
        GspError::Internal(format!(
            "HIGH-CRYPTO-1: Failed to get cryptographic randomness for payment ID: {}. \
             Cannot generate secure payment IDs without CSPRNG. \
             This indicates a critical system-level failure.",
            e
        ))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(b"ghost-instant-payment-v2"); // Version bump indicates new format
    hasher.update(lock_id.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(height.to_le_bytes());
    hasher.update(random_bytes); // 32 bytes of cryptographic randomness
    Ok(hasher.finalize().into())
}

/// M-9 FIX: Verify the BIP-340 Schnorr signature on a SignedInstantPayment
///
/// This function verifies that the sender has properly signed the payment details
/// using their lock's private key. The message format is defined in SignedInstantPayment.
///
/// Returns Ok(()) if signature is valid, Err with description if invalid.
fn verify_instant_payment_signature(signed_payment: &SignedInstantPayment) -> Result<(), String> {
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use sha2::{Digest, Sha256};

    // Get the secp256k1 context for verification
    let secp = Secp256k1::verification_only();

    // Parse the sender's public key (x-only, 32 bytes)
    let pubkey = XOnlyPublicKey::from_slice(&signed_payment.sender_pubkey)
        .map_err(|e| format!("Invalid sender public key: {}", e))?;

    // Parse the signature (64 bytes)
    let signature = Signature::from_slice(&signed_payment.signature)
        .map_err(|e| format!("Invalid signature format: {}", e))?;

    // Compute the message that was signed
    // This uses the signing_message() method from SignedInstantPayment
    let msg_bytes = signed_payment.signing_message();

    // BIP-340 uses SHA256 to hash the message for Schnorr signatures
    let msg_hash = Sha256::digest(&msg_bytes);

    // Create a secp256k1 Message from the hash
    let message = Message::from_digest_slice(&msg_hash)
        .map_err(|e| format!("Failed to create message: {}", e))?;

    // Verify the Schnorr signature
    secp.verify_schnorr(&signature, &message, &pubkey)
        .map_err(|_| "Schnorr signature verification failed".to_string())?;

    Ok(())
}
