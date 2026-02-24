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
//| FILE: main.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Pay L2 Node
//!
//! A privacy-preserving payment layer that runs alongside the mining pool.
//!
//! Features:
//! - Ghost Keys: Silent payment-style addresses for privacy
//! - Ghost Locks: P2TR UTXOs with timelocks for security
//! - Jump Locks: Risk-tiered key rotation for high-value funds
//! - Wraith Protocol: Two-phase mixing for transaction unlinkability
//!
//! Architecture:
//! - REST API for wallet operations
//! - Background scanner for incoming payments
//! - Wraith session coordinator
//! - L1 settlement watcher

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
    GovernorLayer,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::Address;
use bitcoin::Network;

use ghost_common::constants::SATS_PER_BTC_F64;
use ghost_common::error::GhostError;
use ghost_common::rpc::BitcoinRpc;
use ghost_keys::{GhostKeys, GhostKeysExport, PaymentDetector};
use ghost_locks::{Denomination, GhostLock, StateTransition, TimelockTier};
use ghost_reconciliation::{BatchExecutor, ReconciliationInput, Settlement};
use ghost_storage::{
    ConfidentialTransferRecord, Database, GhostLockRecord, GhostLockState as DbLockState,
    WithdrawalRequest, WithdrawalStatus,
};
use ghost_zkp::{
    BalanceTree, CommitmentTree, ConfidentialPublicInputs, ConfidentialTransferProof,
    ConfidentialVerifier,
};
use wraith_protocol::{ParticipantTier, WraithCoordinator, WraithDenomination};

// H-PAY-2: Cryptography for encrypted key storage
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use scrypt::{scrypt, Params as ScryptParams};

/// Ghost Pay L2 Node
#[derive(Parser, Debug)]
#[command(name = "ghost-pay")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// API listen address
    #[arg(long, default_value = "0.0.0.0:8800")]
    api_listen: String,

    /// Data directory
    #[arg(long, default_value = "./ghost-pay-data")]
    data_dir: String,

    /// Bitcoin Core RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8332")]
    bitcoin_rpc: String,

    /// Bitcoin Core RPC user (required, or set BITCOIN_RPC_USER env var)
    #[arg(long, env = "BITCOIN_RPC_USER")]
    rpc_user: Option<String>,

    /// Bitcoin Core RPC password (required, or set BITCOIN_RPC_PASSWORD env var)
    #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
    rpc_password: Option<String>,

    /// Network (mainnet, testnet, signet, regtest)
    #[arg(long, default_value = "regtest")]
    network: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Treasury address for settlement batches (required for withdrawal settlements)
    #[arg(long)]
    treasury_address: Option<String>,

    /// Password for encrypting keys at rest (H-PAY-2 security fix)
    /// If not provided, keys will be stored encrypted with a derived password
    #[arg(long, env = "GHOST_PAY_PASSWORD")]
    key_password: Option<String>,

    /// H-2: API secret for HMAC authentication (required for mainnet)
    /// All authenticated endpoints require X-Ghost-Signature header with HMAC-SHA256
    #[arg(long, env = "GHOST_PAY_API_SECRET")]
    api_secret: Option<String>,

    /// TLS certificate PEM file path (enables HTTPS)
    /// When provided, --tls-key is also required.
    #[arg(long)]
    tls_cert: Option<std::path::PathBuf>,

    /// TLS private key PEM file path (required with --tls-cert)
    #[arg(long)]
    tls_key: Option<std::path::PathBuf>,

    /// MPC parameters directory (for loading Groth16 verification keys)
    /// Defaults to <data-dir>/../mpc_params/ (sibling of data dir)
    #[arg(long, env = "GHOST_MPC_PARAMS_DIR")]
    mpc_params_dir: Option<std::path::PathBuf>,
}

// =============================================================================
// H-PAY-2: ENCRYPTED KEY STORAGE
// =============================================================================

/// Salt size for scrypt key derivation
const SALT_SIZE: usize = 32;
/// Nonce size for AES-GCM
const NONCE_SIZE: usize = 12;
/// scrypt parameters (N=2^15, r=8, p=1) - secure but not too slow
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

// =============================================================================
// CONFIDENTIAL TRANSFER VERIFIER LOADING
// =============================================================================

/// Commitment tree depth — 2^20 = ~1M notes
const COMMITMENT_TREE_DEPTH: usize = 20;

/// Load the confidential transfer Groth16 verifier from MPC params directory.
///
/// Returns `Some(Arc<ConfidentialVerifier>)` if the VK file exists and loads successfully.
/// Returns `None` if no VK file found (confidential transfers will be unavailable).
fn load_confidential_verifier_from_params(args: &Args) -> Option<Arc<ConfidentialVerifier>> {
    let mpc_dir = if let Some(ref dir) = args.mpc_params_dir {
        dir.clone()
    } else {
        // Default: sibling of data_dir (e.g., /home/ghost/.ghost/mpc_params/)
        let data_path = std::path::PathBuf::from(&args.data_dir);
        if let Some(parent) = data_path.parent() {
            parent.join("mpc_params")
        } else {
            std::path::PathBuf::from("mpc_params")
        }
    };

    let vk_path = mpc_dir.join("confidential_vk.bin");
    if !vk_path.exists() {
        warn!(
            path = %vk_path.display(),
            "Confidential VK not found — confidential transfers will be unavailable"
        );
        return None;
    }

    match ghost_zkp::load_confidential_verifier(&vk_path, COMMITMENT_TREE_DEPTH) {
        Ok(verifier) => {
            info!(
                path = %vk_path.display(),
                has_groth16_vk = verifier.has_groth16_vk(),
                "Loaded confidential transfer verifier"
            );
            Some(Arc::new(verifier))
        }
        Err(e) => {
            error!(
                error = %e,
                path = %vk_path.display(),
                "Failed to load confidential transfer verifier"
            );
            None
        }
    }
}

// =============================================================================
// H-21: SAFE BLOCK HEIGHT CONVERSION
// =============================================================================

/// H-21: Safely convert a block height from i64/u64 to u32 with bounds checking.
/// Returns an error if the value is out of range for u32.
fn safe_block_height_u64(height: u64) -> Result<u32, anyhow::Error> {
    if height > u32::MAX as u64 {
        return Err(anyhow::anyhow!(
            "H-21 SECURITY: Block height {} exceeds u32::MAX ({})",
            height,
            u32::MAX
        ));
    }
    Ok(height as u32)
}

/// H-21: Safely convert a block height from i64 to u32 with bounds checking.
/// Returns an error if the value is negative or out of range for u32.
#[allow(dead_code)] // Kept for potential future use with Bitcoin RPC responses
fn safe_block_height_i64(height: i64) -> Result<u32, anyhow::Error> {
    if height < 0 {
        return Err(anyhow::anyhow!(
            "H-21 SECURITY: Block height {} is negative",
            height
        ));
    }
    if height > u32::MAX as i64 {
        return Err(anyhow::anyhow!(
            "H-21 SECURITY: Block height {} exceeds u32::MAX ({})",
            height,
            u32::MAX
        ));
    }
    Ok(height as u32)
}

/// Derive encryption key from password using scrypt
fn derive_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|e| anyhow::anyhow!("scrypt params error: {}", e))?;

    let mut key = [0u8; 32];
    scrypt(password.as_bytes(), salt, &params, &mut key)
        .map_err(|e| anyhow::anyhow!("scrypt error: {}", e))?;

    Ok(key)
}

/// Encrypt data with password using AES-256-GCM
/// Returns: salt (32) || nonce (12) || ciphertext
fn encrypt_keys(plaintext: &[u8], password: &str) -> Result<Vec<u8>, anyhow::Error> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];

    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("RNG error: {}", e))?;
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("RNG error: {}", e))?;

    // Derive key from password
    let key = derive_encryption_key(password, &salt)?;

    // Encrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher error: {}", e))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption error: {}", e))?;

    // Combine: salt || nonce || ciphertext
    let mut result = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with password using AES-256-GCM
/// Expects: salt (32) || nonce (12) || ciphertext
fn decrypt_keys(encrypted: &[u8], password: &str) -> Result<Vec<u8>, anyhow::Error> {
    if encrypted.len() < SALT_SIZE + NONCE_SIZE + 16 {
        // 16 is min auth tag
        return Err(anyhow::anyhow!("encrypted data too short"));
    }

    // Extract components
    let salt = &encrypted[0..SALT_SIZE];
    let nonce_bytes = &encrypted[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted[SALT_SIZE + NONCE_SIZE..];

    // Derive key
    let key = derive_encryption_key(password, salt)?;

    // Decrypt
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher error: {}", e))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed - wrong password?"))?;

    Ok(plaintext)
}

/// Password file name for auto-generated secure passwords
const AUTO_PASSWORD_FILE: &str = ".ghost-pay-key";

/// Get or derive the encryption password
/// For mainnet, requires explicit password via --key-password or GHOST_PAY_PASSWORD env var
/// For non-mainnet, generates and stores a secure random password in the data directory
fn get_encryption_password(args: &Args, network: Network) -> Result<String> {
    // Check explicit password argument first
    if let Some(ref password) = args.key_password {
        return Ok(password.clone());
    }

    // Check environment variable
    if let Ok(password) = std::env::var("GHOST_PAY_PASSWORD") {
        return Ok(password);
    }

    // For mainnet, require explicit password - no auto-generation
    if network == Network::Bitcoin {
        return Err(anyhow::anyhow!(
            "GHOST_PAY_PASSWORD environment variable or --key-password required for mainnet"
        ));
    }

    // M-13 FIX: For non-mainnet, use a secure random password stored in a file
    // This replaces the predictable hostname-based derivation
    let password_path = std::path::Path::new(&args.data_dir).join(AUTO_PASSWORD_FILE);

    // Try to read existing password file
    if let Ok(password) = std::fs::read_to_string(&password_path) {
        let password = password.trim().to_string();
        if password.len() >= 32 {
            info!("Using stored key password from {}", password_path.display());
            return Ok(password);
        }
        // Password file exists but is too short - regenerate
        warn!(
            "Existing password file too short, regenerating: {}",
            password_path.display()
        );
    }

    // Generate new secure random password (64 hex chars = 32 bytes of entropy)
    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate secure random password: {}", e))?;

    let password = hex::encode(random_bytes);

    // Store the password with restricted permissions
    // First, ensure the data directory exists
    std::fs::create_dir_all(&args.data_dir)?;

    // Write password file
    std::fs::write(&password_path, &password).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write password file {}: {}",
            password_path.display(),
            e
        )
    })?;

    // On Unix, set restrictive permissions (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&password_path, perms).map_err(|e| {
            anyhow::anyhow!(
                "Failed to set permissions on password file {}: {}",
                password_path.display(),
                e
            )
        })?;
    }

    info!(
        "Generated and stored new key password at {} (non-mainnet only)",
        password_path.display()
    );

    Ok(password)
}

// =============================================================================
// H-7/H-8: IP-BASED RATE LIMITING FOR API SECURITY
// =============================================================================

/// L-21 FIX: Validate that an IP address is acceptable as a trusted proxy.
fn is_valid_trusted_proxy(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_unspecified()
                || ipv4.is_link_local()
                || ipv4.is_multicast()
                || ipv4.is_broadcast()
            {
                return false;
            }
            // Reject documentation addresses
            let octets = ipv4.octets();
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                return false;
            }
            true
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_unspecified() || ipv6.is_multicast() {
                return false;
            }
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return false; // Link-local
            }
            true
        }
    }
}

/// PAY-2: Get trusted proxy IPs from environment or use defaults
///
/// Load from environment variables (comma-separated IPs):
/// - TRUSTED_PROXY_IPS (preferred, as specified in PAY-2 fix)
/// - GHOST_TRUSTED_PROXIES (legacy, for backward compatibility)
fn get_trusted_proxies() -> Vec<std::net::IpAddr> {
    use std::net::IpAddr;

    // PAY-2: Check TRUSTED_PROXY_IPS first (preferred), then GHOST_TRUSTED_PROXIES (legacy)
    let proxies_str =
        std::env::var("TRUSTED_PROXY_IPS").or_else(|_| std::env::var("GHOST_TRUSTED_PROXIES"));

    if let Ok(proxies_str) = proxies_str {
        let proxies: Vec<IpAddr> = proxies_str
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim();
                match trimmed.parse::<IpAddr>() {
                    Ok(ip) if is_valid_trusted_proxy(&ip) => Some(ip),
                    _ => None,
                }
            })
            .collect();

        if proxies.is_empty() {
            vec![
                "127.0.0.1"
                    .parse()
                    .expect("L-1: Valid hardcoded IPv4 localhost"),
                "::1".parse().expect("L-1: Valid hardcoded IPv6 localhost"),
            ]
        } else {
            tracing::info!(
                proxy_count = proxies.len(),
                "PAY-2: Loaded trusted proxy IPs from environment"
            );
            proxies
        }
    } else {
        vec![
            "127.0.0.1"
                .parse()
                .expect("L-1: Valid hardcoded IPv4 localhost"),
            "::1".parse().expect("L-1: Valid hardcoded IPv6 localhost"),
        ]
    }
}

fn is_trusted_proxy(ip: &std::net::IpAddr, trusted: &[std::net::IpAddr]) -> bool {
    trusted.contains(ip)
}

/// H-8: IP-based key extractor for rate limiting
#[derive(Debug, Clone)]
struct IpKeyExtractor {
    trusted_proxies: Vec<std::net::IpAddr>,
}

impl Default for IpKeyExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl IpKeyExtractor {
    fn new() -> Self {
        Self {
            trusted_proxies: get_trusted_proxies(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IpKey(String);

impl KeyExtractor for IpKeyExtractor {
    type Key = IpKey;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());

        let trust_proxy_headers = peer_ip
            .as_ref()
            .map(|ip| is_trusted_proxy(ip, &self.trusted_proxies))
            .unwrap_or(false);

        if trust_proxy_headers {
            if let Some(xff) = req.headers().get("X-Forwarded-For") {
                if let Ok(xff_str) = xff.to_str() {
                    if let Some(ip_str) = xff_str.split(',').next_back() {
                        let ip_trimmed = ip_str.trim();
                        if !ip_trimmed.is_empty() {
                            return Ok(IpKey(ip_trimmed.to_string()));
                        }
                    }
                }
            }
            if let Some(xri) = req.headers().get("X-Real-IP") {
                if let Ok(ip_str) = xri.to_str() {
                    return Ok(IpKey(ip_str.to_string()));
                }
            }
        }

        if let Some(ip) = peer_ip {
            return Ok(IpKey(ip.to_string()));
        }

        Err(GovernorError::UnableToExtractKey)
    }
}

// =============================================================================
// H-2: API AUTHENTICATION MIDDLEWARE
// =============================================================================

use axum::{body::Body, extract::Request, http::HeaderMap, middleware::Next, response::Response};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// H-2: API secret holder for authentication middleware
#[derive(Clone)]
struct ApiAuth {
    secret: Option<String>,
    network: Network,
}

impl ApiAuth {
    fn new(secret: Option<String>, network: Network) -> Self {
        Self { secret, network }
    }

    /// Verify HMAC signature from request headers
    fn verify_signature(&self, headers: &HeaderMap, body: &[u8]) -> bool {
        let secret = match &self.secret {
            Some(s) => s,
            None => return false, // No secret configured
        };

        // Get signature from X-Ghost-Signature header
        let signature_header = match headers.get("X-Ghost-Signature") {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => return false,
            },
            None => return false,
        };

        // Get timestamp from X-Ghost-Timestamp header (replay protection)
        let timestamp = match headers.get("X-Ghost-Timestamp") {
            Some(h) => match h.to_str() {
                Ok(s) => match s.parse::<i64>() {
                    Ok(ts) => ts,
                    Err(_) => return false,
                },
                Err(_) => return false,
            },
            None => return false,
        };

        // Check timestamp is within 5 minutes
        let now = chrono::Utc::now().timestamp();
        if (now - timestamp).abs() > 300 {
            warn!("H-2: Request timestamp too old or in future: {}", timestamp);
            return false;
        }

        // Compute expected HMAC: HMAC-SHA256(secret, timestamp + body)
        let mut mac: Hmac<Sha256> = match <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(timestamp.to_string().as_bytes());
        mac.update(body);

        let expected = hex::encode(mac.finalize().into_bytes());

        // Constant-time comparison
        if signature_header.len() != expected.len() {
            return false;
        }

        let mut diff = 0u8;
        for (a, b) in signature_header.bytes().zip(expected.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// H-2: Authentication middleware for sensitive endpoints
async fn require_api_auth(
    axum::extract::State(auth): axum::extract::State<ApiAuth>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // HIGH-API-2: API authentication is ALWAYS required, regardless of network
    // There is no valid reason to allow unauthenticated access to payment APIs
    // even on testnet/signet - this could mask bugs in auth integration.
    // This check is now redundant since we fail at startup if secret is not configured,
    // but we keep it as defense-in-depth.
    if auth.secret.is_none() {
        error!(
            network = ?auth.network,
            "HIGH-API-2 SECURITY: API secret (api_secret) not configured - rejecting request. \
             This should never happen as startup validation should prevent this."
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Extract body for signature verification
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Verify signature
    if !auth.verify_signature(&parts.headers, &body_bytes) {
        warn!(
            path = %parts.uri.path(),
            "H-2: Authentication failed - invalid signature"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Reconstruct request with body
    let request = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(request).await)
}

/// LOW-API-1: Security headers middleware for all HTTP responses
async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    use axum::http::HeaderValue;

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    response
}

/// Application state
struct AppState {
    /// Ghost keys for this node
    /// 2.5 HIGH: GhostKeys wrapped in Arc to allow sharing across async boundaries
    /// without cloning the secret key material.
    keys: RwLock<Option<Arc<GhostKeys>>>,
    /// Ghost ID (owner identifier for DB)
    ghost_id: RwLock<Option<String>>,
    /// Active ghost locks (actual GhostLock objects) - cached from DB
    ghost_locks: RwLock<Vec<GhostLock>>,
    /// Lock metadata for API responses - cached from DB
    locks: RwLock<Vec<LockInfo>>,
    /// Active Wraith sessions
    sessions: RwLock<Vec<SessionInfo>>,
    /// Wraith coordinators for active sessions
    coordinators: RwLock<std::collections::HashMap<String, WraithCoordinator>>,
    /// Pending payments to scan
    scanner_tx: mpsc::Sender<ScanRequest>,
    /// Configuration
    config: Args,
    /// Network for address generation
    network: Network,
    /// Database for persistence
    db: Arc<Database>,
    /// Bitcoin Core RPC client
    rpc: Arc<BitcoinRpc>,
    /// Confidential transfer commitment tree (MiMC-based, depth 20)
    commitment_tree: RwLock<CommitmentTree>,
    /// L2 balance tree for state transition witnesses
    balance_tree: RwLock<BalanceTree>,
    /// Groth16 confidential transfer verifier (None if MPC params not available)
    confidential_verifier: Option<Arc<ConfidentialVerifier>>,
}

/// Lock information with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LockInfo {
    id: String,
    denomination: String,
    amount_sats: u64,
    state: String,
    created_at: u64,
    timelock_tier: String,
    jump_risk: String,
    needs_jump: bool,
    /// Taproot address for funding
    address: String,
    /// Output public key (x-only, hex)
    output_pubkey: String,
    /// Recovery height (block when recovery becomes available)
    recovery_height: u32,
    /// Blocks until jump needed (0 if not applicable)
    blocks_until_jump: u32,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionInfo {
    id: String,
    tier: String,
    denomination: String,
    state: String,
    participants: usize,
    fill_percentage: f64,
}

/// Scan request for background scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanRequest {
    txid: String,
    vout: u32,
}

/// Convert an x-only pubkey hex to a P2TR address
fn pubkey_hex_to_p2tr_address(pubkey_hex: &str, network: Network) -> String {
    use bitcoin::key::TweakedPublicKey;
    use bitcoin::secp256k1::XOnlyPublicKey;

    // Parse the x-only public key from hex
    let bytes = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return format!("(invalid pubkey: {})", pubkey_hex),
    };

    let xonly = match XOnlyPublicKey::from_slice(&bytes) {
        Ok(k) => k,
        Err(_) => return format!("(invalid pubkey: {})", pubkey_hex),
    };

    // Create tweaked key (assuming no script tree, so merkle root is None)
    // For display purposes, we use the untweaked key
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly);
    let address = Address::p2tr_tweaked(tweaked, network);
    address.to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Extract TLS config before args is moved into AppState
    let tls_cert_path = args.tls_cert.clone();
    let tls_key_path = args.tls_key.clone();

    // Setup logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Ghost Pay L2 Node v{}", env!("CARGO_PKG_VERSION"));
    info!("API listen: {}", args.api_listen);
    info!("Data dir: {}", args.data_dir);
    info!("Network: {}", args.network);

    // Create data directory
    std::fs::create_dir_all(&args.data_dir)?;

    // Create scanner channel
    let (scanner_tx, scanner_rx) = mpsc::channel(1000);

    // Parse network
    let network = match args.network.to_lowercase().as_str() {
        "mainnet" | "main" => Network::Bitcoin,
        "testnet" | "test" => Network::Testnet,
        "signet" => Network::Signet,
        _ => Network::Regtest,
    };

    // Initialize database
    let db_path = std::path::Path::new(&args.data_dir).join("ghost-pay.db");
    let db = Arc::new(Database::open(&db_path)?);
    info!("Database opened: {}", db_path.display());

    // Create pending_transfers table for L2 block production
    db.with_connection(|conn| {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pending_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_index INTEGER NOT NULL,
                recipient_index INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                sender_balance_before INTEGER NOT NULL,
                recipient_balance_before INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS l2_balances (
                account_index INTEGER PRIMARY KEY,
                balance INTEGER NOT NULL
            );",
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(())
    })?;

    // Load L2 balance tree from persisted state
    let mut balance_tree = BalanceTree::new(COMMITMENT_TREE_DEPTH);
    db.with_connection(|conn| {
        let mut stmt = conn
            .prepare("SELECT account_index, balance FROM l2_balances")
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        for row in rows {
            let (index, bal) =
                row.map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
            balance_tree.set_balance(index, bal);
        }
        Ok(())
    })?;
    info!(
        accounts = balance_tree.account_count(),
        "L2 balance tree loaded"
    );

    // M-16 FIX: Require explicit RPC credentials - no defaults
    let rpc_user = args.rpc_user.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Bitcoin RPC user required. Set --rpc-user or BITCOIN_RPC_USER environment variable."
        )
    })?;
    let rpc_password = args.rpc_password.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Bitcoin RPC password required. Set --rpc-password or BITCOIN_RPC_PASSWORD environment variable."
        )
    })?;

    // Parse Bitcoin RPC URL and create client
    let rpc_url = &args.bitcoin_rpc;
    let (rpc_host, rpc_port) = parse_rpc_url(rpc_url, network);
    let rpc = Arc::new(BitcoinRpc::new(
        &rpc_host,
        rpc_port,
        rpc_user,
        rpc_password,
    )?);
    info!("Bitcoin RPC configured: {}:{}", rpc_host, rpc_port);

    // Check treasury address configuration before args is moved
    let treasury_configured = args.treasury_address.is_some();
    if !treasury_configured {
        warn!("No treasury address configured - settlement features disabled");
    }

    // Reconstruct commitment tree from DB
    let mut commitment_tree = CommitmentTree::new(COMMITMENT_TREE_DEPTH);
    match db.load_all_confidential_notes() {
        Ok(notes) => {
            for (index, commitment) in &notes {
                commitment_tree.insert(*index, *commitment);
            }
            if !notes.is_empty() {
                info!(count = notes.len(), "Reconstructed commitment tree from DB");
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to load confidential notes — starting with empty tree");
        }
    }
    // Reconstruct spent nullifiers
    match db.load_all_nullifiers() {
        Ok(nullifiers) => {
            for nullifier in &nullifiers {
                commitment_tree.spend_nullifier(*nullifier);
            }
            if !nullifiers.is_empty() {
                info!(
                    count = nullifiers.len(),
                    "Loaded nullifiers into commitment tree"
                );
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to load nullifiers — nullifier set empty");
        }
    }

    // Load confidential transfer verifier from MPC params (before args is moved)
    let confidential_verifier = load_confidential_verifier_from_params(&args);

    // Initialize state
    let state = Arc::new(AppState {
        keys: RwLock::new(None),
        ghost_id: RwLock::new(None),
        ghost_locks: RwLock::new(Vec::new()),
        locks: RwLock::new(Vec::new()),
        sessions: RwLock::new(Vec::new()),
        coordinators: RwLock::new(std::collections::HashMap::new()),
        scanner_tx,
        config: args,
        network,
        db: db.clone(),
        rpc,
        commitment_tree: RwLock::new(commitment_tree),
        balance_tree: RwLock::new(balance_tree),
        confidential_verifier,
    });

    // H-PAY-2 FIX: Load existing keys from database with encryption support
    // Try encrypted keys first (new format), fall back to legacy plaintext for migration
    let encryption_password = get_encryption_password(&state.config, network)?;
    let mut keys_loaded = false;

    // Try to load encrypted keys first (new secure format)
    if let Ok(Some(encrypted_hex)) = db.kv_get("ghost_keys_encrypted") {
        if let Ok(encrypted_bytes) = hex::decode(&encrypted_hex) {
            match decrypt_keys(&encrypted_bytes, &encryption_password) {
                Ok(decrypted) => {
                    if let Ok(keys_json) = String::from_utf8(decrypted) {
                        if let Ok(keys_export) = serde_json::from_str::<GhostKeysExport>(&keys_json)
                        {
                            if let Ok(keys) = GhostKeys::try_from(keys_export) {
                                let ghost_id = keys.ghost_id();
                                let ghost_id_str = ghost_id.to_string();

                                // Load locks for this ghost_id
                                if let Ok(db_locks) = db.get_ghost_locks_by_owner(&ghost_id_str) {
                                    let lock_infos: Vec<LockInfo> = db_locks
                                        .iter()
                                        .filter(|r| {
                                            r.state != ghost_storage::GhostLockState::Spent
                                                && r.state != ghost_storage::GhostLockState::PendingSettlement
                                        })
                                        .map(|r| LockInfo {
                                            id: r.lock_id.clone(),
                                            denomination: r.denomination.clone(),
                                            amount_sats: r.amount_sats,
                                            state: r.state.as_str().to_string(),
                                            created_at: r.created_at as u64,
                                            timelock_tier: r.timelock_tier.clone(),
                                            jump_risk: r.jump_risk_tier.clone(),
                                            needs_jump: r
                                                .next_jump_height
                                                .map(|h| h <= r.creation_height + 1000)
                                                .unwrap_or(false),
                                            address: pubkey_hex_to_p2tr_address(&r.lock_pubkey, network),
                                            output_pubkey: r.lock_pubkey.clone(),
                                            recovery_height: r.recovery_height,
                                            blocks_until_jump: r
                                                .next_jump_height
                                                .unwrap_or(0)
                                                .saturating_sub(r.creation_height),
                                        })
                                        .collect();

                                    info!(
                                        "Loaded {} existing locks from database",
                                        lock_infos.len()
                                    );
                                    *state.locks.write() = lock_infos;
                                }

                                info!("Loaded existing ghost keys (encrypted): {}", ghost_id);
                                *state.keys.write() = Some(Arc::new(keys));
                                *state.ghost_id.write() = Some(ghost_id_str);
                                keys_loaded = true;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to decrypt keys: {}. Check GHOST_PAY_PASSWORD.", e);
                }
            }
        }
    }

    // Fall back to legacy plaintext keys (migrate to encrypted)
    if !keys_loaded {
        if let Ok(Some(keys_json)) = db.kv_get("ghost_keys") {
            if let Ok(keys_export) = serde_json::from_str::<GhostKeysExport>(&keys_json) {
                if let Ok(keys) = GhostKeys::try_from(keys_export.clone()) {
                    let ghost_id = keys.ghost_id();
                    let ghost_id_str = ghost_id.to_string();

                    // Migrate: encrypt and save, then delete plaintext
                    warn!("Migrating plaintext keys to encrypted storage (H-PAY-2 security fix)");
                    if let Ok(keys_json_bytes) = serde_json::to_vec(&keys_export) {
                        match encrypt_keys(&keys_json_bytes, &encryption_password) {
                            Ok(encrypted) => {
                                let encrypted_hex = hex::encode(&encrypted);
                                if let Err(e) = db.kv_set("ghost_keys_encrypted", &encrypted_hex) {
                                    warn!("Failed to save encrypted keys: {}", e);
                                } else {
                                    // Delete plaintext keys after successful encryption
                                    if let Err(e) = db.kv_delete("ghost_keys") {
                                        warn!("Failed to delete plaintext keys: {}", e);
                                    } else {
                                        info!("Successfully migrated keys to encrypted storage");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to encrypt keys during migration: {}", e);
                            }
                        }
                    }

                    // Load locks for this ghost_id
                    if let Ok(db_locks) = db.get_ghost_locks_by_owner(&ghost_id_str) {
                        let lock_infos: Vec<LockInfo> = db_locks
                            .iter()
                            .filter(|r| {
                                r.state != ghost_storage::GhostLockState::Spent
                                    && r.state != ghost_storage::GhostLockState::PendingSettlement
                            })
                            .map(|r| LockInfo {
                                id: r.lock_id.clone(),
                                denomination: r.denomination.clone(),
                                amount_sats: r.amount_sats,
                                state: r.state.as_str().to_string(),
                                created_at: r.created_at as u64,
                                timelock_tier: r.timelock_tier.clone(),
                                jump_risk: r.jump_risk_tier.clone(),
                                needs_jump: r
                                    .next_jump_height
                                    .map(|h| h <= r.creation_height + 1000)
                                    .unwrap_or(false),
                                address: pubkey_hex_to_p2tr_address(&r.lock_pubkey, network),
                                output_pubkey: r.lock_pubkey.clone(),
                                recovery_height: r.recovery_height,
                                blocks_until_jump: r
                                    .next_jump_height
                                    .unwrap_or(0)
                                    .saturating_sub(r.creation_height),
                            })
                            .collect();

                        info!("Loaded {} existing locks from database", lock_infos.len());
                        *state.locks.write() = lock_infos;
                    }

                    info!(
                        "Loaded existing ghost keys (migrated from plaintext): {}",
                        ghost_id
                    );
                    *state.keys.write() = Some(Arc::new(keys));
                    *state.ghost_id.write() = Some(ghost_id_str);
                }
            }
        }
    }

    // Graceful shutdown: broadcast channel signals all background tasks to stop
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Spawn background scanner
    let state_clone = Arc::clone(&state);
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            _ = run_scanner(state_clone, scanner_rx) => {}
            _ = shutdown_rx.recv() => {
                info!("Scanner shutting down");
            }
        }
    });

    // Spawn session coordinator
    let state_clone = Arc::clone(&state);
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            _ = run_session_coordinator(state_clone) => {}
            _ = shutdown_rx.recv() => {
                info!("Session coordinator shutting down");
            }
        }
    });

    // Spawn L1 settlement loop (only if treasury address is configured)
    if treasury_configured {
        let state_clone = Arc::clone(&state);
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                _ = run_settlement_loop(state_clone) => {}
                _ = shutdown_rx.recv() => {
                    info!("Settlement loop shutting down");
                }
            }
        });
        info!("L1 settlement loop enabled");
    }

    // H-2: Create API authentication state
    let api_auth = ApiAuth::new(state.config.api_secret.clone(), state.network);

    // HIGH-API-1: Fail startup if api_secret not configured on mainnet
    if api_auth.secret.is_none() {
        if state.network == Network::Bitcoin {
            return Err(anyhow::anyhow!(
                "HIGH-API-1 SECURITY: API secret REQUIRED for mainnet! \
                 Set GHOST_PAY_API_SECRET environment variable or --api-secret flag. \
                 Ghost Pay will NOT start without authentication on mainnet."
            ));
        } else {
            // HIGH-API-2: Also require auth on all networks for consistency
            return Err(anyhow::anyhow!(
                "HIGH-API-2 SECURITY: API secret REQUIRED on all networks! \
                 Set GHOST_PAY_API_SECRET environment variable or --api-secret flag. \
                 This prevents bugs in auth integration from being masked on non-mainnet."
            ));
        }
    }

    info!("H-2: API authentication enabled");

    // H-2: Build authenticated routes (require HMAC signature)
    let authenticated_routes = Router::new()
        // Key management (SENSITIVE - can export private keys)
        .route("/api/v1/keys/generate", post(generate_keys))
        .route("/api/v1/keys/export", get(export_keys))
        // Lock management (SENSITIVE - controls funds)
        .route("/api/v1/locks/create", post(create_lock))
        .route("/api/v1/locks/:id/jump", post(initiate_jump))
        // Wraith sessions (SENSITIVE - privacy operations)
        .route("/api/v1/wraith/join", post(join_session))
        // Withdrawals (SENSITIVE - moves funds)
        .route("/api/v1/withdrawals/request", post(request_withdrawal))
        .route("/api/v1/withdrawals/:id/cancel", post(cancel_withdrawal))
        // Confidential transfers (SENSITIVE - moves private balances)
        .route(
            "/api/v1/confidential/transfer",
            post(submit_confidential_transfer),
        )
        .route("/api/v1/confidential/shield", post(shield_balance))
        // Lock reconciliation (SENSITIVE - settles lock to L1)
        .route("/api/v1/locks/:id/reconcile", post(reconcile_lock))
        // L2 payments (SENSITIVE - instant off-chain transfer)
        .route("/api/v1/payments/send", post(send_l2_payment))
        .layer(axum::middleware::from_fn_with_state(
            api_auth.clone(),
            require_api_auth,
        ))
        .with_state(state.clone());

    // Public routes (read-only, no authentication required)
    let public_routes = Router::new()
        // Read-only key info
        .route("/api/v1/keys/ghost-id", get(get_ghost_id))
        // Read-only lock info
        .route("/api/v1/locks", get(list_locks))
        .route("/api/v1/locks/:id", get(get_lock))
        // Read-only session info
        .route("/api/v1/wraith/sessions", get(list_sessions))
        .route("/api/v1/wraith/sessions/:id", get(get_session))
        // Payments (derive address is safe, scan is read-only)
        .route("/api/v1/payments/address", post(derive_payment_address))
        .route("/api/v1/payments/scan", post(scan_transaction))
        // Read-only withdrawal info
        .route("/api/v1/withdrawals", get(list_withdrawals))
        .route("/api/v1/withdrawals/:id", get(get_withdrawal))
        // Status endpoints
        .route("/api/v1/status", get(get_status))
        .route("/health", get(health_check))
        // GhostPay verification endpoint for node capability challenges
        .route("/verify/ghostpay", get(verify_ghostpay))
        // Confidential transfer read-only endpoints
        .route("/api/v1/confidential/tree", get(get_tree_state))
        .route(
            "/api/v1/confidential/notes/:owner_pubkey",
            get(get_confidential_notes),
        )
        // L2 block production endpoints (localhost-only, called by ghost-pool)
        .route("/api/v1/l2/state", get(l2_state_handler))
        .route("/api/v1/l2/pending", get(l2_pending_handler))
        .route("/api/v1/l2/finalize", post(l2_finalize_handler))
        .with_state(state.clone());

    // L-14 SECURITY: Read CORS origins from environment variable with secure defaults.
    // Format: comma-separated list of origins (e.g., "https://example.com,https://app.example.com")
    let cors_origins_str = std::env::var("GHOST_PAY_CORS_ORIGINS")
        .unwrap_or_else(|_| "https://bitcoinghost.org,https://wallet.bitcoinghost.org".to_string());

    let cors_origins: Vec<_> = cors_origins_str
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<http::HeaderValue>() {
                Ok(hv) => Some(hv),
                Err(e) => {
                    warn!(origin = trimmed, error = %e, "Invalid CORS origin in GHOST_PAY_CORS_ORIGINS - skipping");
                    None
                }
            }
        })
        .collect();

    if cors_origins.is_empty() {
        error!("No valid CORS origins configured - API will reject all cross-origin requests");
    } else {
        info!(origins = ?cors_origins_str, "CORS origins configured");
    }

    // H-8: Build rate limiter for API protection
    // 30 requests per minute per IP, with burst of 10
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(1) // 1 request per second sustained
        .burst_size(10) // Allow bursts of up to 10 requests
        .key_extractor(IpKeyExtractor::new())
        .finish()
        .expect("L-1: Valid hardcoded rate limiter config");

    let governor_conf = std::sync::Arc::new(governor_conf);

    // Spawn background task to clean up rate limiter state
    let governor_limiter = governor_conf.limiter().clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    governor_limiter.retain_recent();
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    });

    info!("H-8: Rate limiting enabled (10 burst / 1 per sec per IP)");

    // Merge routes and apply common layers
    // H-7: 1MB body size limit to prevent memory exhaustion
    // H-8: Rate limiting to prevent API abuse
    // LOW-API-1: Security headers for all responses
    let app = public_routes
        .merge(authenticated_routes)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(cors_origins))
                .allow_methods([http::Method::GET, http::Method::POST, http::Method::OPTIONS])
                .allow_headers([
                    http::header::CONTENT_TYPE,
                    http::header::AUTHORIZATION,
                    "X-Ghost-Signature"
                        .parse()
                        .expect("L-1: Valid hardcoded header name"),
                    "X-Ghost-Timestamp"
                        .parse()
                        .expect("L-1: Valid hardcoded header name"),
                ])
                .max_age(std::time::Duration::from_secs(3600)),
        )
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(1024 * 1024)); // H-7: 1MB body limit

    info!("H-7: Request body limit set to 1MB");

    // Parse listen address
    let addr: SocketAddr = state.config.api_listen.parse()?;

    // Build TLS config for HTTPS — only when operator provides explicit cert/key.
    // Without explicit certs, serve plain HTTP so that the verification client
    // (which uses HTTP on signet/testnet) can reach us without TLS issues.
    let tls_config = if let (Some(cert_path), Some(key_path)) = (tls_cert_path, tls_key_path) {
        let tls_cfg = ghost_common::config::TlsConfig {
            cert_path: Some(cert_path),
            key_path: Some(key_path),
        };
        match ghost_common::tls::build_server_config(&tls_cfg) {
            Ok(tls) => {
                info!("Ghost Pay API starting on {} (HTTPS, operator cert)", addr);
                Some(tls)
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to build TLS config: {}", e));
            }
        }
    } else {
        info!("Ghost Pay API starting on {} (HTTP)", addr);
        None
    };

    // Start server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
        info!("Received shutdown signal, starting graceful shutdown...");
    };

    match tls_config {
        Some(tls) => {
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls);
            let mut make_service =
                app.into_make_service_with_connect_info::<std::net::SocketAddr>();

            // We need to handle graceful shutdown manually for TLS
            let shutdown = tokio::signal::ctrl_c();
            tokio::pin!(shutdown);

            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        let (tcp_stream, remote_addr) = accept_result?;
                        let acceptor = tls_acceptor.clone();

                        let tower_service = {
                            use tower::Service;
                            match make_service.call(remote_addr).await {
                                Ok(s) => s,
                                Err(_) => continue,
                            }
                        };

                        let hyper_service = hyper_util::service::TowerToHyperService::new(tower_service);

                        tokio::spawn(async move {
                            let tls_stream = match acceptor.accept(tcp_stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(error = %e, "TLS handshake failed");
                                    return;
                                }
                            };
                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(io, hyper_service)
                            .await
                            {
                                tracing::debug!(error = %e, "Connection error");
                            }
                        });
                    }
                    _ = &mut shutdown => {
                        info!("Received shutdown signal, starting graceful shutdown...");
                        break;
                    }
                }
            }
        }
        None => {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal)
            .await?;
        }
    }

    // Signal all background tasks to stop
    info!("HTTP server stopped, signaling background tasks...");
    let _ = shutdown_tx.send(());

    // Give background tasks time to finish in-flight work
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    info!("Ghost Pay shutdown complete");

    Ok(())
}

// ============================================================================
// Key Management Handlers
// ============================================================================

/// Generate new ghost keys
async fn generate_keys(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let ghost_id_str = ghost_id.to_string();

    // H-PAY-2 FIX: Save keys to database with encryption
    let keys_export = GhostKeysExport::from(&keys);
    if let Ok(keys_json) = serde_json::to_vec(&keys_export) {
        let encryption_password = match get_encryption_password(&state.config, state.network) {
            Ok(pwd) => pwd,
            Err(e) => {
                error!("Cannot generate keys without encryption password: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        match encrypt_keys(&keys_json, &encryption_password) {
            Ok(encrypted) => {
                let encrypted_hex = hex::encode(&encrypted);
                if let Err(e) = state.db.kv_set("ghost_keys_encrypted", &encrypted_hex) {
                    warn!("Failed to persist encrypted keys: {}", e);
                }
                // Ensure no plaintext keys exist
                let _ = state.db.kv_delete("ghost_keys");
            }
            Err(e) => {
                warn!("Failed to encrypt keys: {}", e);
            }
        }
    }

    *state.keys.write() = Some(Arc::new(keys));
    *state.ghost_id.write() = Some(ghost_id_str.clone());

    // Load existing locks from database for this ghost_id (pending and active, not spent/settling)
    if let Ok(db_locks) = state.db.get_ghost_locks_by_owner(&ghost_id_str) {
        let network = state.network;
        let lock_infos: Vec<LockInfo> = db_locks
            .iter()
            // H-PAY-1 FIX: Exclude both Spent and PendingSettlement locks
            .filter(|r| {
                r.state != ghost_storage::GhostLockState::Spent
                    && r.state != ghost_storage::GhostLockState::PendingSettlement
            })
            .map(|r| LockInfo {
                id: r.lock_id.clone(),
                denomination: r.denomination.clone(),
                amount_sats: r.amount_sats,
                state: r.state.as_str().to_string(),
                created_at: r.created_at as u64,
                timelock_tier: r.timelock_tier.clone(),
                jump_risk: r.jump_risk_tier.clone(),
                needs_jump: r
                    .next_jump_height
                    .map(|h| h <= r.creation_height + 1000)
                    .unwrap_or(false),
                address: pubkey_hex_to_p2tr_address(&r.lock_pubkey, network),
                output_pubkey: r.lock_pubkey.clone(),
                recovery_height: r.recovery_height,
                blocks_until_jump: r
                    .next_jump_height
                    .unwrap_or(0)
                    .saturating_sub(r.creation_height),
            })
            .collect();

        info!("Loaded {} existing locks from database", lock_infos.len());
        *state.locks.write() = lock_infos;
    }

    info!("Generated new ghost keys: {}", ghost_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "ghost_id": ghost_id.to_string()
    })))
}

/// Export keys (encrypted)
async fn export_keys(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let export = keys.export();

    Ok(Json(serde_json::json!({
        "scan_pubkey": export.scan_pubkey_hex,
        "spend_pubkey": export.spend_pubkey_hex,
        "ghost_id": export.ghost_id
    })))
}

/// Get ghost ID for receiving
async fn get_ghost_id(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let ghost_id = keys.ghost_id();

    Ok(Json(serde_json::json!({
        "ghost_id": ghost_id.to_string(),
        "scan_pubkey": hex::encode(ghost_id.scan_pubkey().serialize()),
        "spend_pubkey": hex::encode(ghost_id.spend_pubkey().serialize())
    })))
}

// ============================================================================
// Lock Management Handlers
// ============================================================================

/// List all locks
async fn list_locks(State(state): State<Arc<AppState>>) -> Json<Vec<LockInfo>> {
    let locks = state.locks.read().clone();
    Json(locks)
}

/// Create lock request
#[derive(Debug, Deserialize)]
struct CreateLockRequest {
    amount_sats: u64,
    timelock_tier: Option<String>,
}

/// Create a new ghost lock
async fn create_lock(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateLockRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Fetch current block height from Bitcoin Core first (before acquiring locks)
    // H-21: Use safe block height conversion with bounds checking
    let creation_height = state
        .rpc
        .get_blockchain_info()
        .await
        .map_err(|e| {
            error!(error = %e, "Bitcoin RPC unavailable - cannot determine block height");
            StatusCode::SERVICE_UNAVAILABLE
        })
        .and_then(|info| {
            safe_block_height_u64(info.blocks).map_err(|e| {
                error!(error = %e, "H-21: Invalid block height from RPC");
                StatusCode::INTERNAL_SERVER_ERROR
            })
        })?;

    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    // Determine denomination
    let denomination = Denomination::from_sats(req.amount_sats).ok_or(StatusCode::BAD_REQUEST)?;

    // Determine timelock tier
    let timelock_tier = match req.timelock_tier.as_deref() {
        Some("short") => TimelockTier::Short,
        Some("long") => TimelockTier::Long,
        _ => TimelockTier::Standard,
    };

    // Get current lock index
    // H-21: Safe conversion with bounds checking
    let lock_count = state.ghost_locks.read().len();
    let lock_index = u32::try_from(lock_count).map_err(|_| {
        error!("H-21: Lock index {} exceeds u32::MAX", lock_count);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Derive lock and recovery secrets
    let lock_secret = keys
        .derive_lock_secret(lock_index)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let recovery_secret = keys
        .derive_recovery_secret(lock_index)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create the actual GhostLock
    let secp = Secp256k1::new();
    let ghost_lock = GhostLock::new(
        &secp,
        &lock_secret,
        &recovery_secret,
        denomination,
        timelock_tier,
        creation_height,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate P2WSH address from script pubkey (quantum-safe)
    let address = Address::from_script(ghost_lock.script_pubkey(), state.network)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Determine jump risk based on amount
    let jump_risk = ghost_lock.jump_risk_tier();

    let lock_info = LockInfo {
        id: ghost_lock.lock_id_hex(),
        denomination: denomination.name().to_string(),
        amount_sats: denomination.sats(),
        state: format!("{:?}", ghost_lock.state()),
        created_at: now,
        timelock_tier: format!("{:?}", timelock_tier),
        jump_risk: format!("{:?}", jump_risk),
        needs_jump: ghost_lock.needs_jump(creation_height),
        address: address.to_string(),
        output_pubkey: hex::encode(ghost_lock.lock_pubkey().serialize()),
        recovery_height: ghost_lock.recovery_height(),
        blocks_until_jump: ghost_lock.blocks_until_jump(creation_height),
    };

    // Get the ghost_id for database
    let owner_ghost_id = state
        .ghost_id
        .read()
        .clone()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create database record
    let db_record = GhostLockRecord {
        lock_id: ghost_lock.lock_id_hex(),
        owner_ghost_id,
        lock_pubkey: hex::encode(ghost_lock.lock_pubkey().serialize()),
        recovery_pubkey: hex::encode(ghost_lock.recovery_pubkey().serialize()),
        denomination: denomination.name().to_string(),
        amount_sats: denomination.sats(),
        timelock_tier: format!("{:?}", timelock_tier),
        creation_height,
        recovery_height: ghost_lock.recovery_height(),
        state: DbLockState::Pending,
        funding_txid: None,
        funding_vout: None,
        spend_txid: None,
        output_script: hex::encode(address.script_pubkey().as_bytes()),
        jump_risk_tier: format!("{:?}", jump_risk),
        next_jump_height: Some(ghost_lock.jump_schedule().deadline_height),
        created_at: now as i64,
        updated_at: now as i64,
    };

    // Persist to database
    state
        .db
        .insert_ghost_lock(&db_record)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store the actual lock in memory cache
    state.ghost_locks.write().push(ghost_lock);
    state.locks.write().push(lock_info.clone());

    info!(
        id = %lock_info.id,
        denomination = ?denomination,
        address = %lock_info.address,
        "Created new ghost lock (persisted to database)"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "lock": lock_info
    })))
}

/// Get specific lock
async fn get_lock(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<LockInfo>, StatusCode> {
    let locks = state.locks.read();
    let lock = locks
        .iter()
        .find(|l| l.id == id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(lock))
}

/// Initiate jump for a lock
async fn initiate_jump(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Update database state
    state
        .db
        .update_ghost_lock_state(&id, DbLockState::Jumping)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update the actual GhostLock state in memory
    {
        let mut ghost_locks = state.ghost_locks.write();
        if let Some(ghost_lock) = ghost_locks.iter_mut().find(|l| l.lock_id_hex() == id) {
            if let Err(e) = ghost_lock.transition(StateTransition::StartJump) {
                warn!(lock_id = %id, error = %e, "Failed to transition lock to jumping state");
            }
        }
    }

    // Update the metadata cache
    {
        let mut locks = state.locks.write();
        if let Some(lock) = locks.iter_mut().find(|l| l.id == id) {
            lock.state = "Jumping".to_string();
        }
    }

    info!(id = %id, "Initiated jump for lock (persisted to database)");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Jump initiated - funds will be moved to new lock with fresh keys"
    })))
}

// ============================================================================
// Wraith Session Handlers
// ============================================================================

/// List active sessions
async fn list_sessions(State(state): State<Arc<AppState>>) -> Json<Vec<SessionInfo>> {
    let sessions = state.sessions.read().clone();
    Json(sessions)
}

/// Join session request
#[derive(Debug, Deserialize)]
struct JoinSessionRequest {
    tier: String,
    denomination: String,
    /// Lock ID to use for this session (reserved for future lock validation)
    #[allow(dead_code)]
    lock_id: String,
}

/// Join a Wraith mixing session
async fn join_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JoinSessionRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Parse tier (based on participant balance range)
    let tier = match req.tier.to_lowercase().as_str() {
        "micro" | "express" | "quick" => ParticipantTier::Micro,
        "small" => ParticipantTier::Small,
        "medium" => ParticipantTier::Medium,
        "standard" => ParticipantTier::Standard,
        "large" => ParticipantTier::Large,
        "whale" => ParticipantTier::Whale,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // Parse denomination (will be used for session matching)
    let _denomination = match req.denomination.to_lowercase().as_str() {
        "micro" => WraithDenomination::Micro,
        "small" => WraithDenomination::Small,
        "medium" => WraithDenomination::Medium,
        "large" => WraithDenomination::Large,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // Create or join session
    let mut sessions = state.sessions.write();

    // Look for existing session
    let session = sessions
        .iter_mut()
        .find(|s| s.tier == req.tier && s.denomination == req.denomination && s.state == "waiting");

    match session {
        Some(s) => {
            s.participants += 1;
            s.fill_percentage = (s.participants as f64 / tier.min_participants() as f64) * 100.0;

            info!(id = %s.id, participants = s.participants, "Joined existing session");

            Ok(Json(serde_json::json!({
                "success": true,
                "session_id": s.id,
                "participants": s.participants,
                "fill_percentage": s.fill_percentage
            })))
        }
        None => {
            // Create new session
            let session_id = uuid::Uuid::new_v4().to_string();
            let new_session = SessionInfo {
                id: session_id.clone(),
                tier: req.tier,
                denomination: req.denomination,
                state: "waiting".to_string(),
                participants: 1,
                fill_percentage: (1.0 / tier.min_participants() as f64) * 100.0,
            };
            sessions.push(new_session);

            info!(id = %session_id, "Created new Wraith session");

            Ok(Json(serde_json::json!({
                "success": true,
                "session_id": session_id,
                "participants": 1,
                "fill_percentage": (1.0 / tier.min_participants() as f64) * 100.0
            })))
        }
    }
}

/// Get session details
async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionInfo>, StatusCode> {
    let sessions = state.sessions.read();
    let session = sessions
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(session))
}

// ============================================================================
// Payment Handlers
// ============================================================================

/// Derive payment address request
#[derive(Debug, Deserialize)]
struct DeriveAddressRequest {
    index: u32,
}

/// Derive a payment address for receiving
async fn derive_payment_address(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeriveAddressRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let ghost_id = keys.ghost_id();

    // Derive payment address using v2 (k-based, position-independent)
    // The 'index' parameter in the API now represents k (sequential counter)
    let (output_pubkey, ephemeral_pubkey) = ghost_id
        .derive_payment_address_v2(req.index)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "output_pubkey": hex::encode(output_pubkey.serialize()),
        "ephemeral_pubkey": hex::encode(ephemeral_pubkey.serialize()),
        "k": req.index
    })))
}

/// Scan transaction for payments
async fn scan_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Queue for background scanning
    state
        .scanner_tx
        .send(req.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Transaction queued for scanning"
    })))
}

// ============================================================================
// Withdrawal Handlers
// ============================================================================

/// Withdrawal request body
#[derive(Debug, Deserialize)]
struct WithdrawalRequestBody {
    /// Lock ID to withdraw from
    lock_id: String,
    /// Destination Bitcoin address
    destination_address: String,
    /// Amount to withdraw in satoshis (must be <= lock amount minus fees)
    amount_sats: u64,
}

/// List pending withdrawals
async fn list_withdrawals(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    let withdrawals = state
        .db
        .get_pending_withdrawals(&ghost_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result: Vec<serde_json::Value> = withdrawals
        .iter()
        .map(|w| {
            serde_json::json!({
                "id": w.id,
                "lock_id": w.lock_id,
                "destination_address": w.destination_address,
                "amount_sats": w.amount_sats,
                "fee_sats": w.fee_sats,
                "status": w.status.as_str(),
                "batch_id": w.batch_id,
                "l1_txid": w.l1_txid,
                "created_at": w.created_at
            })
        })
        .collect();

    Ok(Json(result))
}

/// Request a withdrawal from a lock
async fn request_withdrawal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WithdrawalRequestBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    // Validate the lock exists and is owned by this ghost_id
    let lock = state
        .db
        .get_ghost_lock(&req.lock_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if lock.owner_ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate lock is active and funded
    if lock.state != DbLockState::Active {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not active"
        })));
    }

    if lock.funding_txid.is_none() {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not funded"
        })));
    }

    // Validate amount
    let settlement_fee = 1000u64; // Base settlement fee
    let max_withdrawal = lock.amount_sats.saturating_sub(settlement_fee);
    if req.amount_sats > max_withdrawal {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Amount exceeds maximum withdrawal of {} sats", max_withdrawal)
        })));
    }

    // Validate destination address format
    if !req.destination_address.starts_with("bc1")
        && !req.destination_address.starts_with("tb1")
        && !req.destination_address.starts_with("bcrt1")
    {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Invalid destination address format (must be bech32)"
        })));
    }

    let now = chrono::Utc::now().timestamp();

    // Create withdrawal request
    let withdrawal = WithdrawalRequest {
        id: None,
        ghost_id: ghost_id.clone(),
        lock_id: req.lock_id.clone(),
        destination_address: req.destination_address.clone(),
        amount_sats: req.amount_sats,
        fee_sats: settlement_fee,
        status: WithdrawalStatus::Pending,
        batch_id: None,
        l1_txid: None,
        created_at: now,
        updated_at: now,
    };

    // Atomically check for existing pending/batched withdrawal and insert if none exists
    // This prevents double-spend race conditions (C-PAY-3) by using a database transaction
    // with a partial unique index as defense-in-depth
    let id = match state
        .db
        .insert_withdrawal_request_atomic(&withdrawal)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(id) => id,
        None => {
            // A pending/batched withdrawal already exists for this lock
            return Ok(Json(serde_json::json!({
                "success": false,
                "error": "A withdrawal is already pending for this lock"
            })));
        }
    };

    info!(
        id = id,
        lock_id = %req.lock_id,
        amount = req.amount_sats,
        destination = %req.destination_address,
        "Created withdrawal request"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "withdrawal_id": id,
        "lock_id": req.lock_id,
        "amount_sats": req.amount_sats,
        "fee_sats": settlement_fee,
        "destination_address": req.destination_address,
        "status": "pending"
    })))
}

/// Get a specific withdrawal
async fn get_withdrawal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    let withdrawal = state
        .db
        .get_withdrawal_request(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify ownership
    if withdrawal.ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(serde_json::json!({
        "id": withdrawal.id,
        "lock_id": withdrawal.lock_id,
        "destination_address": withdrawal.destination_address,
        "amount_sats": withdrawal.amount_sats,
        "fee_sats": withdrawal.fee_sats,
        "status": withdrawal.status.as_str(),
        "batch_id": withdrawal.batch_id,
        "l1_txid": withdrawal.l1_txid,
        "created_at": withdrawal.created_at,
        "updated_at": withdrawal.updated_at
    })))
}

/// Cancel a pending withdrawal
async fn cancel_withdrawal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    let withdrawal = state
        .db
        .get_withdrawal_request(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify ownership
    if withdrawal.ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Can only cancel pending withdrawals
    if withdrawal.status != WithdrawalStatus::Pending {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Cannot cancel withdrawal in '{}' status", withdrawal.status.as_str())
        })));
    }

    state
        .db
        .cancel_withdrawal(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(id = id, "Cancelled withdrawal request");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Withdrawal cancelled"
    })))
}

// ============================================================================
// Status Handlers
// ============================================================================

/// Get node status
async fn get_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let has_keys = state.keys.read().is_some();
    let lock_count = state.locks.read().len();
    let session_count = state.sessions.read().len();

    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "has_keys": has_keys,
        "lock_count": lock_count,
        "active_sessions": session_count,
        "network": state.config.network
    }))
}

/// L-13 FIX: Dynamic health check that verifies actual system health
///
/// Checks database connectivity and RPC health before returning OK.
/// Returns 503 Service Unavailable if any component is unhealthy.
async fn health_check(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    // Check database connectivity
    if let Err(e) = state.db.health_check() {
        error!("L-13: Database health check failed: {}", e);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "database unhealthy".to_string(),
        );
    }

    // Check Bitcoin RPC connectivity (async call)
    if let Err(e) = state.rpc.get_block_count().await {
        error!("L-13: Bitcoin RPC health check failed: {}", e);
        return (StatusCode::SERVICE_UNAVAILABLE, "rpc unhealthy".to_string());
    }

    (StatusCode::OK, "OK".to_string())
}

// ============================================================================
// GhostPay Verification Endpoint
// ============================================================================

/// Query parameters for GhostPay verification
#[derive(Debug, Deserialize)]
struct GhostPayVerifyQuery {
    /// Epoch to challenge (if not provided, uses current)
    challenge_epoch: Option<u64>,
    /// Random nonce for binding proof (256-bit hex string)
    challenge_nonce: Option<String>,
    /// Skip signature (for verification client) - not used since ghost-pay doesn't sign
    #[serde(default)]
    #[allow(dead_code)]
    unsigned: Option<bool>,
}

/// L2 block state from ghost-pay's blocks table
struct L2BlockState {
    height: u64,
    epoch_id: u64,
    state_root: String,
}

/// L2 blocks database path
/// The L2 blocks are stored in a separate database with a simpler schema.
/// This is the standard XDG data directory for ghost-pay.
const L2_BLOCKS_DB_PATH: &str = "/home/ghost/.local/share/ghost-pay/ghost-pay.db";

/// Get latest L2 block from ghost-pay's blocks table
/// Opens a direct connection to the L2 blocks database (separate from ghost-storage).
fn get_latest_l2_block() -> Result<Option<L2BlockState>, String> {
    let conn = match rusqlite::Connection::open_with_flags(
        L2_BLOCKS_DB_PATH,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to open L2 blocks database: {}", e)),
    };

    let result = conn.query_row(
        "SELECT height, epoch_id, state_root FROM blocks ORDER BY height DESC LIMIT 1",
        [],
        |row| {
            let height: i64 = row.get(0)?;
            let epoch_id: i64 = row.get(1)?;
            let state_root: String = row.get(2)?;
            Ok((height, epoch_id, state_root))
        },
    );

    match result {
        Ok((height, epoch_id, state_root)) => {
            if height < 0 || epoch_id < 0 {
                return Err("Invalid negative height or epoch".to_string());
            }
            Ok(Some(L2BlockState {
                height: height as u64,
                epoch_id: epoch_id as u64,
                state_root,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Database query error: {}", e)),
    }
}

/// Get L2 block state at a specific epoch from ghost-pay's blocks table
fn get_l2_block_at_epoch(epoch: u64) -> Result<Option<L2BlockState>, String> {
    let conn = match rusqlite::Connection::open_with_flags(
        L2_BLOCKS_DB_PATH,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to open L2 blocks database: {}", e)),
    };

    let result = conn.query_row(
        "SELECT height, epoch_id, state_root FROM blocks WHERE epoch_id = ?1 ORDER BY height DESC LIMIT 1",
        [epoch as i64],
        |row| {
            let height: i64 = row.get(0)?;
            let epoch_id: i64 = row.get(1)?;
            let state_root: String = row.get(2)?;
            Ok((height, epoch_id, state_root))
        },
    );

    match result {
        Ok((height, epoch_id, state_root)) => {
            if height < 0 || epoch_id < 0 {
                return Err("Invalid negative height or epoch".to_string());
            }
            Ok(Some(L2BlockState {
                height: height as u64,
                epoch_id: epoch_id as u64,
                state_root,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Database query error: {}", e)),
    }
}

/// Get the number of L2 blocks in a specific epoch
fn get_epoch_tx_count(epoch: u64) -> Result<u64, String> {
    let conn = match rusqlite::Connection::open_with_flags(
        L2_BLOCKS_DB_PATH,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to open L2 blocks database: {}", e)),
    };

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocks WHERE epoch_id = ?1",
            [epoch as i64],
            |row| row.get(0),
        )
        .map_err(|e| format!("Failed to count epoch blocks: {}", e))?;

    Ok(count as u64)
}

/// GhostPay verification response
///
/// Returns real L2 state from the database for verification challenges.
/// This endpoint is used by the verification system to prove GhostPay capability.
async fn verify_ghostpay(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GhostPayVerifyQuery>,
) -> impl axum::response::IntoResponse {
    // Get latest L2 state from ghost-pay's blocks table (separate L2 database)
    let current_state = match get_latest_l2_block() {
        Ok(Some(info)) => info,
        Ok(None) => {
            // No L2 blocks yet - return failure response
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "signed": false,
                    "response": {
                        "success": false,
                        "l2_enabled": false,
                        "virtual_block": null,
                        "epoch": null,
                        "balance_sats": null,
                        "wraith_enabled": false,
                        "epoch_state_hash": null,
                        "epoch_tx_count": null,
                        "nonce_bound_proof": null,
                        "epoch_proof": null,
                        "error": "No L2 blocks in database"
                    }
                })),
            );
        }
        Err(e) => {
            error!("Failed to get L2 state: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "signed": false,
                    "response": {
                        "success": false,
                        "l2_enabled": false,
                        "error": format!("Database error: {}", e)
                    }
                })),
            );
        }
    };

    // Determine which epoch to prove
    let challenge_epoch = query.challenge_epoch.unwrap_or(current_state.epoch_id);

    // Get state for challenged epoch (may be different from current)
    let epoch_state = if challenge_epoch == current_state.epoch_id {
        current_state.state_root.clone()
    } else {
        match get_l2_block_at_epoch(challenge_epoch) {
            Ok(Some(info)) => info.state_root,
            Ok(None) => {
                // Requested epoch doesn't exist
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "signed": false,
                        "response": {
                            "success": false,
                            "l2_enabled": true,
                            "virtual_block": current_state.height,
                            "epoch": current_state.epoch_id,
                            "error": format!("Epoch {} not found (current epoch: {})", challenge_epoch, current_state.epoch_id)
                        }
                    })),
                );
            }
            Err(e) => {
                error!("Failed to get epoch state: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "signed": false,
                        "response": {
                            "success": false,
                            "l2_enabled": true,
                            "error": format!("Database error: {}", e)
                        }
                    })),
                );
            }
        }
    };

    // Compute nonce-bound proof if nonce provided
    // nonce_bound_proof = SHA256(epoch_state_hash || challenge_nonce)
    let nonce_bound_proof = if let Some(ref nonce) = query.challenge_nonce {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(epoch_state.as_bytes());
        hasher.update(nonce.as_bytes());
        Some(hex::encode(hasher.finalize()))
    } else {
        None
    };

    // Check if Wraith protocol is enabled (has active sessions)
    let wraith_enabled = !state.sessions.read().is_empty();

    // Get L2 block count for challenged epoch
    let epoch_tx_count = get_epoch_tx_count(challenge_epoch).unwrap_or(0);

    // Return success response with real L2 state
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "signed": false,
            "response": {
                "success": true,
                "l2_enabled": true,
                "virtual_block": current_state.height,
                "epoch": current_state.epoch_id,
                "balance_sats": null,
                "wraith_enabled": wraith_enabled,
                "epoch_state_hash": epoch_state,
                "epoch_tx_count": epoch_tx_count,
                "nonce_bound_proof": nonce_bound_proof,
                "epoch_proof": null,
                "error": null
            }
        })),
    )
}

// ============================================================================
// Confidential Transfer Handlers
// ============================================================================

/// Parse a hex string into exactly 32 bytes, returning error on invalid input
fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], StatusCode> {
    let bytes = hex::decode(hex_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(arr)
}

/// Request body for submitting a confidential transfer
#[derive(Debug, Deserialize)]
struct ConfidentialTransferRequest {
    proof_hex: String,
    old_commitment_root: String,
    new_commitment_root: String,
    nullifier: String,
    sender_new_commitment: String,
    recipient_new_commitment: String,
    sender_index: u64,
    recipient_index: u64,
    recipient_owner_pubkey: String,
}

/// Submit a confidential transfer with Groth16 proof
async fn submit_confidential_transfer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConfidentialTransferRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Parse all hex fields
    let proof_bytes = hex::decode(&req.proof_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid proof hex"})),
        )
    })?;
    if proof_bytes.len() != 192 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Proof must be exactly 192 bytes"})),
        ));
    }

    let old_root = parse_hex_32(&req.old_commitment_root).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid old_commitment_root hex (need 32 bytes)"})),
        )
    })?;
    let new_root = parse_hex_32(&req.new_commitment_root).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid new_commitment_root hex (need 32 bytes)"})),
        )
    })?;
    let nullifier = parse_hex_32(&req.nullifier).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid nullifier hex (need 32 bytes)"})),
        )
    })?;
    let sender_new_commitment = parse_hex_32(&req.sender_new_commitment).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid sender_new_commitment hex (need 32 bytes)"})),
        )
    })?;
    let recipient_new_commitment = parse_hex_32(&req.recipient_new_commitment).map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid recipient_new_commitment hex (need 32 bytes)"})))
    })?;
    let recipient_owner_pubkey = parse_hex_32(&req.recipient_owner_pubkey).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Invalid recipient_owner_pubkey hex (need 32 bytes)"}),
            ),
        )
    })?;

    // Step 1: Read-lock tree, verify old_commitment_root matches current
    {
        let tree = state.commitment_tree.read();
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != old_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }
        // Check nullifier not already spent (in-memory)
        if tree.is_nullifier_spent(&nullifier) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Nullifier already spent"})),
            ));
        }
    }

    // Step 2: Also check nullifier in DB (belt and suspenders)
    if state.db.is_nullifier_spent(&nullifier).unwrap_or(true) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Nullifier already spent"})),
        ));
    }

    // Step 3: Verify Groth16 proof
    let verifier = state.confidential_verifier.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Confidential verifier not initialized (MPC params unavailable)"})))
    })?;

    let public_inputs = ConfidentialPublicInputs {
        old_commitment_root: old_root,
        new_commitment_root: new_root,
        nullifier,
        sender_new_commitment,
        recipient_new_commitment,
    };

    // Compute prover_id matching ConfidentialProver's convention
    let prover_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-confidential-prover-v1");
        hasher.update(COMMITMENT_TREE_DEPTH.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hash
    };

    let transfer_proof = ConfidentialTransferProof {
        public_inputs: public_inputs.clone(),
        proof: proof_bytes.clone(),
        prover_id,
    };

    let valid = verifier.verify(&transfer_proof).map_err(|e| {
        warn!(error = %e, "Proof verification failed");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid proof: {}", e)})),
        )
    })?;

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Proof verification returned false"})),
        ));
    }

    // Step 4: Write-lock tree, re-check root (TOCTOU), apply update
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let computed_new_root;
    {
        let mut tree = state.commitment_tree.write();

        // Re-check root under write lock
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != old_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root (concurrent update)",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }

        // Re-check nullifier under write lock
        if tree.is_nullifier_spent(&nullifier) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Nullifier already spent (concurrent spend)"})),
            ));
        }

        // Apply: insert new commitments and record nullifier
        tree.insert(req.sender_index, sender_new_commitment);
        tree.insert(req.recipient_index, recipient_new_commitment);
        tree.spend_nullifier(nullifier);

        // Verify computed root matches expected
        computed_new_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute new tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if computed_new_root != new_root {
            // Rollback: this should not happen if proof is valid — indicates bug
            error!(
                expected = %hex::encode(new_root),
                computed = %hex::encode(computed_new_root),
                "New root mismatch after applying transfer"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Root mismatch after applying transfer"})),
            ));
        }
    }

    // Step 5: Persist to DB
    let current_height = state.rpc.get_block_count().await.unwrap_or(0);

    // Insert notes
    if let Err(e) = state.db.insert_confidential_note(
        req.sender_index,
        &sender_new_commitment,
        &[0u8; 32], // Sender's pubkey not known from transfer; updated by owner
        current_height,
    ) {
        warn!(error = %e, "Failed to persist sender note");
    }
    if let Err(e) = state.db.insert_confidential_note(
        req.recipient_index,
        &recipient_new_commitment,
        &recipient_owner_pubkey,
        current_height,
    ) {
        warn!(error = %e, "Failed to persist recipient note");
    }

    // Insert nullifier
    if let Err(e) = state
        .db
        .insert_nullifier(&nullifier, current_height, &transfer_id)
    {
        warn!(error = %e, "Failed to persist nullifier");
    }

    // Insert transfer record
    let record = ConfidentialTransferRecord {
        transfer_id: transfer_id.clone(),
        block_height: Some(current_height),
        nullifier,
        sender_new_commitment,
        recipient_new_commitment,
        old_commitment_root: old_root,
        new_commitment_root: new_root,
        proof: proof_bytes,
        sender_index: req.sender_index,
        recipient_index: req.recipient_index,
        status: "confirmed".to_string(),
    };
    if let Err(e) = state.db.insert_confidential_transfer(&record) {
        warn!(error = %e, "Failed to persist transfer record");
    }

    info!(
        transfer_id = %transfer_id,
        sender_idx = req.sender_index,
        recipient_idx = req.recipient_index,
        "Confidential transfer applied"
    );

    Ok(Json(serde_json::json!({
        "transfer_id": transfer_id,
        "new_commitment_root": hex::encode(computed_new_root),
        "sender_index": req.sender_index,
        "recipient_index": req.recipient_index,
    })))
}

/// Request body for shielding plaintext balance into a commitment
#[derive(Debug, Deserialize)]
struct ShieldBalanceRequest {
    amount_sats: u64,
    blinding_hex: String,
    owner_pubkey: String,
}

/// Shield plaintext balance into a confidential commitment
async fn shield_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ShieldBalanceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let owner_pubkey = parse_hex_32(&req.owner_pubkey).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid owner_pubkey hex (need 32 bytes)"})),
        )
    })?;
    let blinding = parse_hex_32(&req.blinding_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid blinding hex (need 32 bytes)"})),
        )
    })?;

    if req.amount_sats == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Amount must be > 0"})),
        ));
    }

    // Compute commitment: C = MiMC(MiMC(value, blinding), domain_sep)
    let commitment =
        ghost_zkp::compute_commitment_bytes(req.amount_sats, &blinding).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid blinding: {}", e)})),
            )
        })?;

    // Get next index and insert into tree + DB
    let note_index;
    let new_root;
    {
        let mut tree = state.commitment_tree.write();
        note_index = tree.next_index();
        tree.insert(note_index, commitment);
        new_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root after shield");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
    }

    // Persist
    let current_height = state.rpc.get_block_count().await.unwrap_or(0);
    if let Err(e) =
        state
            .db
            .insert_confidential_note(note_index, &commitment, &owner_pubkey, current_height)
    {
        warn!(error = %e, "Failed to persist shielded note");
    }

    info!(
        note_index = note_index,
        amount = req.amount_sats,
        "Balance shielded into commitment"
    );

    Ok(Json(serde_json::json!({
        "note_index": note_index,
        "commitment": hex::encode(commitment),
        "new_root": hex::encode(new_root),
    })))
}

/// Get commitment tree state
async fn get_tree_state(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let tree = state.commitment_tree.read();
    let root = tree.root().unwrap_or([0u8; 32]);
    let nullifier_count = tree.nullifier_count();

    Json(serde_json::json!({
        "root": hex::encode(root),
        "note_count": tree.note_count(),
        "next_index": tree.next_index(),
        "tree_depth": 20,
        "nullifier_count": nullifier_count,
    }))
}

/// Get confidential notes for an owner
async fn get_confidential_notes(
    State(state): State<Arc<AppState>>,
    Path(owner_pubkey_hex): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let owner_pubkey = parse_hex_32(&owner_pubkey_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    let notes = state.db.get_notes_for_owner(&owner_pubkey).map_err(|e| {
        error!(error = %e, "Failed to query notes");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let notes_json: Vec<serde_json::Value> = notes
        .iter()
        .map(|n| {
            serde_json::json!({
                "index": n.tree_index,
                "commitment": hex::encode(n.commitment),
                "created_height": n.created_at_height,
                "spent": n.spent_at_height.is_some(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "owner": owner_pubkey_hex,
        "notes": notes_json,
    })))
}

// ============================================================================
// Background Tasks
// ============================================================================

/// Background payment scanner
async fn run_scanner(state: Arc<AppState>, mut rx: mpsc::Receiver<ScanRequest>) {
    use bitcoin::secp256k1::PublicKey;
    use tracing::{debug, error, warn};

    info!("Starting background payment scanner");

    while let Some(req) = rx.recv().await {
        // Clone the Arc to release lock before await (Arc clone, not key clone)
        let keys = {
            let keys_guard = state.keys.read();
            match keys_guard.as_ref() {
                Some(k) => Arc::clone(k),
                None => {
                    debug!("No keys loaded, skipping scan");
                    continue;
                }
            }
        };

        info!(txid = %req.txid, vout = req.vout, "Scanning transaction");

        // Fetch the raw transaction from Bitcoin Core
        let tx_result = state.rpc.get_raw_transaction(&req.txid, true).await;
        let tx_json = match tx_result {
            Ok(json) => json,
            Err(e) => {
                warn!(txid = %req.txid, error = %e, "Failed to fetch transaction");
                continue;
            }
        };

        // Parse transaction outputs
        let vout_array = match tx_json.get("vout").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                warn!(txid = %req.txid, "No vout array in transaction");
                continue;
            }
        };

        // Look for ephemeral pubkey in OP_RETURN output (Ghost Pay protocol)
        // Format: OP_RETURN <33-byte ephemeral pubkey>
        let mut ephemeral_pubkey: Option<PublicKey> = None;
        let mut outputs: Vec<(PublicKey, Option<u64>)> = Vec::new();

        for vout in vout_array.iter() {
            let value_btc = vout.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
            // SECURITY: Use round() to prevent precision loss from f64 representation
            // Bitcoin Core RPC returns BTC as f64, this is the standard conversion approach
            let value_sats = (value_btc * SATS_PER_BTC_F64).round() as u64;

            // Get scriptPubKey hex
            let script_hex = vout
                .get("scriptPubKey")
                .and_then(|s| s.get("hex"))
                .and_then(|h| h.as_str())
                .unwrap_or("");

            let script_bytes = match hex::decode(script_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Check for OP_RETURN with ephemeral pubkey (6a21 = OP_RETURN PUSH33)
            if script_bytes.len() == 35 && script_bytes[0] == 0x6a && script_bytes[1] == 0x21 {
                if let Ok(pubkey) = PublicKey::from_slice(&script_bytes[2..35]) {
                    ephemeral_pubkey = Some(pubkey);
                    debug!("Found ephemeral pubkey in OP_RETURN");
                }
                continue;
            }

            // Check for P2TR output (5120 = OP_1 PUSH32)
            if script_bytes.len() == 34 && script_bytes[0] == 0x51 && script_bytes[1] == 0x20 {
                // For P2TR, we need to convert x-only key to full pubkey.
                // P2TR only stores the 32-byte x-coordinate, so we must try both
                // Y coordinate parities (even=0x02, odd=0x03) since we don't know
                // which was used. Add both to outputs for the scanner to check.
                let mut full_key_even = vec![0x02]; // Even Y
                full_key_even.extend_from_slice(&script_bytes[2..34]);
                if let Ok(pubkey) = PublicKey::from_slice(&full_key_even) {
                    outputs.push((pubkey, Some(value_sats)));
                }

                let mut full_key_odd = vec![0x03]; // Odd Y
                full_key_odd.extend_from_slice(&script_bytes[2..34]);
                if let Ok(pubkey) = PublicKey::from_slice(&full_key_odd) {
                    outputs.push((pubkey, Some(value_sats)));
                }
            }
        }

        // If we have both ephemeral pubkey and outputs, scan for payments
        if let Some(ephemeral) = ephemeral_pubkey {
            if outputs.is_empty() {
                debug!(txid = %req.txid, "No P2TR outputs to scan");
                continue;
            }

            let detector = PaymentDetector::new(&keys);
            let found_payments = detector.scan_transaction(&ephemeral, &outputs);

            if found_payments.is_empty() {
                debug!(txid = %req.txid, "No payments found for our keys");
                continue;
            }

            info!(
                txid = %req.txid,
                count = found_payments.len(),
                "Detected payments to our ghost keys"
            );

            // Process found payments
            let ghost_id = state.ghost_id.read().clone();
            for payment in found_payments {
                let amount = payment.amount.unwrap_or(0);
                info!(
                    txid = %req.txid,
                    vout = payment.output_index,
                    amount = amount,
                    "Payment detected"
                );

                // Update lock funding if this matches a pending lock
                if let Some(ref gid) = ghost_id {
                    // Find pending lock that matches this amount
                    if let Ok(locks) = state.db.get_ghost_locks_by_owner(gid) {
                        for lock in locks {
                            if lock.state == DbLockState::Pending && lock.amount_sats == amount {
                                if let Err(e) = state.db.update_ghost_lock_funding(
                                    &lock.lock_id,
                                    &req.txid,
                                    payment.output_index,
                                ) {
                                    error!(error = %e, "Failed to update lock funding");
                                } else {
                                    info!(
                                        lock_id = %lock.lock_id,
                                        txid = %req.txid,
                                        vout = payment.output_index,
                                        "Lock funded"
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            debug!(txid = %req.txid, "No ephemeral pubkey found in transaction");
        }
    }
}

/// Wraith session coordinator
///
/// Manages the lifecycle of Wraith mixing sessions:
/// 1. Waits for minimum participants
/// 2. Executes Phase 1 (split transaction)
/// 3. Waits for Phase 1 confirmation
/// 4. Executes Phase 2 (merge transaction)
/// 5. Completes the session
async fn run_session_coordinator(state: Arc<AppState>) {
    use tracing::{debug, error};

    info!("Starting Wraith session coordinator");

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Get session IDs and their current states to avoid holding lock during async work
        let session_states: Vec<(String, String)> = {
            let sessions = state.sessions.read();
            sessions
                .iter()
                .map(|s| (s.id.clone(), s.state.clone()))
                .collect()
        };

        for (session_id, session_state) in session_states {
            match session_state.as_str() {
                "waiting" => {
                    // Check if we have enough participants
                    let mut sessions = state.sessions.write();
                    if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
                        let tier = match session.tier.as_str() {
                            "micro" | "express" | "quick" => ParticipantTier::Micro,
                            "small" => ParticipantTier::Small,
                            "medium" => ParticipantTier::Medium,
                            "standard" => ParticipantTier::Standard,
                            "large" => ParticipantTier::Large,
                            "whale" => ParticipantTier::Whale,
                            _ => continue,
                        };

                        if session.participants >= tier.min_participants() {
                            session.state = "building_phase1".to_string();
                            info!(id = %session.id, participants = session.participants, "Session ready, building Phase 1");
                        }
                    }
                }

                "building_phase1" => {
                    // Build Phase 1 - get tx_hex first, then release lock before broadcast
                    let tx_hex = {
                        let mut coordinators = state.coordinators.write();
                        if let Some(coordinator) = coordinators.get_mut(&session_id) {
                            match coordinator.build_phase1() {
                                Ok(split_tx) => {
                                    let hex = bitcoin::consensus::encode::serialize_hex(
                                        &split_tx.transaction,
                                    );
                                    info!(
                                        session_id = %session_id,
                                        outputs = split_tx.intermediate_count,
                                        "Phase 1 transaction built"
                                    );
                                    Some(hex)
                                }
                                Err(e) => {
                                    error!(
                                        session_id = %session_id,
                                        error = %e,
                                        "Failed to build Phase 1"
                                    );
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    };

                    // Broadcast Phase 1 (lock released)
                    if let Some(tx_hex) = tx_hex {
                        match state.rpc.send_raw_transaction(&tx_hex).await {
                            Ok(txid) => {
                                info!(
                                    session_id = %session_id,
                                    txid = %txid,
                                    "Phase 1 broadcast successful"
                                );

                                // Reacquire lock to update coordinator
                                let mut coordinators = state.coordinators.write();
                                if let Some(coordinator) = coordinators.get_mut(&session_id) {
                                    if let Err(e) = coordinator.broadcast_phase1(&txid) {
                                        error!(error = %e, "Failed to update coordinator after broadcast");
                                    }
                                }
                                drop(coordinators);

                                // Update session state
                                let mut sessions = state.sessions.write();
                                if let Some(session) =
                                    sessions.iter_mut().find(|s| s.id == session_id)
                                {
                                    session.state = "confirming_phase1".to_string();
                                }
                            }
                            Err(e) => {
                                error!(
                                    session_id = %session_id,
                                    error = %e,
                                    "Phase 1 broadcast failed"
                                );
                                // Mark session as failed
                                let mut sessions = state.sessions.write();
                                if let Some(session) =
                                    sessions.iter_mut().find(|s| s.id == session_id)
                                {
                                    session.state = "failed".to_string();
                                }
                            }
                        }
                    }
                }

                "confirming_phase1" => {
                    // Check if Phase 1 is confirmed on-chain
                    const REQUIRED_CONFIRMATIONS: u32 = 1; // 1 confirmation for mixing

                    // Get phase 1 txid
                    let phase1_txid = {
                        let coordinators = state.coordinators.read();
                        coordinators.get(&session_id).and_then(|c| c.phase1_txid())
                    };

                    if let Some(txid) = phase1_txid {
                        // Check transaction confirmations via RPC
                        match state.rpc.get_raw_transaction(&txid.to_string(), true).await {
                            Ok(tx_info) => {
                                let confirmations = tx_info
                                    .get("confirmations")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0);
                                if confirmations >= REQUIRED_CONFIRMATIONS as i64 {
                                    // Get the block height where it was confirmed
                                    // H-21: Safe block height conversion with bounds checking
                                    let raw_height = tx_info
                                        .get("blockheight")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let confirm_height = match safe_block_height_u64(raw_height) {
                                        Ok(h) => h,
                                        Err(e) => {
                                            warn!(error = %e, "Invalid block height, skipping confirmation");
                                            continue;
                                        }
                                    };

                                    // Confirm phase 1
                                    let mut coordinators = state.coordinators.write();
                                    if let Some(coordinator) = coordinators.get_mut(&session_id) {
                                        if let Err(e) = coordinator.confirm_phase1(confirm_height) {
                                            warn!(error = %e, "Failed to confirm phase 1");
                                        } else {
                                            info!(
                                                session_id = %session_id,
                                                txid = %txid,
                                                confirmations = confirmations,
                                                "Phase 1 confirmed on-chain"
                                            );

                                            // Update session state
                                            drop(coordinators);
                                            let mut sessions = state.sessions.write();
                                            if let Some(session) =
                                                sessions.iter_mut().find(|s| s.id == session_id)
                                            {
                                                session.state = "building_phase2".to_string();
                                            }
                                        }
                                    }
                                } else {
                                    debug!(
                                        session_id = %session_id,
                                        txid = %txid,
                                        confirmations = confirmations,
                                        required = REQUIRED_CONFIRMATIONS,
                                        "Waiting for more confirmations"
                                    );
                                }
                            }
                            Err(e) => {
                                // Transaction might not be indexed yet
                                debug!(
                                    session_id = %session_id,
                                    txid = %txid,
                                    error = %e,
                                    "Cannot get phase 1 tx info"
                                );
                            }
                        }
                    } else {
                        // No txid yet, phase 1 not broadcast
                        debug!(session_id = %session_id, "Phase 1 not yet broadcast");
                    }
                }

                "building_phase2" => {
                    // Build Phase 2 - get tx_hex first, then release lock
                    let tx_hex = {
                        let mut coordinators = state.coordinators.write();
                        if let Some(coordinator) = coordinators.get_mut(&session_id) {
                            match coordinator.build_phase2() {
                                Ok(merge_tx) => {
                                    let hex = bitcoin::consensus::encode::serialize_hex(
                                        &merge_tx.transaction,
                                    );
                                    info!(
                                        session_id = %session_id,
                                        participants = merge_tx.participant_count,
                                        "Phase 2 transaction built"
                                    );
                                    Some(hex)
                                }
                                Err(e) => {
                                    error!(
                                        session_id = %session_id,
                                        error = %e,
                                        "Failed to build Phase 2"
                                    );
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    };

                    // Broadcast Phase 2 (lock released)
                    if let Some(tx_hex) = tx_hex {
                        match state.rpc.send_raw_transaction(&tx_hex).await {
                            Ok(txid) => {
                                info!(
                                    session_id = %session_id,
                                    txid = %txid,
                                    "Phase 2 broadcast successful"
                                );

                                // Reacquire lock to update coordinator
                                let mut coordinators = state.coordinators.write();
                                if let Some(coordinator) = coordinators.get_mut(&session_id) {
                                    if let Err(e) = coordinator.broadcast_phase2(&txid) {
                                        error!(error = %e, "Failed to update coordinator after Phase 2 broadcast");
                                    }
                                }
                                drop(coordinators);

                                // Update session state
                                let mut sessions = state.sessions.write();
                                if let Some(session) =
                                    sessions.iter_mut().find(|s| s.id == session_id)
                                {
                                    session.state = "confirming_phase2".to_string();
                                }
                            }
                            Err(e) => {
                                error!(
                                    session_id = %session_id,
                                    error = %e,
                                    "Phase 2 broadcast failed"
                                );
                                let mut sessions = state.sessions.write();
                                if let Some(session) =
                                    sessions.iter_mut().find(|s| s.id == session_id)
                                {
                                    session.state = "failed".to_string();
                                }
                            }
                        }
                    }
                }

                "confirming_phase2" => {
                    // Check if Phase 2 is already complete
                    let is_complete = {
                        let coordinators = state.coordinators.read();
                        coordinators
                            .get(&session_id)
                            .map(|c| matches!(c.state(), wraith_protocol::SessionState::Completed))
                            .unwrap_or(false)
                    };

                    if is_complete {
                        let mut sessions = state.sessions.write();
                        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
                            session.state = "complete".to_string();
                            info!(id = %session_id, "Wraith session complete");
                        }
                    } else {
                        // Get Phase 2 txid and check on-chain confirmations
                        let phase2_txid = {
                            let coordinators = state.coordinators.read();
                            coordinators.get(&session_id).and_then(|c| c.phase2_txid())
                        };

                        if let Some(txid) = phase2_txid {
                            const REQUIRED_CONFIRMATIONS: u32 = 1;

                            match state.rpc.get_raw_transaction(&txid.to_string(), true).await {
                                Ok(tx_info) => {
                                    let confirmations = tx_info
                                        .get("confirmations")
                                        .and_then(|v| v.as_i64())
                                        .unwrap_or(0);

                                    if confirmations >= REQUIRED_CONFIRMATIONS as i64 {
                                        // H-21: Safe block height conversion with bounds checking
                                        let raw_height = tx_info
                                            .get("blockheight")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let confirm_height = match safe_block_height_u64(raw_height)
                                        {
                                            Ok(h) => h,
                                            Err(e) => {
                                                warn!(error = %e, "Invalid block height, skipping phase 2 confirmation");
                                                continue;
                                            }
                                        };

                                        let mut coordinators = state.coordinators.write();
                                        if let Some(coordinator) = coordinators.get_mut(&session_id)
                                        {
                                            if let Err(e) =
                                                coordinator.confirm_phase2(confirm_height)
                                            {
                                                warn!(error = %e, "Failed to confirm phase 2");
                                            } else {
                                                info!(
                                                    session_id = %session_id,
                                                    txid = %txid,
                                                    confirmations = confirmations,
                                                    "Phase 2 confirmed on-chain"
                                                );
                                            }
                                        }
                                    } else {
                                        debug!(
                                            session_id = %session_id,
                                            txid = %txid,
                                            confirmations = confirmations,
                                            required = REQUIRED_CONFIRMATIONS,
                                            "Waiting for Phase 2 confirmations"
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        session_id = %session_id,
                                        txid = %txid,
                                        error = %e,
                                        "Cannot get phase 2 tx info"
                                    );
                                }
                            }
                        }
                    }
                }

                "complete" | "failed" => {
                    // Clean up completed/failed sessions after some time
                    debug!(session_id = %session_id, state = %session_state, "Session finished");
                }

                _ => {
                    debug!(session_id = %session_id, state = %session_state, "Unknown session state");
                }
            }
        }
    }
}

/// L1 Settlement loop - reconciles L2 balances to Bitcoin L1
///
/// This background task periodically:
/// 1. Checks for pending withdrawal requests
/// 2. Validates locks have sufficient funds
/// 3. Batches settlements according to rules
/// 4. Broadcasts settlement transactions to L1
/// 5. Updates withdrawal and lock states based on confirmations
async fn run_settlement_loop(state: Arc<AppState>) {
    use tracing::{debug, error, warn};

    info!("Starting L1 settlement loop");

    // Settlement check interval (5 minutes)
    let check_interval = std::time::Duration::from_secs(300);

    // Fix 5: Track failed broadcast attempts per lock_id for exponential backoff
    // Maps lock_id -> (attempt_count, last_attempt_time)
    let mut retry_tracker: std::collections::HashMap<String, (u32, std::time::Instant)> =
        std::collections::HashMap::new();

    // Create batch executor with treasury address from config
    // Note: Settlement loop only starts if treasury_address is configured (checked in main)
    let treasury_address = state.config.treasury_address.clone().unwrap_or_default();
    let mut executor = BatchExecutor::new(state.network, treasury_address);

    // Track processed withdrawal IDs for current batch
    let mut processed_withdrawal_ids: Vec<i64> = Vec::new();

    loop {
        tokio::time::sleep(check_interval).await;

        // Fix 5: Clean stale retry entries (>24 hours old) to prevent memory growth
        retry_tracker.retain(|_, (_, last_try)| last_try.elapsed().as_secs() < 86400);

        // Get ghost_id
        let ghost_id = match state.ghost_id.read().clone() {
            Some(id) => id,
            None => {
                debug!("No ghost keys loaded, skipping settlement check");
                continue;
            }
        };

        // H-PAY-1 FIX: Check for stale PendingSettlement locks and revert them to Active
        // Locks stuck in PendingSettlement for > 24 hours are reverted (broadcast likely failed)
        const STALE_SETTLEMENT_TIMEOUT_SECS: i64 = 24 * 60 * 60; // 24 hours
        if let Ok(db_locks) = state.db.get_ghost_locks_by_owner(&ghost_id) {
            let now = chrono::Utc::now().timestamp();
            for lock in db_locks {
                if lock.state == DbLockState::PendingSettlement {
                    let age_secs = now - lock.updated_at;
                    if age_secs > STALE_SETTLEMENT_TIMEOUT_SECS {
                        warn!(
                            lock_id = %lock.lock_id,
                            age_hours = age_secs / 3600,
                            "Reverting stale PendingSettlement lock to Active"
                        );
                        if let Err(e) = state
                            .db
                            .update_ghost_lock_state(&lock.lock_id, DbLockState::Active)
                        {
                            error!(
                                lock_id = %lock.lock_id,
                                error = %e,
                                "Failed to revert stale lock to Active"
                            );
                        }
                    }
                }
            }
        }

        // Estimate fee rate from recent network activity
        // In production, this would call Bitcoin Core's estimatesmartfee RPC
        let fee_rate = estimate_fee_rate(&state).await;
        debug!(fee_rate = fee_rate, "Using estimated fee rate");

        // Get pending withdrawal requests
        let pending_withdrawals: Vec<WithdrawalRequest> =
            match state.db.get_pending_withdrawals(&ghost_id) {
                Ok(requests) => requests,
                Err(e) => {
                    warn!(error = %e, "Failed to get pending withdrawals");
                    continue;
                }
            };

        if pending_withdrawals.is_empty() {
            debug!("No pending withdrawal requests");
            continue;
        }

        info!(
            count = pending_withdrawals.len(),
            "Processing pending withdrawal requests"
        );

        // Clear processed list for new batch
        processed_withdrawal_ids.clear();

        // Process each withdrawal request
        for withdrawal in &pending_withdrawals {
            // Get the associated lock
            let lock = match state.db.get_ghost_lock(&withdrawal.lock_id) {
                Ok(Some(l)) => l,
                Ok(None) => {
                    warn!(lock_id = %withdrawal.lock_id, "Lock not found for withdrawal");
                    continue;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to get lock");
                    continue;
                }
            };

            // Verify lock is funded and active
            if lock.state != DbLockState::Active || lock.funding_txid.is_none() {
                warn!(
                    lock_id = %lock.lock_id,
                    state = ?lock.state,
                    "Lock not ready for settlement"
                );
                continue;
            }

            // Fix 5: Check if lock is in cooldown from a previous failed broadcast
            if let Some(&(attempts, last_try)) = retry_tracker.get(&lock.lock_id) {
                let backoff_secs =
                    std::cmp::min(300u64.saturating_mul(2u64.saturating_pow(attempts)), 7200);
                if last_try.elapsed().as_secs() < backoff_secs {
                    debug!(
                        lock_id = %lock.lock_id,
                        attempts = attempts,
                        backoff_secs = backoff_secs,
                        "Lock in cooldown after failed broadcast, skipping"
                    );
                    continue;
                }
            }

            // Get funding info
            let (txid, vout) = match (lock.funding_txid.as_ref(), lock.funding_vout) {
                (Some(txid_str), Some(vout)) => {
                    let txid: bitcoin::Txid = match txid_str.parse() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    (txid, vout)
                }
                _ => continue,
            };

            // Fix 4: Verify UTXO exists on-chain before including in settlement
            match state.rpc.get_tx_out(&txid.to_string(), vout, false).await {
                Ok(Some(_)) => { /* UTXO exists, proceed */ }
                Ok(None) => {
                    warn!(
                        lock_id = %lock.lock_id,
                        txid = %txid,
                        vout = vout,
                        "UTXO not found on-chain, skipping settlement"
                    );
                    if let Err(e) = state
                        .db
                        .update_ghost_lock_state(&lock.lock_id, DbLockState::Spent)
                    {
                        error!(
                            lock_id = %lock.lock_id,
                            error = %e,
                            "Failed to mark lock as spent"
                        );
                    }
                    continue;
                }
                Err(e) => {
                    warn!(
                        lock_id = %lock.lock_id,
                        error = %e,
                        "Failed to verify UTXO existence, skipping this withdrawal"
                    );
                    continue;
                }
            }

            // Create settlement input
            let input = ReconciliationInput {
                txid,
                vout,
                amount: lock.amount_sats,
                ghost_id: lock.owner_ghost_id.clone(),
                lock_id: Some(hex_to_32bytes(&lock.lock_id)),
            };

            executor.add_input(input);

            // Create settlement from withdrawal request
            let source_lock_id = hex_to_32bytes(&lock.lock_id);
            let settlement = match Settlement::new(
                withdrawal.ghost_id.clone(),
                source_lock_id,
                withdrawal.destination_address.clone(),
                withdrawal.amount_sats,
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        withdrawal_id = ?withdrawal.id,
                        error = %e,
                        "Failed to create settlement"
                    );
                    continue;
                }
            };

            // SECURITY: Ownership was already verified when the withdrawal request was
            // submitted to the L2 system. The Ghost Pay backend only processes withdrawals
            // that were authenticated by the user's Ghost Key signature at request time.
            #[allow(deprecated)]
            if let Err(e) = executor.add_settlement(settlement) {
                warn!(
                    withdrawal_id = ?withdrawal.id,
                    error = %e,
                    "Failed to add settlement"
                );
                continue;
            }

            // Track this withdrawal for batch update
            if let Some(id) = withdrawal.id {
                processed_withdrawal_ids.push(id);
            }
        }

        // Check if we should form a batch
        if executor.should_form_batch() {
            info!("Forming settlement batch");

            match executor.form_batch() {
                Ok(batch) => {
                    let batch_id = batch.id_hex();
                    info!(batch_id = %batch_id, "Formed settlement batch");

                    // Build the batch transaction with estimated fee rate
                    match executor.build_transaction(&batch, fee_rate) {
                        Ok(batch_tx) => {
                            let txid = batch_tx.txid();

                            // Update withdrawal requests to batched status
                            for withdrawal_id in &processed_withdrawal_ids {
                                if let Err(e) = state
                                    .db
                                    .update_withdrawal_batched(*withdrawal_id, &batch_id)
                                {
                                    error!(
                                        withdrawal_id = withdrawal_id,
                                        error = %e,
                                        "Failed to update withdrawal status"
                                    );
                                }
                            }

                            // H-PAY-1 FIX: Mark associated locks as PendingSettlement BEFORE broadcast
                            // This prevents double-spend if broadcast succeeds but we crash before
                            // updating state. Safe to revert to Active if broadcast fails.
                            for withdrawal in &pending_withdrawals {
                                if processed_withdrawal_ids.contains(&withdrawal.id.unwrap_or(-1)) {
                                    if let Err(e) = state.db.update_ghost_lock_state(
                                        &withdrawal.lock_id,
                                        DbLockState::PendingSettlement,
                                    ) {
                                        error!(
                                            lock_id = %withdrawal.lock_id,
                                            error = %e,
                                            "Failed to update lock state to PendingSettlement"
                                        );
                                    }
                                }
                            }

                            // Fix 3: Sign each input using the lock owner's keys
                            let secp = Secp256k1::new();
                            let sign_result: Result<bitcoin::Transaction, String> = (|| {
                                let keys_guard = state.keys.read();
                                let keys = keys_guard
                                    .as_ref()
                                    .ok_or("No ghost keys loaded for settlement signing")?;

                                let mut signed_tx = batch_tx.transaction.clone();
                                let mut input_idx = 0usize;

                                for withdrawal in &pending_withdrawals {
                                    if !processed_withdrawal_ids
                                        .contains(&withdrawal.id.unwrap_or(-1))
                                    {
                                        continue;
                                    }

                                    // Get lock record for pubkeys and timelock info
                                    let lock = state
                                        .db
                                        .get_ghost_lock(&withdrawal.lock_id)
                                        .map_err(|e| format!("DB error: {}", e))?
                                        .ok_or_else(|| {
                                            format!("Lock {} not found", withdrawal.lock_id)
                                        })?;

                                    // Get derivation index for this lock
                                    let lock_index = state
                                        .db
                                        .get_lock_index_for_owner(
                                            &lock.owner_ghost_id,
                                            &lock.lock_id,
                                        )
                                        .map_err(|e| format!("Failed to get lock index: {}", e))?;

                                    // Derive the lock secret key
                                    let lock_secret = keys
                                        .derive_lock_secret(lock_index)
                                        .map_err(|e| format!("Key derivation error: {:?}", e))?;

                                    // Parse stored pubkeys from hex
                                    let lock_pubkey_bytes = hex::decode(&lock.lock_pubkey)
                                        .map_err(|e| format!("Invalid lock_pubkey hex: {}", e))?;
                                    let lock_pubkey = bitcoin::secp256k1::PublicKey::from_slice(
                                        &lock_pubkey_bytes,
                                    )
                                    .map_err(|e| format!("Invalid lock_pubkey: {}", e))?;
                                    let recovery_pubkey_bytes = hex::decode(&lock.recovery_pubkey)
                                        .map_err(|e| {
                                            format!("Invalid recovery_pubkey hex: {}", e)
                                        })?;
                                    let recovery_pubkey =
                                        bitcoin::secp256k1::PublicKey::from_slice(
                                            &recovery_pubkey_bytes,
                                        )
                                        .map_err(|e| format!("Invalid recovery_pubkey: {}", e))?;

                                    // Verify derived key matches stored key
                                    let derived_pubkey =
                                        bitcoin::secp256k1::PublicKey::from_secret_key(
                                            &secp,
                                            &lock_secret,
                                        );
                                    if derived_pubkey != lock_pubkey {
                                        return Err(format!(
                                            "Derived pubkey mismatch for lock {} at index {}",
                                            lock.lock_id, lock_index
                                        ));
                                    }

                                    // Compute recovery_blocks from stored heights
                                    let recovery_blocks =
                                        lock.recovery_height.saturating_sub(lock.creation_height);

                                    // Reconstruct witness script
                                    let witness_script = ghost_locks::build_wsh_witness_script(
                                        &lock_pubkey,
                                        &recovery_pubkey,
                                        recovery_blocks,
                                    )
                                    .map_err(|e| format!("Witness script error: {}", e))?;

                                    // Compute P2WSH sighash
                                    let sighash = {
                                        let mut cache =
                                            bitcoin::sighash::SighashCache::new(&signed_tx);
                                        cache
                                            .p2wsh_signature_hash(
                                                input_idx,
                                                &witness_script,
                                                bitcoin::Amount::from_sat(lock.amount_sats),
                                                bitcoin::EcdsaSighashType::All,
                                            )
                                            .map_err(|e| format!("Sighash error: {}", e))?
                                    };

                                    // Sign with ECDSA (P2WSH uses ECDSA, not Schnorr)
                                    let sighash_bytes: [u8; 32] = sighash[..]
                                        .try_into()
                                        .map_err(|_| "Sighash not 32 bytes".to_string())?;
                                    let msg =
                                        bitcoin::secp256k1::Message::from_digest(sighash_bytes);
                                    let sig = secp.sign_ecdsa(&msg, &lock_secret);

                                    // Build DER signature with SIGHASH_ALL byte
                                    let mut sig_bytes = sig.serialize_der().to_vec();
                                    sig_bytes.push(0x01); // SIGHASH_ALL

                                    // Build witness: [signature, 0x01 (IF branch), witness_script]
                                    let witness_vec = ghost_locks::build_normal_witness(
                                        &sig_bytes,
                                        &witness_script,
                                    );
                                    signed_tx.input[input_idx].witness =
                                        bitcoin::Witness::from_slice(&witness_vec);

                                    input_idx += 1;
                                }

                                Ok(signed_tx)
                            })(
                            );

                            let signed_tx = match sign_result {
                                Ok(tx) => tx,
                                Err(e) => {
                                    error!(
                                        batch_id = %batch_id,
                                        error = %e,
                                        "Settlement transaction signing failed"
                                    );
                                    // Revert lock states on signing failure
                                    for withdrawal in &pending_withdrawals {
                                        if processed_withdrawal_ids
                                            .contains(&withdrawal.id.unwrap_or(-1))
                                        {
                                            let _ = state.db.update_ghost_lock_state(
                                                &withdrawal.lock_id,
                                                DbLockState::Active,
                                            );
                                        }
                                    }
                                    continue;
                                }
                            };

                            // Serialize signed transaction and broadcast via Bitcoin Core RPC
                            let tx_hex = bitcoin::consensus::encode::serialize_hex(&signed_tx);

                            match state.rpc.send_raw_transaction(&tx_hex).await {
                                Ok(broadcast_txid) => {
                                    info!(
                                        batch_id = %batch_id,
                                        txid = %broadcast_txid,
                                        total_sats = batch_tx.total_input_sats,
                                        outputs = batch_tx.settlement_count(),
                                        fee = batch_tx.mining_fee,
                                        "Settlement batch broadcast successful"
                                    );

                                    // Update executor state with confirmed txid
                                    let confirmed_txid: bitcoin::Txid =
                                        broadcast_txid.parse().unwrap_or(txid);
                                    if let Err(e) =
                                        executor.mark_submitted(&batch_id, confirmed_txid)
                                    {
                                        error!(error = %e, "Failed to mark batch as submitted");
                                    }

                                    // Update withdrawals to submitted status
                                    for withdrawal_id in &processed_withdrawal_ids {
                                        if let Err(e) = state.db.update_withdrawal_submitted(
                                            *withdrawal_id,
                                            &broadcast_txid,
                                        ) {
                                            error!(
                                                withdrawal_id = withdrawal_id,
                                                error = %e,
                                                "Failed to update withdrawal to submitted"
                                            );
                                        }
                                    }

                                    // Fix 5: Clear retry tracker on success
                                    for withdrawal in &pending_withdrawals {
                                        if processed_withdrawal_ids
                                            .contains(&withdrawal.id.unwrap_or(-1))
                                        {
                                            retry_tracker.remove(&withdrawal.lock_id);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        batch_id = %batch_id,
                                        error = %e,
                                        "Settlement batch broadcast failed"
                                    );

                                    // Revert lock states back to Active on broadcast failure
                                    for withdrawal in &pending_withdrawals {
                                        if processed_withdrawal_ids
                                            .contains(&withdrawal.id.unwrap_or(-1))
                                        {
                                            if let Err(revert_err) =
                                                state.db.update_ghost_lock_state(
                                                    &withdrawal.lock_id,
                                                    DbLockState::Active,
                                                )
                                            {
                                                error!(
                                                    lock_id = %withdrawal.lock_id,
                                                    error = %revert_err,
                                                    "Failed to revert lock state after broadcast failure"
                                                );
                                            }

                                            // Fix 5: Increment retry count with exponential backoff
                                            let entry = retry_tracker
                                                .entry(withdrawal.lock_id.clone())
                                                .or_insert((0, std::time::Instant::now()));
                                            entry.0 += 1;
                                            entry.1 = std::time::Instant::now();
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to build batch transaction");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to form batch");
                }
            }
        }

        // Check current batch for confirmations
        if let Some(batch) = executor.current_batch() {
            let batch_id = batch.id_hex();
            let txid = batch.l1_txid();

            if let Some(txid_str) = txid {
                // Check transaction confirmations via RPC
                match state.rpc.get_raw_transaction(txid_str, true).await {
                    Ok(tx_json) => {
                        // Check for confirmations field
                        if let Some(confirmations) =
                            tx_json.get("confirmations").and_then(|c| c.as_u64())
                        {
                            debug!(
                                batch_id = %batch_id,
                                txid = %txid_str,
                                confirmations = confirmations,
                                "Checking settlement confirmations"
                            );

                            // Require 6 confirmations for finalization (or 1 for testnet/regtest)
                            let required_confirmations = match state.network {
                                Network::Bitcoin => 6,
                                _ => 1,
                            };

                            if confirmations >= required_confirmations {
                                info!(
                                    batch_id = %batch_id,
                                    txid = %txid_str,
                                    confirmations = confirmations,
                                    "Settlement batch confirmed, finalizing"
                                );

                                // Get block height from transaction
                                // H-21: Safe block height conversion with bounds checking
                                let raw_height = tx_json
                                    .get("blockheight")
                                    .and_then(|h| h.as_u64())
                                    .unwrap_or(0);
                                let block_height = match safe_block_height_u64(raw_height) {
                                    Ok(h) => h,
                                    Err(e) => {
                                        error!(error = %e, "Invalid block height, cannot finalize batch");
                                        continue;
                                    }
                                };

                                // Mark batch as confirmed in executor
                                if let Err(e) = executor.mark_confirmed(&batch_id, block_height) {
                                    error!(error = %e, "Failed to mark batch as confirmed");
                                } else {
                                    // Update all withdrawals in this batch to confirmed status
                                    if let Ok(withdrawals) = state.db.get_all_pending_withdrawals()
                                    {
                                        for withdrawal in withdrawals {
                                            if withdrawal.batch_id.as_deref() == Some(&batch_id) {
                                                // H-PAY-1 FIX: Now mark locks as Spent after confirmations
                                                // This is the safe point - transaction is confirmed on-chain
                                                if let Err(e) = state.db.update_ghost_lock_state(
                                                    &withdrawal.lock_id,
                                                    DbLockState::Spent,
                                                ) {
                                                    error!(
                                                        lock_id = %withdrawal.lock_id,
                                                        error = %e,
                                                        "Failed to update lock state to Spent"
                                                    );
                                                }

                                                if let Some(id) = withdrawal.id {
                                                    if let Err(e) =
                                                        state.db.update_withdrawal_confirmed(id)
                                                    {
                                                        error!(
                                                            withdrawal_id = id,
                                                            error = %e,
                                                            "Failed to confirm withdrawal"
                                                        );
                                                    } else {
                                                        info!(
                                                            withdrawal_id = id,
                                                            "Withdrawal confirmed"
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Store finalization in database
                                    if let Err(e) =
                                        state.db.finalize_reconciliation_batch(&batch_id)
                                    {
                                        error!(error = %e, "Failed to finalize batch in database");
                                    }
                                }
                            }
                        } else {
                            debug!(
                                batch_id = %batch_id,
                                txid = %txid_str,
                                "Transaction not yet confirmed (0 confirmations)"
                            );
                        }
                    }
                    Err(e) => {
                        // Transaction might be in mempool or not found
                        debug!(
                            batch_id = %batch_id,
                            txid = %txid_str,
                            error = %e,
                            "Could not fetch transaction status"
                        );
                    }
                }
            }
        }
    }
}

/// Estimate fee rate in sat/vbyte
///
/// Uses Bitcoin Core's `estimatesmartfee` RPC with fallback to cached or default values.
async fn estimate_fee_rate(state: &Arc<AppState>) -> u64 {
    // Target confirmation in 6 blocks (~1 hour)
    const CONF_TARGET: u32 = 6;

    // Try to get fee estimate from Bitcoin Core
    match state.rpc.estimate_smart_fee(CONF_TARGET).await {
        Ok(estimate) => {
            if let Some(feerate_btc_kvb) = estimate.feerate {
                // Convert from BTC/kvB to sat/vB
                // feerate is in BTC per 1000 vbytes, we need sat per vbyte
                // 1 BTC = 100_000_000 sats, 1 kvB = 1000 vB
                // sat/vB = (BTC/kvB) * 100_000_000 / 1000 = BTC/kvB * 100_000
                let sat_per_vb = (feerate_btc_kvb * 100_000.0) as u64;
                let rate = sat_per_vb.clamp(1, 1000); // Clamp to 1-1000 sat/vB

                // Cache the rate with timestamp
                let cached_value = format!("{}:{}", rate, chrono::Utc::now().timestamp());
                let _ = state.db.kv_set("fee_rate_cache", &cached_value);

                debug!(
                    rate = rate,
                    conf_target = CONF_TARGET,
                    source = "rpc",
                    "Fee rate estimated"
                );
                return rate;
            }
            // RPC returned but no feerate (not enough data)
            if let Some(errors) = estimate.errors {
                debug!(errors = ?errors, "Fee estimation returned errors, using fallback");
            }
        }
        Err(e) => {
            debug!(error = %e, "Failed to estimate fee via RPC, using fallback");
        }
    }

    // Try to get cached fee rate from database (with staleness check)
    if let Ok(Some(cached)) = state.db.kv_get("fee_rate_cache") {
        if let Some((rate_str, timestamp_str)) = cached.split_once(':') {
            if let (Ok(rate), Ok(timestamp)) =
                (rate_str.parse::<u64>(), timestamp_str.parse::<i64>())
            {
                let now = chrono::Utc::now().timestamp();
                let age_secs = now.saturating_sub(timestamp);

                // Use cached rate if less than 10 minutes old
                if age_secs < 600 {
                    debug!(
                        rate = rate,
                        age_secs = age_secs,
                        source = "cache",
                        "Using cached fee rate"
                    );
                    return rate.clamp(1, 1000);
                }
            }
        }
    }

    // Fallback to network defaults
    let default_rate = match state.network {
        Network::Bitcoin => 10, // Mainnet: ~10 sat/vB for standard priority
        Network::Testnet => 2,  // Testnet: lower fees
        Network::Signet => 1,   // Signet: minimal fees
        Network::Regtest => 1,  // Regtest: minimal fees
        _ => 5,                 // Unknown: conservative default
    };

    debug!(
        rate = default_rate,
        network = ?state.network,
        source = "default",
        "Using default fee rate"
    );

    default_rate
}

/// Convert hex string to [u8; 32]
///
/// Returns a 32-byte array from hex input.
/// Logs a warning if input length is not exactly 64 hex characters (32 bytes).
fn hex_to_32bytes(hex: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    match hex::decode(hex) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                warn!(
                    expected = 32,
                    actual = bytes.len(),
                    hex = %hex,
                    "hex_to_32bytes: unexpected input length"
                );
            }
            let len = bytes.len().min(32);
            result[..len].copy_from_slice(&bytes[..len]);
        }
        Err(e) => {
            warn!(error = %e, hex = %hex, "hex_to_32bytes: invalid hex input");
        }
    }
    result
}

/// Parse RPC URL into host and port
///
/// Uses network-appropriate default port if not specified:
/// - Mainnet: 8332
/// - Testnet: 18332
/// - Signet: 38332
/// - Regtest: 18443
fn parse_rpc_url(url: &str, network: Network) -> (String, u16) {
    let default_port = match network {
        Network::Bitcoin => 8332,
        Network::Testnet | Network::Testnet4 => 18332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
    };

    // Handle URL format: http://host:port or just host:port
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    if let Some(idx) = stripped.rfind(':') {
        let host = stripped[..idx].to_string();
        let port = stripped[idx + 1..].parse().unwrap_or(default_port);
        (host, port)
    } else {
        (stripped.to_string(), default_port)
    }
}

// =============================================================================
// Wizard endpoint handlers (Reconcile Lock, Send L2 Payment)
// =============================================================================

/// Request body for lock reconciliation (settle to L1)
#[derive(Debug, Deserialize)]
struct ReconcileLockRequest {
    /// Destination Bitcoin address for settlement (bech32)
    destination_address: String,
    /// Settlement class: "standard" or "batched"
    #[serde(default = "default_settlement_class")]
    settlement_class: String,
}

fn default_settlement_class() -> String {
    "standard".to_string()
}

/// POST /api/v1/locks/:id/reconcile — Settle a Ghost Lock to L1
///
/// Reconciles (closes) an active lock by sending funds to a specified
/// L1 Bitcoin address. Similar to withdrawal but specifically for
/// closing out the full lock balance.
async fn reconcile_lock(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ReconcileLockRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    // Validate settlement class
    if !["standard", "batched"].contains(&req.settlement_class.as_str()) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Invalid settlement_class. Must be 'standard' or 'batched'"
        })));
    }

    // Validate the lock exists and is owned by this ghost_id
    let lock = state
        .db
        .get_ghost_lock(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if lock.owner_ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Lock must be active and funded
    if lock.state != DbLockState::Active {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not active"
        })));
    }

    if lock.funding_txid.is_none() {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not funded"
        })));
    }

    // Validate destination address format (bech32)
    if !req.destination_address.starts_with("bc1")
        && !req.destination_address.starts_with("tb1")
        && !req.destination_address.starts_with("bcrt1")
    {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Invalid destination address format (must be bech32)"
        })));
    }

    // Settlement fee
    let settlement_fee = if req.settlement_class == "batched" {
        500u64
    } else {
        1000u64
    };
    let settlement_amount = lock.amount_sats.saturating_sub(settlement_fee);

    let now = chrono::Utc::now().timestamp();

    // Create withdrawal request for the full lock balance
    let withdrawal = WithdrawalRequest {
        id: None,
        ghost_id: ghost_id.clone(),
        lock_id: id.clone(),
        destination_address: req.destination_address.clone(),
        amount_sats: settlement_amount,
        fee_sats: settlement_fee,
        status: WithdrawalStatus::Pending,
        batch_id: None,
        l1_txid: None,
        created_at: now,
        updated_at: now,
    };

    // Atomically insert withdrawal if none pending for this lock
    let withdrawal_id = match state
        .db
        .insert_withdrawal_request_atomic(&withdrawal)
        .map_err(|e| {
            tracing::error!("Failed to create reconciliation withdrawal: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })? {
        Some(wid) => wid,
        None => {
            return Ok(Json(serde_json::json!({
                "success": false,
                "error": "A pending withdrawal already exists for this lock"
            })));
        }
    };

    // Update lock state to indicate reconciliation in progress
    state
        .db
        .update_ghost_lock_state(&id, DbLockState::Jumping)
        .map_err(|e| {
            tracing::error!("Failed to update lock state for reconciliation: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "withdrawal_id": withdrawal_id,
        "lock_id": id,
        "settlement_amount": settlement_amount,
        "fee_sats": settlement_fee,
        "settlement_class": req.settlement_class,
        "destination_address": req.destination_address,
        "message": format!("Lock reconciliation initiated, settlement of {} sats", settlement_amount)
    })))
}

/// Request body for L2 payment
#[derive(Debug, Deserialize)]
struct SendL2PaymentRequest {
    /// Recipient Ghost ID or payment address
    recipient: String,
    /// Amount in satoshis
    amount_sats: u64,
    /// Optional memo (max 59 characters for OP_RETURN compatibility)
    #[serde(default)]
    memo: Option<String>,
}

/// POST /api/v1/payments/send — Send an L2 instant payment
///
/// Sends an instant off-chain payment to another Ghost user.
/// Wraps the confidential transfer system for a simpler API.
async fn send_l2_payment(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendL2PaymentRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    // Validate amount
    if req.amount_sats == 0 {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        })));
    }

    // Validate memo length
    if let Some(ref memo) = req.memo {
        if memo.len() > 59 {
            return Ok(Json(serde_json::json!({
                "success": false,
                "error": "Memo cannot exceed 59 characters"
            })));
        }
    }

    // Validate recipient format (Ghost ID is a hex pubkey or bech32 address)
    if req.recipient.is_empty() {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Recipient is required"
        })));
    }

    // Query sender's available L2 balance:
    // Sum of unsettled received payments + unspent lock amounts owned by sender
    let sender_gid = ghost_id.clone();
    let available_balance: i64 = state
        .db
        .with_connection(|conn| {
            // L2 balance = received payments not yet settled + active lock funds
            let received: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(amount_sats), 0) FROM accepted_instant_payments \
                     WHERE merchant_wallet_id = ?1 AND settlement_block = 0",
                    rusqlite::params![sender_gid],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let lock_balance: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(amount_sats), 0) FROM ghost_locks \
                     WHERE owner_ghost_id = ?1 AND state = 'Active'",
                    rusqlite::params![sender_gid],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(received + lock_balance)
        })
        .map_err(|e| {
            tracing::error!("Failed to query L2 balance: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if (req.amount_sats as i64) > available_balance {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Insufficient L2 balance",
            "available_sats": available_balance,
            "requested_sats": req.amount_sats
        })));
    }

    // Generate deterministic payment ID from (sender, recipient, amount, timestamp)
    let now = chrono::Utc::now().timestamp();
    let payment_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(ghost_id.as_bytes());
        hasher.update(req.recipient.as_bytes());
        hasher.update(req.amount_sats.to_le_bytes());
        hasher.update(now.to_le_bytes());
        format!("pay_{}", hex::encode(&hasher.finalize()[..16]))
    };

    // Get sender pubkey from loaded ghost keys
    let sender_pubkey = {
        let keys_guard = state.keys.read();
        match keys_guard.as_ref() {
            Some(keys) => hex::encode(keys.spend_pubkey().serialize()),
            None => {
                return Ok(Json(serde_json::json!({
                    "success": false,
                    "error": "Ghost keys not loaded"
                })));
            }
        }
    };

    // Record the L2 payment intent with real sender pubkey.
    // The ZK proof must be submitted separately via /api/v1/confidential/transfer
    // since proof generation requires the sender's private key (client-side only).
    let pid = payment_id.clone();
    let gid = ghost_id.clone();
    let recipient = req.recipient.clone();
    let amount = req.amount_sats;
    let pubkey_bytes = hex::decode(&sender_pubkey).unwrap_or_default();

    state
        .db
        .with_connection(|conn| {
            conn.execute(
                "INSERT INTO accepted_instant_payments \
                 (payment_id, sender_lock_id, merchant_wallet_id, amount_sats, \
                  accepted_at, settlement_block, confidence, sender_pubkey, signature) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, 0.0, ?6, X'00')",
                rusqlite::params![
                    pid.as_bytes(),
                    gid,
                    recipient,
                    amount as i64,
                    now,
                    pubkey_bytes,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
        .map_err(|e| {
            tracing::error!("Failed to record L2 payment: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "payment_id": payment_id,
        "sender": ghost_id,
        "recipient": req.recipient,
        "amount_sats": req.amount_sats,
        "memo": req.memo,
        "status": "pending",
        "proof_required": true,
        "transfer_endpoint": "/api/v1/confidential/transfer",
        "message": format!(
            "L2 payment of {} sats recorded. Submit ZK proof via /api/v1/confidential/transfer to complete.",
            req.amount_sats
        )
    })))
}

// =============================================================================
// L2 BLOCK PRODUCTION ENDPOINTS
// =============================================================================

/// GET /api/v1/l2/state — Current L2 state for block producer
async fn l2_state_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let tree = state.commitment_tree.read();
    let state_root = tree.root().unwrap_or([0u8; 32]);

    // Get latest L2 block height from blocks table (matches verify_ghostpay)
    let height: u64 = state
        .db
        .with_connection(|conn| {
            let result: Option<i64> = conn
                .query_row(
                    "SELECT height FROM blocks ORDER BY height DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .ok();
            Ok(result.unwrap_or(0) as u64)
        })
        .unwrap_or(0);

    // Count pending transfers
    let pending_count: i64 = state
        .db
        .with_connection(|conn| {
            conn.query_row("SELECT COUNT(*) FROM pending_transfers", [], |row| {
                row.get(0)
            })
            .map_err(|e| GhostError::Database(e.to_string()))
        })
        .unwrap_or(0);

    Json(serde_json::json!({
        "height": height,
        "state_root": hex::encode(state_root),
        "pending_count": pending_count,
    }))
}

/// GET /api/v1/l2/pending — Build a block witness from pending transfers
async fn l2_pending_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tree = state.commitment_tree.read();
    let prev_state_root = tree.root().unwrap_or([0u8; 32]);

    // Load pending transfers ordered by creation time
    let pending: Vec<(i64, u64, u64, u64, u64, u64)> = state
        .db
        .with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, sender_index, recipient_index, amount, \
                     sender_balance_before, recipient_balance_before \
                     FROM pending_transfers ORDER BY created_at ASC LIMIT 100",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u64,
                        row.get::<_, i64>(3)? as u64,
                        row.get::<_, i64>(4)? as u64,
                        row.get::<_, i64>(5)? as u64,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| GhostError::Database(e.to_string()))?);
            }
            Ok(result)
        })
        .map_err(|e| {
            error!(error = %e, "Failed to load pending transfers");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if pending.is_empty() {
        // Empty block witness — state doesn't change
        return Ok(Json(serde_json::json!({
            "prev_state_root": hex::encode(prev_state_root),
            "new_state_root": hex::encode(prev_state_root),
            "tx_count": 0,
            "tx_ids": [],
            "transitions": [],
            "intermediate_roots": [],
        })));
    }

    // Build witness by applying transfers to a cloned balance tree
    let balance_tree = state.balance_tree.read();
    let mut work_tree = balance_tree.clone();
    drop(balance_tree);

    let prev_root = work_tree.root().unwrap_or([0u8; 32]);
    let mut transitions = Vec::new();
    let mut intermediate_roots = Vec::new();
    let mut included_ids = Vec::new();

    for (id, sender_idx, recipient_idx, amount, _, _) in &pending {
        match work_tree.apply_payment(*sender_idx, *recipient_idx, *amount) {
            Ok(witness) => {
                let root = work_tree.root().unwrap_or([0u8; 32]);
                intermediate_roots.push(root);
                transitions.push(witness);
                included_ids.push(*id);
            }
            Err(e) => {
                warn!(id, error = %e, "Skipping invalid L2 transfer");
            }
        }
    }

    let new_root = work_tree.root().unwrap_or([0u8; 32]);

    Ok(Json(serde_json::json!({
        "prev_state_root": hex::encode(prev_root),
        "new_state_root": hex::encode(new_root),
        "tx_count": transitions.len(),
        "tx_ids": included_ids,
        "transitions": transitions.iter().map(|t| serde_json::json!({
            "sender_index": t.sender_index,
            "recipient_index": t.recipient_index,
            "amount": t.amount,
            "sender_balance_before": t.sender_balance_before,
            "recipient_balance_before": t.recipient_balance_before,
            "sender_merkle_proof": {
                "siblings": t.sender_merkle_proof.siblings.iter()
                    .map(|s| hex::encode(s)).collect::<Vec<_>>(),
                "index": t.sender_merkle_proof.leaf_index,
            },
            "recipient_merkle_proof": {
                "siblings": t.recipient_merkle_proof.siblings.iter()
                    .map(|s| hex::encode(s)).collect::<Vec<_>>(),
                "index": t.recipient_merkle_proof.leaf_index,
            },
        })).collect::<Vec<_>>(),
        "intermediate_roots": intermediate_roots.iter()
            .map(|r| hex::encode(r)).collect::<Vec<_>>(),
    })))
}

/// POST /api/v1/l2/finalize — Called by ghost-pool when consensus approves a block
async fn l2_finalize_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let height = req["height"].as_u64().ok_or(StatusCode::BAD_REQUEST)?;
    let state_root_hex = req["state_root"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let attestation_count = req["attestation_count"].as_u64().unwrap_or(0);

    let state_root_bytes = parse_hex_32(state_root_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Delete included transfers
    let included_ids: Vec<i64> = req["included_tx_ids"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default();

    if !included_ids.is_empty() {
        // Load the transfers we're about to finalize (for balance tree application)
        let finalized_transfers: Vec<(i64, u64, u64, u64)> = state
            .db
            .with_connection(|conn| {
                let placeholders: String = included_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT id, sender_index, recipient_index, amount \
                         FROM pending_transfers WHERE id IN ({})",
                        placeholders
                    ))
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)? as u64,
                            row.get::<_, i64>(2)? as u64,
                            row.get::<_, i64>(3)? as u64,
                        ))
                    })
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row.map_err(|e| GhostError::Database(e.to_string()))?);
                }
                Ok(result)
            })
            .map_err(|e| {
                error!(error = %e, "Failed to load finalized transfers");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Apply finalized transfers to the persistent balance tree
        {
            let mut tree = state.balance_tree.write();
            for (_id, sender_idx, recipient_idx, amount) in &finalized_transfers {
                if let Err(e) = tree.apply_payment(*sender_idx, *recipient_idx, *amount) {
                    warn!(error = %e, "Failed to apply finalized transfer to balance tree");
                }
            }

            // Persist updated balances
            state
                .db
                .with_connection(|conn| {
                    for (&idx, &bal) in tree.balances() {
                        conn.execute(
                            "INSERT OR REPLACE INTO l2_balances (account_index, balance) \
                             VALUES (?1, ?2)",
                            rusqlite::params![idx as i64, bal as i64],
                        )
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    }
                    Ok(())
                })
                .map_err(|e| {
                    error!(error = %e, "Failed to persist L2 balances");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
        }

        // Delete the finalized transfers from pending
        state
            .db
            .with_connection(|conn| {
                let placeholders: String = included_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                conn.execute(
                    &format!(
                        "DELETE FROM pending_transfers WHERE id IN ({})",
                        placeholders
                    ),
                    [],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
                Ok(())
            })
            .map_err(|e| {
                error!(error = %e, "Failed to delete finalized transfers");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Verify state root consistency
    {
        let tree = state.balance_tree.read();
        let current_root = tree.root().unwrap_or([0u8; 32]);
        if current_root != state_root_bytes && !included_ids.is_empty() {
            warn!(
                height,
                expected = hex::encode(state_root_bytes),
                actual = hex::encode(current_root),
                "L2 balance tree root mismatch on finalize — tree may need resync"
            );
        }
    }

    // Record L2 block in the `blocks` table (read by verify_ghostpay endpoint)
    let epoch_id = height / 2160; // 2160 blocks per epoch (6 hours at 10s intervals)
    state
        .db
        .with_connection(|conn| {
            // Ensure blocks table exists (schema from old binary, not in migrations)
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS blocks (
                    height INTEGER PRIMARY KEY,
                    epoch_id INTEGER NOT NULL,
                    state_root TEXT NOT NULL
                );",
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            conn.execute(
                "INSERT OR REPLACE INTO blocks (height, epoch_id, state_root) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![height as i64, epoch_id as i64, state_root_hex],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
        .map_err(|e| {
            error!(error = %e, "Failed to record L2 block");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(
        height,
        attestation_count,
        state_root = state_root_hex,
        "L2 block finalized"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "height": height,
        "state_root": state_root_hex,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // derive_encryption_key tests
    // =========================================================================

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let password = "test-password-123";
        let salt = [0xABu8; 32];

        let key1 = derive_encryption_key(password, &salt).expect("first derivation failed");
        let key2 = derive_encryption_key(password, &salt).expect("second derivation failed");

        assert_eq!(key1, key2, "same password and salt must produce same key");
        assert_ne!(key1, [0u8; 32], "derived key must not be all zeros");
    }

    #[test]
    fn test_derive_encryption_key_different_passwords_produce_different_keys() {
        let salt = [0x01u8; 32];

        let key_a = derive_encryption_key("password-a", &salt).expect("derivation a failed");
        let key_b = derive_encryption_key("password-b", &salt).expect("derivation b failed");

        assert_ne!(
            key_a, key_b,
            "different passwords must produce different keys"
        );
    }

    #[test]
    fn test_derive_encryption_key_different_salts_produce_different_keys() {
        let password = "same-password";
        let salt_a = [0x01u8; 32];
        let salt_b = [0x02u8; 32];

        let key_a = derive_encryption_key(password, &salt_a).expect("derivation a failed");
        let key_b = derive_encryption_key(password, &salt_b).expect("derivation b failed");

        assert_ne!(key_a, key_b, "different salts must produce different keys");
    }

    #[test]
    fn test_derive_encryption_key_empty_password() {
        let salt = [0xFFu8; 32];
        let key = derive_encryption_key("", &salt).expect("empty password derivation failed");
        assert_ne!(
            key, [0u8; 32],
            "derived key from empty password must not be all zeros"
        );
    }

    // =========================================================================
    // encrypt_keys / decrypt_keys roundtrip tests
    // =========================================================================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"secret key material for ghost pay";
        let password = "strong-encryption-password";

        let encrypted = encrypt_keys(plaintext, password).expect("encryption failed");
        let decrypted = decrypt_keys(&encrypted, password).expect("decryption failed");

        assert_eq!(
            decrypted, plaintext,
            "roundtrip must recover original plaintext"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_empty_plaintext() {
        let plaintext = b"";
        let password = "password";

        let encrypted = encrypt_keys(plaintext, password).expect("encryption failed");
        let decrypted = decrypt_keys(&encrypted, password).expect("decryption failed");

        assert_eq!(
            decrypted, plaintext,
            "roundtrip with empty plaintext must work"
        );
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let plaintext = b"same data each time";
        let password = "password";

        let encrypted1 = encrypt_keys(plaintext, password).expect("encryption 1 failed");
        let encrypted2 = encrypt_keys(plaintext, password).expect("encryption 2 failed");

        // Random salt and nonce mean ciphertexts differ even for same input
        assert_ne!(
            encrypted1, encrypted2,
            "two encryptions of same data must produce different ciphertexts"
        );
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let plaintext = b"secret data";
        let encrypted = encrypt_keys(plaintext, "correct-password").expect("encryption failed");

        let result = decrypt_keys(&encrypted, "wrong-password");
        assert!(result.is_err(), "decryption with wrong password must fail");
    }

    #[test]
    fn test_decrypt_truncated_data_fails() {
        // Minimum size is SALT_SIZE + NONCE_SIZE + 16 (auth tag)
        let too_short = vec![0u8; SALT_SIZE + NONCE_SIZE + 15];
        let result = decrypt_keys(&too_short, "password");
        assert!(result.is_err(), "decryption of truncated data must fail");
    }

    #[test]
    fn test_encrypted_format_has_expected_prefix_size() {
        let plaintext = b"test";
        let password = "pw";
        let encrypted = encrypt_keys(plaintext, password).expect("encryption failed");

        // Encrypted output: salt (32) + nonce (12) + ciphertext (plaintext + 16 tag)
        let expected_len = SALT_SIZE + NONCE_SIZE + plaintext.len() + 16;
        assert_eq!(
            encrypted.len(),
            expected_len,
            "encrypted data must be salt + nonce + ciphertext + tag"
        );
    }

    // =========================================================================
    // safe_block_height_u64 tests
    // =========================================================================

    #[test]
    fn test_safe_block_height_u64_zero() {
        let result = safe_block_height_u64(0).expect("0 should be valid");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_safe_block_height_u64_typical_height() {
        let result = safe_block_height_u64(850_000).expect("typical height should be valid");
        assert_eq!(result, 850_000);
    }

    #[test]
    fn test_safe_block_height_u64_max_u32() {
        let result = safe_block_height_u64(u32::MAX as u64).expect("u32::MAX should be valid");
        assert_eq!(result, u32::MAX);
    }

    #[test]
    fn test_safe_block_height_u64_overflow() {
        let result = safe_block_height_u64(u32::MAX as u64 + 1);
        assert!(result.is_err(), "u32::MAX + 1 must be rejected");
    }

    #[test]
    fn test_safe_block_height_u64_u64_max() {
        let result = safe_block_height_u64(u64::MAX);
        assert!(result.is_err(), "u64::MAX must be rejected");
    }

    // =========================================================================
    // safe_block_height_i64 tests
    // =========================================================================

    #[test]
    fn test_safe_block_height_i64_zero() {
        let result = safe_block_height_i64(0).expect("0 should be valid");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_safe_block_height_i64_typical_height() {
        let result = safe_block_height_i64(850_000).expect("typical height should be valid");
        assert_eq!(result, 850_000);
    }

    #[test]
    fn test_safe_block_height_i64_negative() {
        let result = safe_block_height_i64(-1);
        assert!(result.is_err(), "negative height must be rejected");
    }

    #[test]
    fn test_safe_block_height_i64_large_negative() {
        let result = safe_block_height_i64(i64::MIN);
        assert!(result.is_err(), "i64::MIN must be rejected");
    }

    #[test]
    fn test_safe_block_height_i64_max_u32() {
        let result = safe_block_height_i64(u32::MAX as i64).expect("u32::MAX should be valid");
        assert_eq!(result, u32::MAX);
    }

    #[test]
    fn test_safe_block_height_i64_overflow() {
        let result = safe_block_height_i64(u32::MAX as i64 + 1);
        assert!(result.is_err(), "u32::MAX + 1 as i64 must be rejected");
    }

    // =========================================================================
    // hex_to_32bytes tests
    // =========================================================================

    #[test]
    fn test_hex_to_32bytes_valid_64_char_hex() {
        let hex_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let result = hex_to_32bytes(hex_str);
        let expected: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hex_to_32bytes_all_zeros() {
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = hex_to_32bytes(hex_str);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_hex_to_32bytes_all_ff() {
        let hex_str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let result = hex_to_32bytes(hex_str);
        assert_eq!(result, [0xFFu8; 32]);
    }

    #[test]
    fn test_hex_to_32bytes_short_input() {
        // 4 hex chars = 2 bytes; should zero-pad the remaining 30 bytes
        let hex_str = "abcd";
        let result = hex_to_32bytes(hex_str);
        let mut expected = [0u8; 32];
        expected[0] = 0xAB;
        expected[1] = 0xCD;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hex_to_32bytes_long_input_truncated() {
        // 66 hex chars = 33 bytes; should only take the first 32 bytes
        let hex_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let result = hex_to_32bytes(hex_str);
        let expected: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hex_to_32bytes_invalid_hex() {
        // Invalid hex chars should result in all zeros (fallback)
        let result = hex_to_32bytes("not-valid-hex!!");
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_hex_to_32bytes_empty_string() {
        // Empty string: 0 bytes decoded, zero-padded result
        let result = hex_to_32bytes("");
        assert_eq!(result, [0u8; 32]);
    }
}
