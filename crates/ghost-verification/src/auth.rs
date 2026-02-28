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
//| FILE: auth.rs                                                                                                        |
//|======================================================================================================================|

//! Authentication for internal API endpoints (H10, H11 security fixes)
//!
//! Provides HMAC-SHA256 authentication for internal endpoints that should not be
//! publicly accessible. This prevents unauthorized share submissions and admin
//! operations from external sources.
//!
//! # Security Model
//!
//! Internal endpoints (`/api/internal/*`, `/admin/*`) are protected by HMAC-SHA256.
//! The shared secret must be configured at startup and shared between:
//! - ghost-pool (the pool server)
//! - ghost-verification (this service)
//! - Any other internal services that need to communicate
//!
//! # Usage
//!
//! Requests must include the `X-Ghost-Signature` header containing:
//! `HMAC-SHA256(secret, timestamp + body)`
//!
//! And the `X-Ghost-Timestamp` header with Unix timestamp (seconds).
//! Timestamps must be within 5 minutes of server time to prevent replay attacks.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

/// API-4 FIX: Maximum timestamp drift allowed (30 seconds)
/// Reduced from 60 seconds to further minimize replay attack window.
/// 30 seconds is still generous for properly synchronized nodes while
/// reducing the attack surface by 50%. Nodes MUST use NTP for accurate time.
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Internal API authentication using HMAC-SHA256
///
/// # Security (H10)
///
/// All internal endpoints that receive share data or trigger privileged operations
/// must be protected by this authentication to prevent:
/// - Unauthorized share injection attacks
/// - Spoofed work credits
/// - Fake consensus triggers
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InternalAuth {
    secret: [u8; 32],
}

impl InternalAuth {
    /// Create a new InternalAuth with the given secret
    ///
    /// # Errors
    ///
    /// Returns error if secret is too short or has insufficient entropy
    pub fn new(secret: &[u8]) -> Result<Self, AuthError> {
        // H10: Require minimum 32 bytes for security
        if secret.len() < 32 {
            return Err(AuthError::WeakSecret(
                "Internal API secret must be at least 32 bytes".to_string(),
            ));
        }

        // Check for trivially weak secrets (all same byte)
        if secret.iter().all(|&b| b == secret[0]) {
            return Err(AuthError::WeakSecret(
                "Internal API secret has insufficient entropy".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&secret[..32]);
        Ok(Self { secret: key })
    }

    /// Create from a hex-encoded secret string
    pub fn from_hex(hex_secret: &str) -> Result<Self, AuthError> {
        let bytes = hex::decode(hex_secret)
            .map_err(|_| AuthError::InvalidSecret("Invalid hex encoding".to_string()))?;
        Self::new(&bytes)
    }

    /// Verify a request signature
    ///
    /// # Arguments
    ///
    /// * `signature` - The HMAC-SHA256 signature from X-Ghost-Signature header
    /// * `timestamp` - The Unix timestamp from X-Ghost-Timestamp header
    /// * `body` - The request body bytes
    ///
    /// # Returns
    ///
    /// Ok(()) if signature is valid and timestamp is within acceptable range
    pub fn verify(&self, signature: &str, timestamp: u64, body: &[u8]) -> Result<(), AuthError> {
        // Check timestamp is within acceptable range (replay prevention)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let drift = timestamp.abs_diff(now);

        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(AuthError::TimestampOutOfRange {
                received: timestamp,
                server_time: now,
            });
        }

        // Compute expected signature: HMAC-SHA256(secret, timestamp_bytes || body)
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&timestamp.to_le_bytes());
        mac.update(body);
        let expected = mac.finalize().into_bytes();

        // Decode provided signature
        let provided = hex::decode(signature)
            .map_err(|_| AuthError::InvalidSignature("Invalid hex encoding".to_string()))?;

        // Constant-time comparison
        if !constant_time_eq(&expected, &provided) {
            return Err(AuthError::InvalidSignature(
                "Signature verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Generate a signature for a request (for testing/client use)
    pub fn sign(&self, timestamp: u64, body: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&timestamp.to_le_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Constant-time byte comparison to prevent timing attacks
///
/// L-18 SECURITY NOTE: The length comparison on line 186 does leak timing information
/// about whether the lengths match. However, this is acceptable here because:
///
/// 1. HMAC-SHA256 always produces exactly 32 bytes of output
/// 2. Attackers already know the expected signature length is 32 bytes (it's public knowledge)
/// 3. The length check only reveals "signature is/isn't 32 bytes" which provides no
///    useful information about the actual signature value
/// 4. The actual byte comparison in the loop below is constant-time and does not
///    leak information about which bytes differ or how many match
///
/// To fully eliminate timing information, we could pad shorter inputs and always
/// compare 32 bytes, but this would add complexity for zero security benefit since
/// the HMAC output size is already public.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // L-18: This length check leaks timing info about length mismatch, but HMAC-SHA256
    // is always 32 bytes so attackers already know the expected length. No information
    // about the actual signature value is revealed.
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Authentication error types
#[derive(Debug, Clone)]
pub enum AuthError {
    /// Missing required header
    MissingHeader(String),
    /// Invalid signature format or verification failed
    InvalidSignature(String),
    /// Timestamp outside acceptable range
    TimestampOutOfRange { received: u64, server_time: u64 },
    /// Secret key is too weak
    WeakSecret(String),
    /// Invalid secret format
    InvalidSecret(String),
}

impl AuthError {
    /// Return a generic message safe for HTTP responses (no internal details).
    pub fn client_message(&self) -> &'static str {
        match self {
            AuthError::MissingHeader(_) => "Missing required authentication header",
            AuthError::InvalidSignature(_) => "Invalid signature",
            AuthError::TimestampOutOfRange { .. } => "Request timestamp out of acceptable range",
            AuthError::WeakSecret(_) => "Authentication configuration error",
            AuthError::InvalidSecret(_) => "Authentication configuration error",
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingHeader(h) => write!(f, "Missing required header: {}", h),
            AuthError::InvalidSignature(reason) => write!(f, "Invalid signature: {}", reason),
            AuthError::TimestampOutOfRange {
                received,
                server_time,
            } => {
                write!(
                    f,
                    "Timestamp {} outside acceptable range (server time: {})",
                    received, server_time
                )
            }
            AuthError::WeakSecret(reason) => write!(f, "Weak secret: {}", reason),
            AuthError::InvalidSecret(reason) => write!(f, "Invalid secret: {}", reason),
        }
    }
}

impl std::error::Error for AuthError {}

/// Extract and verify HMAC authentication from request headers
///
/// # Usage with Axum
///
/// ```ignore
/// async fn internal_handler(
///     State(state): State<Arc<AppState>>,
///     headers: HeaderMap,
///     body: Bytes,
/// ) -> Result<impl IntoResponse, StatusCode> {
///     verify_internal_auth(&state.internal_auth, &headers, &body)?;
///     // ... handler logic
/// }
/// ```
pub fn verify_internal_auth(
    auth: &InternalAuth,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), (StatusCode, String)> {
    // SEC-ERR-3: Distinguish between missing and malformed headers
    // Extract signature header
    let signature_header = headers.get("X-Ghost-Signature").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Missing X-Ghost-Signature header".to_string(),
        )
    })?;
    let signature = signature_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Malformed X-Ghost-Signature header: contains non-ASCII characters".to_string(),
        )
    })?;

    // Extract timestamp header
    let timestamp_header = headers.get("X-Ghost-Timestamp").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Missing X-Ghost-Timestamp header".to_string(),
        )
    })?;
    let timestamp_str = timestamp_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Malformed X-Ghost-Timestamp header: contains non-ASCII characters".to_string(),
        )
    })?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid X-Ghost-Timestamp format".to_string(),
        )
    })?;

    // Verify signature
    auth.verify(signature, timestamp, body).map_err(|e| {
        warn!(error = %e, "Internal API authentication failed");
        (
            StatusCode::UNAUTHORIZED,
            format!("Authentication failed: {}", e.client_message()),
        )
    })
}

/// Middleware-style authentication for internal endpoints
///
/// Use this with axum's `from_fn_with_state` for route-layer protection:
///
/// ```ignore
/// Router::new()
///     .route("/api/internal/share", post(share_handler))
///     .route_layer(from_fn_with_state(auth.clone(), require_internal_auth))
/// ```
pub async fn require_internal_auth(
    State(auth): State<Arc<InternalAuth>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Bytes, (StatusCode, String)> {
    verify_internal_auth(&auth, &headers, &body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        // Use a proper 32-byte secret for testing
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        secret
    }

    #[test]
    fn test_internal_auth_creation() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_weak_secret_rejected() {
        // Too short
        let short_secret = [0u8; 16];
        assert!(matches!(
            InternalAuth::new(&short_secret),
            Err(AuthError::WeakSecret(_))
        ));

        // All same byte
        let weak_secret = [0x42u8; 32];
        assert!(matches!(
            InternalAuth::new(&weak_secret),
            Err(AuthError::WeakSecret(_))
        ));
    }

    #[test]
    fn test_sign_and_verify() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"test body content";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature = auth.sign(timestamp, body);
        let result = auth.verify(&signature, timestamp, body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"test body content";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Wrong signature
        let bad_sig = "00".repeat(32);
        let result = auth.verify(&bad_sig, timestamp, body);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    #[test]
    fn test_old_timestamp_rejected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"test body content";
        // L-27: 2 minutes ago (beyond 60 second window)
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120;

        let signature = auth.sign(old_timestamp, body);
        let result = auth.verify(&signature, old_timestamp, body);
        assert!(matches!(result, Err(AuthError::TimestampOutOfRange { .. })));
    }

    #[test]
    fn test_body_tampering_detected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"original body";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature = auth.sign(timestamp, body);

        // Try to verify with tampered body
        let tampered_body = b"modified body";
        let result = auth.verify(&signature, timestamp, tampered_body);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        let d = [1u8, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_from_hex() {
        // Valid 32-byte hex secret
        let hex_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let auth = InternalAuth::from_hex(hex_secret);
        assert!(auth.is_ok());

        // Invalid hex
        let bad_hex = "not valid hex";
        assert!(matches!(
            InternalAuth::from_hex(bad_hex),
            Err(AuthError::InvalidSecret(_))
        ));
    }

    #[test]
    fn test_secret_zeroized_on_drop() {
        use zeroize::Zeroize;

        let secret = test_secret();
        let mut auth = InternalAuth::new(&secret).unwrap();

        // Verify it works before zeroization
        let body = b"test";
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sig = auth.sign(ts, body);
        assert!(auth.verify(&sig, ts, body).is_ok());

        // Zeroize and verify the secret is zeroed
        auth.zeroize();
        assert_eq!(auth.secret, [0u8; 32], "Secret must be zeroed after zeroize()");
    }

    #[test]
    fn test_client_message_contains_no_timestamps() {
        let err = AuthError::TimestampOutOfRange {
            received: 1700000000,
            server_time: 1700000099,
        };
        let msg = err.client_message();
        // Must not contain any numeric timestamp values
        assert!(
            !msg.contains("1700000000"),
            "client_message must not leak received timestamp"
        );
        assert!(
            !msg.contains("1700000099"),
            "client_message must not leak server timestamp"
        );
        // Display (for logs) SHOULD contain timestamps
        let display = format!("{}", err);
        assert!(
            display.contains("1700000000") && display.contains("1700000099"),
            "Display should contain timestamps for logging"
        );
    }

    #[test]
    fn test_client_messages_are_generic() {
        let cases: Vec<AuthError> = vec![
            AuthError::MissingHeader("X-Ghost-Signature".to_string()),
            AuthError::InvalidSignature("bad hex".to_string()),
            AuthError::TimestampOutOfRange {
                received: 100,
                server_time: 200,
            },
            AuthError::WeakSecret("too short".to_string()),
            AuthError::InvalidSecret("bad encoding".to_string()),
        ];
        for err in &cases {
            let msg = err.client_message();
            assert!(!msg.is_empty(), "client_message should not be empty");
            // None should contain numeric details from the variant fields
            assert!(
                !msg.contains("100") && !msg.contains("200"),
                "client_message should not contain internal details: {}",
                msg
            );
        }
    }

    // L-27: Verify 60-second timestamp tolerance
    #[test]
    fn test_timestamp_within_60_seconds_accepted() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();
        let body = b"test body";

        // 30 seconds ago should be accepted (within 60 second window)
        let timestamp_30s_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 30;

        let signature = auth.sign(timestamp_30s_ago, body);
        let result = auth.verify(&signature, timestamp_30s_ago, body);
        assert!(
            result.is_ok(),
            "L-27: Timestamp 30s ago should be within 60s tolerance"
        );
    }

    #[test]
    fn test_timestamp_just_over_30_seconds_rejected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();
        let body = b"test body";

        // API-4 FIX: 35 seconds ago should be rejected (outside 30 second window)
        let timestamp_35s_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 35;

        let signature = auth.sign(timestamp_35s_ago, body);
        let result = auth.verify(&signature, timestamp_35s_ago, body);
        assert!(
            matches!(result, Err(AuthError::TimestampOutOfRange { .. })),
            "API-4: Timestamp 35s ago should be outside 30s tolerance"
        );
    }

    #[test]
    fn test_timestamp_tolerance_constant() {
        // API-4 FIX: Verify the constant is 30 seconds (reduced from 60)
        assert_eq!(
            MAX_TIMESTAMP_DRIFT_SECS, 30,
            "API-4: Timestamp tolerance should be 30 seconds"
        );
    }
}
