//! Shared-secret HMAC for the inter-coordinator gossip route.
//!
//! Mirrors the `X-Ghost-Signature` / `X-Ghost-Timestamp` scheme used
//! by ghost-pay's authenticated endpoints (see
//! `bins/ghost-pay/src/main.rs`). HMAC-SHA256 of `timestamp_secs ||
//! body_bytes` keyed by the shared secret, hex-encoded; the timestamp
//! header doubles as a replay-protection nonce within a 5-minute
//! window.
//!
//! The Active signs every gossip POST; every Standby in the pool
//! verifies before applying. When the secret is unset on either side
//! the route falls back to firewall-trust (no auth, operator
//! responsible for restricting access). Mainnet operators set the
//! secret and rotate it as they would any other shared credential.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Header carrying the hex-encoded HMAC of `timestamp || body`.
pub const SIGNATURE_HEADER: &str = "X-Ghost-Signature";
/// Header carrying the Unix-seconds timestamp; replayed against a
/// 5-minute window.
pub const TIMESTAMP_HEADER: &str = "X-Ghost-Timestamp";
/// Maximum clock skew between Active and Standby for a request to be
/// accepted. Tracks ghost-pay's value so operators don't have to
/// reason about two different windows.
pub const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

/// Compute the hex-encoded HMAC-SHA256 of `timestamp_secs || body`
/// using `secret` as the key.
pub fn sign(secret: &str, timestamp_secs: i64, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts arbitrary-length key");
    mac.update(timestamp_secs.to_string().as_bytes());
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a hex-encoded HMAC against `(timestamp_secs, body)`.
/// Constant-time comparison; rejects on bad encoding or stale
/// timestamps too.
pub fn verify(
    secret: &str,
    signature_hex: &str,
    timestamp_secs: i64,
    body: &[u8],
    now_secs: i64,
) -> bool {
    if (now_secs - timestamp_secs).abs() > TIMESTAMP_TOLERANCE_SECS {
        return false;
    }
    let expected = sign(secret, timestamp_secs, body);
    if signature_hex.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in signature_hex.bytes().zip(expected.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_round_trips() {
        let secret = "shared-pool-secret";
        let body = b"{\"type\":\"session_created\"}";
        let ts = 1_700_000_000;
        let sig = sign(secret, ts, body);
        assert!(verify(secret, &sig, ts, body, ts));
    }

    #[test]
    fn wrong_secret_rejected() {
        let body = b"x";
        let sig = sign("a", 1, body);
        assert!(!verify("b", &sig, 1, body, 1));
    }

    #[test]
    fn body_tamper_rejected() {
        let secret = "s";
        let sig = sign(secret, 1, b"original");
        assert!(!verify(secret, &sig, 1, b"tampered", 1));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let secret = "s";
        let body = b"x";
        let sig = sign(secret, 1_000, body);
        // 301s outside the window
        assert!(!verify(secret, &sig, 1_000, body, 1_000 + 301));
        // 301s in the future
        assert!(!verify(secret, &sig, 1_000 + 301, body, 1_000));
    }

    #[test]
    fn malformed_signature_rejected() {
        let secret = "s";
        // Missing characters
        assert!(!verify(secret, "deadbeef", 1, b"x", 1));
    }
}
