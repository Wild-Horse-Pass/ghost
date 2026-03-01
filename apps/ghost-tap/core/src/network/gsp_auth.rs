//! GSP authentication module
//!
//! Handles wallet registration, session creation, and BIP-340 Schnorr
//! signature proofs for authenticating with a Ghost Service Provider.

use super::NetworkError;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Registration / session request-response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct RegisterRequest {
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    wallet_id: String,
    #[allow(dead_code)]
    challenge: String,
}

#[derive(Debug, Serialize)]
struct SessionRequest {
    wallet_id: String,
    signature: String,
    challenge: String,
}

#[derive(Debug, Deserialize)]
struct SessionResponse {
    token: String,
    #[allow(dead_code)]
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register a wallet with the GSP and obtain a wallet ID.
///
/// Sends the public key to the GSP registration endpoint. The GSP
/// stores the public key and returns a stable `wallet_id` that is
/// used in subsequent session requests.
///
/// # Arguments
/// * `endpoint` - GSP HTTP base URL (e.g. `https://gsp.ghost.network`)
/// * `pubkey` - The wallet's 33-byte compressed public key (secp256k1)
///
/// # Returns
/// The assigned wallet ID string.
pub async fn register(
    endpoint: &str,
    pubkey: &[u8],
) -> Result<String, NetworkError> {
    register_with_client(&reqwest::Client::new(), endpoint, pubkey).await
}

/// Like `register()` but uses a pre-configured `reqwest::Client`
/// (e.g. one with certificate pinning enabled).
pub async fn register_with_client(
    client: &reqwest::Client,
    endpoint: &str,
    pubkey: &[u8],
) -> Result<String, NetworkError> {
    let url = format!("{}/api/v1/wallet/register", endpoint.trim_end_matches('/'));
    let pubkey_hex = hex::encode(pubkey);

    let resp = client
        .post(&url)
        .json(&RegisterRequest {
            pubkey: pubkey_hex,
        })
        .send()
        .await
        .map_err(|e| NetworkError::RequestFailed(format!("register: {}", e)))?;

    if !resp.status().is_success() {
        return Err(NetworkError::AuthenticationFailed(format!(
            "registration failed: HTTP {}",
            resp.status()
        )));
    }

    let body: RegisterResponse = resp
        .json()
        .await
        .map_err(|e| NetworkError::InvalidResponse(format!("register body: {}", e)))?;

    Ok(body.wallet_id)
}

/// Create an authenticated session with the GSP.
///
/// Fetches a challenge from the GSP, signs it with the wallet's private
/// key using BIP-340 Schnorr, and exchanges the signature for a JWT
/// session token.
///
/// # Arguments
/// * `endpoint` - GSP HTTP base URL
/// * `wallet_id` - The wallet ID obtained from `register()`
/// * `privkey` - 32-byte secp256k1 private key
///
/// # Returns
/// A JWT session token string suitable for `MobileGspClient::authenticate()`.
pub async fn create_session(
    endpoint: &str,
    wallet_id: &str,
    privkey: &[u8; 32],
) -> Result<String, NetworkError> {
    create_session_with_client(&reqwest::Client::new(), endpoint, wallet_id, privkey).await
}

/// Like `create_session()` but uses a pre-configured `reqwest::Client`.
pub async fn create_session_with_client(
    client: &reqwest::Client,
    endpoint: &str,
    wallet_id: &str,
    privkey: &[u8; 32],
) -> Result<String, NetworkError> {
    let base = endpoint.trim_end_matches('/');

    // Step 1: Request a challenge.
    let challenge_url = format!("{}/api/v1/wallet/{}/challenge", base, wallet_id);
    let challenge_resp = client
        .get(&challenge_url)
        .send()
        .await
        .map_err(|e| NetworkError::RequestFailed(format!("challenge: {}", e)))?;

    if !challenge_resp.status().is_success() {
        return Err(NetworkError::AuthenticationFailed(format!(
            "challenge failed: HTTP {}",
            challenge_resp.status()
        )));
    }

    let challenge_body: ChallengeResponse = challenge_resp
        .json()
        .await
        .map_err(|e| NetworkError::InvalidResponse(format!("challenge body: {}", e)))?;

    let challenge_bytes = hex::decode(&challenge_body.challenge)
        .map_err(|e| NetworkError::InvalidResponse(format!("challenge hex: {}", e)))?;

    // Step 2: Sign the challenge.
    let signature = create_wallet_proof(privkey, &challenge_bytes)?;
    let signature_hex = hex::encode(&signature);

    // Step 3: Exchange signature for session token.
    let session_url = format!("{}/api/v1/wallet/{}/session", base, wallet_id);
    let session_resp = client
        .post(&session_url)
        .json(&SessionRequest {
            wallet_id: wallet_id.to_string(),
            signature: signature_hex,
            challenge: challenge_body.challenge,
        })
        .send()
        .await
        .map_err(|e| NetworkError::RequestFailed(format!("session: {}", e)))?;

    if !session_resp.status().is_success() {
        return Err(NetworkError::AuthenticationFailed(format!(
            "session creation failed: HTTP {}",
            session_resp.status()
        )));
    }

    let session_body: SessionResponse = session_resp
        .json()
        .await
        .map_err(|e| NetworkError::InvalidResponse(format!("session body: {}", e)))?;

    Ok(session_body.token)
}

/// Create a BIP-340 Schnorr signature proof over a challenge.
///
/// This is a deterministic Schnorr signature using the secp256k1 curve.
/// The challenge bytes are SHA-256 hashed before signing to ensure a
/// 32-byte message.
///
/// # Arguments
/// * `privkey` - 32-byte secp256k1 private key
/// * `challenge` - Arbitrary-length challenge bytes from the GSP
///
/// # Returns
/// 64-byte Schnorr signature.
pub fn create_wallet_proof(
    privkey: &[u8; 32],
    challenge: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    use secp256k1::{Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    let secp = Secp256k1::new();

    let secret_key = SecretKey::from_slice(privkey)
        .map_err(|e| NetworkError::AuthenticationFailed(format!("invalid privkey: {}", e)))?;

    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);

    // Hash the challenge to get a 32-byte message.
    let msg_hash = Sha256::digest(challenge);
    let msg = secp256k1::Message::from_digest_slice(&msg_hash)
        .map_err(|e| NetworkError::AuthenticationFailed(format!("message digest: {}", e)))?;

    // Produce a BIP-340 Schnorr signature.
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    Ok(sig.serialize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_proof_deterministic() {
        // A fixed private key (not used in production).
        let privkey: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let challenge = b"test-challenge-12345";

        let sig1 = create_wallet_proof(&privkey, challenge).unwrap();
        let sig2 = create_wallet_proof(&privkey, challenge).unwrap();

        // Schnorr with no aux rand should be deterministic.
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64);
    }

    #[test]
    fn test_wallet_proof_different_challenges() {
        let privkey: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let sig_a = create_wallet_proof(&privkey, b"challenge-a").unwrap();
        let sig_b = create_wallet_proof(&privkey, b"challenge-b").unwrap();

        // Different challenges should produce different signatures.
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn test_wallet_proof_invalid_key() {
        let bad_privkey: [u8; 32] = [0u8; 32]; // zero is invalid for secp256k1
        let result = create_wallet_proof(&bad_privkey, b"challenge");
        assert!(result.is_err());
    }
}
