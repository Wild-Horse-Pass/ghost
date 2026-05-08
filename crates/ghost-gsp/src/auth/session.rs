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
//| FILE: auth/session.rs                                                                                                |
//|======================================================================================================================|

//! JWT session management

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tracing::warn;

use ghost_gsp_proto::{SessionToken, WalletId};

use crate::error::{GspError, GspResult};

/// M-14: JWT issuer for token validation
const JWT_ISSUER: &str = "ghost-gsp";

/// M-14: JWT audience for token validation
const JWT_AUDIENCE: &str = "ghost-wallet";

/// JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject (wallet ID)
    sub: String,

    /// Issued at (Unix timestamp)
    iat: i64,

    /// Expiration (Unix timestamp)
    exp: i64,

    /// M-14: Issuer
    iss: String,

    /// M-14: Audience
    aud: String,

    /// M-13 FIX: Client IP address for token binding
    /// Tokens are bound to the IP that created them to prevent session hijacking.
    /// If IP changes, a new token must be obtained.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,

    /// Static wallet ID derived directly from the wallet's public key
    /// (`WalletId::from_pubkey`). Distinct from `sub`, which carries
    /// the session-rotating wallet ID. We need both so that
    /// per-action `WalletProof` checks (which compare against the
    /// static derivation) can find the right wallet without needing
    /// the wallet to embed the session nonce in every proof.
    /// Optional for backwards compatibility with tokens issued
    /// before this field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    static_wallet_id: Option<String>,
}

/// H-10/M-2: Duration during which the previous key remains valid (graceful rotation window)
///
/// H-10 FIX: Reduced from 1 hour to 15 minutes to limit exposure window if a key is compromised.
/// The 15-minute window is sufficient for clients to refresh their tokens while minimizing
/// the time an attacker could exploit a stolen key.
const KEY_ROTATION_WINDOW_SECS: i64 = 900; // 15 minutes

/// JWT session manager with M-2 key rotation support
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// M-2: Previous key for graceful rotation (if any)
    previous_decoding_key: Option<DecodingKey>,
    /// M-2: When the previous key was rotated out (None if no previous key)
    previous_key_rotated_at: Option<i64>,
    expiry_secs: u64,
}

impl JwtManager {
    /// Create a new JWT manager
    pub fn new(secret: &[u8], expiry_secs: u64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            previous_decoding_key: None,
            previous_key_rotated_at: None,
            expiry_secs,
        }
    }

    /// M-2: Rotate to a new secret key
    ///
    /// The previous key will remain valid for verification during the rotation window
    /// (1 hour by default). This allows existing tokens to continue working during
    /// key rotation while all new tokens use the new key.
    ///
    /// # Security
    /// - Always sign new tokens with the current (new) key
    /// - Accept tokens signed with either current or previous key during rotation window
    /// - After rotation window, previous key is no longer accepted
    pub fn rotate_key(&mut self, new_secret: &[u8]) {
        // Move current key to previous
        let current_decoding_key =
            std::mem::replace(&mut self.decoding_key, DecodingKey::from_secret(new_secret));
        self.previous_decoding_key = Some(current_decoding_key);
        self.previous_key_rotated_at = Some(chrono::Utc::now().timestamp());

        // Update encoding key to new secret
        self.encoding_key = EncodingKey::from_secret(new_secret);
    }

    /// M-2: Check if the previous key is still within the rotation window
    fn is_previous_key_valid(&self) -> bool {
        if let Some(rotated_at) = self.previous_key_rotated_at {
            let now = chrono::Utc::now().timestamp();
            now - rotated_at < KEY_ROTATION_WINDOW_SECS
        } else {
            false
        }
    }

    /// Create a new session token
    ///
    /// # M-13 Security Fix
    /// Accepts an optional client IP to bind the token to. When provided, the
    /// token can only be validated from the same IP address, preventing session
    /// hijacking through token theft.
    pub fn create_token(&self, wallet_id: &WalletId) -> GspResult<SessionToken> {
        self.create_token_with_ip(wallet_id, None)
    }

    /// M-13 FIX: Create a new session token bound to a specific client IP
    pub fn create_token_with_ip(
        &self,
        wallet_id: &WalletId,
        client_ip: Option<String>,
    ) -> GspResult<SessionToken> {
        self.create_token_full(wallet_id, None, client_ip)
    }

    /// Create a session token carrying both the rotating session wallet ID
    /// (`sub`) AND the static wallet ID derived directly from the
    /// wallet's public key (`static_wallet_id`). The static ID lets
    /// per-action `WalletProof` checks find the wallet by its
    /// pubkey-derived ID without the wallet having to embed its
    /// session nonce in every proof — the rotating `sub` stays the
    /// privacy-preserving on-the-wire identifier.
    pub fn create_token_full(
        &self,
        wallet_id: &WalletId,
        static_wallet_id: Option<&WalletId>,
        client_ip: Option<String>,
    ) -> GspResult<SessionToken> {
        let now = chrono::Utc::now().timestamp();
        let exp = now + self.expiry_secs as i64;

        let claims = Claims {
            sub: wallet_id.to_string(),
            iat: now,
            exp,
            iss: JWT_ISSUER.to_string(),
            aud: JWT_AUDIENCE.to_string(),
            client_ip,
            static_wallet_id: static_wallet_id.map(|w| w.to_string()),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;

        Ok(SessionToken {
            token,
            wallet_id: wallet_id.clone(),
            created_at: now,
            expires_at: exp,
        })
    }

    /// Validate a token and return the wallet ID
    ///
    /// M-14: Validates issuer and audience claims to prevent token misuse
    /// M-2: During key rotation, accepts tokens signed with either current or previous key
    pub fn validate_token(&self, token: &str) -> GspResult<WalletId> {
        self.validate_token_with_ip(token, None)
    }

    /// M-13 FIX: Validate a token with IP binding check
    ///
    /// If the token has a bound IP and current_ip is provided, they must match.
    /// This prevents session hijacking through token theft - even if an attacker
    /// steals a token, they cannot use it from a different IP address.
    ///
    /// # Arguments
    /// * `token` - The JWT to validate
    /// * `current_ip` - The IP address of the current request (if available)
    ///
    /// # Security
    /// - If token has client_ip and current_ip is provided, they must match
    /// - If token has client_ip but current_ip is None, validation fails (fail closed)
    /// - If token has no client_ip, IP check is skipped (backwards compatible)
    pub fn validate_token_with_ip(
        &self,
        token: &str,
        current_ip: Option<&str>,
    ) -> GspResult<WalletId> {
        self.validate_token_full(token, current_ip)
            .map(|(session_id, _static)| session_id)
    }

    /// Validate the token and return BOTH the session-rotating wallet
    /// ID (`sub`) and the static wallet ID derived from the wallet's
    /// public key. The static ID is `None` for tokens issued before
    /// `static_wallet_id` was added to the JWT claims (backwards
    /// compatibility window). Callers that need the static ID for
    /// per-action `WalletProof` checks should refuse on `None` and
    /// surface a clear "session predates static-id binding,
    /// re-authenticate" error to the wallet.
    pub fn validate_token_full(
        &self,
        token: &str,
        current_ip: Option<&str>,
    ) -> GspResult<(WalletId, Option<WalletId>)> {
        let mut validation = Validation::default();
        // M-14: Require correct issuer
        validation.set_issuer(&[JWT_ISSUER]);
        // M-14: Require correct audience
        validation.set_audience(&[JWT_AUDIENCE]);

        // Try current key first
        match decode::<Claims>(token, &self.decoding_key, &validation) {
            Ok(token_data) => {
                self.verify_ip_binding(&token_data.claims, current_ip)?;
                let session_id = WalletId::from(token_data.claims.sub);
                let static_id = token_data.claims.static_wallet_id.map(WalletId::from);
                Ok((session_id, static_id))
            }
            Err(e) => {
                // M-2: If current key fails and we have a previous key in rotation window, try it
                if self.is_previous_key_valid() {
                    if let Some(ref prev_key) = self.previous_decoding_key {
                        if let Ok(token_data) = decode::<Claims>(token, prev_key, &validation) {
                            self.verify_ip_binding(&token_data.claims, current_ip)?;
                            let session_id = WalletId::from(token_data.claims.sub);
                            let static_id =
                                token_data.claims.static_wallet_id.map(WalletId::from);
                            return Ok((session_id, static_id));
                        }
                    }
                }

                // Neither key worked, return the error from the current key attempt
                Err(match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => GspError::SessionExpired,
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                        GspError::InvalidToken("Invalid token issuer".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                        GspError::InvalidToken("Invalid token audience".to_string())
                    }
                    _ => GspError::InvalidToken(e.to_string()),
                })
            }
        }
    }

    /// M-13 FIX: Verify IP binding in token claims
    ///
    /// If the token has a bound client_ip, verify it matches the current request IP.
    /// Fail closed: if token has IP but we can't verify, reject the token.
    fn verify_ip_binding(&self, claims: &Claims, current_ip: Option<&str>) -> GspResult<()> {
        match (&claims.client_ip, current_ip) {
            // Token has IP binding and we have current IP - must match
            (Some(bound_ip), Some(request_ip)) => {
                if bound_ip != request_ip {
                    warn!(
                        bound_ip = %bound_ip,
                        request_ip = %request_ip,
                        wallet_id = %claims.sub,
                        "M-13: Token IP binding mismatch - possible session hijacking attempt"
                    );
                    return Err(GspError::InvalidToken(
                        "Token IP binding mismatch - re-authentication required".to_string(),
                    ));
                }
                Ok(())
            }
            // Token has IP binding but we don't have current IP - fail closed for security
            (Some(bound_ip), None) => {
                warn!(
                    bound_ip = %bound_ip,
                    wallet_id = %claims.sub,
                    "M-13: Token has IP binding but current IP not available - rejecting"
                );
                Err(GspError::InvalidToken(
                    "Cannot verify IP binding - re-authentication required".to_string(),
                ))
            }
            // Token has no IP binding - allow (backwards compatible with old tokens)
            (None, _) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_token() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let manager = JwtManager::new(secret, 3600);

        let wallet_id = WalletId::from("test_wallet_id_123456789".to_string());
        let token = manager.create_token(&wallet_id).unwrap();

        assert!(!token.token.is_empty());
        assert_eq!(token.wallet_id, wallet_id);
        assert!(token.expires_at > token.created_at);

        // Validate token
        let validated_id = manager.validate_token(&token.token).unwrap();
        assert_eq!(validated_id, wallet_id);
    }

    #[test]
    fn test_invalid_token() {
        let secret = b"test_secret_key_32_bytes_long!!!";
        let manager = JwtManager::new(secret, 3600);

        let result = manager.validate_token("invalid_token");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret() {
        let secret1 = b"test_secret_key_32_bytes_long!!!";
        let secret2 = b"different_secret_key_32_bytes!!!";

        let manager1 = JwtManager::new(secret1, 3600);
        let manager2 = JwtManager::new(secret2, 3600);

        let wallet_id = WalletId::from("test_wallet".to_string());
        let token = manager1.create_token(&wallet_id).unwrap();

        // Token created with secret1 should not validate with secret2
        let result = manager2.validate_token(&token.token);
        assert!(result.is_err());
    }

    #[test]
    fn test_m2_key_rotation() {
        // M-2: Test key rotation with graceful window
        let secret1 = b"test_secret_key_32_bytes_long!!!";
        let secret2 = b"new_rotated_secret_32_bytes!!!!!";

        let mut manager = JwtManager::new(secret1, 3600);

        let wallet_id = WalletId::from("test_wallet".to_string());

        // Create token with old key
        let old_token = manager.create_token(&wallet_id).unwrap();

        // Rotate to new key
        manager.rotate_key(secret2);

        // Old token should still validate (within rotation window)
        let result = manager.validate_token(&old_token.token);
        assert!(
            result.is_ok(),
            "Old token should be valid during rotation window"
        );
        assert_eq!(result.unwrap(), wallet_id);

        // New token should also validate
        let new_token = manager.create_token(&wallet_id).unwrap();
        let result = manager.validate_token(&new_token.token);
        assert!(result.is_ok(), "New token should be valid");
        assert_eq!(result.unwrap(), wallet_id);
    }

    #[test]
    fn test_m2_new_tokens_use_new_key() {
        // M-2: Ensure new tokens are signed with the new key
        let secret1 = b"test_secret_key_32_bytes_long!!!";
        let secret2 = b"new_rotated_secret_32_bytes!!!!!";

        let mut manager = JwtManager::new(secret1, 3600);
        let wallet_id = WalletId::from("test_wallet".to_string());

        // Rotate to new key
        manager.rotate_key(secret2);

        // Create a token (should use new key)
        let new_token = manager.create_token(&wallet_id).unwrap();

        // Verify with a fresh manager using ONLY the new key
        let fresh_manager = JwtManager::new(secret2, 3600);
        let result = fresh_manager.validate_token(&new_token.token);
        assert!(result.is_ok(), "Token should be signed with new key");

        // Old key should NOT work for new tokens
        let old_only_manager = JwtManager::new(secret1, 3600);
        let result = old_only_manager.validate_token(&new_token.token);
        assert!(result.is_err(), "Token should NOT validate with old key");
    }
}
