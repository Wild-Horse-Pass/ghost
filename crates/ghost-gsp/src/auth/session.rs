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
}

/// JWT session manager
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_secs: u64,
}

impl JwtManager {
    /// Create a new JWT manager
    pub fn new(secret: &[u8], expiry_secs: u64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            expiry_secs,
        }
    }

    /// Create a new session token
    pub fn create_token(&self, wallet_id: &WalletId) -> GspResult<SessionToken> {
        let now = chrono::Utc::now().timestamp();
        let exp = now + self.expiry_secs as i64;

        let claims = Claims {
            sub: wallet_id.to_string(),
            iat: now,
            exp,
            iss: JWT_ISSUER.to_string(),
            aud: JWT_AUDIENCE.to_string(),
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
    pub fn validate_token(&self, token: &str) -> GspResult<WalletId> {
        let mut validation = Validation::default();
        // M-14: Require correct issuer
        validation.set_issuer(&[JWT_ISSUER]);
        // M-14: Require correct audience
        validation.set_audience(&[JWT_AUDIENCE]);

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => GspError::SessionExpired,
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    GspError::InvalidToken("Invalid token issuer".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    GspError::InvalidToken("Invalid token audience".to_string())
                }
                _ => GspError::InvalidToken(e.to_string()),
            }
        })?;

        Ok(WalletId::from(token_data.claims.sub))
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
}
