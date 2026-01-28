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
//| FILE: keys/storage.rs                                                                                                |
//|======================================================================================================================|

//! Encrypted key storage using scrypt + ChaCha20-Poly1305

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use scrypt::{scrypt, Params as ScryptParams};

use crate::error::{LightWalletError, WalletResult};

/// Salt size for scrypt
const SALT_SIZE: usize = 32;

/// Nonce size for AES-GCM
const NONCE_SIZE: usize = 12;

/// scrypt parameters (N=2^15, r=8, p=1)
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Derive encryption key from password using scrypt
fn derive_key(password: &str, salt: &[u8]) -> WalletResult<[u8; 32]> {
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|e| LightWalletError::Encryption(format!("scrypt params error: {}", e)))?;

    let mut key = [0u8; 32];
    scrypt(password.as_bytes(), salt, &params, &mut key)
        .map_err(|e| LightWalletError::Encryption(format!("scrypt error: {}", e)))?;

    Ok(key)
}

/// Encrypt data with password
///
/// Returns: salt (32) || nonce (12) || ciphertext
pub fn encrypt_key(plaintext: &[u8], password: &str) -> WalletResult<Vec<u8>> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];

    getrandom::getrandom(&mut salt)
        .map_err(|e| LightWalletError::Encryption(format!("RNG error: {}", e)))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| LightWalletError::Encryption(format!("RNG error: {}", e)))?;

    // Derive key
    let key = derive_key(password, &salt)?;

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| LightWalletError::Encryption(format!("cipher error: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LightWalletError::Encryption(format!("encryption error: {}", e)))?;

    // Combine: salt || nonce || ciphertext
    let mut result = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with password
///
/// Expects: salt (32) || nonce (12) || ciphertext
pub fn decrypt_key(encrypted: &[u8], password: &str) -> WalletResult<Vec<u8>> {
    if encrypted.len() < SALT_SIZE + NONCE_SIZE + 16 {
        // 16 is min auth tag
        return Err(LightWalletError::DecryptionFailed);
    }

    // Extract components
    let salt = &encrypted[0..SALT_SIZE];
    let nonce_bytes = &encrypted[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted[SALT_SIZE + NONCE_SIZE..];

    // Derive key
    let key = derive_key(password, salt)?;

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| LightWalletError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LightWalletError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = b"secret key data here";
        let password = "test_password_123";

        let encrypted = encrypt_key(plaintext, password).unwrap();

        // Encrypted should be larger than plaintext
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_key(&encrypted, password).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password() {
        let plaintext = b"secret key data here";

        let encrypted = encrypt_key(plaintext, "correct_password").unwrap();

        let result = decrypt_key(&encrypted, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_key_derivation() {
        let password = "test_password";
        let salt = [1u8; 32];

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_salts() {
        let password = "test_password";

        let key1 = derive_key(password, &[1u8; 32]).unwrap();
        let key2 = derive_key(password, &[2u8; 32]).unwrap();

        assert_ne!(key1, key2);
    }
}
