//! Encrypted keystore for the wallet's master seed.
//!
//! On-disk format (binary, single file):
//!
//! ```text
//! offset  bytes        meaning
//! ------  -----------  -------
//! 0       4            file version (LE u32, currently 1)
//! 4       32           Argon2id salt
//! 36      12           AES-256-GCM nonce
//! 48      ...          ciphertext (BIP39 mnemonic in UTF-8 + GCM tag)
//! ```
//!
//! KDF: Argon2id (m=64MiB, t=3, p=4) → 32-byte key.
//! AEAD: AES-256-GCM with the derived key.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

const FILE_VERSION: u32 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + SALT_LEN + NONCE_LEN;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("kdf error: {0}")]
    Kdf(String),
    #[error("decryption failed (wrong passphrase or tampered file)")]
    Decrypt,
    #[error("invalid file format: {0}")]
    Format(String),
    #[error("bip39 error: {0}")]
    Bip39(String),
}

/// In-memory unlocked wallet seed. Mnemonic is zeroized on drop.
pub struct Keystore {
    mnemonic: Zeroizing<String>,
}

impl Keystore {
    /// Generate a new wallet with a fresh 24-word BIP39 mnemonic.
    /// Returns the keystore and the mnemonic string (display once at create time).
    pub fn create() -> Result<(Self, String), KeystoreError> {
        let mut entropy = [0u8; 32]; // 256 bits → 24 words
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| KeystoreError::Bip39(e.to_string()))?;
        let words = mnemonic.to_string();
        entropy.zeroize();
        Ok((
            Self {
                mnemonic: Zeroizing::new(words.clone()),
            },
            words,
        ))
    }

    /// Save the keystore to `path`, encrypted with `passphrase`.
    pub fn save(&self, path: &Path, passphrase: &SecretString) -> Result<(), KeystoreError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key = derive_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key.0)
            .map_err(|e| KeystoreError::Kdf(format!("cipher init: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, self.mnemonic.as_bytes())
            .map_err(|_| KeystoreError::Decrypt)?;

        let mut buf = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        buf.extend_from_slice(&FILE_VERSION.to_le_bytes());
        buf.extend_from_slice(&salt);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ciphertext);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &buf)?;
        // Restrict to user only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load the keystore from `path` and decrypt with `passphrase`.
    pub fn load(path: &Path, passphrase: &SecretString) -> Result<Self, KeystoreError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < HEADER_LEN {
            return Err(KeystoreError::Format("file shorter than header".into()));
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if version != FILE_VERSION {
            return Err(KeystoreError::Format(format!(
                "unsupported file version {version}"
            )));
        }
        let salt = &bytes[4..4 + SALT_LEN];
        let nonce_bytes = &bytes[4 + SALT_LEN..HEADER_LEN];
        let ciphertext = &bytes[HEADER_LEN..];

        let key = derive_key(passphrase, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key.0)
            .map_err(|e| KeystoreError::Kdf(format!("cipher init: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| KeystoreError::Decrypt)?;
        let mnemonic_str = String::from_utf8(plaintext)
            .map_err(|_| KeystoreError::Format("non-utf8 plaintext".into()))?;
        Ok(Self {
            mnemonic: Zeroizing::new(mnemonic_str),
        })
    }

    /// Return the mnemonic words. Avoid; use only when the user has explicitly
    /// asked to display the seed (recovery / backup).
    pub fn expose_mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }
}

struct KdfKey([u8; KEY_LEN]);
impl Drop for KdfKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn derive_key(passphrase: &SecretString, salt: &[u8]) -> Result<KdfKey, KeystoreError> {
    let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN))
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(KdfKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.bin");
        let pass = SecretString::new("correct horse battery staple".to_string().into());

        let (ks, mnemonic) = Keystore::create().unwrap();
        ks.save(&path, &pass).unwrap();

        let ks2 = Keystore::load(&path, &pass).unwrap();
        assert_eq!(ks.expose_mnemonic(), ks2.expose_mnemonic());
        assert_eq!(mnemonic, ks.expose_mnemonic());
        assert_eq!(mnemonic.split_whitespace().count(), 24);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.bin");
        let good = SecretString::new("good".to_string().into());
        let bad = SecretString::new("bad".to_string().into());

        let (ks, _) = Keystore::create().unwrap();
        ks.save(&path, &good).unwrap();
        match Keystore::load(&path, &bad) {
            Err(KeystoreError::Decrypt) => {}
            Err(other) => panic!("expected Decrypt error, got {other:?}"),
            Ok(_) => panic!("expected Decrypt error, got Ok"),
        }
    }

    #[test]
    fn wrong_version_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.bin");
        let pass = SecretString::new("p".to_string().into());

        let (ks, _) = Keystore::create().unwrap();
        ks.save(&path, &pass).unwrap();

        // Tamper with the version byte.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] = 99;
        std::fs::write(&path, bytes).unwrap();

        match Keystore::load(&path, &pass) {
            Err(KeystoreError::Format(msg)) if msg.contains("unsupported file version") => {}
            Err(other) => panic!("expected Format error, got {other:?}"),
            Ok(_) => panic!("expected Format error, got Ok"),
        }
    }
}
