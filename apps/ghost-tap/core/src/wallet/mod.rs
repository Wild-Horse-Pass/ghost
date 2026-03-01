//! Wallet management module
//!
//! Handles wallet creation, recovery, key derivation, and balance tracking.

pub mod auth;
mod balance;
mod history;
mod keys;

pub use auth::*;
pub use balance::*;
pub use history::*;
pub use keys::*;

use secrecy::SecretString;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid mnemonic phrase")]
    InvalidMnemonic,

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Wallet not initialized")]
    NotInitialized,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Wallet is locked")]
    Locked,
}

/// Represents a Ghost Pay wallet
pub struct Wallet {
    /// Wallet identifier (hash of master public key)
    pub id: String,
    /// Master seed (encrypted in production)
    seed: Zeroizing<[u8; 64]>,
    /// Current account index
    account_index: u32,
    /// Next receive address index
    next_receive_index: u32,
    /// Next change address index
    next_change_index: u32,
    /// UTXO set for this wallet
    utxo_set: UtxoSet,
    /// Transaction history
    history: TransactionHistory,
    /// Whether wallet is locked
    is_locked: bool,
}

impl Wallet {
    /// Create a new wallet from a mnemonic phrase
    ///
    /// # Arguments
    /// * `mnemonic` - BIP39 mnemonic phrase (12 or 24 words)
    /// * `passphrase` - Optional BIP39 passphrase
    ///
    /// # Returns
    /// A new wallet instance
    pub fn from_mnemonic(
        mnemonic: &SecretString,
        passphrase: Option<&SecretString>,
    ) -> Result<Self, WalletError> {
        let seed = derive_seed_from_mnemonic(mnemonic, passphrase)?;

        // Derive wallet ID from first address public key
        let (_, pubkey) = derive_keypair_at_path(&seed, 0, 0, 0)?;
        let pubkey_hash = Sha256::digest(pubkey.serialize());
        let id = hex::encode(&pubkey_hash[..8]);

        Ok(Self {
            id,
            seed,
            account_index: 0,
            next_receive_index: 0,
            next_change_index: 0,
            utxo_set: UtxoSet::new(),
            history: TransactionHistory::new(),
            is_locked: false,
        })
    }

    /// Generate a new wallet with a fresh mnemonic
    ///
    /// # Arguments
    /// * `word_count` - Number of words (12 or 24)
    ///
    /// # Returns
    /// Tuple of (wallet, mnemonic phrase)
    pub fn generate(word_count: WordCount) -> Result<(Self, SecretString), WalletError> {
        let mnemonic = generate_mnemonic(word_count)?;
        let wallet = Self::from_mnemonic(&mnemonic, None)?;
        Ok((wallet, mnemonic))
    }

    /// Lock the wallet (requires authentication to unlock)
    pub fn lock(&mut self) {
        self.is_locked = true;
    }

    /// Unlock the wallet
    pub fn unlock(&mut self) {
        self.is_locked = false;
    }

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Get the current confirmed balance
    pub fn balance(&self) -> u64 {
        self.utxo_set.balance().confirmed
    }

    /// Get detailed balance information
    pub fn balance_details(&self) -> Balance {
        self.utxo_set.balance()
    }

    /// Generate a new receive address
    pub fn new_receive_address(&mut self) -> Result<String, WalletError> {
        if self.is_locked {
            return Err(WalletError::Locked);
        }

        let address = derive_address_at_path(
            &self.seed,
            self.account_index,
            0, // receive addresses use change=0
            self.next_receive_index,
        )?;

        self.next_receive_index += 1;
        Ok(address)
    }

    /// Generate a new change address (internal use)
    pub fn new_change_address(&mut self) -> Result<String, WalletError> {
        if self.is_locked {
            return Err(WalletError::Locked);
        }

        let address = derive_address_at_path(
            &self.seed,
            self.account_index,
            1, // change addresses use change=1
            self.next_change_index,
        )?;

        self.next_change_index += 1;
        Ok(address)
    }

    /// Get the private key for a specific address path
    pub fn get_private_key(
        &self,
        change: u32,
        address_index: u32,
    ) -> Result<Zeroizing<[u8; 32]>, WalletError> {
        if self.is_locked {
            return Err(WalletError::Locked);
        }

        derive_key_at_path(&self.seed, self.account_index, change, address_index)
    }

    /// Get all addresses generated so far (for scanning)
    pub fn get_all_addresses(&self) -> Result<Vec<String>, WalletError> {
        let mut addresses = Vec::new();

        // Receive addresses
        for i in 0..self.next_receive_index {
            addresses.push(derive_address_at_path(&self.seed, self.account_index, 0, i)?);
        }

        // Change addresses
        for i in 0..self.next_change_index {
            addresses.push(derive_address_at_path(&self.seed, self.account_index, 1, i)?);
        }

        Ok(addresses)
    }

    /// Add a UTXO to the wallet
    pub fn add_utxo(&mut self, utxo: Utxo) {
        self.utxo_set.add(utxo);
    }

    /// Mark a UTXO as spent
    pub fn spend_utxo(&mut self, txid: &str, vout: u32) -> Option<Utxo> {
        self.utxo_set.spend(txid, vout)
    }

    /// Get all available UTXOs
    pub fn get_utxos(&self) -> &[Utxo] {
        self.utxo_set.all()
    }

    /// Get the UTXO set (for transaction building)
    pub fn utxo_set(&self) -> &UtxoSet {
        &self.utxo_set
    }

    /// Add a transaction to history
    pub fn add_history(&mut self, entry: HistoryEntry) {
        self.history.add(entry);
    }

    /// Get transaction history
    pub fn get_history(&self) -> &[HistoryEntry] {
        self.history.all()
    }

    /// Get pending transactions
    pub fn get_pending_transactions(&self) -> Vec<&HistoryEntry> {
        self.history.pending()
    }
}

/// Create an encrypted backup of a mnemonic phrase.
///
/// Derives an AES-256-GCM key from `password` via SHA-256 and encrypts
/// the mnemonic bytes. The returned blob is nonce ‖ ciphertext.
pub fn export_encrypted_backup(
    mnemonic: &SecretString,
    password: &str,
) -> Result<Vec<u8>, WalletError> {
    use secrecy::ExposeSecret;

    let key = Sha256::digest(password.as_bytes());
    let key: [u8; 32] = key.into();
    crate::crypto::encrypt_aes_gcm(mnemonic.expose_secret().as_bytes(), &key)
        .map_err(|e| WalletError::KeyDerivation(format!("backup encryption failed: {e}")))
}

/// Restore a wallet from an encrypted backup.
///
/// Decrypts the blob with the password-derived key, validates the
/// resulting mnemonic, and returns both the wallet and mnemonic.
pub fn from_encrypted_backup(
    encrypted: &[u8],
    password: &str,
) -> Result<(Wallet, SecretString), WalletError> {
    let key = Sha256::digest(password.as_bytes());
    let key: [u8; 32] = key.into();
    let plaintext = crate::crypto::decrypt_aes_gcm(encrypted, &key)
        .map_err(|e| WalletError::KeyDerivation(format!("backup decryption failed: {e}")))?;

    let mnemonic_str = String::from_utf8(plaintext)
        .map_err(|_| WalletError::InvalidMnemonic)?;

    if !validate_mnemonic(&mnemonic_str) {
        return Err(WalletError::InvalidMnemonic);
    }

    let secret = SecretString::new(mnemonic_str);
    let wallet = Wallet::from_mnemonic(&secret, None)?;
    Ok((wallet, secret))
}

impl Drop for Wallet {
    fn drop(&mut self) {
        // Seed is automatically zeroized via Zeroizing wrapper
        self.id.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let result = Wallet::generate(WordCount::Words12);
        assert!(result.is_ok());

        let (wallet, _mnemonic) = result.unwrap();
        assert!(!wallet.id.is_empty());
    }

    #[test]
    fn test_address_generation() {
        let (mut wallet, _) = Wallet::generate(WordCount::Words12).unwrap();

        let addr1 = wallet.new_receive_address().unwrap();
        let addr2 = wallet.new_receive_address().unwrap();

        // Each address should be unique
        assert_ne!(addr1, addr2);

        // Addresses should be base58 encoded
        assert!(addr1.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_wallet_locking() {
        let (mut wallet, _) = Wallet::generate(WordCount::Words12).unwrap();

        // Should work when unlocked
        assert!(wallet.new_receive_address().is_ok());

        // Lock wallet
        wallet.lock();
        assert!(wallet.is_locked());

        // Should fail when locked
        assert!(matches!(
            wallet.new_receive_address(),
            Err(WalletError::Locked)
        ));

        // Unlock and try again
        wallet.unlock();
        assert!(wallet.new_receive_address().is_ok());
    }

    #[test]
    fn test_deterministic_recovery() {
        let mnemonic = SecretString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into()
        );

        let wallet1 = Wallet::from_mnemonic(&mnemonic, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(&mnemonic, None).unwrap();

        // Same mnemonic should produce same wallet ID
        assert_eq!(wallet1.id, wallet2.id);
    }

    #[test]
    fn test_encrypted_backup_roundtrip() {
        use secrecy::ExposeSecret;

        let mnemonic = SecretString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into()
        );
        let password = "test-password-123";

        let encrypted = export_encrypted_backup(&mnemonic, password).unwrap();
        assert!(!encrypted.is_empty());

        let (wallet, recovered) = from_encrypted_backup(&encrypted, password).unwrap();
        assert_eq!(recovered.expose_secret(), mnemonic.expose_secret());
        assert!(!wallet.id.is_empty());
    }

    #[test]
    fn test_encrypted_backup_wrong_password() {
        let mnemonic = SecretString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into()
        );
        let encrypted = export_encrypted_backup(&mnemonic, "correct").unwrap();
        assert!(from_encrypted_backup(&encrypted, "wrong").is_err());
    }
}
