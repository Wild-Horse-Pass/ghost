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

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Derive a 32-byte key from a password and salt using Argon2id.
fn derive_key_argon2(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    use argon2::Argon2;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| WalletError::KeyDerivation(format!("Argon2 KDF failed: {e}")))?;
    Ok(key)
}

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
    /// L2 confidential spending key (lazily derived from seed)
    l2_spending_key: Option<Zeroizing<[u8; 32]>>,
    /// L2 scan secret key (lazily derived from seed)
    l2_scan_secret: Option<SecretKey>,
    /// L2 note store (lazily initialized)
    note_store: Option<crate::l2::NoteStore>,
    /// L2 tree sync (lazily initialized)
    tree_sync: Option<crate::l2::TreeSync>,
    /// L2 prover (lazily initialized, heavy — loads MPC params)
    l2_prover: Option<crate::l2::L2Prover>,
    /// L2 params cache
    params_cache: Option<crate::l2::ParamsCache>,
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
            l2_spending_key: None,
            l2_scan_secret: None,
            note_store: None,
            tree_sync: None,
            l2_prover: None,
            params_cache: None,
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

    /// Unlock the wallet after verifying PIN.
    /// If no PIN is set, allows unlock directly (first-time use).
    pub fn unlock_with_pin(&mut self, pin: &str) -> Result<(), WalletError> {
        let pm = crate::wallet::auth::PinManager::new();
        if pm.has_pin() {
            match pm.verify_pin(pin) {
                Ok(true) => {
                    self.is_locked = false;
                    Ok(())
                }
                Ok(false) => Err(WalletError::Locked),
                Err(e) => Err(WalletError::KeyDerivation(e.to_string())),
            }
        } else {
            self.is_locked = false;
            Ok(())
        }
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
            addresses.push(derive_address_at_path(
                &self.seed,
                self.account_index,
                0,
                i,
            )?);
        }

        // Change addresses
        for i in 0..self.next_change_index {
            addresses.push(derive_address_at_path(
                &self.seed,
                self.account_index,
                1,
                i,
            )?);
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

    // =============================================================================
    // L2 Confidential Key Access
    // =============================================================================

    /// Ensure L2 keys are derived. Lazily derives from seed on first call.
    pub fn ensure_l2_keys(&mut self) -> Result<(), WalletError> {
        if self.l2_spending_key.is_none() {
            self.l2_spending_key = Some(derive_l2_spending_key(&self.seed)?);
        }
        if self.l2_scan_secret.is_none() {
            self.l2_scan_secret = Some(derive_l2_scan_secret(&self.seed)?);
        }
        Ok(())
    }

    /// Get the L2 confidential spending key (derives if needed).
    pub fn l2_spending_key(&mut self) -> Result<&[u8; 32], WalletError> {
        self.ensure_l2_keys()?;
        Ok(self.l2_spending_key.as_ref().unwrap())
    }

    /// Get the L2 scan secret key (derives if needed).
    pub fn l2_scan_secret(&mut self) -> Result<&SecretKey, WalletError> {
        self.ensure_l2_keys()?;
        Ok(self.l2_scan_secret.as_ref().unwrap())
    }

    /// Get the L2 owner public key for receiving encrypted notes.
    pub fn l2_owner_pubkey(&mut self) -> Result<PublicKey, WalletError> {
        let secret = *self.l2_scan_secret()?;
        let secp = Secp256k1::new();
        Ok(PublicKey::from_secret_key(&secp, &secret))
    }

    /// Get the raw seed bytes (for L2 key derivation by external modules).
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Ensure the L2 NoteStore is initialized.
    pub fn ensure_note_store(&mut self) -> Result<(), WalletError> {
        if self.note_store.is_none() {
            let spending_key = derive_l2_spending_key(&self.seed)?;
            self.note_store = Some(crate::l2::NoteStore::new(*spending_key));
        }
        Ok(())
    }

    /// Ensure the L2 TreeSync is initialized.
    pub fn ensure_tree_sync(&mut self) {
        if self.tree_sync.is_none() {
            self.tree_sync = Some(crate::l2::TreeSync::new(20));
        }
    }

    /// Get L2 confidential balance.
    pub fn l2_balance(&mut self) -> Result<u64, WalletError> {
        self.ensure_note_store()?;
        Ok(self.note_store.as_ref().unwrap().l2_balance())
    }

    /// Get count of unspent L2 notes.
    pub fn l2_note_count(&mut self) -> Result<usize, WalletError> {
        self.ensure_note_store()?;
        Ok(self.note_store.as_ref().unwrap().unspent_count())
    }

    /// Get a reference to the note store (initializes if needed).
    pub fn note_store_mut(&mut self) -> Result<&mut crate::l2::NoteStore, WalletError> {
        self.ensure_note_store()?;
        Ok(self.note_store.as_mut().unwrap())
    }

    /// Get a reference to the tree sync (initializes if needed).
    pub fn tree_sync_mut(&mut self) -> &mut crate::l2::TreeSync {
        self.ensure_tree_sync();
        self.tree_sync.as_mut().unwrap()
    }

    /// Get the NoteStore (immutable, for reading).
    pub fn note_store(&self) -> Option<&crate::l2::NoteStore> {
        self.note_store.as_ref()
    }

    /// Get the TreeSync (immutable).
    pub fn tree_sync(&self) -> Option<&crate::l2::TreeSync> {
        self.tree_sync.as_ref()
    }

    /// Set the note store (e.g., loaded from storage).
    pub fn set_note_store(&mut self, store: crate::l2::NoteStore) {
        self.note_store = Some(store);
    }

    /// Set the params cache directory.
    pub fn set_params_cache(&mut self, cache: crate::l2::ParamsCache) {
        self.params_cache = Some(cache);
    }

    /// Ensure the L2 prover is loaded from cached MPC params.
    pub fn ensure_l2_prover(&mut self, params_dir: &std::path::Path) -> Result<(), WalletError> {
        if self.l2_prover.is_some() {
            return Ok(());
        }
        let prover = crate::l2::L2Prover::from_params_dir(params_dir, 20)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to load L2 prover: {}", e)))?;
        self.l2_prover = Some(prover);
        Ok(())
    }

    /// Get a reference to the L2 prover (must be initialized first).
    pub fn l2_prover(&self) -> Option<&crate::l2::L2Prover> {
        self.l2_prover.as_ref()
    }

    /// Get the params cache (if set).
    pub fn params_cache(&self) -> Option<&crate::l2::ParamsCache> {
        self.params_cache.as_ref()
    }
}

/// Create an encrypted backup of a mnemonic phrase.
///
/// Derives an AES-256-GCM key from `password` via Argon2id with a random
/// 16-byte salt. Output format: `salt(16) || nonce(12) || ciphertext`.
pub fn export_encrypted_backup(
    mnemonic: &SecretString,
    password: &str,
) -> Result<Vec<u8>, WalletError> {
    use secrecy::ExposeSecret;

    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| WalletError::KeyDerivation(format!("RNG failed: {e}")))?;

    let key = derive_key_argon2(password.as_bytes(), &salt)?;
    let encrypted = crate::crypto::encrypt_aes_gcm(mnemonic.expose_secret().as_bytes(), &key)
        .map_err(|e| WalletError::KeyDerivation(format!("backup encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(16 + encrypted.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

/// Restore a wallet from an encrypted backup.
///
/// Reads 16-byte salt prefix, derives key via Argon2id, decrypts the
/// remainder, validates the mnemonic, and returns both wallet and mnemonic.
pub fn from_encrypted_backup(
    encrypted: &[u8],
    password: &str,
) -> Result<(Wallet, SecretString), WalletError> {
    if encrypted.len() < 16 {
        return Err(WalletError::KeyDerivation("backup too short".into()));
    }

    let (salt, ciphertext) = encrypted.split_at(16);
    let key = derive_key_argon2(password.as_bytes(), salt)?;
    let plaintext = crate::crypto::decrypt_aes_gcm(ciphertext, &key)
        .map_err(|e| WalletError::KeyDerivation(format!("backup decryption failed: {e}")))?;

    let mnemonic_str =
        Zeroizing::new(String::from_utf8(plaintext).map_err(|_| WalletError::InvalidMnemonic)?);

    if !validate_mnemonic(&mnemonic_str) {
        return Err(WalletError::InvalidMnemonic);
    }

    let secret = SecretString::new(mnemonic_str.to_string());
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
        wallet.unlock_with_pin("").unwrap();
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
