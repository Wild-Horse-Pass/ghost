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
//| FILE: auth/registry.rs                                                                                               |
//|======================================================================================================================|

//! Wallet registry - stores wallet_id -> pubkey mappings

use std::path::Path;

use parking_lot::Mutex;
use rusqlite::{params, Connection};

use ghost_gsp_proto::{WalletId, WalletProof};

use crate::auth::verify_schnorr_proof;
use crate::error::{GspError, GspResult};

/// Wallet registry backed by SQLite
pub struct WalletRegistry {
    conn: Mutex<Connection>,
}

impl WalletRegistry {
    /// Open or create the wallet registry database
    pub fn open(path: &Path) -> GspResult<Self> {
        let conn = Connection::open(path)?;

        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS wallets (
                wallet_id TEXT PRIMARY KEY,
                pubkey BLOB NOT NULL,
                display_name TEXT,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            )",
            [],
        )?;

        // Create index on created_at
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_wallets_created ON wallets(created_at)",
            [],
        )?;

        // Create nonce tracking table for replay protection
        conn.execute(
            "CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                wallet_id TEXT NOT NULL,
                used_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Create index for nonce cleanup
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nonces_used_at ON used_nonces(used_at)",
            [],
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Check if a wallet is registered
    pub fn is_registered(&self, wallet_id: &WalletId) -> GspResult<bool> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM wallets WHERE wallet_id = ?",
            [wallet_id.as_str()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Register a new wallet
    pub fn register(
        &self,
        wallet_id: &WalletId,
        pubkey: &[u8; 32],
        display_name: Option<&str>,
    ) -> GspResult<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO wallets (wallet_id, pubkey, display_name, created_at, last_seen)
             VALUES (?, ?, ?, ?, ?)",
            params![wallet_id.as_str(), pubkey.as_slice(), display_name, now, now],
        )?;

        Ok(())
    }

    /// Get the public key for a wallet
    pub fn get_pubkey(&self, wallet_id: &WalletId) -> GspResult<Option<[u8; 32]>> {
        let conn = self.conn.lock();
        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT pubkey FROM wallets WHERE wallet_id = ?",
            [wallet_id.as_str()],
            |row| row.get(0),
        );

        match result {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            Ok(_) => Err(GspError::Database("Invalid pubkey length".to_string())),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update last seen timestamp
    pub fn update_last_seen(&self, wallet_id: &WalletId) -> GspResult<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "UPDATE wallets SET last_seen = ? WHERE wallet_id = ?",
            params![now, wallet_id.as_str()],
        )?;

        Ok(())
    }

    /// Check if a nonce has been used (replay protection)
    pub fn is_nonce_used(&self, nonce: &str) -> GspResult<bool> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM used_nonces WHERE nonce = ?",
            [nonce],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Mark a nonce as used
    pub fn mark_nonce_used(&self, nonce: &str, wallet_id: &WalletId) -> GspResult<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT OR IGNORE INTO used_nonces (nonce, wallet_id, used_at)
             VALUES (?, ?, ?)",
            params![nonce, wallet_id.as_str(), now],
        )?;

        Ok(())
    }

    /// Cleanup old nonces (older than 1 hour)
    pub fn cleanup_old_nonces(&self) -> GspResult<usize> {
        let conn = self.conn.lock();
        let cutoff = chrono::Utc::now().timestamp() - 3600;

        let deleted = conn.execute(
            "DELETE FROM used_nonces WHERE used_at < ?",
            [cutoff],
        )?;

        Ok(deleted)
    }

    /// Verify a wallet proof (signature + nonce)
    pub fn verify_proof(&self, proof: &WalletProof) -> GspResult<()> {
        // Check nonce hasn't been used
        if self.is_nonce_used(&proof.nonce)? {
            return Err(GspError::InvalidCredentials("Nonce already used".to_string()));
        }

        // Verify Schnorr signature
        verify_schnorr_proof(proof)?;

        // Mark nonce as used
        let wallet_id = proof.wallet_id().map_err(|e| {
            GspError::InvalidCredentials(format!("Invalid wallet ID: {}", e))
        })?;
        self.mark_nonce_used(&proof.nonce, &wallet_id)?;

        Ok(())
    }

    /// Get total number of registered wallets
    pub fn wallet_count(&self) -> GspResult<u64> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM wallets", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_registry() -> (WalletRegistry, NamedTempFile) {
        let temp = NamedTempFile::new().unwrap();
        let registry = WalletRegistry::open(temp.path()).unwrap();
        (registry, temp)
    }

    #[test]
    fn test_register_wallet() {
        let (registry, _temp) = create_test_registry();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());
        let pubkey = [1u8; 32];

        // Not registered initially
        assert!(!registry.is_registered(&wallet_id).unwrap());

        // Register
        registry.register(&wallet_id, &pubkey, Some("Test Wallet")).unwrap();

        // Now registered
        assert!(registry.is_registered(&wallet_id).unwrap());

        // Can get pubkey
        let stored = registry.get_pubkey(&wallet_id).unwrap();
        assert_eq!(stored, Some(pubkey));
    }

    #[test]
    fn test_nonce_tracking() {
        let (registry, _temp) = create_test_registry();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());

        // Nonce not used
        assert!(!registry.is_nonce_used("test_nonce").unwrap());

        // Mark as used
        registry.mark_nonce_used("test_nonce", &wallet_id).unwrap();

        // Now used
        assert!(registry.is_nonce_used("test_nonce").unwrap());
    }

    #[test]
    fn test_wallet_count() {
        let (registry, _temp) = create_test_registry();

        assert_eq!(registry.wallet_count().unwrap(), 0);

        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());
        registry.register(&wallet_id, &[1u8; 32], None).unwrap();

        assert_eq!(registry.wallet_count().unwrap(), 1);
    }
}
