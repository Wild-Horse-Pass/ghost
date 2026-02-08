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

use crate::auth::{verify_proof_and_extract_wallet_id, verify_proof_with_wallet_id};
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
            params![
                wallet_id.as_str(),
                pubkey.as_slice(),
                display_name,
                now,
                now
            ],
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

    /// M-14 FIX: Cleanup old nonces with safe buffer to prevent replay attacks
    ///
    /// Nonces must be kept for at least PROOF_TIMESTAMP_TOLERANCE_SECS + buffer to prevent
    /// a race condition where:
    /// 1. User creates proof at T
    /// 2. Cleanup runs at T + tolerance, deleting the nonce
    /// 3. Attacker replays the proof at T + tolerance (still within tolerance window)
    ///
    /// The cleanup cutoff is now PROOF_TIMESTAMP_TOLERANCE_SECS + 300 seconds (5 min buffer)
    /// to ensure nonces are never deleted while the corresponding proof could still be valid.
    pub fn cleanup_old_nonces(&self) -> GspResult<usize> {
        use ghost_gsp_proto::PROOF_TIMESTAMP_TOLERANCE_SECS;

        let conn = self.conn.lock();
        // M-14: Ensure cleanup cutoff is at least PROOF_TIMESTAMP_TOLERANCE_SECS + 300 second buffer
        // This prevents the race condition where a nonce is cleaned up while its proof is still valid.
        // PROOF_TIMESTAMP_TOLERANCE_SECS = 300 (5 min), buffer = 300 (5 min), total = 600 seconds
        let safe_retention_secs = PROOF_TIMESTAMP_TOLERANCE_SECS + 300;
        let cutoff = chrono::Utc::now().timestamp() - safe_retention_secs;

        let deleted = conn.execute("DELETE FROM used_nonces WHERE used_at < ?", [cutoff])?;

        Ok(deleted)
    }

    /// Verify a wallet proof for registration (signature + nonce + extract wallet ID)
    ///
    /// This is used during registration when we don't yet have an expected wallet ID.
    /// The wallet ID is derived from the proof's public key.
    pub fn verify_proof(&self, proof: &WalletProof) -> GspResult<()> {
        // Check nonce hasn't been used (replay protection)
        if self.is_nonce_used(&proof.nonce)? {
            return Err(GspError::NonceReplay);
        }

        // Verify signature and extract wallet ID
        let wallet_id = verify_proof_and_extract_wallet_id(proof)?;

        // Mark nonce as used to prevent replay attacks
        self.mark_nonce_used(&proof.nonce, &wallet_id)?;

        Ok(())
    }

    /// Verify a wallet proof against an expected wallet ID (signature + nonce + wallet ID validation)
    ///
    /// This is used for authenticated operations where we have a session wallet ID.
    /// It verifies:
    /// 1. Schnorr signature is valid
    /// 2. Public key in proof derives to the expected wallet ID
    /// 3. Nonce hasn't been used (replay protection)
    ///
    /// MED-RESOURCE-1 FIX: Periodically cleans up old nonces on each verification.
    pub fn verify_proof_for_wallet(
        &self,
        proof: &WalletProof,
        expected_wallet_id: &WalletId,
    ) -> GspResult<()> {
        // MED-RESOURCE-1 FIX: Probabilistically cleanup old nonces
        // Run cleanup ~1% of the time to avoid overhead on every request
        // while still ensuring nonces are eventually cleaned up
        self.maybe_cleanup_nonces();

        // Check nonce hasn't been used (replay protection)
        if self.is_nonce_used(&proof.nonce)? {
            return Err(GspError::NonceReplay);
        }

        // Verify signature and wallet ID derivation
        verify_proof_with_wallet_id(proof, expected_wallet_id)?;

        // Mark nonce as used to prevent replay attacks
        self.mark_nonce_used(&proof.nonce, expected_wallet_id)?;

        Ok(())
    }

    /// MED-RESOURCE-1 FIX: Probabilistically cleanup old nonces
    ///
    /// Runs cleanup approximately 1% of the time to avoid overhead
    /// while ensuring nonces are eventually cleaned up.
    fn maybe_cleanup_nonces(&self) {
        // Use a simple random check - cleanup ~1% of the time
        // H-3 FIX: Use OsRng for cryptographic security instead of thread_rng()
        use rand::rngs::OsRng;
        use rand::Rng;
        if OsRng.gen_range(0..100) == 0 {
            if let Ok(deleted) = self.cleanup_old_nonces() {
                if deleted > 0 {
                    tracing::debug!(
                        deleted_nonces = deleted,
                        "MED-RESOURCE-1: Cleaned up old nonces"
                    );
                }
            }
        }
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
        registry
            .register(&wallet_id, &pubkey, Some("Test Wallet"))
            .unwrap();

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
