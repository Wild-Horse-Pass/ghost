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
//| FILE: state/cache.rs                                                                                                 |
//|======================================================================================================================|

//! SQLite-based encrypted wallet cache

use std::path::Path;

use rusqlite::{params, Connection};
use tracing::{debug, info};

use crate::error::{LightWalletError, WalletResult};
use crate::keys::{decrypt_key, encrypt_key, MasterKey};
use crate::wallet::WalletBalance;

/// Current cache schema version
const SCHEMA_VERSION: u32 = 1;

/// Local wallet cache using SQLite
pub struct WalletCache {
    /// Database connection
    conn: Connection,
}

impl WalletCache {
    /// Open or create the cache database
    pub fn open(path: &Path, _password: &str) -> WalletResult<Self> {
        info!(path = ?path, "Opening wallet cache");

        let conn = Connection::open(path)?;

        let cache = Self { conn };
        cache.init_schema()?;

        Ok(cache)
    }

    /// Initialize database schema
    fn init_schema(&self) -> WalletResult<()> {
        // Check schema version
        let user_version: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);

        if user_version < SCHEMA_VERSION {
            debug!(
                current = user_version,
                target = SCHEMA_VERSION,
                "Upgrading schema"
            );
            self.create_tables()?;
            self.conn
                .execute(&format!("PRAGMA user_version = {}", SCHEMA_VERSION), [])?;
        }

        Ok(())
    }

    /// Create database tables
    fn create_tables(&self) -> WalletResult<()> {
        self.conn.execute_batch(
            "
            -- Encrypted master key storage
            CREATE TABLE IF NOT EXISTS master_key (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                encrypted_data BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- Cached balance
            CREATE TABLE IF NOT EXISTS balance (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                confirmed INTEGER NOT NULL DEFAULT 0,
                unconfirmed INTEGER NOT NULL DEFAULT 0,
                locked INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            );

            -- Transaction history cache
            CREATE TABLE IF NOT EXISTS transactions (
                txid TEXT PRIMARY KEY,
                amount_sats INTEGER NOT NULL,
                is_incoming INTEGER NOT NULL,
                status TEXT NOT NULL,
                counterparty TEXT,
                memo TEXT,
                created_at INTEGER NOT NULL,
                confirmed_at INTEGER
            );

            -- Ghost Lock cache
            CREATE TABLE IF NOT EXISTS ghost_locks (
                lock_id TEXT PRIMARY KEY,
                capacity_sats INTEGER NOT NULL,
                used_sats INTEGER NOT NULL,
                status TEXT NOT NULL,
                funding_txid TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- Addresses cache
            CREATE TABLE IF NOT EXISTS addresses (
                address TEXT PRIMARY KEY,
                address_type TEXT NOT NULL,
                derivation_index INTEGER,
                label TEXT,
                created_at INTEGER NOT NULL
            );

            -- Key-value settings
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_ghost_locks_status ON ghost_locks(status);
            ",
        )?;

        Ok(())
    }

    /// Save encrypted master key
    pub fn save_master_key(&self, master_key: &MasterKey, password: &str) -> WalletResult<()> {
        let export = master_key.export_secrets();
        let plaintext = export.to_bytes();
        let encrypted = encrypt_key(&plaintext, password)?;
        let now = chrono::Utc::now().timestamp();

        self.conn.execute(
            "INSERT OR REPLACE INTO master_key (id, encrypted_data, created_at, updated_at)
             VALUES (1, ?1, COALESCE((SELECT created_at FROM master_key WHERE id = 1), ?2), ?2)",
            params![encrypted, now],
        )?;

        debug!("Saved encrypted master key");
        Ok(())
    }

    /// Load and decrypt master key
    pub fn load_master_key(&self, password: &str) -> WalletResult<MasterKey> {
        let encrypted: Vec<u8> = self
            .conn
            .query_row(
                "SELECT encrypted_data FROM master_key WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| LightWalletError::NotInitialized)?;

        let plaintext = decrypt_key(&encrypted, password)?;
        let export = crate::keys::master::MasterKeyExport::from_bytes(&plaintext)?;
        let master_key = MasterKey::from_export(export)?;

        debug!("Loaded master key from encrypted storage");
        Ok(master_key)
    }

    /// Update cached balance
    pub fn update_balance(&self, balance: &WalletBalance) -> WalletResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.conn.execute(
            "INSERT OR REPLACE INTO balance (id, confirmed, unconfirmed, locked, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![balance.confirmed, balance.unconfirmed, balance.locked, now],
        )?;

        debug!(
            confirmed = balance.confirmed,
            unconfirmed = balance.unconfirmed,
            locked = balance.locked,
            "Updated cached balance"
        );

        Ok(())
    }

    /// Get cached balance
    pub fn get_balance(&self) -> WalletResult<WalletBalance> {
        self.conn
            .query_row(
                "SELECT confirmed, unconfirmed, locked FROM balance WHERE id = 1",
                [],
                |row| {
                    Ok(WalletBalance {
                        confirmed: row.get(0)?,
                        unconfirmed: row.get(1)?,
                        locked: row.get(2)?,
                    })
                },
            )
            .map_err(|_| {
                // No cached balance yet
                LightWalletError::Storage("No cached balance".to_string())
            })
    }

    /// Save a transaction to cache
    pub fn save_transaction(
        &self,
        txid: &str,
        amount_sats: i64,
        is_incoming: bool,
        status: &str,
        counterparty: Option<&str>,
        memo: Option<&str>,
    ) -> WalletResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.conn.execute(
            "INSERT OR REPLACE INTO transactions
             (txid, amount_sats, is_incoming, status, counterparty, memo, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                txid,
                amount_sats,
                is_incoming,
                status,
                counterparty,
                memo,
                now
            ],
        )?;

        Ok(())
    }

    /// Get recent transactions
    pub fn get_recent_transactions(&self, limit: u32) -> WalletResult<Vec<CachedTransaction>> {
        let mut stmt = self.conn.prepare(
            "SELECT txid, amount_sats, is_incoming, status, counterparty, memo, created_at, confirmed_at
             FROM transactions
             ORDER BY created_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(CachedTransaction {
                txid: row.get(0)?,
                amount_sats: row.get(1)?,
                is_incoming: row.get(2)?,
                status: row.get(3)?,
                counterparty: row.get(4)?,
                memo: row.get(5)?,
                created_at: row.get(6)?,
                confirmed_at: row.get(7)?,
            })
        })?;

        let mut transactions = Vec::new();
        for row in rows {
            transactions.push(row?);
        }

        Ok(transactions)
    }

    /// Save a setting
    pub fn set_setting(&self, key: &str, value: &str) -> WalletResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a setting
    pub fn get_setting(&self, key: &str) -> WalletResult<Option<String>> {
        let result: Result<String, _> = self.conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Clear all cached data (but keep master key)
    pub fn clear_cache(&self) -> WalletResult<()> {
        self.conn.execute_batch(
            "
            DELETE FROM balance;
            DELETE FROM transactions;
            DELETE FROM ghost_locks;
            DELETE FROM addresses;
            ",
        )?;

        info!("Cleared wallet cache");
        Ok(())
    }
}

/// Cached transaction record
#[derive(Debug, Clone)]
pub struct CachedTransaction {
    pub txid: String,
    pub amount_sats: i64,
    pub is_incoming: bool,
    pub status: String,
    pub counterparty: Option<String>,
    pub memo: Option<String>,
    pub created_at: i64,
    pub confirmed_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_creation() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.db");

        let cache = WalletCache::open(&path, "password").unwrap();
        assert!(path.exists());

        // Verify tables exist
        let tables: Vec<String> = cache
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert!(tables.contains(&"master_key".to_string()));
        assert!(tables.contains(&"balance".to_string()));
        assert!(tables.contains(&"transactions".to_string()));
    }

    #[test]
    fn test_balance_cache() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.db");
        let cache = WalletCache::open(&path, "password").unwrap();

        let balance = WalletBalance {
            confirmed: 100_000,
            unconfirmed: 50_000,
            locked: 25_000,
        };

        cache.update_balance(&balance).unwrap();

        let loaded = cache.get_balance().unwrap();
        assert_eq!(loaded.confirmed, balance.confirmed);
        assert_eq!(loaded.unconfirmed, balance.unconfirmed);
        assert_eq!(loaded.locked, balance.locked);
    }

    #[test]
    fn test_settings() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.db");
        let cache = WalletCache::open(&path, "password").unwrap();

        cache
            .set_setting("gsp_url", "wss://gsp.example.com")
            .unwrap();

        let value = cache.get_setting("gsp_url").unwrap();
        assert_eq!(value, Some("wss://gsp.example.com".to_string()));

        let missing = cache.get_setting("nonexistent").unwrap();
        assert_eq!(missing, None);
    }
}
