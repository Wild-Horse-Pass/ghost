//! Local encrypted storage
//!
//! Uses rusqlite for persistence with AES-256-GCM encryption for sensitive values.

mod keychain;

pub use keychain::*;

use crate::crypto::{decrypt_aes_gcm, encrypt_aes_gcm};
use crate::wallet::{HistoryEntry, Utxo};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Keychain error: {0}")]
    Keychain(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        StorageError::Database(e.to_string())
    }
}

/// Wallet metadata stored in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMeta {
    pub wallet_id: String,
    pub account_index: u32,
    pub next_receive_index: u32,
    pub next_change_index: u32,
    pub created_at: u64,
}

/// Encrypted local database for wallet data
pub struct WalletStorage {
    conn: Mutex<Connection>,
    encryption_key: Zeroizing<[u8; 32]>,
}

impl WalletStorage {
    /// Open or create a wallet database
    pub fn open(path: &str, encryption_key: &[u8; 32]) -> Result<Self, StorageError> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            // Ensure parent directory exists
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StorageError::Database(format!("Failed to create dir: {e}")))?;
            }
            Connection::open(path)?
        };

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        let storage = Self {
            conn: Mutex::new(conn),
            encryption_key: Zeroizing::new(*encryption_key),
        };

        storage.create_tables()?;
        Ok(storage)
    }

    /// Schema version history:
    /// - 0/1: Original plaintext columns for utxos, history, wash_queue
    /// - 2: Encrypted blob storage for utxos, history, wash_queue (M-14 audit fix)
    /// - 3: L2 confidential payment tables (l2_notes, l2_sync, l2_params)
    const SCHEMA_VERSION: i32 = 3;

    fn create_tables(&self) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Check current schema version
        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap_or(0);

        if version < Self::SCHEMA_VERSION {
            // Drop old plaintext tables (data loss is acceptable — pre-release audit fix)
            conn.execute_batch(
                "DROP TABLE IF EXISTS utxos;
                 DROP TABLE IF EXISTS history;
                 DROP TABLE IF EXISTS wash_queue;",
            )?;
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                encrypted INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS utxos (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS history (
                txid TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                data BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wallet_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                wallet_id TEXT NOT NULL,
                account_index INTEGER NOT NULL DEFAULT 0,
                next_receive_index INTEGER NOT NULL DEFAULT 0,
                next_change_index INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS merchant_profile (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wash_queue (
                txid TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                data BLOB NOT NULL
            );

            -- L2 confidential payment tables
            CREATE TABLE IF NOT EXISTS l2_notes (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data BLOB
            );

            CREATE TABLE IF NOT EXISTS l2_sync (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_synced_height INTEGER DEFAULT 0,
                current_epoch INTEGER DEFAULT 0,
                tree_root TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS l2_params (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                params_path TEXT,
                downloaded_at INTEGER
            );",
        )?;

        if version < Self::SCHEMA_VERSION {
            conn.pragma_update(None, "user_version", Self::SCHEMA_VERSION)?;
        }

        Ok(())
    }

    /// Encrypt a value before storing
    fn encrypt_value(&self, value: &[u8]) -> Result<Vec<u8>, StorageError> {
        encrypt_aes_gcm(value, &self.encryption_key)
            .map_err(|e| StorageError::Encryption(e.to_string()))
    }

    /// Decrypt a value after retrieval
    fn decrypt_value(&self, ciphertext: &[u8]) -> Result<Vec<u8>, StorageError> {
        decrypt_aes_gcm(ciphertext, &self.encryption_key)
            .map_err(|e| StorageError::Encryption(e.to_string()))
    }

    // --- Key-Value Store ---

    /// Store a key-value pair (optionally encrypted)
    pub fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, encrypted) VALUES (?1, ?2, 0)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Store an encrypted key-value pair
    pub fn set_encrypted(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let encrypted = self.encrypt_value(value)?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, encrypted) VALUES (?1, ?2, 1)",
            params![key, encrypted],
        )?;
        Ok(())
    }

    /// Retrieve a value by key (auto-decrypts if encrypted)
    pub fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let (value, encrypted): (Vec<u8>, bool) = conn
            .query_row(
                "SELECT value, encrypted FROM kv_store WHERE key = ?1",
                params![key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound(key.to_string()),
                _ => StorageError::Database(e.to_string()),
            })?;

        if encrypted {
            self.decrypt_value(&value)
        } else {
            Ok(value)
        }
    }

    /// Delete a key
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute("DELETE FROM kv_store WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// List all keys with a prefix
    pub fn list_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let escaped = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("{escaped}%");
        let mut stmt = conn.prepare("SELECT key FROM kv_store WHERE key LIKE ?1 ESCAPE '\\'")?;
        let keys = stmt
            .query_map(params![pattern], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(keys)
    }

    // --- UTXOs ---

    /// Save the UTXO set (replaces all existing) as a single encrypted blob.
    pub fn save_utxos(&self, utxos: &[Utxo]) -> Result<(), StorageError> {
        let json =
            serde_json::to_vec(utxos).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = self.encrypt_value(&json)?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO utxos (id, data) VALUES (1, ?1)",
            params![encrypted],
        )?;
        Ok(())
    }

    /// Load all UTXOs from the encrypted blob.
    pub fn load_utxos(&self) -> Result<Vec<Utxo>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let encrypted: Vec<u8> =
            match conn.query_row("SELECT data FROM utxos WHERE id = 1", [], |row| row.get(0)) {
                Ok(data) => data,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(Vec::new()),
                Err(e) => return Err(StorageError::Database(e.to_string())),
            };
        drop(conn);
        let json = self.decrypt_value(&encrypted)?;
        serde_json::from_slice(&json).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    // --- History ---

    /// Save a history entry (encrypted blob with plaintext txid + timestamp for ordering).
    pub fn save_history_entry(&self, entry: &HistoryEntry) -> Result<(), StorageError> {
        let json =
            serde_json::to_vec(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = self.encrypt_value(&json)?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO history (txid, timestamp, data) VALUES (?1, ?2, ?3)",
            params![entry.txid, entry.timestamp as i64, encrypted],
        )?;
        Ok(())
    }

    /// Load transaction history (newest first)
    pub fn load_history(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut stmt =
            conn.prepare("SELECT data FROM history ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2")?;
        let blobs: Vec<Vec<u8>> = stmt
            .query_map(params![limit as i64, offset as i64], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(conn);

        let mut entries = Vec::with_capacity(blobs.len());
        for blob in &blobs {
            let json = self.decrypt_value(blob)?;
            let entry: HistoryEntry = serde_json::from_slice(&json)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Load all history entries
    pub fn load_all_history(&self) -> Result<Vec<HistoryEntry>, StorageError> {
        self.load_history(0, i32::MAX as usize)
    }

    // --- Wallet Meta ---

    /// Save wallet metadata
    pub fn save_wallet_meta(&self, meta: &WalletMeta) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO wallet_meta (id, wallet_id, account_index, next_receive_index, next_change_index, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                meta.wallet_id,
                meta.account_index,
                meta.next_receive_index,
                meta.next_change_index,
                meta.created_at as i64,
            ],
        )?;
        Ok(())
    }

    /// Load wallet metadata
    pub fn load_wallet_meta(&self) -> Result<WalletMeta, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.query_row(
            "SELECT wallet_id, account_index, next_receive_index, next_change_index, created_at FROM wallet_meta WHERE id = 1",
            [],
            |row| {
                Ok(WalletMeta {
                    wallet_id: row.get(0)?,
                    account_index: row.get(1)?,
                    next_receive_index: row.get(2)?,
                    next_change_index: row.get(3)?,
                    created_at: row.get::<_, i64>(4)? as u64,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound("wallet_meta".into()),
            _ => StorageError::Database(e.to_string()),
        })
    }

    // --- Merchant Profile ---

    /// Save merchant profile (serialized as JSON, encrypted)
    pub fn save_merchant_profile(&self, data: &[u8]) -> Result<(), StorageError> {
        let encrypted = self.encrypt_value(data)?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO merchant_profile (id, data) VALUES (1, ?1)",
            params![encrypted],
        )?;
        Ok(())
    }

    /// Load merchant profile (decrypted)
    pub fn load_merchant_profile(&self) -> Result<Vec<u8>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let encrypted: Vec<u8> = conn
            .query_row(
                "SELECT data FROM merchant_profile WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound("merchant_profile".into())
                }
                _ => StorageError::Database(e.to_string()),
            })?;
        self.decrypt_value(&encrypted)
    }

    // --- Wash Queue ---

    /// Save a wash request (encrypted blob with plaintext txid, status, updated_at for queries).
    pub fn save_wash_request(
        &self,
        req: &crate::merchant::wraith::WashRequest,
    ) -> Result<(), StorageError> {
        let json =
            serde_json::to_vec(req).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = self.encrypt_value(&json)?;
        let status = req.status.to_string();
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO wash_queue (txid, status, updated_at, data) VALUES (?1, ?2, ?3, ?4)",
            params![req.txid, status, req.updated_at as i64, encrypted],
        )?;
        Ok(())
    }

    /// Load all wash requests from the database (decrypts each row).
    pub fn load_wash_queue(
        &self,
    ) -> Result<Vec<crate::merchant::wraith::WashRequest>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut stmt = conn.prepare("SELECT data FROM wash_queue")?;
        let blobs: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(conn);

        let mut requests = Vec::with_capacity(blobs.len());
        for blob in &blobs {
            let json = self.decrypt_value(blob)?;
            let req: crate::merchant::wraith::WashRequest = serde_json::from_slice(&json)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            requests.push(req);
        }
        Ok(requests)
    }

    /// Delete a wash request by txid
    pub fn delete_wash_request(&self, txid: &str) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute("DELETE FROM wash_queue WHERE txid = ?1", params![txid])?;
        Ok(())
    }

    // --- L2 Notes ---

    /// Save the NoteStore as an encrypted blob.
    pub fn save_l2_notes(&self, note_store: &crate::l2::NoteStore) -> Result<(), StorageError> {
        let json = note_store
            .to_json()
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = self.encrypt_value(json.as_bytes())?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO l2_notes (id, data) VALUES (1, ?1)",
            params![encrypted],
        )?;
        Ok(())
    }

    /// Load the NoteStore from encrypted storage.
    pub fn load_l2_notes(
        &self,
        spending_key: [u8; 32],
    ) -> Result<Option<crate::l2::NoteStore>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let encrypted: Vec<u8> =
            match conn.query_row("SELECT data FROM l2_notes WHERE id = 1", [], |row| {
                row.get(0)
            }) {
                Ok(data) => data,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(StorageError::Database(e.to_string())),
            };
        drop(conn);

        let json_bytes = self.decrypt_value(&encrypted)?;
        let json = String::from_utf8(json_bytes)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let store = crate::l2::NoteStore::from_json(&json, spending_key)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        Ok(Some(store))
    }

    // --- L2 Sync State ---

    /// Save L2 sync state (plaintext metadata).
    pub fn save_l2_sync_state(
        &self,
        height: u64,
        epoch: u64,
        root: &str,
    ) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO l2_sync (id, last_synced_height, current_epoch, tree_root)
             VALUES (1, ?1, ?2, ?3)",
            params![height as i64, epoch as i64, root],
        )?;
        Ok(())
    }

    /// Load L2 sync state.
    pub fn load_l2_sync_state(&self) -> Result<(u64, u64, String), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.query_row(
            "SELECT last_synced_height, current_epoch, tree_root FROM l2_sync WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound("l2_sync".into()),
            _ => StorageError::Database(e.to_string()),
        })
    }

    // --- L2 Params Metadata ---

    /// Save MPC params cache metadata.
    pub fn save_l2_params_info(&self, path: &str, timestamp: u64) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO l2_params (id, params_path, downloaded_at)
             VALUES (1, ?1, ?2)",
            params![path, timestamp as i64],
        )?;
        Ok(())
    }

    /// Load MPC params cache metadata.
    pub fn load_l2_params_info(&self) -> Result<(String, u64), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        conn.query_row(
            "SELECT params_path, downloaded_at FROM l2_params WHERE id = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound("l2_params".into()),
            _ => StorageError::Database(e.to_string()),
        })
    }

    // --- Wash Queue ---

    /// Prune completed/failed wash requests older than max_age seconds
    pub fn prune_wash_queue(&self, now: u64, max_age: u64) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let cutoff = now.saturating_sub(max_age) as i64;
        conn.execute(
            "DELETE FROM wash_queue WHERE (status = 'Completed' OR status = 'Failed') AND updated_at < ?1",
            params![cutoff],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{TxDirection, TxStatus};

    fn test_storage() -> WalletStorage {
        WalletStorage::open(":memory:", &[42u8; 32]).unwrap()
    }

    #[test]
    fn test_kv_store() {
        let storage = test_storage();
        storage.set("key1", b"value1").unwrap();
        assert_eq!(storage.get("key1").unwrap(), b"value1");
        storage.delete("key1").unwrap();
        assert!(storage.get("key1").is_err());
    }

    #[test]
    fn test_encrypted_kv() {
        let storage = test_storage();
        storage.set_encrypted("secret", b"my_seed_data").unwrap();
        assert_eq!(storage.get("secret").unwrap(), b"my_seed_data");
    }

    #[test]
    fn test_list_keys() {
        let storage = test_storage();
        storage.set("wallet:id", b"1").unwrap();
        storage.set("wallet:name", b"test").unwrap();
        storage.set("other:key", b"x").unwrap();
        let keys = storage.list_keys("wallet:").unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_utxos() {
        let storage = test_storage();
        let utxos = vec![
            Utxo {
                txid: "tx1".into(),
                vout: 0,
                amount: 100_000,
                confirmations: 6,
                address: "addr1".into(),
                address_index: 0,
                change: 0,
            },
            Utxo {
                txid: "tx2".into(),
                vout: 1,
                amount: 200_000,
                confirmations: 3,
                address: "addr2".into(),
                address_index: 1,
                change: 1,
            },
        ];
        storage.save_utxos(&utxos).unwrap();
        let loaded = storage.load_utxos().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].txid, "tx1");
        assert_eq!(loaded[0].amount, 100_000);
    }

    #[test]
    fn test_history() {
        let storage = test_storage();
        let entry = HistoryEntry {
            txid: "txabc".into(),
            direction: TxDirection::Incoming,
            amount: 50_000,
            fee: None,
            address: "ghost1abc".into(),
            status: TxStatus::Confirmed(10),
            timestamp: 1700000000,
            memo: Some("test payment".into()),
        };
        storage.save_history_entry(&entry).unwrap();
        let loaded = storage.load_all_history().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].txid, "txabc");
        assert_eq!(loaded[0].memo, Some("test payment".into()));
    }

    #[test]
    fn test_wallet_meta() {
        let storage = test_storage();
        let meta = WalletMeta {
            wallet_id: "abc123".into(),
            account_index: 0,
            next_receive_index: 5,
            next_change_index: 2,
            created_at: 1700000000,
        };
        storage.save_wallet_meta(&meta).unwrap();
        let loaded = storage.load_wallet_meta().unwrap();
        assert_eq!(loaded.wallet_id, "abc123");
        assert_eq!(loaded.next_receive_index, 5);
    }

    #[test]
    fn test_merchant_profile() {
        let storage = test_storage();
        let data = b"{\"name\":\"Test Shop\"}";
        storage.save_merchant_profile(data).unwrap();
        let loaded = storage.load_merchant_profile().unwrap();
        assert_eq!(loaded, data);
    }
}
