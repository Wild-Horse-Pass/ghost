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
//| FILE: audit_log.rs                                                                                                   |
//|======================================================================================================================|

//! Immutable audit log for security-critical operations
//!
//! Provides an append-only log of security-relevant events for:
//! - Post-incident forensics
//! - Compliance requirements
//! - Anomaly detection
//!
//! Log entries are chained via cryptographic hashes to detect tampering.

use rusqlite::params;

/// L-STOR-1: Maximum allowed JSON size for deserialization from database (10 MB)
/// Prevents OOM attacks from maliciously large data
const MAX_JSON_SIZE: usize = 10 * 1024 * 1024;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, error, warn};

use ghost_common::error::{GhostError, GhostResult};

/// L-13 FIX: Parse JSON details with logging on failure
///
/// Instead of silently falling back to Null on parse errors, this logs a warning
/// so operators can investigate potential data corruption or encoding issues.
fn parse_details_json(details_str: &str, entry_id: i64) -> serde_json::Value {
    match serde_json::from_str(details_str) {
        Ok(value) => value,
        Err(e) => {
            // L-13 FIX: Log warning instead of silently using null
            warn!(
                entry_id = entry_id,
                error = %e,
                details_len = details_str.len(),
                "L-13: Failed to parse audit log details JSON, using null fallback"
            );
            serde_json::Value::Null
        }
    }
}

use crate::Database;

/// Audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Payout events
    PayoutProposed,
    PayoutApproved,
    PayoutRejected,
    PayoutBroadcast,
    PayoutConfirmed,

    // Block events
    BlockFound,
    BlockSubmitted,
    BlockConfirmed,
    BlockOrphaned,

    // Reorg events
    ReorgDetected,
    RoundsOrphaned,

    // Authentication events
    MinerConnected,
    MinerAuthorized,
    AuthFailure,
    MinerBanned,

    // Security events
    SignatureInvalid,
    RateLimitExceeded,
    SuspiciousActivity,
    PeerBanned,

    // Consensus events
    VoteProposed,
    VoteReceived,
    ConsensusReached,
    ConsensusFailed,

    // Configuration events
    ConfigChanged,
    NodeStarted,
    NodeStopped,

    // Administrative events
    ManualIntervention,
    EmergencyShutdown,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).unwrap_or_else(|_| "unknown".to_string());
        // Remove quotes from JSON string
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// An audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID (auto-assigned)
    pub id: i64,
    /// Unix timestamp (seconds)
    pub timestamp: i64,
    /// Event type
    pub event_type: AuditEventType,
    /// Actor (node ID, miner ID, "system", etc.)
    pub actor: String,
    /// Target (what was affected)
    pub target: Option<String>,
    /// Additional details as JSON
    pub details: serde_json::Value,
    /// Hash of previous entry (for tamper detection)
    pub prev_hash: String,
    /// Hash of this entry
    pub entry_hash: String,
}

/// Audit log manager
pub struct AuditLog {
    db: Arc<Database>,
}

impl AuditLog {
    /// Create a new audit log
    pub fn new(db: Arc<Database>) -> GhostResult<Self> {
        let log = Self { db };
        log.init_table()?;
        Ok(log)
    }

    /// Initialize the audit log table
    fn init_table(&self) -> GhostResult<()> {
        self.db.with_connection(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    target TEXT,
                    details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Index for time-range queries
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Index for event type queries
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Index for actor queries
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(())
        })
    }

    /// Get the hash of the last entry (for chaining)
    /// Note: Used by verify_chain() for chain integrity checks
    #[allow(dead_code)]
    fn get_last_hash(&self) -> GhostResult<String> {
        self.db.with_connection(|conn| {
            let result: Result<String, _> = conn.query_row(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            );

            match result {
                Ok(hash) => Ok(hash),
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    // Genesis hash for empty log
                    Ok(
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    )
                }
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Compute hash of an entry
    fn compute_hash(
        timestamp: i64,
        event_type: &str,
        actor: &str,
        target: &Option<String>,
        details: &str,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(timestamp.to_le_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(actor.as_bytes());
        if let Some(t) = target {
            hasher.update(t.as_bytes());
        }
        hasher.update(details.as_bytes());
        hasher.update(prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Append a new entry to the audit log
    ///
    /// This is append-only - entries cannot be modified or deleted.
    ///
    /// M-12: Uses a transaction to ensure atomicity between get_last_hash and INSERT.
    /// This prevents concurrent appends from creating broken chains where multiple
    /// entries claim the same prev_hash.
    pub fn append(
        &self,
        event_type: AuditEventType,
        actor: &str,
        target: Option<&str>,
        details: serde_json::Value,
    ) -> GhostResult<i64> {
        let timestamp = chrono::Utc::now().timestamp();
        let event_type_str = event_type.to_string();
        let target_owned = target.map(|s| s.to_string());
        let details_str = details.to_string();
        let actor_owned = actor.to_string();

        // M-12: Use transaction to atomically get_last_hash + INSERT
        // This prevents race conditions where concurrent appends get the same prev_hash
        let id = self.db.transaction(|tx| {
            // Get prev_hash inside the transaction
            let prev_hash: String = tx
                .query_row(
                    "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| {
                    // Genesis hash for empty log
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
                });

            let entry_hash = Self::compute_hash(
                timestamp,
                &event_type_str,
                &actor_owned,
                &target_owned,
                &details_str,
                &prev_hash,
            );

            tx.execute(
                "INSERT INTO audit_log (timestamp, event_type, actor, target, details, prev_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    timestamp,
                    event_type_str,
                    actor_owned,
                    target_owned,
                    details_str,
                    prev_hash,
                    entry_hash,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(tx.last_insert_rowid())
        })?;

        debug!(
            id = id,
            event_type = %event_type_str,
            actor = actor,
            "Audit log entry created"
        );

        Ok(id)
    }

    /// Convenience method for logging with JSON details
    pub fn log(
        &self,
        event_type: AuditEventType,
        actor: &str,
        target: Option<&str>,
        details: impl Serialize,
    ) -> GhostResult<i64> {
        let details_json =
            serde_json::to_value(details).map_err(|e| GhostError::Serialization(e.to_string()))?;
        self.append(event_type, actor, target, details_json)
    }

    /// Verify the integrity of the audit log chain
    pub fn verify_chain(&self) -> GhostResult<ChainVerification> {
        self.db.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, timestamp, event_type, actor, target, details, prev_hash, entry_hash
                     FROM audit_log ORDER BY id ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut expected_prev_hash =
                "0000000000000000000000000000000000000000000000000000000000000000".to_string();
            let mut total_entries = 0u64;
            let mut broken_at: Option<i64> = None;

            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,            // id
                        row.get::<_, i64>(1)?,            // timestamp
                        row.get::<_, String>(2)?,         // event_type
                        row.get::<_, String>(3)?,         // actor
                        row.get::<_, Option<String>>(4)?, // target
                        row.get::<_, String>(5)?,         // details
                        row.get::<_, String>(6)?,         // prev_hash
                        row.get::<_, String>(7)?,         // entry_hash
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            for row_result in rows {
                let (id, timestamp, event_type, actor, target, details, prev_hash, entry_hash) =
                    row_result.map_err(|e| GhostError::Database(e.to_string()))?;

                total_entries += 1;

                // Check prev_hash matches expected
                if prev_hash != expected_prev_hash {
                    error!(
                        id = id,
                        expected = %expected_prev_hash,
                        found = %prev_hash,
                        "Audit log chain broken - prev_hash mismatch"
                    );
                    if broken_at.is_none() {
                        broken_at = Some(id);
                    }
                }

                // Verify entry hash
                let computed_hash = Self::compute_hash(
                    timestamp,
                    &event_type,
                    &actor,
                    &target,
                    &details,
                    &prev_hash,
                );

                if computed_hash != entry_hash {
                    error!(
                        id = id,
                        computed = %computed_hash,
                        stored = %entry_hash,
                        "Audit log entry tampered - hash mismatch"
                    );
                    if broken_at.is_none() {
                        broken_at = Some(id);
                    }
                }

                expected_prev_hash = entry_hash;
            }

            Ok(ChainVerification {
                total_entries,
                is_valid: broken_at.is_none(),
                broken_at_id: broken_at,
            })
        })
    }

    /// Query audit log entries by time range
    pub fn query_by_time(
        &self,
        start_time: i64,
        end_time: i64,
        limit: usize,
    ) -> GhostResult<Vec<AuditEntry>> {
        self.db.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, timestamp, event_type, actor, target, details, prev_hash, entry_hash
                     FROM audit_log
                     WHERE timestamp >= ?1 AND timestamp <= ?2
                     ORDER BY id DESC
                     LIMIT ?3",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entries = stmt
                .query_map(params![start_time, end_time, limit as i64], |row| {
                    let entry_id: i64 = row.get(0)?;
                    let details_str: String = row.get(5)?;
                    // L-STOR-1: Check size before deserializing to prevent OOM
                    // 3.21: Reject oversized JSON instead of silently returning Null
                    if details_str.len() > MAX_JSON_SIZE {
                        return Err(rusqlite::Error::InvalidParameterName(format!(
                            "JSON size {} exceeds maximum {}",
                            details_str.len(),
                            MAX_JSON_SIZE
                        )));
                    }
                    // L-13 FIX: Use helper that logs on parse failure
                    let details = parse_details_json(&details_str, entry_id);
                    Ok(AuditEntry {
                        id: entry_id,
                        timestamp: row.get(1)?,
                        event_type: serde_json::from_str(&format!(
                            "\"{}\"",
                            row.get::<_, String>(2)?
                        ))
                        .unwrap_or(AuditEventType::ManualIntervention),
                        actor: row.get(3)?,
                        target: row.get(4)?,
                        details,
                        prev_hash: row.get(6)?,
                        entry_hash: row.get(7)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                // M-3 FIX: Log errors instead of silently dropping them
                .filter_map(|r| match r {
                    Ok(entry) => Some(entry),
                    Err(e) => {
                        warn!("M-3: Failed to parse audit log entry: {}", e);
                        None
                    }
                })
                .collect();

            Ok(entries)
        })
    }

    /// Query audit log entries by event type
    pub fn query_by_type(
        &self,
        event_type: AuditEventType,
        limit: usize,
    ) -> GhostResult<Vec<AuditEntry>> {
        self.db.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, timestamp, event_type, actor, target, details, prev_hash, entry_hash
                     FROM audit_log
                     WHERE event_type = ?1
                     ORDER BY id DESC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entries = stmt
                .query_map(params![event_type.to_string(), limit as i64], |row| {
                    let entry_id: i64 = row.get(0)?;
                    let details_str: String = row.get(5)?;
                    // L-STOR-1: Check size before deserializing to prevent OOM
                    // 3.21: Reject oversized JSON instead of silently returning Null
                    if details_str.len() > MAX_JSON_SIZE {
                        return Err(rusqlite::Error::InvalidParameterName(format!(
                            "JSON size {} exceeds maximum {}",
                            details_str.len(),
                            MAX_JSON_SIZE
                        )));
                    }
                    // L-13 FIX: Use helper that logs on parse failure
                    let details = parse_details_json(&details_str, entry_id);
                    Ok(AuditEntry {
                        id: entry_id,
                        timestamp: row.get(1)?,
                        event_type,
                        actor: row.get(3)?,
                        target: row.get(4)?,
                        details,
                        prev_hash: row.get(6)?,
                        entry_hash: row.get(7)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                // M-3 FIX: Log errors instead of silently dropping them
                .filter_map(|r| match r {
                    Ok(entry) => Some(entry),
                    Err(e) => {
                        warn!("M-3: Failed to parse audit log entry by type: {}", e);
                        None
                    }
                })
                .collect();

            Ok(entries)
        })
    }

    /// Query audit log entries by actor
    pub fn query_by_actor(&self, actor: &str, limit: usize) -> GhostResult<Vec<AuditEntry>> {
        self.db.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, timestamp, event_type, actor, target, details, prev_hash, entry_hash
                     FROM audit_log
                     WHERE actor = ?1
                     ORDER BY id DESC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entries = stmt
                .query_map(params![actor, limit as i64], |row| {
                    let entry_id: i64 = row.get(0)?;
                    let details_str: String = row.get(5)?;
                    // L-STOR-1: Check size before deserializing to prevent OOM
                    // 3.21: Reject oversized JSON instead of silently returning Null
                    if details_str.len() > MAX_JSON_SIZE {
                        return Err(rusqlite::Error::InvalidParameterName(format!(
                            "JSON size {} exceeds maximum {}",
                            details_str.len(),
                            MAX_JSON_SIZE
                        )));
                    }
                    // L-13 FIX: Use helper that logs on parse failure
                    let details = parse_details_json(&details_str, entry_id);
                    Ok(AuditEntry {
                        id: entry_id,
                        timestamp: row.get(1)?,
                        event_type: serde_json::from_str(&format!(
                            "\"{}\"",
                            row.get::<_, String>(2)?
                        ))
                        .unwrap_or(AuditEventType::ManualIntervention),
                        actor: row.get(3)?,
                        target: row.get(4)?,
                        details,
                        prev_hash: row.get(6)?,
                        entry_hash: row.get(7)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                // M-3 FIX: Log errors instead of silently dropping them
                .filter_map(|r| match r {
                    Ok(entry) => Some(entry),
                    Err(e) => {
                        warn!("M-3: Failed to parse audit log entry by actor: {}", e);
                        None
                    }
                })
                .collect();

            Ok(entries)
        })
    }

    /// Get the total number of audit log entries
    ///
    /// M-11 FIX: Uses safe i64 to u64 conversion with error handling for negative values.
    /// SQLite returns COUNT(*) as i64, but count should never be negative.
    pub fn count(&self) -> GhostResult<u64> {
        self.db.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // M-11 FIX: Safely convert i64 to u64, rejecting negative values
            if count < 0 {
                return Err(GhostError::Database(format!(
                    "Invalid negative audit log count: {}",
                    count
                )));
            }
            Ok(count as u64)
        })
    }
}

/// Result of chain verification
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// Total entries checked
    pub total_entries: u64,
    /// Whether the chain is valid
    pub is_valid: bool,
    /// First entry ID where chain broke (if invalid)
    pub broken_at_id: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Arc<Database> {
        Arc::new(Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database"))
    }

    #[test]
    fn test_append_and_query() {
        let db = test_db();
        let log = AuditLog::new(db).expect("LOW-STOR-8: Failed to create audit log");

        // Append entry
        let id = log
            .append(
                AuditEventType::BlockFound,
                "miner1",
                Some("block123"),
                serde_json::json!({"height": 800000}),
            )
            .expect("LOW-STOR-8: Failed to append audit entry");

        assert!(id > 0);

        // Query by type
        let entries = log
            .query_by_type(AuditEventType::BlockFound, 10)
            .expect("LOW-STOR-8: Failed to query by type");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor, "miner1");
    }

    #[test]
    fn test_chain_verification() {
        let db = test_db();
        let log = AuditLog::new(db).expect("LOW-STOR-8: Failed to create audit log");

        // Add several entries
        for i in 0..5 {
            log.append(
                AuditEventType::MinerConnected,
                &format!("miner{}", i),
                None,
                serde_json::json!({}),
            )
            .expect("LOW-STOR-8: Failed to append audit entry");
        }

        // Verify chain
        let verification = log
            .verify_chain()
            .expect("LOW-STOR-8: Failed to verify chain");
        assert!(verification.is_valid);
        assert_eq!(verification.total_entries, 5);
        assert!(verification.broken_at_id.is_none());
    }

    #[test]
    fn test_query_by_time() {
        let db = test_db();
        let log = AuditLog::new(db).expect("LOW-STOR-8: Failed to create audit log");

        // Add entry
        log.append(
            AuditEventType::ConfigChanged,
            "admin",
            None,
            serde_json::json!({"key": "value"}),
        )
        .expect("LOW-STOR-8: Failed to append audit entry");

        // Query with wide time range
        let now = chrono::Utc::now().timestamp();
        let entries = log
            .query_by_time(now - 3600, now + 3600, 100)
            .expect("LOW-STOR-8: Failed to query by time");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_log_convenience_method() {
        let db = test_db();
        let log = AuditLog::new(db).expect("LOW-STOR-8: Failed to create audit log");

        #[derive(Serialize)]
        struct BlockDetails {
            height: u64,
            hash: String,
        }

        let details = BlockDetails {
            height: 800000,
            hash: "abc123".to_string(),
        };

        let id = log
            .log(AuditEventType::BlockFound, "system", Some("block"), details)
            .expect("LOW-STOR-8: Failed to log audit entry");

        assert!(id > 0);
    }
}
