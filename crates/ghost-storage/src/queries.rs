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
//| FILE: queries.rs                                                                                                     |
//|======================================================================================================================|

//! Database query operations

use rusqlite::{params, Connection, OptionalExtension};

use ghost_common::error::{GhostError, GhostResult};

use crate::database::Database;
use crate::models::*;

/// Type alias for node rotation data: (is_elder, elder_order, pow_proof, capabilities, first_seen)
type NodeRotationData = (
    bool,
    Option<u32>,
    Option<String>,
    Option<String>,
    Option<i64>,
);

// =============================================================================
// SAFE TYPE CONVERSIONS
// =============================================================================

/// SEC-DATA-1: Safely convert i64 from SQLite to u64, rejecting negative values
///
/// SQLite stores integers as signed, but satoshi values should never be negative.
/// This helper validates the conversion to catch database corruption.
fn i64_to_u64_sats(value: i64, field_name: &str) -> Result<u64, rusqlite::Error> {
    if value < 0 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid negative {} value: {}", field_name, value),
            )),
        ));
    }
    Ok(value as u64)
}

/// SEC-DATA-2: Safely convert i64 to u32 for counts, rejecting negative/overflow
fn i64_to_u32_count(value: i64, field_name: &str) -> Result<u32, rusqlite::Error> {
    if value < 0 || value > u32::MAX as i64 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid {} value: {} (expected 0-{})", field_name, value, u32::MAX),
            )),
        ));
    }
    Ok(value as u32)
}

// =============================================================================
// SHARE QUERIES
// =============================================================================

impl Database {
    /// Insert a new share
    pub fn insert_share(&self, share: &ShareRecord) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    share.round_id,
                    share.miner_id,
                    share.difficulty,
                    share.work,
                    share.share_hash,
                    share.timestamp,
                    share.received_by,
                    share.valid,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Maximum rows returned by unbounded queries (H-7: OOM prevention)
    pub const MAX_QUERY_RESULTS: u32 = 10000;

    /// Get shares for a round
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_shares_by_round(&self, round_id: u64) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares WHERE round_id = ?1 ORDER BY timestamp LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map(params![round_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok(ShareRecord {
                        id: Some(row.get(0)?),
                        round_id: row.get(1)?,
                        miner_id: row.get(2)?,
                        difficulty: row.get(3)?,
                        work: row.get(4)?,
                        share_hash: row.get(5)?,
                        timestamp: row.get(6)?,
                        received_by: row.get(7)?,
                        valid: row.get(8)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get miner shares for a round
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_miner_shares(&self, round_id: u64, miner_id: &str) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares WHERE round_id = ?1 AND miner_id = ?2 ORDER BY timestamp LIMIT ?3",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map(
                    params![round_id, miner_id, Self::MAX_QUERY_RESULTS],
                    |row| {
                        Ok(ShareRecord {
                            id: Some(row.get(0)?),
                            round_id: row.get(1)?,
                            miner_id: row.get(2)?,
                            difficulty: row.get(3)?,
                            work: row.get(4)?,
                            share_hash: row.get(5)?,
                            timestamp: row.get(6)?,
                            received_by: row.get(7)?,
                            valid: row.get(8)?,
                        })
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get total work for a miner in a round
    pub fn get_miner_work(&self, round_id: u64, miner_id: &str) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let work: f64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(work), 0) FROM shares WHERE round_id = ?1 AND miner_id = ?2 AND valid = 1",
                    params![round_id, miner_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(work)
        })
    }

    /// Get all miners with work in a round
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_round_miners(&self, round_id: u64) -> GhostResult<Vec<(String, f64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, SUM(work) as total_work
                     FROM shares WHERE round_id = ?1 AND valid = 1
                     GROUP BY miner_id ORDER BY total_work DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miners = stmt
                .query_map(params![round_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miners)
        })
    }

    /// Minimum query length for miner search (DB-H1)
    /// Prevents expensive full-table scans with very short queries
    pub const MIN_MINER_SEARCH_LENGTH: usize = 3;

    /// Search miners by ID/address (partial match) and get their stats
    ///
    /// Returns empty results if query is too short (DB-H1 protection).
    pub fn search_miners(&self, query: &str) -> GhostResult<Vec<MinerSearchResult>> {
        // DB-H1: Require minimum query length to prevent expensive LIKE operations
        // Returns empty result instead of error for API convenience
        if query.len() < Self::MIN_MINER_SEARCH_LENGTH {
            tracing::debug!(
                query_len = query.len(),
                min_len = Self::MIN_MINER_SEARCH_LENGTH,
                "Miner search query too short, returning empty results"
            );
            return Ok(vec![]);
        }

        self.with_connection(|conn| {
            // M-STOR-1: Escape SQL LIKE wildcards to prevent injection
            let escaped_query = query
                .replace('\\', "\\\\") // Escape backslash first
                .replace('%', "\\%")
                .replace('_', "\\_");
            let search_pattern = format!("%{}%", escaped_query);
            let mut stmt = conn
                .prepare(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty
                     FROM shares
                     WHERE miner_id LIKE ?1 ESCAPE '\\'
                     GROUP BY miner_id
                     ORDER BY total_work DESC
                     LIMIT 50",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let results = stmt
                .query_map([&search_pattern], |row| {
                    Ok(MinerSearchResult {
                        miner_id: row.get(0)?,
                        total_shares: row.get(1)?,
                        total_work: row.get(2)?,
                        valid_shares: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_seen: row.get(5)?,
                        avg_difficulty: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(results)
        })
    }

    /// Get detailed stats for a specific miner
    pub fn get_miner_stats(&self, miner_id: &str) -> GhostResult<Option<MinerDetailedStats>> {
        self.with_connection(|conn| {
            // Get aggregate stats
            let stats: Option<MinerDetailedStats> = conn
                .query_row(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        SUM(CASE WHEN valid = 0 THEN 1 ELSE 0 END) as invalid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty,
                        COUNT(DISTINCT round_id) as rounds_participated
                     FROM shares
                     WHERE miner_id = ?1
                     GROUP BY miner_id",
                    params![miner_id],
                    |row| {
                        Ok(MinerDetailedStats {
                            miner_id: row.get(0)?,
                            total_shares: row.get(1)?,
                            total_work: row.get(2)?,
                            valid_shares: row.get(3)?,
                            invalid_shares: row.get(4)?,
                            first_seen: row.get(5)?,
                            last_seen: row.get(6)?,
                            avg_difficulty: row.get(7)?,
                            rounds_participated: row.get(8)?,
                            recent_shares: vec![],
                        })
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // Get recent shares if miner exists
            if let Some(mut stats) = stats {
                let mut stmt = conn
                    .prepare(
                        "SELECT round_id, difficulty, work, timestamp, valid
                         FROM shares WHERE miner_id = ?1
                         ORDER BY timestamp DESC LIMIT 10",
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                let recent = stmt
                    .query_map([miner_id], |row| {
                        Ok(RecentShare {
                            round_id: row.get(0)?,
                            difficulty: row.get(1)?,
                            work: row.get(2)?,
                            timestamp: row.get(3)?,
                            valid: row.get(4)?,
                        })
                    })
                    .map_err(|e| GhostError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                stats.recent_shares = recent;
                Ok(Some(stats))
            } else {
                Ok(None)
            }
        })
    }
}

// =============================================================================
// ROUND QUERIES
// =============================================================================

impl Database {
    /// Create a new round
    pub fn create_round(&self, round: &RoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO rounds (round_id, block_height, start_time, payout_status)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    round.round_id,
                    round.block_height,
                    round.start_time,
                    round.payout_status.as_str(),
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a round by ID
    pub fn get_round(&self, round_id: u64) -> GhostResult<Option<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds WHERE round_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let round = stmt
                .query_row([round_id], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: PayoutStatus::parse(&status_str)
                            .unwrap_or(PayoutStatus::Active),
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(round)
        })
    }

    /// Update round with block found
    pub fn update_round_block_found(
        &self,
        round_id: u64,
        block_hash: &str,
        winning_miner: &str,
        found_by_node: &str,
        subsidy_sats: u64,
        tx_fees_sats: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE rounds SET
                    block_hash = ?1, winning_miner = ?2, found_by_node = ?3,
                    subsidy_sats = ?4, tx_fees_sats = ?5, payout_status = 'pending'
                 WHERE round_id = ?6",
                params![
                    block_hash,
                    winning_miner,
                    found_by_node,
                    subsidy_sats,
                    tx_fees_sats,
                    round_id
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// End a round
    pub fn end_round(&self, round_id: u64, end_time: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            // Update round totals
            conn.execute(
                "UPDATE rounds SET
                    end_time = ?1,
                    total_shares = (SELECT COUNT(*) FROM shares WHERE round_id = ?2 AND valid = 1),
                    total_work = (SELECT COALESCE(SUM(work), 0) FROM shares WHERE round_id = ?2 AND valid = 1)
                 WHERE round_id = ?2",
                params![end_time, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update round payout status
    pub fn update_round_status(&self, round_id: u64, status: PayoutStatus) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE rounds SET payout_status = ?1 WHERE round_id = ?2",
                params![status.as_str(), round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark rounds as orphaned by block hash (called on reorg)
    ///
    /// Returns the number of rounds affected.
    /// Only affects rounds that haven't been confirmed yet.
    pub fn mark_rounds_orphaned_by_hash(&self, block_hash: &str) -> GhostResult<usize> {
        self.with_connection(|conn| {
            // Only orphan rounds that are pending/approved/broadcast - not already confirmed
            let affected = conn
                .execute(
                    "UPDATE rounds SET payout_status = 'orphaned'
                 WHERE block_hash = ?1
                   AND payout_status IN ('pending', 'approved', 'broadcast')",
                    params![block_hash],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(affected)
        })
    }

    /// Get rounds by block hash
    pub fn get_rounds_by_block_hash(&self, block_hash: &str) -> GhostResult<Vec<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds WHERE block_hash = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([block_hash], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: PayoutStatus::parse(&status_str)
                            .unwrap_or(PayoutStatus::Active),
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }

    /// Get recent rounds
    pub fn get_recent_rounds(&self, limit: u32) -> GhostResult<Vec<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds ORDER BY round_id DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([limit], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: PayoutStatus::parse(&status_str)
                            .unwrap_or(PayoutStatus::Active),
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }
}

// =============================================================================
// NODE QUERIES
// =============================================================================

impl Database {
    /// Upsert a node record
    pub fn upsert_node(&self, node: &NodeRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO nodes (node_id, public_address, display_name, first_seen, last_seen,
                                   is_elder, elder_order, capabilities, payout_address)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(node_id) DO UPDATE SET
                    public_address = COALESCE(?2, public_address),
                    display_name = COALESCE(?3, display_name),
                    last_seen = ?5,
                    is_elder = ?6,
                    elder_order = ?7,
                    capabilities = ?8,
                    payout_address = COALESCE(?9, payout_address)",
                params![
                    node.node_id,
                    node.public_address,
                    node.display_name,
                    node.first_seen,
                    node.last_seen,
                    node.is_elder,
                    node.elder_order,
                    node.capabilities,
                    node.payout_address,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: &str) -> GhostResult<Option<NodeRecord>> {
        self.with_connection(|conn| get_node_internal(conn, node_id))
    }

    /// Get all elders (ordered by registration)
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    /// Note: Protocol limits elders to 101, but we add LIMIT for defense in depth
    pub fn get_elders(&self) -> GhostResult<Vec<NodeRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, public_address, display_name, first_seen, last_seen,
                            is_elder, elder_order, capabilities, total_uptime_secs,
                            uptime_7d_percent, verification_pass_rate, total_shares_received,
                            total_blocks_found, payout_address
                     FROM nodes WHERE is_elder = 1 ORDER BY elder_order LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let nodes = stmt
                .query_map([Self::MAX_QUERY_RESULTS], node_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(nodes)
        })
    }

    /// Get all node IDs with payout addresses
    ///
    /// Returns node IDs from the nodes table that have a payout address configured.
    /// Used for payout calculations to include all registered nodes.
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_all_node_ids_with_payout(&self) -> GhostResult<Vec<String>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id FROM nodes WHERE payout_address IS NOT NULL AND payout_address != '' LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let node_ids = stmt
                .query_map([Self::MAX_QUERY_RESULTS], |row| row.get::<_, String>(0))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(node_ids)
        })
    }

    /// Get top N nodes by shares received
    pub fn get_top_nodes_by_shares(&self, limit: u32) -> GhostResult<Vec<NodeRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, public_address, display_name, first_seen, last_seen,
                            is_elder, elder_order, capabilities, total_uptime_secs,
                            uptime_7d_percent, verification_pass_rate, total_shares_received,
                            total_blocks_found, payout_address
                     FROM nodes ORDER BY total_shares_received DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let nodes = stmt
                .query_map([limit], node_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(nodes)
        })
    }

    /// Update node last seen timestamp
    pub fn update_node_last_seen(&self, node_id: &str, timestamp: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET last_seen = ?1 WHERE node_id = ?2",
                params![timestamp, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Register a node and check if it should be an elder
    /// Returns (is_elder, elder_order) - elder_order is Some(n) if node is elder
    ///
    /// Uses deterministic elder selection: lowest node_id (lexicographically) wins ties.
    /// This prevents race conditions at genesis where multiple nodes register simultaneously.
    ///
    /// **Sybil Resistance**: Nodes must provide valid PoW proof to be eligible for elder status.
    /// Call `register_node_with_elder_check_and_pow` for the full-featured version.
    ///
    /// The algorithm:
    /// 1. Insert the node if it doesn't exist (IGNORE on conflict)
    /// 2. Within an IMMEDIATE transaction (exclusive write lock):
    ///    - Count current elders
    ///    - If < MAX_ELDERS, promote eligible non-elder nodes by node_id order
    /// 3. Return the node's final elder status
    pub fn register_node_with_elder_check(
        &self,
        node_id: &str,
        public_address: Option<&str>,
        display_name: Option<&str>,
        capabilities: &str,
    ) -> GhostResult<(bool, Option<u32>)> {
        // Delegate to the version with PoW (using None for backwards compatibility)
        self.register_node_with_elder_check_and_pow(
            node_id,
            public_address,
            display_name,
            capabilities,
            None,
        )
    }

    /// Register a node with PoW proof for Sybil-resistant elder eligibility
    ///
    /// **IMPORTANT**: Nodes without valid PoW proofs will NOT be eligible for elder status.
    /// This prevents Sybil attacks where attackers generate many node_ids to capture elder slots.
    ///
    /// Uses deterministic elder selection: lowest node_id (lexicographically) wins ties.
    /// This prevents race conditions at genesis where multiple nodes register simultaneously.
    ///
    /// This is safe because:
    /// - IMMEDIATE transaction takes write lock before reading
    /// - Elder promotion is deterministic (by node_id)
    /// - Same result regardless of registration order
    pub fn register_node_with_elder_check_and_pow(
        &self,
        node_id: &str,
        public_address: Option<&str>,
        display_name: Option<&str>,
        capabilities: &str,
        pow_proof: Option<&str>,
    ) -> GhostResult<(bool, Option<u32>)> {
        use ghost_common::identity::{verify_node_id_pow_hex, NODE_ID_POW_DIFFICULTY};

        let now = chrono::Utc::now().timestamp();
        let max_elders = ghost_common::constants::MAX_ELDERS;

        // Verify PoW if provided
        let has_valid_pow = if let Some(proof) = pow_proof {
            verify_node_id_pow_hex(node_id, proof, NODE_ID_POW_DIFFICULTY)
        } else {
            false
        };

        self.with_connection(|conn| {
            // DB-C2: BEGIN IMMEDIATE transaction FIRST to prevent TOCTOU race conditions
            // This acquires a write lock before ANY reads or writes, ensuring atomicity
            // of the entire node registration + elder promotion operation.
            conn.execute("BEGIN IMMEDIATE", [])
                .map_err(|e| GhostError::Database(format!("Failed to begin transaction: {}", e)))?;

            let result = (|| -> GhostResult<(bool, Option<u32>)> {
                // Step 1: Insert node if not exists (now inside transaction)
                conn.execute(
                    "INSERT OR IGNORE INTO nodes (node_id, public_address, display_name, first_seen, last_seen,
                                                  is_elder, elder_order, capabilities, pow_proof)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?7)",
                    params![
                        node_id,
                        public_address,
                        display_name,
                        now,
                        now,
                        capabilities,
                        pow_proof,
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Update last_seen and pow_proof if node already existed
                conn.execute(
                    "UPDATE nodes SET last_seen = ?1, public_address = COALESCE(?2, public_address),
                                      pow_proof = COALESCE(?3, pow_proof)
                     WHERE node_id = ?4",
                    params![now, public_address, pow_proof, node_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Step 2: Atomic elder promotion (deterministic)
                // Count current elders
                let elder_count: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM nodes WHERE is_elder = 1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                // If we have room for more elders, promote by node_id order (deterministic)
                // SYBIL RESISTANCE: Only nodes with valid PoW are eligible for elder status
                if elder_count < max_elders {
                    let slots_available = max_elders - elder_count;

                    // Promote non-elder nodes with lowest node_ids first
                    // BUT only if they have a valid PoW proof!
                    // (pow_proof IS NOT NULL means they submitted a proof - validated on insert)
                    conn.execute(
                        "UPDATE nodes SET is_elder = 1, elder_order = (
                            SELECT COUNT(*) + 1 FROM nodes n2 WHERE n2.is_elder = 1
                        )
                        WHERE node_id IN (
                            SELECT node_id FROM nodes
                            WHERE is_elder = 0 AND pow_proof IS NOT NULL
                            ORDER BY node_id ASC
                            LIMIT ?1
                        )",
                        params![slots_available],
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                }

                // Fetch final status for this node
                let (is_elder, elder_order): (bool, Option<u32>) = conn
                    .query_row(
                        "SELECT is_elder, elder_order FROM nodes WHERE node_id = ?1",
                        [node_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                // Log warning if node could have been elder but lacks PoW
                if !is_elder && !has_valid_pow && elder_count < max_elders {
                    tracing::warn!(
                        node_id = %&node_id[..8.min(node_id.len())],
                        "Node not eligible for elder status: missing or invalid proof-of-work"
                    );
                }

                Ok((is_elder, elder_order))
            })();

            // Commit or rollback based on result
            match &result {
                Ok(_) => {
                    conn.execute("COMMIT", [])
                        .map_err(|e| GhostError::Database(format!("Failed to commit: {}", e)))?;
                }
                Err(_) => {
                    let _ = conn.execute("ROLLBACK", []);
                }
            }

            result
        })
    }

    /// Get elder status for a node (queries database)
    /// Returns (is_elder, elder_order)
    pub fn get_node_elder_status(&self, node_id: &str) -> GhostResult<(bool, Option<u32>)> {
        self.with_connection(|conn| {
            let result: Option<(bool, Option<u32>)> = conn
                .query_row(
                    "SELECT is_elder, elder_order FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result.unwrap_or((false, None)))
        })
    }

    // =========================================================================
    // ELDER BOND MANAGEMENT (Nothing-at-Stake Prevention)
    // =========================================================================

    /// Minimum bond required to be eligible as an elder (0.001 BTC = 100k sats)
    /// This is enough to have skin in the game without being prohibitive
    pub const MIN_ELDER_BOND_SATS: u64 = 100_000;

    /// Register an elder bond UTXO
    /// The bond must be confirmed before the node becomes eligible for elder status
    pub fn register_elder_bond(
        &self,
        node_id: &str,
        txid: &str,
        vout: u32,
        amount_sats: u64,
        script_pubkey: &str,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // Insert or update the bond
            conn.execute(
                "INSERT INTO elder_bonds (node_id, txid, vout, amount_sats, script_pubkey, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)
                 ON CONFLICT(node_id) DO UPDATE SET
                     txid = excluded.txid,
                     vout = excluded.vout,
                     amount_sats = excluded.amount_sats,
                     script_pubkey = excluded.script_pubkey,
                     status = 'pending',
                     confirmation_height = NULL,
                     spent_txid = NULL,
                     updated_at = excluded.updated_at",
                params![node_id, txid, vout, amount_sats, script_pubkey, now, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Also update the node's elder_bond_sats and elder_bond_txid
            conn.execute(
                "UPDATE nodes SET elder_bond_sats = ?1, elder_bond_txid = ?2 WHERE node_id = ?3",
                params![amount_sats, txid, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            tracing::info!(
                node_id = %&node_id[..8.min(node_id.len())],
                txid = %&txid[..16.min(txid.len())],
                amount_sats,
                "Elder bond registered"
            );

            Ok(())
        })
    }

    /// Confirm an elder bond (called when UTXO is confirmed on-chain)
    pub fn confirm_elder_bond(&self, node_id: &str, confirmation_height: u64) -> GhostResult<bool> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            let updated = conn.execute(
                "UPDATE elder_bonds SET status = 'confirmed', confirmation_height = ?1, updated_at = ?2
                 WHERE node_id = ?3 AND status = 'pending'",
                params![confirmation_height, now, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated > 0 {
                tracing::info!(
                    node_id = %&node_id[..8.min(node_id.len())],
                    height = confirmation_height,
                    "Elder bond confirmed"
                );
            }

            Ok(updated > 0)
        })
    }

    /// Check if a node has a sufficient confirmed bond
    pub fn has_valid_elder_bond(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let amount: Option<u64> = conn
                .query_row(
                    "SELECT amount_sats FROM elder_bonds
                     WHERE node_id = ?1 AND status = 'confirmed' AND spent_txid IS NULL",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(amount.unwrap_or(0) >= Self::MIN_ELDER_BOND_SATS)
        })
    }

    /// Mark an elder bond as spent (slashed or withdrawn)
    ///
    /// H-13: This operation is wrapped in a transaction to ensure atomicity.
    /// Both the elder_bonds table and nodes table must be updated together,
    /// or neither should be updated (in case of failure).
    pub fn spend_elder_bond(&self, node_id: &str, spent_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        let node_id = node_id.to_string();
        let spent_txid = spent_txid.to_string();

        // H-13: Use transaction to ensure atomic update of both tables
        self.transaction(|tx| {
            tx.execute(
                "UPDATE elder_bonds SET status = 'spent', spent_txid = ?1, updated_at = ?2
                 WHERE node_id = ?3 AND status = 'confirmed'",
                params![spent_txid, now, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Update node's bond info - must be atomic with above
            tx.execute(
                "UPDATE nodes SET elder_bond_sats = 0, elder_bond_txid = NULL WHERE node_id = ?1",
                params![node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(())
        })
    }

    /// Record a slashing event for an elder
    /// This is called when an elder is caught misbehaving (e.g., double-voting)
    ///
    /// H-13: This operation is wrapped in a transaction to ensure atomicity.
    /// The slashing record and node status update must happen together,
    /// or neither should happen (in case of failure).
    pub fn record_elder_slashing(
        &self,
        node_id: &str,
        reason: &str,
        evidence_hash: &str,
        slashed_amount_sats: u64,
        slashing_txid: Option<&str>,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        let node_id = node_id.to_string();
        let reason = reason.to_string();
        let evidence_hash = evidence_hash.to_string();
        let slashing_txid = slashing_txid.map(|s| s.to_string());

        // H-13: Use transaction to ensure atomic insert and update
        self.transaction(|tx| {
            // Record the slashing event
            tx.execute(
                "INSERT INTO elder_slashing (node_id, reason, evidence_hash, slashed_amount_sats, slashing_txid, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![node_id, reason, evidence_hash, slashed_amount_sats, slashing_txid, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Mark the node as slashed and remove elder status - must be atomic with above
            tx.execute(
                "UPDATE nodes SET is_elder = 0, elder_order = NULL, slashed_at = ?1 WHERE node_id = ?2",
                params![now, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            tracing::warn!(
                node_id = %&node_id[..8.min(node_id.len())],
                reason = %reason,
                slashed_amount_sats,
                "Elder slashed for misbehavior"
            );

            Ok(())
        })
    }

    /// Check if a node has been slashed
    pub fn is_node_slashed(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let slashed_at: Option<i64> = conn
                .query_row(
                    "SELECT slashed_at FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            Ok(slashed_at.is_some())
        })
    }

    /// Get elder bond info for a node
    pub fn get_elder_bond(&self, node_id: &str) -> GhostResult<Option<ElderBondRecord>> {
        self.with_connection(|conn| {
            let record: Option<ElderBondRecord> = conn
                .query_row(
                    "SELECT node_id, txid, vout, amount_sats, script_pubkey, confirmation_height, spent_txid, status, created_at, updated_at
                     FROM elder_bonds WHERE node_id = ?1",
                    [node_id],
                    |row| {
                        Ok(ElderBondRecord {
                            node_id: row.get(0)?,
                            txid: row.get(1)?,
                            vout: row.get(2)?,
                            amount_sats: row.get(3)?,
                            script_pubkey: row.get(4)?,
                            confirmation_height: row.get(5)?,
                            spent_txid: row.get(6)?,
                            status: row.get(7)?,
                            created_at: row.get(8)?,
                            updated_at: row.get(9)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(record)
        })
    }

    /// Get elder count
    pub fn get_elder_count(&self) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: u32 = conn
                .query_row("SELECT COUNT(*) FROM nodes WHERE is_elder = 1", [], |row| {
                    row.get(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count)
        })
    }

    /// Increment node share count
    pub fn increment_node_shares(&self, node_id: &str, count: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET total_shares_received = total_shares_received + ?1 WHERE node_id = ?2",
                params![count, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

// =============================================================================
// MINER QUERIES
// =============================================================================

impl Database {
    /// Get a miner by ID
    pub fn get_miner(&self, miner_id: &str) -> GhostResult<Option<MinerRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, payout_address, first_seen, last_seen,
                            connected_node, total_shares, total_work, blocks_won,
                            total_payouts_sats, avg_hashrate_ths
                     FROM miners WHERE miner_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miner = stmt
                .query_row([miner_id], |row| {
                    Ok(MinerRecord {
                        miner_id: row.get(0)?,
                        payout_address: row.get(1)?,
                        first_seen: row.get(2)?,
                        last_seen: row.get(3)?,
                        connected_node: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        blocks_won: row.get(7)?,
                        total_payouts_sats: row.get(8)?,
                        avg_hashrate_ths: row.get(9)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miner)
        })
    }

    /// Get miner's payout address by ID
    pub fn get_miner_payout_address(&self, miner_id: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let address: Option<String> = conn
                .query_row(
                    "SELECT payout_address FROM miners WHERE miner_id = ?1",
                    [miner_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(address)
        })
    }

    /// Upsert a miner (insert or update)
    pub fn upsert_miner(&self, miner: &MinerRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO miners (
                    miner_id, payout_address, first_seen, last_seen,
                    connected_node, total_shares, total_work, blocks_won,
                    total_payouts_sats, avg_hashrate_ths
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(miner_id) DO UPDATE SET
                    payout_address = ?2,
                    last_seen = ?4,
                    connected_node = ?5,
                    total_shares = ?6,
                    total_work = ?7,
                    blocks_won = ?8,
                    total_payouts_sats = ?9,
                    avg_hashrate_ths = ?10",
                params![
                    miner.miner_id,
                    miner.payout_address,
                    miner.first_seen,
                    miner.last_seen,
                    miner.connected_node,
                    miner.total_shares,
                    miner.total_work,
                    miner.blocks_won,
                    miner.total_payouts_sats,
                    miner.avg_hashrate_ths,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update miner's payout address
    pub fn update_miner_address(&self, miner_id: &str, payout_address: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // Try update first
            let updated = conn
                .execute(
                    "UPDATE miners SET payout_address = ?1, last_seen = ?2 WHERE miner_id = ?3",
                    params![payout_address, now, miner_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // If no row updated, insert new miner
            if updated == 0 {
                conn.execute(
                    "INSERT INTO miners (miner_id, payout_address, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?3)",
                    params![miner_id, payout_address, now],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            }

            Ok(())
        })
    }

    /// Increment miner share count and work
    pub fn increment_miner_stats(&self, miner_id: &str, shares: u64, work: f64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute(
                "UPDATE miners SET
                    total_shares = total_shares + ?1,
                    total_work = total_work + ?2,
                    last_seen = ?3
                 WHERE miner_id = ?4",
                params![shares, work, now, miner_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get node's payout address by ID
    pub fn get_node_payout_address(&self, node_id: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let address: Option<String> = conn
                .query_row(
                    "SELECT payout_address FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();
            Ok(address)
        })
    }

    /// Update node's payout address
    pub fn update_node_payout_address(
        &self,
        node_id: &str,
        payout_address: &str,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET payout_address = ?1 WHERE node_id = ?2",
                params![payout_address, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn get_node_internal(conn: &Connection, node_id: &str) -> GhostResult<Option<NodeRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT node_id, public_address, display_name, first_seen, last_seen,
                    is_elder, elder_order, capabilities, total_uptime_secs,
                    uptime_7d_percent, verification_pass_rate, total_shares_received,
                    total_blocks_found, payout_address
             FROM nodes WHERE node_id = ?1",
        )
        .map_err(|e| GhostError::Database(e.to_string()))?;

    let node = stmt
        .query_row([node_id], node_from_row)
        .optional()
        .map_err(|e| GhostError::Database(e.to_string()))?;

    Ok(node)
}

fn node_from_row(row: &rusqlite::Row) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        public_address: row.get(1)?,
        display_name: row.get(2)?,
        first_seen: row.get(3)?,
        last_seen: row.get(4)?,
        is_elder: row.get(5)?,
        elder_order: row.get(6)?,
        capabilities: row.get(7)?,
        total_uptime_secs: row.get(8)?,
        uptime_7d_percent: row.get(9)?,
        verification_pass_rate: row.get(10)?,
        total_shares_received: row.get(11)?,
        total_blocks_found: row.get(12)?,
        payout_address: row.get(13)?,
    })
}

// =============================================================================
// NODE REWARD LEDGER QUERIES
// =============================================================================

impl Database {
    /// Get or create node reward entry
    pub fn get_or_create_node_reward(&self, node_id: &str) -> GhostResult<NodeRewardEntry> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // Try to get existing
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, balance_sats, last_credited_round, total_credits_sats,
                            total_withdrawals_sats, created_at, updated_at
                     FROM node_rewards WHERE node_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if let Some(entry) = stmt
                .query_row([node_id], |row| {
                    Ok(NodeRewardEntry {
                        node_id: row.get(0)?,
                        balance_sats: row.get(1)?,
                        last_credited_round: row.get(2)?,
                        total_credits_sats: row.get(3)?,
                        total_withdrawals_sats: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
            {
                return Ok(entry);
            }

            // Create new entry
            conn.execute(
                "INSERT INTO node_rewards (node_id, balance_sats, created_at, updated_at)
                 VALUES (?1, 0, ?2, ?2)",
                params![node_id, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(NodeRewardEntry {
                node_id: node_id.to_string(),
                balance_sats: 0,
                last_credited_round: 0,
                total_credits_sats: 0,
                total_withdrawals_sats: 0,
                created_at: now,
                updated_at: now,
            })
        })
    }

    /// Credit node reward
    ///
    /// DB-H2: Uses explicit transaction for atomicity and validates the node exists.
    /// Returns error if the node doesn't exist in node_rewards table.
    pub fn credit_node_reward(&self, node_id: &str, amount: u64, round_id: u64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // DB-H2: Use transaction for atomic credit operation
            conn.execute("BEGIN IMMEDIATE", [])
                .map_err(|e| GhostError::Database(format!("Failed to begin transaction: {}", e)))?;

            let result = conn.execute(
                "UPDATE node_rewards SET
                    balance_sats = balance_sats + ?1,
                    last_credited_round = ?2,
                    total_credits_sats = total_credits_sats + ?1,
                    updated_at = ?3
                 WHERE node_id = ?4",
                params![amount, round_id, now, node_id],
            );

            match result {
                Ok(rows_affected) => {
                    if rows_affected == 0 {
                        // Node doesn't exist - rollback and return error
                        let _ = conn.execute("ROLLBACK", []);
                        return Err(GhostError::Database(format!(
                            "Node {} not found in node_rewards table",
                            node_id
                        )));
                    }
                    conn.execute("COMMIT", [])
                        .map_err(|e| GhostError::Database(format!("Failed to commit: {}", e)))?;
                    Ok(())
                }
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", []);
                    Err(GhostError::Database(e.to_string()))
                }
            }
        })
    }

    /// Get nodes with balance above threshold
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_nodes_with_balance(&self, min_balance: u64) -> GhostResult<Vec<NodeRewardEntry>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, balance_sats, last_credited_round, total_credits_sats,
                            total_withdrawals_sats, created_at, updated_at
                     FROM node_rewards WHERE balance_sats >= ?1 ORDER BY balance_sats DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entries = stmt
                .query_map(params![min_balance, Self::MAX_QUERY_RESULTS], |row| {
                    Ok(NodeRewardEntry {
                        node_id: row.get(0)?,
                        balance_sats: row.get(1)?,
                        last_credited_round: row.get(2)?,
                        total_credits_sats: row.get(3)?,
                        total_withdrawals_sats: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(entries)
        })
    }
}

// =============================================================================
// KEY-VALUE STORE
// =============================================================================

impl Database {
    /// Get a value from the key-value store
    pub fn kv_get(&self, key: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let value: Option<String> = conn
                .query_row("SELECT value FROM kv_store WHERE key = ?1", [key], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(value)
        })
    }

    /// Set a value in the key-value store
    pub fn kv_set(&self, key: &str, value: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                params![key, value, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Delete a key from the key-value store
    pub fn kv_delete(&self, key: &str) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute("DELETE FROM kv_store WHERE key = ?1", [key])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

// =============================================================================
// GHOST LOCK QUERIES
// =============================================================================

impl Database {
    /// Insert a new Ghost Lock
    pub fn insert_ghost_lock(&self, lock: &GhostLockRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO ghost_locks (
                    lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                    denomination, amount_sats, timelock_tier, creation_height,
                    recovery_height, state, funding_txid, funding_vout,
                    spend_txid, output_script, jump_risk_tier, next_jump_height,
                    created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    lock.lock_id,
                    lock.owner_ghost_id,
                    lock.lock_pubkey,
                    lock.recovery_pubkey,
                    lock.denomination,
                    lock.amount_sats,
                    lock.timelock_tier,
                    lock.creation_height,
                    lock.recovery_height,
                    lock.state.as_str(),
                    lock.funding_txid,
                    lock.funding_vout,
                    lock.spend_txid,
                    lock.output_script,
                    lock.jump_risk_tier,
                    lock.next_jump_height,
                    lock.created_at,
                    lock.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a Ghost Lock by ID
    pub fn get_ghost_lock(&self, lock_id: &str) -> GhostResult<Option<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks WHERE lock_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let lock = stmt
                .query_row([lock_id], ghost_lock_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(lock)
        })
    }

    /// Get all Ghost Locks for an owner
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_ghost_locks_by_owner(
        &self,
        owner_ghost_id: &str,
    ) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks WHERE owner_ghost_id = ?1 ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map(params![owner_ghost_id, Self::MAX_QUERY_RESULTS], ghost_lock_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Get active Ghost Locks for an owner
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_active_ghost_locks(
        &self,
        owner_ghost_id: &str,
    ) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks
                     WHERE owner_ghost_id = ?1 AND state = 'active'
                     ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map(params![owner_ghost_id, Self::MAX_QUERY_RESULTS], ghost_lock_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Get Ghost Locks that need to jump by a certain height
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_locks_needing_jump(&self, current_height: u32) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks
                     WHERE state = 'active' AND next_jump_height IS NOT NULL AND next_jump_height <= ?1
                     ORDER BY next_jump_height ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map(params![current_height, Self::MAX_QUERY_RESULTS], ghost_lock_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Update Ghost Lock state
    pub fn update_ghost_lock_state(&self, lock_id: &str, state: GhostLockState) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET state = ?1, updated_at = ?2 WHERE lock_id = ?3",
                params![state.as_str(), now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock funding info
    pub fn update_ghost_lock_funding(
        &self,
        lock_id: &str,
        txid: &str,
        vout: u32,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET
                    funding_txid = ?1, funding_vout = ?2, state = 'active', updated_at = ?3
                 WHERE lock_id = ?4",
                params![txid, vout, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock spend info
    pub fn update_ghost_lock_spent(&self, lock_id: &str, spend_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET
                    spend_txid = ?1, state = 'spent', updated_at = ?2
                 WHERE lock_id = ?3",
                params![spend_txid, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock next jump height
    pub fn update_ghost_lock_jump_height(
        &self,
        lock_id: &str,
        next_jump_height: u32,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET next_jump_height = ?1, updated_at = ?2 WHERE lock_id = ?3",
                params![next_jump_height, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get total balance in active Ghost Locks for an owner
    pub fn get_ghost_lock_balance(&self, owner_ghost_id: &str) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let balance: u64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(amount_sats), 0) FROM ghost_locks
                     WHERE owner_ghost_id = ?1 AND state = 'active'",
                    [owner_ghost_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(balance)
        })
    }
}

fn ghost_lock_from_row(row: &rusqlite::Row) -> rusqlite::Result<GhostLockRecord> {
    let state_str: String = row.get(9)?;
    Ok(GhostLockRecord {
        lock_id: row.get(0)?,
        owner_ghost_id: row.get(1)?,
        lock_pubkey: row.get(2)?,
        recovery_pubkey: row.get(3)?,
        denomination: row.get(4)?,
        amount_sats: row.get(5)?,
        timelock_tier: row.get(6)?,
        creation_height: row.get(7)?,
        recovery_height: row.get(8)?,
        state: GhostLockState::parse(&state_str).unwrap_or(GhostLockState::Pending),
        funding_txid: row.get(10)?,
        funding_vout: row.get(11)?,
        spend_txid: row.get(12)?,
        output_script: row.get(13)?,
        jump_risk_tier: row.get(14)?,
        next_jump_height: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

// =============================================================================
// PEER QUERIES
// =============================================================================

impl Database {
    /// Upsert a peer record
    pub fn upsert_peer(&self, peer: &PeerRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO peers (
                    peer_id, address, port, node_id, first_seen, last_seen,
                    last_success, last_failure, connection_count, failure_count,
                    is_banned, ban_until, capabilities, protocol_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                ON CONFLICT(peer_id) DO UPDATE SET
                    address = COALESCE(NULLIF(?2, ''), address),
                    last_seen = ?6,
                    last_success = COALESCE(?7, last_success),
                    last_failure = COALESCE(?8, last_failure),
                    connection_count = ?9,
                    failure_count = ?10,
                    is_banned = ?11,
                    ban_until = ?12,
                    capabilities = COALESCE(?13, capabilities),
                    protocol_version = COALESCE(?14, protocol_version)",
                params![
                    peer.peer_id,
                    peer.address,
                    peer.port,
                    peer.node_id,
                    peer.first_seen,
                    peer.last_seen,
                    peer.last_success,
                    peer.last_failure,
                    peer.connection_count,
                    peer.failure_count,
                    peer.is_banned,
                    peer.ban_until,
                    peer.capabilities,
                    peer.protocol_version,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a peer by ID
    pub fn get_peer(&self, peer_id: &str) -> GhostResult<Option<PeerRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT peer_id, address, port, node_id, first_seen, last_seen,
                            last_success, last_failure, connection_count, failure_count,
                            is_banned, ban_until, capabilities, protocol_version
                     FROM peers WHERE peer_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let peer = stmt
                .query_row([peer_id], peer_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(peer)
        })
    }

    /// Get active (non-banned) peers
    pub fn get_active_peers(&self, limit: u32) -> GhostResult<Vec<PeerRecord>> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT peer_id, address, port, node_id, first_seen, last_seen,
                            last_success, last_failure, connection_count, failure_count,
                            is_banned, ban_until, capabilities, protocol_version
                     FROM peers
                     WHERE is_banned = 0 OR ban_until < ?1
                     ORDER BY last_success DESC NULLS LAST
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let peers = stmt
                .query_map(params![now, limit], peer_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(peers)
        })
    }

    /// Ban a peer
    pub fn ban_peer(&self, peer_id: &str, ban_until: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE peers SET is_banned = 1, ban_until = ?1 WHERE peer_id = ?2",
                params![ban_until, peer_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn peer_from_row(row: &rusqlite::Row) -> rusqlite::Result<PeerRecord> {
    Ok(PeerRecord {
        peer_id: row.get(0)?,
        address: row.get(1)?,
        port: row.get(2)?,
        node_id: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        last_success: row.get(6)?,
        last_failure: row.get(7)?,
        connection_count: row.get(8)?,
        failure_count: row.get(9)?,
        is_banned: row.get(10)?,
        ban_until: row.get(11)?,
        capabilities: row.get(12)?,
        protocol_version: row.get(13)?,
    })
}

// =============================================================================
// WRAITH ROUND QUERIES
// =============================================================================

impl Database {
    /// Insert a new Wraith round
    pub fn insert_wraith_round(&self, round: &WraithRoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO wraith_rounds (
                    round_id, coordinator_id, denomination, amount_sats, phase,
                    participant_count, min_participants, max_participants,
                    registration_deadline, execution_deadline, split_txid, merge_txid,
                    status, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    round.round_id,
                    round.coordinator_id,
                    round.denomination,
                    round.amount_sats,
                    round.phase.as_str(),
                    round.participant_count,
                    round.min_participants,
                    round.max_participants,
                    round.registration_deadline,
                    round.execution_deadline,
                    round.split_txid,
                    round.merge_txid,
                    round.status.as_str(),
                    round.created_at,
                    round.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a Wraith round by ID
    pub fn get_wraith_round(&self, round_id: &str) -> GhostResult<Option<WraithRoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, coordinator_id, denomination, amount_sats, phase,
                            participant_count, min_participants, max_participants,
                            registration_deadline, execution_deadline, split_txid, merge_txid,
                            status, created_at, updated_at
                     FROM wraith_rounds WHERE round_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let round = stmt
                .query_row([round_id], wraith_round_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(round)
        })
    }

    /// Get active Wraith rounds
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_active_wraith_rounds(&self) -> GhostResult<Vec<WraithRoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, coordinator_id, denomination, amount_sats, phase,
                            participant_count, min_participants, max_participants,
                            registration_deadline, execution_deadline, split_txid, merge_txid,
                            status, created_at, updated_at
                     FROM wraith_rounds WHERE status = 'active'
                     ORDER BY registration_deadline ASC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([Self::MAX_QUERY_RESULTS], wraith_round_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }

    /// Update Wraith round phase
    pub fn update_wraith_round_phase(&self, round_id: &str, phase: WraithPhase) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE wraith_rounds SET phase = ?1, updated_at = ?2 WHERE round_id = ?3",
                params![phase.as_str(), now, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Wraith round status
    pub fn update_wraith_round_status(
        &self,
        round_id: &str,
        status: WraithStatus,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE wraith_rounds SET status = ?1, updated_at = ?2 WHERE round_id = ?3",
                params![status.as_str(), now, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn wraith_round_from_row(row: &rusqlite::Row) -> rusqlite::Result<WraithRoundRecord> {
    let phase_str: String = row.get(4)?;
    let status_str: String = row.get(12)?;
    Ok(WraithRoundRecord {
        round_id: row.get(0)?,
        coordinator_id: row.get(1)?,
        denomination: row.get(2)?,
        amount_sats: row.get(3)?,
        phase: WraithPhase::parse(&phase_str).unwrap_or(WraithPhase::Registration),
        participant_count: row.get(5)?,
        min_participants: row.get(6)?,
        max_participants: row.get(7)?,
        registration_deadline: row.get(8)?,
        execution_deadline: row.get(9)?,
        split_txid: row.get(10)?,
        merge_txid: row.get(11)?,
        status: WraithStatus::parse(&status_str).unwrap_or(WraithStatus::Active),
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

// =============================================================================
// RECONCILIATION QUERIES
// =============================================================================

impl Database {
    /// Insert a reconciliation batch
    pub fn insert_reconciliation_batch(&self, batch: &ReconciliationRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO reconciliation_state (
                    batch_id, settlement_class, participant_count, total_amount_sats,
                    merkle_root, l1_txid, l1_block_height, dispute_deadline,
                    status, created_at, finalized_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    batch.batch_id,
                    batch.settlement_class,
                    batch.participant_count,
                    batch.total_amount_sats,
                    batch.merkle_root,
                    batch.l1_txid,
                    batch.l1_block_height,
                    batch.dispute_deadline,
                    batch.status.as_str(),
                    batch.created_at,
                    batch.finalized_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a reconciliation batch by ID
    pub fn get_reconciliation_batch(
        &self,
        batch_id: &str,
    ) -> GhostResult<Option<ReconciliationRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT batch_id, settlement_class, participant_count, total_amount_sats,
                            merkle_root, l1_txid, l1_block_height, dispute_deadline,
                            status, created_at, finalized_at
                     FROM reconciliation_state WHERE batch_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let batch = stmt
                .query_row([batch_id], reconciliation_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(batch)
        })
    }

    /// Get pending reconciliation batches
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_pending_reconciliation_batches(&self) -> GhostResult<Vec<ReconciliationRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT batch_id, settlement_class, participant_count, total_amount_sats,
                            merkle_root, l1_txid, l1_block_height, dispute_deadline,
                            status, created_at, finalized_at
                     FROM reconciliation_state WHERE status IN ('pending', 'submitted')
                     ORDER BY created_at ASC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let batches = stmt
                .query_map([Self::MAX_QUERY_RESULTS], reconciliation_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(batches)
        })
    }

    /// Update reconciliation batch L1 submission
    pub fn update_reconciliation_l1_submitted(
        &self,
        batch_id: &str,
        txid: &str,
        block_height: u64,
        dispute_deadline: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE reconciliation_state SET
                    l1_txid = ?1, l1_block_height = ?2, dispute_deadline = ?3, status = 'submitted'
                 WHERE batch_id = ?4",
                params![txid, block_height, dispute_deadline, batch_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Finalize reconciliation batch
    pub fn finalize_reconciliation_batch(&self, batch_id: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE reconciliation_state SET status = 'finalized', finalized_at = ?1 WHERE batch_id = ?2",
                params![now, batch_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn reconciliation_from_row(row: &rusqlite::Row) -> rusqlite::Result<ReconciliationRecord> {
    let status_str: String = row.get(8)?;
    Ok(ReconciliationRecord {
        batch_id: row.get(0)?,
        settlement_class: row.get(1)?,
        participant_count: row.get(2)?,
        total_amount_sats: row.get(3)?,
        merkle_root: row.get(4)?,
        l1_txid: row.get(5)?,
        l1_block_height: row.get(6)?,
        dispute_deadline: row.get(7)?,
        status: ReconciliationStatus::parse(&status_str).unwrap_or(ReconciliationStatus::Pending),
        created_at: row.get(9)?,
        finalized_at: row.get(10)?,
    })
}

// =============================================================================
// WITHDRAWAL REQUEST QUERIES
// =============================================================================

impl Database {
    /// Insert a new withdrawal request
    pub fn insert_withdrawal_request(&self, request: &WithdrawalRequest) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO withdrawal_requests (
                    ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                    status, batch_id, l1_txid, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    request.ghost_id,
                    request.lock_id,
                    request.destination_address,
                    request.amount_sats,
                    request.fee_sats,
                    request.status.as_str(),
                    request.batch_id,
                    request.l1_txid,
                    request.created_at,
                    request.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Atomically insert a withdrawal request if no pending/batched withdrawal exists for the lock
    ///
    /// This prevents double-spend race conditions (C-PAY-3) by:
    /// 1. Using a transaction to ensure atomicity
    /// 2. Checking for existing pending/batched withdrawals within the transaction
    /// 3. Relying solely on the database partial unique index for atomicity
    ///
    /// DB-C3: Removed application-level check to eliminate TOCTOU race window.
    /// The partial unique index `idx_withdrawals_pending_lock` on (lock_id)
    /// WHERE status IN ('pending', 'batched') enforces the constraint atomically.
    ///
    /// Returns:
    /// - Ok(Some(id)) - Successfully inserted, returns the new withdrawal ID
    /// - Ok(None) - A pending/batched withdrawal already exists for this lock
    /// - Err(_) - Database error
    pub fn insert_withdrawal_request_atomic(
        &self,
        request: &WithdrawalRequest,
    ) -> GhostResult<Option<i64>> {
        self.with_connection(|conn| {
            // DB-C3: Directly attempt INSERT and rely on unique constraint
            // The partial unique index ensures atomic double-spend prevention
            // without the TOCTOU race window of check-then-insert
            let result = conn.execute(
                "INSERT INTO withdrawal_requests (
                    ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                    status, batch_id, l1_txid, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    request.ghost_id,
                    request.lock_id,
                    request.destination_address,
                    request.amount_sats,
                    request.fee_sats,
                    request.status.as_str(),
                    request.batch_id,
                    request.l1_txid,
                    request.created_at,
                    request.updated_at,
                ],
            );

            match result {
                Ok(_) => Ok(Some(conn.last_insert_rowid())),
                Err(e) => {
                    // Check if this is a unique constraint violation
                    // This means a pending/batched withdrawal already exists for this lock
                    let err_str = e.to_string();
                    if err_str.contains("UNIQUE constraint failed")
                        || err_str.contains("idx_withdrawals_pending_lock")
                    {
                        // Duplicate withdrawal attempt - return None (not an error)
                        tracing::debug!(
                            lock_id = %request.lock_id,
                            "Withdrawal request rejected: pending/batched withdrawal exists"
                        );
                        Ok(None)
                    } else {
                        Err(GhostError::Database(err_str))
                    }
                }
            }
        })
    }

    /// Get a withdrawal request by ID
    pub fn get_withdrawal_request(&self, id: i64) -> GhostResult<Option<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests WHERE id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let request = stmt
                .query_row([id], withdrawal_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(request)
        })
    }

    /// Get pending withdrawal requests for a ghost_id
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_pending_withdrawals(&self, ghost_id: &str) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE ghost_id = ?1 AND status = 'pending'
                     ORDER BY created_at ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map(params![ghost_id, Self::MAX_QUERY_RESULTS], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get all pending withdrawal requests (for batch processing)
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_all_pending_withdrawals(&self) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE status = 'pending'
                     ORDER BY created_at ASC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map([Self::MAX_QUERY_RESULTS], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get withdrawal requests by lock ID
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_withdrawals_by_lock(&self, lock_id: &str) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE lock_id = ?1
                     ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map(params![lock_id, Self::MAX_QUERY_RESULTS], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Update withdrawal request status
    pub fn update_withdrawal_status(&self, id: i64, status: WithdrawalStatus) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status.as_str(), now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update withdrawal request with batch info
    pub fn update_withdrawal_batched(&self, id: i64, batch_id: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'batched', batch_id = ?1, updated_at = ?2 WHERE id = ?3",
                params![batch_id, now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update withdrawal request with L1 txid
    pub fn update_withdrawal_submitted(&self, id: i64, l1_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'submitted', l1_txid = ?1, updated_at = ?2 WHERE id = ?3",
                params![l1_txid, now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark withdrawal as confirmed
    pub fn update_withdrawal_confirmed(&self, id: i64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'confirmed', updated_at = ?1 WHERE id = ?2",
                params![now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Cancel a pending withdrawal
    pub fn cancel_withdrawal(&self, id: i64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'cancelled', updated_at = ?1 WHERE id = ?2 AND status = 'pending'",
                params![now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    // ========================================================================
    // Verification API Queries
    // ========================================================================

    /// Get recent shares across all rounds (for verification API)
    pub fn get_recent_shares(&self, limit: u32) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares ORDER BY timestamp DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map([limit], |row| {
                    Ok(ShareRecord {
                        id: Some(row.get(0)?),
                        round_id: row.get(1)?,
                        miner_id: row.get(2)?,
                        difficulty: row.get(3)?,
                        work: row.get(4)?,
                        share_hash: row.get(5)?,
                        timestamp: row.get(6)?,
                        received_by: row.get(7)?,
                        valid: row.get(8)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get payouts for a specific round
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_payouts_by_round(&self, round_id: u64) -> GhostResult<Vec<PayoutRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, recipient_id, recipient_type, address, amount_sats,
                            txid, vout, status, created_at, confirmed_at
                     FROM payouts WHERE round_id = ?1 ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let payouts = stmt
                .query_map(params![round_id, Self::MAX_QUERY_RESULTS], payout_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(payouts)
        })
    }

    /// Get recent payouts across all rounds
    pub fn get_recent_payouts(&self, limit: u32) -> GhostResult<Vec<PayoutRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, recipient_id, recipient_type, address, amount_sats,
                            txid, vout, status, created_at, confirmed_at
                     FROM payouts ORDER BY created_at DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let payouts = stmt
                .query_map([limit], payout_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(payouts)
        })
    }

    /// Insert a payout record
    pub fn insert_payout(&self, payout: &PayoutRecord) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO payouts (round_id, recipient_id, recipient_type, address, amount_sats,
                                     txid, vout, status, created_at, confirmed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    payout.round_id,
                    payout.recipient_id,
                    payout.recipient_type.as_str(),
                    payout.address,
                    payout.amount_sats,
                    payout.txid,
                    payout.vout,
                    payout.status.as_str(),
                    payout.created_at,
                    payout.confirmed_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get total payout count
    pub fn get_payout_count(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM payouts", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    /// Query paginated payout history
    ///
    /// Returns round payout summaries ordered by block height descending.
    /// Results are grouped by round and include aggregated payout information.
    ///
    /// The query joins the rounds and payouts tables to provide a complete
    /// picture of each round's payout distribution.
    pub fn query_payout_history(
        &self,
        query: PayoutHistoryQuery,
    ) -> GhostResult<Vec<RoundPayoutSummary>> {
        self.with_connection(|conn| {
            // Build the SQL query with optional height filters
            // We join rounds with payouts to get complete information
            // and aggregate payout counts and amounts by recipient type
            let sql = "
                SELECT
                    r.round_id,
                    r.block_height,
                    r.block_hash,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'miner' THEN 1 ELSE 0 END), 0) as miner_count,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'node' OR p.recipient_type = 'tx_fees' THEN 1 ELSE 0 END), 0) as node_count,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'miner' THEN p.amount_sats ELSE 0 END), 0) as total_miner_sats,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'node' THEN p.amount_sats ELSE 0 END), 0) as total_node_sats,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'treasury' THEN p.amount_sats ELSE 0 END), 0) as treasury_sats,
                    COALESCE(r.tx_fees_sats, 0) as tx_fees_sats,
                    r.payout_status,
                    COALESCE(MIN(p.created_at), r.start_time) as created_at
                FROM rounds r
                LEFT JOIN payouts p ON r.round_id = p.round_id
                WHERE r.payout_status IN ('pending', 'approved', 'broadcast', 'confirmed')
                    AND ($1 IS NULL OR r.block_height >= $1)
                    AND ($2 IS NULL OR r.block_height <= $2)
                GROUP BY r.round_id
                ORDER BY r.block_height DESC
                LIMIT $3 OFFSET $4
            ";

            let mut stmt = conn
                .prepare(sql)
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let summaries = stmt
                .query_map(
                    params![
                        query.min_height,
                        query.max_height,
                        query.limit,
                        query.offset
                    ],
                    |row| {
                        // SEC-DATA-3: Use safe conversions to catch database corruption
                        Ok(RoundPayoutSummary {
                            round_id: row.get(0)?,
                            block_height: row.get(1)?,
                            block_hash: row.get(2)?,
                            miner_count: i64_to_u32_count(row.get::<_, i64>(3)?, "miner_count")?,
                            node_count: i64_to_u32_count(row.get::<_, i64>(4)?, "node_count")?,
                            total_miner_sats: i64_to_u64_sats(row.get::<_, i64>(5)?, "total_miner_sats")?,
                            total_node_sats: i64_to_u64_sats(row.get::<_, i64>(6)?, "total_node_sats")?,
                            treasury_sats: i64_to_u64_sats(row.get::<_, i64>(7)?, "treasury_sats")?,
                            tx_fees_sats: i64_to_u64_sats(row.get::<_, i64>(8)?, "tx_fees_sats")?,
                            status: row.get(9)?,
                            created_at: row.get(10)?,
                        })
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(summaries)
        })
    }

    /// Get total count of rounds with payouts (for pagination metadata)
    pub fn get_payout_round_count(
        &self,
        min_height: Option<u64>,
        max_height: Option<u64>,
    ) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT round_id) FROM rounds
                     WHERE payout_status IN ('pending', 'approved', 'broadcast', 'confirmed')
                       AND ($1 IS NULL OR block_height >= $1)
                       AND ($2 IS NULL OR block_height <= $2)",
                    params![min_height, max_height],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    // =========================================================================
    // KEY ROTATION WITH ELDER STATUS TRANSFER
    // =========================================================================

    /// Check if a node_id has been retired (rotated away from)
    ///
    /// Returns the new node_id if the node was rotated, None if still active.
    pub fn is_node_retired(&self, node_id: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let result: Option<String> = conn
                .query_row(
                    "SELECT new_node_id FROM retired_nodes WHERE old_node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(result)
        })
    }

    /// Check if a rotation proof has been used (prevent replay)
    fn is_rotation_proof_used(
        &self,
        conn: &Connection,
        old_node_id: &str,
        new_node_id: &str,
    ) -> GhostResult<bool> {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rotation_history
                 WHERE old_node_id = ?1 AND new_node_id = ?2 AND status = 'completed'",
                params![old_node_id, new_node_id],
                |row| row.get(0),
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
        Ok(count > 0)
    }

    /// Transfer elder status from old node_id to new node_id using a rotation proof
    ///
    /// This is the ONLY way to preserve elder status during key rotation.
    ///
    /// Security checks performed:
    /// 1. Rotation proof is cryptographically valid (both signatures)
    /// 2. Old node_id is not already retired
    /// 3. New node_id is not already in use as someone else's identity
    /// 4. The rotation proof hasn't been used before (prevent replay)
    /// 5. The rotation proof is recent (not expired)
    ///
    /// Returns (success, elder_transferred)
    pub fn transfer_elder_with_rotation(
        &self,
        rotation_proof: &ghost_common::key_rotation::KeyRotationProof,
    ) -> GhostResult<(bool, bool)> {
        // Step 1: Verify the rotation proof cryptographically (includes expiration check)
        rotation_proof.verify().map_err(|e| {
            GhostError::SignatureVerification(format!("Invalid rotation proof: {}", e))
        })?;

        let old_node_id = hex::encode(rotation_proof.old_node_id);
        let new_node_id = hex::encode(rotation_proof.new_node_id);
        let now = chrono::Utc::now().timestamp();
        let proof_bytes = rotation_proof.to_bytes();

        self.with_connection(|conn| {
            // Step 2: Check if old node is already retired
            let already_retired: Option<String> = conn
                .query_row(
                    "SELECT new_node_id FROM retired_nodes WHERE old_node_id = ?1",
                    [&old_node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if already_retired.is_some() {
                return Err(GhostError::SignatureVerification(format!(
                    "Node {} is already retired",
                    &old_node_id[..16]
                )));
            }

            // Step 3: Check if this rotation proof was already used
            if self.is_rotation_proof_used(conn, &old_node_id, &new_node_id)? {
                return Err(GhostError::SignatureVerification(
                    "Rotation proof has already been used".to_string()
                ));
            }

            // Step 4: Check if new_node_id is already in use by someone else
            let existing_new: Option<String> = conn
                .query_row(
                    "SELECT node_id FROM nodes WHERE node_id = ?1 AND rotated_from IS NULL",
                    [&new_node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if existing_new.is_some() {
                // New node_id exists and wasn't from a rotation - could be hijack attempt
                return Err(GhostError::SignatureVerification(format!(
                    "New node_id {} is already registered by another identity",
                    &new_node_id[..16]
                )));
            }

            // Step 5: Start transaction for atomic elder transfer
            conn.execute("BEGIN IMMEDIATE", [])
                .map_err(|e| GhostError::Database(format!("Failed to start transaction: {}", e)))?;

            let result: GhostResult<(bool, bool)> = (|| {
                // Get old node's elder status and other transferable attributes
                let old_node: Option<NodeRotationData> = conn
                    .query_row(
                        "SELECT is_elder, elder_order, pow_proof, capabilities, first_seen
                         FROM nodes WHERE node_id = ?1",
                        [&old_node_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                    )
                    .optional()
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                let (is_elder, elder_order, pow_proof, capabilities, first_seen) = match old_node {
                    Some(data) => data,
                    None => {
                        return Err(GhostError::SignatureVerification(format!(
                            "Old node {} not found in database",
                            &old_node_id[..16]
                        )));
                    }
                };

                // Insert new node (or update if it exists from a previous incomplete rotation)
                conn.execute(
                    "INSERT INTO nodes (node_id, first_seen, last_seen, is_elder, elder_order,
                                       pow_proof, capabilities, rotated_from)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(node_id) DO UPDATE SET
                         is_elder = excluded.is_elder,
                         elder_order = excluded.elder_order,
                         pow_proof = COALESCE(excluded.pow_proof, pow_proof),
                         capabilities = COALESCE(excluded.capabilities, capabilities),
                         rotated_from = excluded.rotated_from,
                         last_seen = excluded.last_seen",
                    params![
                        &new_node_id,
                        first_seen.unwrap_or(now),  // Preserve original first_seen
                        now,
                        is_elder,
                        elder_order,
                        pow_proof,
                        capabilities,
                        &old_node_id,
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Mark old node as retired (remove elder status)
                conn.execute(
                    "UPDATE nodes SET is_elder = 0, elder_order = NULL, rotated_to = ?1
                     WHERE node_id = ?2",
                    params![&new_node_id, &old_node_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Add to retired_nodes table (permanent record)
                conn.execute(
                    "INSERT INTO retired_nodes (old_node_id, new_node_id, rotation_timestamp, rotation_proof)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![&old_node_id, &new_node_id, now, &proof_bytes],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Add to rotation history
                conn.execute(
                    "INSERT INTO rotation_history (old_node_id, new_node_id, rotation_timestamp,
                                                   finalized_timestamp, status, rotation_proof, elder_transferred)
                     VALUES (?1, ?2, ?3, ?4, 'completed', ?5, ?6)",
                    params![
                        &old_node_id,
                        &new_node_id,
                        rotation_proof.timestamp as i64,
                        now,
                        &proof_bytes,
                        if is_elder { 1 } else { 0 },
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                Ok((true, is_elder))
            })();

            // Commit or rollback
            match &result {
                Ok(_) => {
                    conn.execute("COMMIT", [])
                        .map_err(|e| GhostError::Database(format!("Failed to commit: {}", e)))?;
                }
                Err(_) => {
                    let _ = conn.execute("ROLLBACK", []);
                }
            }

            result
        })
    }

    /// Get the rotation history for a node (follows the chain of rotations)
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows per direction to prevent OOM attacks
    pub fn get_rotation_chain(&self, node_id: &str) -> GhostResult<Vec<(String, String, i64)>> {
        self.with_connection(|conn| {
            let mut chain = Vec::new();

            // First, find all rotations FROM this node
            let mut stmt = conn
                .prepare(
                    "SELECT old_node_id, new_node_id, finalized_timestamp
                     FROM rotation_history
                     WHERE old_node_id = ?1 AND status = 'completed'
                     ORDER BY finalized_timestamp DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rotations = stmt
                .query_map(params![node_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            chain.extend(rotations);

            // Also find rotations TO this node (to build full chain)
            let mut stmt = conn
                .prepare(
                    "SELECT old_node_id, new_node_id, finalized_timestamp
                     FROM rotation_history
                     WHERE new_node_id = ?1 AND status = 'completed'
                     ORDER BY finalized_timestamp DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rotations = stmt
                .query_map(params![node_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            chain.extend(rotations);

            Ok(chain)
        })
    }

    /// Store a pending rotation (before finalization)
    /// This allows for grace period revocation
    pub fn store_pending_rotation(
        &self,
        rotation_proof: &ghost_common::key_rotation::KeyRotationProof,
    ) -> GhostResult<i64> {
        let old_node_id = hex::encode(rotation_proof.old_node_id);
        let new_node_id = hex::encode(rotation_proof.new_node_id);
        let proof_bytes = rotation_proof.to_bytes();

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO rotation_history (old_node_id, new_node_id, rotation_timestamp,
                                               status, rotation_proof, elder_transferred)
                 VALUES (?1, ?2, ?3, 'pending', ?4, 0)",
                params![
                    &old_node_id,
                    &new_node_id,
                    rotation_proof.timestamp as i64,
                    &proof_bytes,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Revoke a pending rotation (during grace period)
    pub fn revoke_pending_rotation(
        &self,
        rotation_id: i64,
        revocation_proof: &ghost_common::key_rotation::RotationRevocation,
    ) -> GhostResult<()> {
        // Serialize revocation proof to JSON
        let revocation_bytes = serde_json::to_vec(revocation_proof)
            .map_err(|e| GhostError::Database(format!("Failed to serialize revocation: {}", e)))?;
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            let rows_affected = conn
                .execute(
                    "UPDATE rotation_history
                     SET status = 'revoked', finalized_timestamp = ?1, revocation_proof = ?2
                     WHERE id = ?3 AND status = 'pending'",
                    params![now, &revocation_bytes, rotation_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if rows_affected == 0 {
                return Err(GhostError::Database(
                    "Rotation not found or already finalized".to_string(),
                ));
            }

            Ok(())
        })
    }
}

fn withdrawal_from_row(row: &rusqlite::Row) -> rusqlite::Result<WithdrawalRequest> {
    let status_str: String = row.get(6)?;
    Ok(WithdrawalRequest {
        id: Some(row.get(0)?),
        ghost_id: row.get(1)?,
        lock_id: row.get(2)?,
        destination_address: row.get(3)?,
        amount_sats: row.get(4)?,
        fee_sats: row.get(5)?,
        status: WithdrawalStatus::parse(&status_str).unwrap_or(WithdrawalStatus::Pending),
        batch_id: row.get(7)?,
        l1_txid: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn payout_from_row(row: &rusqlite::Row) -> rusqlite::Result<PayoutRecord> {
    let recipient_type_str: String = row.get(3)?;
    let status_str: String = row.get(8)?;
    Ok(PayoutRecord {
        id: Some(row.get(0)?),
        round_id: row.get(1)?,
        recipient_id: row.get(2)?,
        recipient_type: RecipientType::parse(&recipient_type_str).unwrap_or(RecipientType::Miner),
        address: row.get(4)?,
        amount_sats: row.get(5)?,
        txid: row.get(6)?,
        vout: row.get(7)?,
        status: PayoutStatus::parse(&status_str).unwrap_or(PayoutStatus::Pending),
        created_at: row.get(9)?,
        confirmed_at: row.get(10)?,
    })
}

// =============================================================================
// TREASURY STATE QUERIES
// =============================================================================

/// Treasury state storage keys
const TREASURY_BALANCE_KEY: &str = "treasury_balance_sats";
const TREASURY_THRESHOLD_REACHED_KEY: &str = "treasury_threshold_reached_at";

impl Database {
    /// Get the current treasury balance in satoshis
    pub fn get_treasury_balance(&self) -> GhostResult<u64> {
        match self.kv_get(TREASURY_BALANCE_KEY)? {
            Some(s) => s.parse().map_err(|e| {
                GhostError::Database(format!("Failed to parse treasury balance: {}", e))
            }),
            None => Ok(0),
        }
    }

    /// Set the current treasury balance in satoshis
    pub fn set_treasury_balance(&self, balance: u64) -> GhostResult<()> {
        self.kv_set(TREASURY_BALANCE_KEY, &balance.to_string())
    }

    /// Get the timestamp when treasury threshold was reached (if ever)
    pub fn get_treasury_threshold_reached(&self) -> GhostResult<Option<i64>> {
        match self.kv_get(TREASURY_THRESHOLD_REACHED_KEY)? {
            Some(s) => {
                let ts: i64 = s.parse().map_err(|e| {
                    GhostError::Database(format!(
                        "Failed to parse treasury threshold timestamp: {}",
                        e
                    ))
                })?;
                Ok(Some(ts))
            }
            None => Ok(None),
        }
    }

    /// Set the timestamp when treasury threshold was reached
    pub fn set_treasury_threshold_reached(&self, timestamp: i64) -> GhostResult<()> {
        self.kv_set(TREASURY_THRESHOLD_REACHED_KEY, &timestamp.to_string())
    }

    /// Add funds to treasury and check if threshold was crossed
    /// Returns true if threshold was just crossed
    ///
    /// # M-10: Atomic Treasury Balance Update
    ///
    /// This method uses a transaction to ensure atomic read-modify-write.
    /// Without this, concurrent calls could result in lost updates.
    pub fn add_treasury_funds(&self, amount: u64, threshold: u64) -> GhostResult<bool> {
        let now = chrono::Utc::now().timestamp();

        // M-10: Use transaction for atomic balance update
        self.transaction(|tx| {
            // Read current balance within transaction
            let current: u64 = tx
                .query_row(
                    "SELECT value FROM kv_store WHERE key = ?1",
                    [TREASURY_BALANCE_KEY],
                    |row| {
                        let s: String = row.get(0)?;
                        Ok(s.parse::<u64>().unwrap_or(0))
                    },
                )
                .unwrap_or(0);

            let new_balance = current.saturating_add(amount);

            // Update balance within same transaction
            tx.execute(
                "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                params![TREASURY_BALANCE_KEY, new_balance.to_string(), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Check if we just crossed threshold
            if current < threshold && new_balance >= threshold {
                tx.execute(
                    "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                    params![TREASURY_THRESHOLD_REACHED_KEY, now.to_string(), now],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                tracing::info!(
                    balance = new_balance,
                    threshold,
                    "Treasury threshold reached - decay begins"
                );
                return Ok(true);
            }

            Ok(false)
        })
    }
}

// =============================================================================
// CAPABILITY VERIFICATION CHALLENGES
// =============================================================================

impl Database {
    /// Insert an archive challenge result
    pub fn insert_archive_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        block_height: u64,
        expected_hash: &str,
        response_hash: Option<&str>,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO archive_challenges
                 (node_id, challenger_id, block_height, expected_hash, response_hash, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node_id,
                    challenger_id,
                    block_height,
                    expected_hash,
                    response_hash,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a policy challenge result
    pub fn insert_policy_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        txid: &str,
        expected_tier: i32,
        response_tier: Option<i32>,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO policy_challenges
                 (node_id, challenger_id, txid, expected_tier, response_tier, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node_id,
                    challenger_id,
                    txid,
                    expected_tier,
                    response_tier,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a stratum challenge result
    pub fn insert_stratum_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        connected: bool,
        latency_ms: Option<u32>,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO stratum_challenges
                 (node_id, challenger_id, connected, latency_ms, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    node_id,
                    challenger_id,
                    connected,
                    latency_ms,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a Ghost Pay challenge result
    pub fn insert_ghostpay_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        endpoint: &str,
        response_valid: bool,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO ghostpay_challenges
                 (node_id, challenger_id, endpoint, response_valid, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    node_id,
                    challenger_id,
                    endpoint,
                    response_valid,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get archive capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_archive_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM archive_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get policy capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_policy_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM policy_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get stratum capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_stratum_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM stratum_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get Ghost Pay capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_ghostpay_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM ghostpay_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    // =========================================================================
    // UNIQUE CHALLENGER COUNT QUERIES (C-2 Sybil Prevention)
    // =========================================================================

    /// Get the count of unique challengers for archive capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_archive_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM archive_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u32)
        })
    }

    /// Get the count of unique challengers for policy capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_policy_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM policy_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u32)
        })
    }

    /// Get the count of unique challengers for stratum capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_stratum_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM stratum_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u32)
        })
    }

    /// Get the count of unique challengers for ghostpay capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_ghostpay_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM ghostpay_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u32)
        })
    }

    /// Record an uptime sample for a node
    pub fn record_uptime_sample(
        &self,
        node_id: &str,
        sample_time: i64,
        was_online: bool,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO uptime_samples (node_id, sample_time, was_online)
                 VALUES (?1, ?2, ?3)",
                params![node_id, sample_time, was_online],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get uptime percentage for a node over trailing period
    /// Returns percentage (0.0 to 1.0)
    pub fn get_uptime_percent(&self, node_id: &str, since: i64) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN was_online = 1 THEN 1 ELSE 0 END) as online,
                        COUNT(*) as total
                     FROM uptime_samples
                     WHERE node_id = ?1 AND sample_time >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let online: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((online.unwrap_or(0), total))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let (online, total) = result;
            if total == 0 {
                return Ok(0.0);
            }
            Ok(online as f64 / total as f64)
        })
    }

    /// Check if a node has elder status
    ///
    /// Elder status is granted to the first 101 registered nodes.
    /// This is tracked by the is_elder flag in the nodes table.
    pub fn is_node_elder(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let is_elder: bool = conn
                .query_row(
                    "SELECT COALESCE(is_elder, 0) FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .unwrap_or(false);
            Ok(is_elder)
        })
    }

    /// Get qualified capabilities for a node
    ///
    /// A capability is qualified if:
    /// 1. Node passes uptime gatekeeper (95% over lookback period)
    /// 2. Capability has min_challenges or more challenges
    /// 3. Pass rate is >= min_pass_rate
    ///
    /// H-4: This function safely handles division by zero by checking total > 0
    /// before computing pass rate. If total is 0, the capability is not qualified.
    pub fn get_qualified_capabilities(
        &self,
        node_id: &str,
        since: i64,
        min_challenges: u32,
        min_pass_rate: f64,
    ) -> GhostResult<ghost_common::types::NodeCapabilities> {
        use ghost_common::types::NodeCapabilities;

        // H-4: Helper function to safely compute qualification without division by zero
        // Returns true only if total >= min_challenges AND total > 0 AND pass_rate >= threshold
        let is_qualified = |passed: u32, total: u32| -> bool {
            // Explicit check for total > 0 to prevent any division by zero
            total > 0 && total >= min_challenges && (passed as f64 / total as f64) >= min_pass_rate
        };

        // Check each capability
        let archive_qualified = {
            let (passed, total) = self.get_archive_pass_rate(node_id, since)?;
            is_qualified(passed, total)
        };

        let policy_qualified = {
            let (passed, total) = self.get_policy_pass_rate(node_id, since)?;
            is_qualified(passed, total)
        };

        let stratum_qualified = {
            let (passed, total) = self.get_stratum_pass_rate(node_id, since)?;
            is_qualified(passed, total)
        };

        let ghostpay_qualified = {
            let (passed, total) = self.get_ghostpay_pass_rate(node_id, since)?;
            is_qualified(passed, total)
        };

        // Elder status is based on is_elder flag in the nodes table
        // First 101 registered nodes are elders (registration order tracked by elder_order)
        let elder_qualified = self.is_node_elder(node_id)?;

        Ok(NodeCapabilities {
            archive_mode: archive_qualified,
            ghost_pay: ghostpay_qualified,
            public_mining: stratum_qualified,
            bitcoin_pure: policy_qualified,
            elder_status: elder_qualified,
        })
    }

    // =========================================================================
    // EQUIVOCATION PROOF QUERIES (P2P4-L7)
    // =========================================================================

    /// Store an equivocation proof for a Byzantine node
    ///
    /// P2P4-L7: Persists cryptographic proof when a node is caught signing
    /// conflicting votes. This evidence is used for:
    /// - Forensic analysis
    /// - Future slashing implementation
    /// - Audit trail
    ///
    /// # Arguments
    /// * `node_id` - The node that committed equivocation (32-byte NodeId)
    /// * `proof_data` - Serialized equivocation proof (both conflicting votes)
    /// * `round_number` - Optional round number where equivocation occurred
    /// * `vote_type` - Optional description of the vote type (e.g., "payout", "block")
    pub fn store_equivocation_proof(
        &self,
        node_id: &[u8; 32],
        proof_data: &[u8],
        round_number: Option<u64>,
        vote_type: Option<&str>,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO equivocation_proofs (node_id, proof_data, detected_at, round_number, vote_type)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    node_id.as_slice(),
                    proof_data,
                    now,
                    round_number.map(|r| r as i64),
                    vote_type,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Get equivocation proofs for a node
    ///
    /// Returns all stored equivocation proofs for forensic analysis.
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_equivocation_proofs(
        &self,
        node_id: &[u8; 32],
    ) -> GhostResult<Vec<EquivocationProofRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, node_id, proof_data, detected_at, round_number, vote_type, created_at
                     FROM equivocation_proofs WHERE node_id = ?1 ORDER BY detected_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let proofs = stmt
                .query_map(params![node_id.as_slice(), Self::MAX_QUERY_RESULTS], |row| {
                    Ok(EquivocationProofRecord {
                        id: row.get(0)?,
                        node_id: row.get(1)?,
                        proof_data: row.get(2)?,
                        detected_at: row.get(3)?,
                        round_number: row.get(4)?,
                        vote_type: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(proofs)
        })
    }

    /// Count equivocation events for a node
    ///
    /// Useful for tracking repeat offenders.
    pub fn count_equivocation_events(&self, node_id: &[u8; 32]) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM equivocation_proofs WHERE node_id = ?1",
                    [node_id.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u32)
        })
    }

    // ==========================================================================
    // P2P-C1/C2/C3: CANONICAL ELDER LIST QUERIES
    // ==========================================================================

    /// Store a canonical elder list for an epoch
    pub fn store_canonical_elder_list(
        &self,
        epoch: u64,
        merkle_root: &str,
        elder_count: u32,
        activated_at: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO canonical_elder_lists (epoch, merkle_root, elder_count, activated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![epoch as i64, merkle_root, elder_count, activated_at as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a canonical elder list by epoch
    pub fn get_canonical_elder_list(
        &self,
        epoch: u64,
    ) -> GhostResult<Option<CanonicalElderListRecord>> {
        self.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT epoch, merkle_root, elder_count, activated_at, created_at
                     FROM canonical_elder_lists WHERE epoch = ?1",
                [epoch as i64],
                |row| {
                    Ok(CanonicalElderListRecord {
                        epoch: row.get::<_, i64>(0)? as u64,
                        merkle_root: row.get(1)?,
                        elder_count: row.get::<_, i64>(2)? as u32,
                        activated_at: row.get::<_, i64>(3)? as u64,
                        created_at: row.get::<_, i64>(4)? as u64,
                    })
                },
            );

            match result {
                Ok(record) => Ok(Some(record)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Get the current (latest) canonical elder list
    pub fn get_current_canonical_elder_list(
        &self,
    ) -> GhostResult<Option<CanonicalElderListRecord>> {
        self.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT epoch, merkle_root, elder_count, activated_at, created_at
                     FROM canonical_elder_lists ORDER BY epoch DESC LIMIT 1",
                [],
                |row| {
                    Ok(CanonicalElderListRecord {
                        epoch: row.get::<_, i64>(0)? as u64,
                        merkle_root: row.get(1)?,
                        elder_count: row.get::<_, i64>(2)? as u32,
                        activated_at: row.get::<_, i64>(3)? as u64,
                        created_at: row.get::<_, i64>(4)? as u64,
                    })
                },
            );

            match result {
                Ok(record) => Ok(Some(record)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Store an elder entry for an epoch
    #[allow(clippy::too_many_arguments)]
    pub fn store_elder_entry(
        &self,
        epoch: u64,
        node_id: &str,
        registered_epoch: u64,
        pow_nonce: u64,
        pow_difficulty: u32,
        first_seen: u64,
        uptime_at_registration: f64,
        position: u32,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO elder_entries
                 (epoch, node_id, registered_epoch, pow_nonce, pow_difficulty, first_seen, uptime_at_registration, position)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    epoch as i64,
                    node_id,
                    registered_epoch as i64,
                    pow_nonce as i64,
                    pow_difficulty,
                    first_seen as i64,
                    uptime_at_registration,
                    position
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get all elder entries for an epoch
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_elder_entries_for_epoch(&self, epoch: u64) -> GhostResult<Vec<ElderEntryRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT epoch, node_id, registered_epoch, pow_nonce, pow_difficulty,
                            first_seen, uptime_at_registration, position
                     FROM elder_entries WHERE epoch = ?1 ORDER BY position ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entries = stmt
                .query_map(params![epoch as i64, Self::MAX_QUERY_RESULTS], |row| {
                    Ok(ElderEntryRecord {
                        epoch: row.get::<_, i64>(0)? as u64,
                        node_id: row.get(1)?,
                        registered_epoch: row.get::<_, i64>(2)? as u64,
                        pow_nonce: row.get::<_, i64>(3)? as u64,
                        pow_difficulty: row.get::<_, i64>(4)? as u32,
                        first_seen: row.get::<_, i64>(5)? as u64,
                        uptime_at_registration: row.get(6)?,
                        position: row.get::<_, i64>(7)? as u32,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(entries)
        })
    }

    /// Store an elder approval (BFT signature)
    pub fn store_elder_approval(
        &self,
        epoch: u64,
        approver_node_id: &str,
        signature: &str,
        approved_at: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO elder_approvals (epoch, approver_node_id, signature, approved_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![epoch as i64, approver_node_id, signature, approved_at as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get all approvals for an epoch
    pub fn get_elder_approvals_for_epoch(
        &self,
        epoch: u64,
    ) -> GhostResult<Vec<ElderApprovalRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT epoch, approver_node_id, signature, approved_at
                     FROM elder_approvals WHERE epoch = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let approvals = stmt
                .query_map([epoch as i64], |row| {
                    Ok(ElderApprovalRecord {
                        epoch: row.get::<_, i64>(0)? as u64,
                        approver_node_id: row.get(1)?,
                        signature: row.get(2)?,
                        approved_at: row.get::<_, i64>(3)? as u64,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(approvals)
        })
    }

    /// Count approvals for an epoch
    pub fn count_elder_approvals(&self, epoch: u64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM elder_approvals WHERE epoch = ?1",
                    [epoch as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u32)
        })
    }

    /// Create an elder registration request
    pub fn create_elder_registration_request(
        &self,
        candidate_node_id: &str,
        pow_nonce: u64,
        pow_difficulty: u32,
        first_seen: u64,
        uptime_percent: f64,
        target_epoch: u64,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT INTO elder_registration_requests
                 (candidate_node_id, pow_nonce, pow_difficulty, first_seen, uptime_percent, target_epoch, requested_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
                rusqlite::params![
                    candidate_node_id,
                    pow_nonce as i64,
                    pow_difficulty,
                    first_seen as i64,
                    uptime_percent,
                    target_epoch as i64,
                    now
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get a pending elder registration request
    pub fn get_elder_registration_request(
        &self,
        candidate_node_id: &str,
    ) -> GhostResult<Option<ElderRegistrationRequestRecord>> {
        self.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT id, candidate_node_id, pow_nonce, pow_difficulty, first_seen,
                            uptime_percent, target_epoch, requested_at, status
                     FROM elder_registration_requests
                     WHERE candidate_node_id = ?1 AND status = 'pending'",
                [candidate_node_id],
                |row| {
                    Ok(ElderRegistrationRequestRecord {
                        id: row.get(0)?,
                        candidate_node_id: row.get(1)?,
                        pow_nonce: row.get::<_, i64>(2)? as u64,
                        pow_difficulty: row.get::<_, i64>(3)? as u32,
                        first_seen: row.get::<_, i64>(4)? as u64,
                        uptime_percent: row.get(5)?,
                        target_epoch: row.get::<_, i64>(6)? as u64,
                        requested_at: row.get::<_, i64>(7)? as u64,
                        status: row.get(8)?,
                    })
                },
            );

            match result {
                Ok(record) => Ok(Some(record)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Record a vote on an elder registration request
    pub fn record_elder_registration_vote(
        &self,
        request_id: i64,
        voter_node_id: &str,
        approve: bool,
        rejection_reason: Option<&str>,
        signature: &str,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT OR REPLACE INTO elder_registration_votes
                 (request_id, voter_node_id, approve, rejection_reason, signature, voted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    request_id,
                    voter_node_id,
                    approve as i64,
                    rejection_reason,
                    signature,
                    now
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Count approvals for an elder registration request
    pub fn count_elder_registration_approvals(&self, request_id: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let approvals: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM elder_registration_votes WHERE request_id = ?1 AND approve = 1",
                    [request_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rejections: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM elder_registration_votes WHERE request_id = ?1 AND approve = 0",
                    [request_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok((approvals as u32, rejections as u32))
        })
    }

    /// Update elder registration request status
    pub fn update_elder_registration_status(
        &self,
        request_id: i64,
        status: &str,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE elder_registration_requests SET status = ?1 WHERE id = ?2",
                rusqlite::params![status, request_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

/// Record for a canonical elder list
#[derive(Debug, Clone)]
pub struct CanonicalElderListRecord {
    pub epoch: u64,
    pub merkle_root: String,
    pub elder_count: u32,
    pub activated_at: u64,
    pub created_at: u64,
}

/// Record for an elder entry in an epoch
#[derive(Debug, Clone)]
pub struct ElderEntryRecord {
    pub epoch: u64,
    pub node_id: String,
    pub registered_epoch: u64,
    pub pow_nonce: u64,
    pub pow_difficulty: u32,
    pub first_seen: u64,
    pub uptime_at_registration: f64,
    pub position: u32,
}

/// Record for an elder approval
#[derive(Debug, Clone)]
pub struct ElderApprovalRecord {
    pub epoch: u64,
    pub approver_node_id: String,
    pub signature: String,
    pub approved_at: u64,
}

/// Record for an elder registration request
#[derive(Debug, Clone)]
pub struct ElderRegistrationRequestRecord {
    pub id: i64,
    pub candidate_node_id: String,
    pub pow_nonce: u64,
    pub pow_difficulty: u32,
    pub first_seen: u64,
    pub uptime_percent: f64,
    pub target_epoch: u64,
    pub requested_at: u64,
    pub status: String,
}

// =============================================================================
// L2 STATE QUERIES (ZK-CONSENSUS)
// =============================================================================

impl Database {
    /// Get current L2 state (height and state root)
    ///
    /// Returns (height, state_root) or (0, [0u8; 32]) if not initialized.
    pub fn get_l2_state(&self) -> GhostResult<(u64, [u8; 32])> {
        self.with_connection(|conn| {
            let result: Option<(i64, Vec<u8>)> = conn
                .query_row(
                    "SELECT height, state_root FROM l2_state WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((height, root_bytes)) => {
                    let height = height as u64;
                    let mut state_root = [0u8; 32];
                    if root_bytes.len() == 32 {
                        state_root.copy_from_slice(&root_bytes);
                    }
                    Ok((height, state_root))
                }
                None => Ok((0, [0u8; 32])),
            }
        })
    }

    /// Save current L2 state
    pub fn save_l2_state(&self, height: u64, state_root: [u8; 32]) -> GhostResult<()> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT OR REPLACE INTO l2_state (id, height, state_root, updated_at)
                 VALUES (1, ?1, ?2, ?3)",
                params![height as i64, state_root.as_slice(), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Save L2 state snapshot for reorg recovery
    pub fn save_l2_snapshot(&self, height: u64, state_root: [u8; 32]) -> GhostResult<()> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT OR REPLACE INTO l2_snapshots (height, state_root, created_at)
                 VALUES (?1, ?2, ?3)",
                params![height as i64, state_root.as_slice(), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get L2 snapshot at or before a given height (for reorg recovery)
    pub fn get_l2_snapshot_at_or_before(&self, height: u64) -> GhostResult<Option<(u64, [u8; 32])>> {
        self.with_connection(|conn| {
            let result: Option<(i64, Vec<u8>)> = conn
                .query_row(
                    "SELECT height, state_root FROM l2_snapshots
                     WHERE height <= ?1 ORDER BY height DESC LIMIT 1",
                    params![height as i64],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((snap_height, root_bytes)) => {
                    let mut state_root = [0u8; 32];
                    if root_bytes.len() == 32 {
                        state_root.copy_from_slice(&root_bytes);
                    }
                    Ok(Some((snap_height as u64, state_root)))
                }
                None => Ok(None),
            }
        })
    }

    /// Prune old L2 snapshots, keeping the most recent N
    pub fn prune_l2_snapshots(&self, keep_count: usize) -> GhostResult<u64> {
        self.with_connection(|conn| {
            // First count how many we have
            let total: i64 = conn
                .query_row("SELECT COUNT(*) FROM l2_snapshots", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if total <= keep_count as i64 {
                return Ok(0);
            }

            // Delete oldest snapshots beyond keep_count
            let delete_count = total - keep_count as i64;
            conn.execute(
                "DELETE FROM l2_snapshots WHERE height IN (
                    SELECT height FROM l2_snapshots ORDER BY height ASC LIMIT ?1
                )",
                params![delete_count],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(delete_count as u64)
        })
    }
}

// =============================================================================
// MPC CEREMONY QUERIES
// =============================================================================

/// MPC ceremony state record (singleton)
#[derive(Debug, Clone)]
pub struct MpcCeremonyState {
    pub contribution_count: u32,
    pub current_params_hash: [u8; 32],
    pub is_ossified: bool,
    pub ossified_at: Option<u64>,
    pub block_vk_hash: Option<[u8; 32]>,
    pub payout_vk_hash: Option<[u8; 32]>,
    pub updated_at: u64,
}

/// MPC contribution record
#[derive(Debug, Clone)]
pub struct MpcContributionRecord {
    pub elder_position: u32,
    pub contributor_node_id: String,
    pub prev_params_hash: [u8; 32],
    pub new_params_hash: [u8; 32],
    pub contribution_proof: Vec<u8>,
    pub epoch: u64,
    pub created_at: u64,
}

/// MPC verification vote record
#[derive(Debug, Clone)]
pub struct MpcVerificationVote {
    pub contribution_position: u32,
    pub voter_node_id: String,
    pub approve: bool,
    pub signature: Vec<u8>,
    pub voted_at: u64,
}

/// MPC parameter file metadata
#[derive(Debug, Clone)]
pub struct MpcParamsFile {
    pub params_hash: [u8; 32],
    pub file_path: String,
    pub size_bytes: u64,
    pub contribution_count: u32,
    pub created_at: u64,
}

impl Database {
    /// Get the MPC ceremony state
    ///
    /// Returns None if the ceremony hasn't been initialized yet.
    pub fn get_mpc_ceremony_state(&self) -> GhostResult<Option<MpcCeremonyState>> {
        self.with_connection(|conn| {
            let result: Option<(i64, Vec<u8>, i64, Option<i64>, Option<Vec<u8>>, Option<Vec<u8>>, i64)> = conn
                .query_row(
                    "SELECT contribution_count, current_params_hash, is_ossified, ossified_at,
                            block_vk_hash, payout_vk_hash, updated_at
                     FROM mpc_ceremony WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((count, hash_bytes, ossified, ossified_at, block_vk, payout_vk, updated)) => {
                    let mut params_hash = [0u8; 32];
                    if hash_bytes.len() == 32 {
                        params_hash.copy_from_slice(&hash_bytes);
                    }

                    let block_vk_hash = block_vk.and_then(|v| {
                        if v.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            Some(arr)
                        } else {
                            None
                        }
                    });

                    let payout_vk_hash = payout_vk.and_then(|v| {
                        if v.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            Some(arr)
                        } else {
                            None
                        }
                    });

                    Ok(Some(MpcCeremonyState {
                        contribution_count: count as u32,
                        current_params_hash: params_hash,
                        is_ossified: ossified != 0,
                        ossified_at: ossified_at.map(|v| v as u64),
                        block_vk_hash,
                        payout_vk_hash,
                        updated_at: updated as u64,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Save or update MPC ceremony state
    pub fn save_mpc_ceremony_state(&self, state: &MpcCeremonyState) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_ceremony (id, contribution_count, current_params_hash, is_ossified,
                                          ossified_at, block_vk_hash, payout_vk_hash, updated_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                    contribution_count = excluded.contribution_count,
                    current_params_hash = excluded.current_params_hash,
                    is_ossified = excluded.is_ossified,
                    ossified_at = excluded.ossified_at,
                    block_vk_hash = excluded.block_vk_hash,
                    payout_vk_hash = excluded.payout_vk_hash,
                    updated_at = excluded.updated_at",
                params![
                    state.contribution_count as i64,
                    &state.current_params_hash[..],
                    if state.is_ossified { 1i64 } else { 0i64 },
                    state.ossified_at.map(|v| v as i64),
                    state.block_vk_hash.as_ref().map(|v| &v[..]),
                    state.payout_vk_hash.as_ref().map(|v| &v[..]),
                    state.updated_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Save an MPC contribution
    pub fn save_mpc_contribution(&self, contribution: &MpcContributionRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_contributions (elder_position, contributor_node_id, prev_params_hash,
                                                new_params_hash, contribution_proof, epoch, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    contribution.elder_position as i64,
                    contribution.contributor_node_id,
                    &contribution.prev_params_hash[..],
                    &contribution.new_params_hash[..],
                    &contribution.contribution_proof,
                    contribution.epoch as i64,
                    contribution.created_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get an MPC contribution by position
    pub fn get_mpc_contribution(&self, position: u32) -> GhostResult<Option<MpcContributionRecord>> {
        self.with_connection(|conn| {
            let result: Option<(String, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64)> = conn
                .query_row(
                    "SELECT contributor_node_id, prev_params_hash, new_params_hash,
                            contribution_proof, epoch, created_at
                     FROM mpc_contributions WHERE elder_position = ?1",
                    params![position as i64],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((node_id, prev_hash, new_hash, proof, epoch, created_at)) => {
                    let mut prev_params_hash = [0u8; 32];
                    let mut new_params_hash = [0u8; 32];
                    if prev_hash.len() == 32 {
                        prev_params_hash.copy_from_slice(&prev_hash);
                    }
                    if new_hash.len() == 32 {
                        new_params_hash.copy_from_slice(&new_hash);
                    }

                    Ok(Some(MpcContributionRecord {
                        elder_position: position,
                        contributor_node_id: node_id,
                        prev_params_hash,
                        new_params_hash,
                        contribution_proof: proof,
                        epoch: epoch as u64,
                        created_at: created_at as u64,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Save an MPC verification vote
    pub fn save_mpc_vote(&self, vote: &MpcVerificationVote) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_verification_votes (contribution_position, voter_node_id, approve,
                                                      signature, voted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(contribution_position, voter_node_id) DO UPDATE SET
                    approve = excluded.approve,
                    signature = excluded.signature,
                    voted_at = excluded.voted_at",
                params![
                    vote.contribution_position as i64,
                    vote.voter_node_id,
                    if vote.approve { 1i64 } else { 0i64 },
                    &vote.signature,
                    vote.voted_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Count MPC approvals for a contribution
    pub fn count_mpc_approvals(&self, contribution_position: u32) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let (approve_count, reject_count): (i64, i64) = conn
                .query_row(
                    "SELECT
                        SUM(CASE WHEN approve = 1 THEN 1 ELSE 0 END),
                        SUM(CASE WHEN approve = 0 THEN 1 ELSE 0 END)
                     FROM mpc_verification_votes WHERE contribution_position = ?1",
                    params![contribution_position as i64],
                    |row| {
                        let approves: Option<i64> = row.get(0)?;
                        let rejects: Option<i64> = row.get(1)?;
                        Ok((approves.unwrap_or(0), rejects.unwrap_or(0)))
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok((approve_count as u32, reject_count as u32))
        })
    }

    /// Get all votes for a contribution
    pub fn get_mpc_votes(&self, contribution_position: u32) -> GhostResult<Vec<MpcVerificationVote>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT voter_node_id, approve, signature, voted_at
                     FROM mpc_verification_votes WHERE contribution_position = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![contribution_position as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut votes = Vec::new();
            for row in rows {
                let (voter_id, approve, sig, voted_at) =
                    row.map_err(|e| GhostError::Database(e.to_string()))?;
                votes.push(MpcVerificationVote {
                    contribution_position,
                    voter_node_id: voter_id,
                    approve: approve != 0,
                    signature: sig,
                    voted_at: voted_at as u64,
                });
            }
            Ok(votes)
        })
    }

    /// Mark ceremony as ossified
    pub fn set_ceremony_ossified(&self, ossified_at: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE mpc_ceremony SET is_ossified = 1, ossified_at = ?1 WHERE id = 1",
                params![ossified_at as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Save MPC parameter file metadata
    pub fn save_mpc_params_file(&self, params_file: &MpcParamsFile) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_params_files (params_hash, file_path, size_bytes, contribution_count, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(params_hash) DO UPDATE SET
                    file_path = excluded.file_path,
                    size_bytes = excluded.size_bytes",
                params![
                    &params_file.params_hash[..],
                    params_file.file_path,
                    params_file.size_bytes as i64,
                    params_file.contribution_count as i64,
                    params_file.created_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get MPC parameter file by hash
    pub fn get_mpc_params_file(&self, params_hash: &[u8; 32]) -> GhostResult<Option<MpcParamsFile>> {
        self.with_connection(|conn| {
            let result: Option<(String, i64, i64, i64)> = conn
                .query_row(
                    "SELECT file_path, size_bytes, contribution_count, created_at
                     FROM mpc_params_files WHERE params_hash = ?1",
                    params![&params_hash[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((path, size, count, created)) => Ok(Some(MpcParamsFile {
                    params_hash: *params_hash,
                    file_path: path,
                    size_bytes: size as u64,
                    contribution_count: count as u32,
                    created_at: created as u64,
                })),
                None => Ok(None),
            }
        })
    }

    /// Get the latest MPC parameter file (highest contribution count)
    pub fn get_latest_mpc_params_file(&self) -> GhostResult<Option<MpcParamsFile>> {
        self.with_connection(|conn| {
            let result: Option<(Vec<u8>, String, i64, i64, i64)> = conn
                .query_row(
                    "SELECT params_hash, file_path, size_bytes, contribution_count, created_at
                     FROM mpc_params_files ORDER BY contribution_count DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((hash_bytes, path, size, count, created)) => {
                    let mut params_hash = [0u8; 32];
                    if hash_bytes.len() == 32 {
                        params_hash.copy_from_slice(&hash_bytes);
                    }
                    Ok(Some(MpcParamsFile {
                        params_hash,
                        file_path: path,
                        size_bytes: size as u64,
                        contribution_count: count as u32,
                        created_at: created as u64,
                    }))
                }
                None => Ok(None),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_insert_and_query() {
        let db = Database::in_memory().unwrap();

        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "abc123".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: "def456".to_string(),
            timestamp: 1234567890,
            received_by: "node1".to_string(),
            valid: true,
        };

        let id = db.insert_share(&share).unwrap();
        assert!(id > 0);

        let shares = db.get_shares_by_round(1).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].miner_id, "abc123");
    }

    #[test]
    fn test_round_operations() {
        let db = Database::in_memory().unwrap();

        let round = RoundRecord {
            round_id: 1,
            block_height: 100,
            block_hash: None,
            start_time: 1234567890,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };

        db.create_round(&round).unwrap();

        let fetched = db.get_round(1).unwrap().unwrap();
        assert_eq!(fetched.block_height, 100);
    }

    #[test]
    fn test_kv_store() {
        let db = Database::in_memory().unwrap();

        db.kv_set("test_key", "test_value").unwrap();
        let value = db.kv_get("test_key").unwrap();
        assert_eq!(value, Some("test_value".to_string()));

        db.kv_delete("test_key").unwrap();
        let value = db.kv_get("test_key").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_node_reward_ledger() {
        let db = Database::in_memory().unwrap();

        let entry = db.get_or_create_node_reward("node123").unwrap();
        assert_eq!(entry.balance_sats, 0);

        db.credit_node_reward("node123", 1000, 1).unwrap();

        let entry = db.get_or_create_node_reward("node123").unwrap();
        assert_eq!(entry.balance_sats, 1000);
        assert_eq!(entry.last_credited_round, 1);
    }

    #[test]
    fn test_ghost_lock_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let lock = GhostLockRecord {
            lock_id: "lock123".to_string(),
            owner_ghost_id: "ghost1abc".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Pending,
            funding_txid: None,
            funding_vout: None,
            spend_txid: None,
            output_script: "5120abcd".to_string(),
            jump_risk_tier: "Medium".to_string(),
            next_jump_height: Some(802016),
            created_at: now,
            updated_at: now,
        };

        db.insert_ghost_lock(&lock).unwrap();

        let fetched = db.get_ghost_lock("lock123").unwrap().unwrap();
        assert_eq!(fetched.amount_sats, 10_000_000);
        assert_eq!(fetched.state, GhostLockState::Pending);

        // Update funding
        db.update_ghost_lock_funding("lock123", "txid123", 0)
            .unwrap();
        let fetched = db.get_ghost_lock("lock123").unwrap().unwrap();
        assert_eq!(fetched.state, GhostLockState::Active);
        assert_eq!(fetched.funding_txid, Some("txid123".to_string()));

        // Get by owner
        let locks = db.get_ghost_locks_by_owner("ghost1abc").unwrap();
        assert_eq!(locks.len(), 1);

        // Get balance
        let balance = db.get_ghost_lock_balance("ghost1abc").unwrap();
        assert_eq!(balance, 10_000_000);
    }

    #[test]
    fn test_peer_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let peer = PeerRecord {
            peer_id: "peer123".to_string(),
            address: "192.168.1.1".to_string(),
            port: 8333,
            node_id: Some("node456".to_string()),
            first_seen: now,
            last_seen: now,
            last_success: Some(now),
            last_failure: None,
            connection_count: 5,
            failure_count: 0,
            is_banned: false,
            ban_until: None,
            capabilities: Some("{}".to_string()),
            protocol_version: Some(1),
        };

        db.upsert_peer(&peer).unwrap();

        let fetched = db.get_peer("peer123").unwrap().unwrap();
        assert_eq!(fetched.address, "192.168.1.1");
        assert_eq!(fetched.connection_count, 5);

        let active = db.get_active_peers(10).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_wraith_round_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let round = WraithRoundRecord {
            round_id: "wraith123".to_string(),
            coordinator_id: "coord456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            phase: WraithPhase::Registration,
            participant_count: 0,
            min_participants: 5,
            max_participants: 50,
            registration_deadline: now + 3600,
            execution_deadline: None,
            split_txid: None,
            merge_txid: None,
            status: WraithStatus::Active,
            created_at: now,
            updated_at: now,
        };

        db.insert_wraith_round(&round).unwrap();

        let fetched = db.get_wraith_round("wraith123").unwrap().unwrap();
        assert_eq!(fetched.phase, WraithPhase::Registration);

        db.update_wraith_round_phase("wraith123", WraithPhase::Split)
            .unwrap();
        let fetched = db.get_wraith_round("wraith123").unwrap().unwrap();
        assert_eq!(fetched.phase, WraithPhase::Split);

        let active = db.get_active_wraith_rounds().unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_reconciliation_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let batch = ReconciliationRecord {
            batch_id: "batch123".to_string(),
            settlement_class: "Standard".to_string(),
            participant_count: 10,
            total_amount_sats: 100_000_000,
            merkle_root: "abc123".to_string(),
            l1_txid: None,
            l1_block_height: None,
            dispute_deadline: None,
            status: ReconciliationStatus::Pending,
            created_at: now,
            finalized_at: None,
        };

        db.insert_reconciliation_batch(&batch).unwrap();

        let fetched = db.get_reconciliation_batch("batch123").unwrap().unwrap();
        assert_eq!(fetched.participant_count, 10);

        db.update_reconciliation_l1_submitted("batch123", "txid456", 800100, 800244)
            .unwrap();
        let fetched = db.get_reconciliation_batch("batch123").unwrap().unwrap();
        assert_eq!(fetched.status, ReconciliationStatus::Submitted);
        assert_eq!(fetched.l1_txid, Some("txid456".to_string()));

        let pending = db.get_pending_reconciliation_batches().unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_payout_history_pagination() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        // Create test rounds with payouts
        for i in 0..5 {
            let round = RoundRecord {
                round_id: i as u64,
                block_height: 800000 + i as u64,
                block_hash: Some(format!("hash{}", i)),
                start_time: now - (5 - i) as i64 * 100,
                end_time: Some(now - (4 - i) as i64 * 100),
                total_shares: 100,
                total_work: 1000.0,
                winning_miner: Some("miner1".to_string()),
                found_by_node: Some("node1".to_string()),
                payout_status: PayoutStatus::Confirmed,
                subsidy_sats: Some(312500000),
                tx_fees_sats: Some(1000000),
            };
            db.create_round(&round).unwrap();

            // Add some payouts for each round
            let miner_payout = PayoutRecord {
                id: None,
                round_id: i as u64,
                recipient_id: "miner1".to_string(),
                recipient_type: RecipientType::Miner,
                address: "bc1qminer".to_string(),
                amount_sats: 309000000,
                txid: None,
                vout: None,
                status: PayoutStatus::Confirmed,
                created_at: now,
                confirmed_at: Some(now),
            };
            db.insert_payout(&miner_payout).unwrap();

            let node_payout = PayoutRecord {
                id: None,
                round_id: i as u64,
                recipient_id: "node1".to_string(),
                recipient_type: RecipientType::Node,
                address: "bc1qnode".to_string(),
                amount_sats: 2000000,
                txid: None,
                vout: None,
                status: PayoutStatus::Confirmed,
                created_at: now,
                confirmed_at: Some(now),
            };
            db.insert_payout(&node_payout).unwrap();
        }

        // Test basic pagination
        let query = PayoutHistoryQuery::with_limit(3);
        let history = db.query_payout_history(query).unwrap();
        assert_eq!(history.len(), 3);
        // Results should be ordered by height descending
        assert!(history[0].block_height >= history[1].block_height);

        // Test offset
        let query = PayoutHistoryQuery::with_limit(2).with_offset(2);
        let history = db.query_payout_history(query).unwrap();
        assert_eq!(history.len(), 2);

        // Test height filters
        let query = PayoutHistoryQuery::with_limit(10)
            .with_min_height(800002)
            .with_max_height(800003);
        let history = db.query_payout_history(query).unwrap();
        assert_eq!(history.len(), 2);
        for summary in &history {
            assert!(summary.block_height >= 800002);
            assert!(summary.block_height <= 800003);
        }

        // Test aggregation
        let query = PayoutHistoryQuery::with_limit(1);
        let history = db.query_payout_history(query).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].miner_count, 1);
        assert_eq!(history[0].node_count, 1);
        assert_eq!(history[0].total_miner_sats, 309000000);
        assert_eq!(history[0].total_node_sats, 2000000);

        // Test round count
        let count = db.get_payout_round_count(None, None).unwrap();
        assert_eq!(count, 5);

        let count = db
            .get_payout_round_count(Some(800002), Some(800003))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_withdrawal_atomic_insert_prevents_duplicates() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        // First, create a ghost lock that we can withdraw from
        let lock = GhostLockRecord {
            lock_id: "lock_atomic_test".to_string(),
            owner_ghost_id: "ghost_atomic".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Active,
            funding_txid: Some("abc123".to_string()),
            funding_vout: Some(0),
            spend_txid: None,
            output_script: "script".to_string(),
            jump_risk_tier: "Low".to_string(),
            next_jump_height: None,
            created_at: now,
            updated_at: now,
        };
        db.insert_ghost_lock(&lock).unwrap();

        // First withdrawal request should succeed
        let withdrawal1 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_atomic".to_string(),
            lock_id: "lock_atomic_test".to_string(),
            destination_address: "bc1qtest1".to_string(),
            amount_sats: 1_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            created_at: now,
            updated_at: now,
        };

        let result = db.insert_withdrawal_request_atomic(&withdrawal1).unwrap();
        assert!(result.is_some(), "First withdrawal should succeed");
        let first_id = result.unwrap();
        assert!(first_id > 0);

        // Second withdrawal for the same lock should be rejected
        let withdrawal2 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_atomic".to_string(),
            lock_id: "lock_atomic_test".to_string(),
            destination_address: "bc1qtest2".to_string(),
            amount_sats: 2_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            created_at: now + 1,
            updated_at: now + 1,
        };

        let result = db.insert_withdrawal_request_atomic(&withdrawal2).unwrap();
        assert!(result.is_none(), "Second withdrawal should be rejected");

        // Verify only one withdrawal exists
        let withdrawals = db.get_withdrawals_by_lock("lock_atomic_test").unwrap();
        assert_eq!(withdrawals.len(), 1);
        assert_eq!(withdrawals[0].destination_address, "bc1qtest1");
    }

    #[test]
    fn test_withdrawal_atomic_allows_after_completion() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        // Create a ghost lock
        let lock = GhostLockRecord {
            lock_id: "lock_complete_test".to_string(),
            owner_ghost_id: "ghost_complete".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Active,
            funding_txid: Some("abc123".to_string()),
            funding_vout: Some(0),
            spend_txid: None,
            output_script: "script".to_string(),
            jump_risk_tier: "Low".to_string(),
            next_jump_height: None,
            created_at: now,
            updated_at: now,
        };
        db.insert_ghost_lock(&lock).unwrap();

        // First withdrawal
        let withdrawal1 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_complete".to_string(),
            lock_id: "lock_complete_test".to_string(),
            destination_address: "bc1qtest1".to_string(),
            amount_sats: 1_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            created_at: now,
            updated_at: now,
        };

        let result = db.insert_withdrawal_request_atomic(&withdrawal1).unwrap();
        let first_id = result.unwrap();

        // Mark the first withdrawal as completed
        db.update_withdrawal_status(first_id, WithdrawalStatus::Confirmed)
            .unwrap();

        // Now a second withdrawal should succeed (since the first is confirmed)
        let withdrawal2 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_complete".to_string(),
            lock_id: "lock_complete_test".to_string(),
            destination_address: "bc1qtest2".to_string(),
            amount_sats: 2_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            created_at: now + 1,
            updated_at: now + 1,
        };

        let result = db.insert_withdrawal_request_atomic(&withdrawal2).unwrap();
        assert!(
            result.is_some(),
            "Second withdrawal should succeed after first is confirmed"
        );
    }

    #[test]
    fn test_withdrawal_atomic_blocks_batched() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        // Create a ghost lock
        let lock = GhostLockRecord {
            lock_id: "lock_batched_test".to_string(),
            owner_ghost_id: "ghost_batched".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Active,
            funding_txid: Some("abc123".to_string()),
            funding_vout: Some(0),
            spend_txid: None,
            output_script: "script".to_string(),
            jump_risk_tier: "Low".to_string(),
            next_jump_height: None,
            created_at: now,
            updated_at: now,
        };
        db.insert_ghost_lock(&lock).unwrap();

        // First withdrawal with pending status
        let withdrawal1 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_batched".to_string(),
            lock_id: "lock_batched_test".to_string(),
            destination_address: "bc1qtest1".to_string(),
            amount_sats: 1_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            created_at: now,
            updated_at: now,
        };

        let result = db.insert_withdrawal_request_atomic(&withdrawal1).unwrap();
        let first_id = result.unwrap();

        // Mark the first withdrawal as batched
        db.update_withdrawal_batched(first_id, "batch123").unwrap();

        // Second withdrawal should still be rejected (batched also blocks)
        let withdrawal2 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_batched".to_string(),
            lock_id: "lock_batched_test".to_string(),
            destination_address: "bc1qtest2".to_string(),
            amount_sats: 2_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            created_at: now + 1,
            updated_at: now + 1,
        };

        let result = db.insert_withdrawal_request_atomic(&withdrawal2).unwrap();
        assert!(
            result.is_none(),
            "Second withdrawal should be rejected when first is batched"
        );
    }

    /// SEC-DATA-TEST-1: Verify that negative satoshi values are properly rejected
    #[test]
    fn test_negative_satoshi_rejected() {
        // Positive values should succeed
        let result = i64_to_u64_sats(100, "test_field");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 100u64);

        // Zero should succeed
        let result = i64_to_u64_sats(0, "test_field");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0u64);

        // Large positive value should succeed
        let result = i64_to_u64_sats(i64::MAX, "test_field");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), i64::MAX as u64);

        // Negative value should fail
        let result = i64_to_u64_sats(-1, "test_field");
        assert!(result.is_err(), "Negative satoshi value should be rejected");

        // Large negative value should fail
        let result = i64_to_u64_sats(-1_000_000, "total_miner_sats");
        assert!(result.is_err(), "Large negative satoshi value should be rejected");
    }
}
