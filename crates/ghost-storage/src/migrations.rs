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
//| FILE: migrations.rs                                                                                                  |
//|======================================================================================================================|

//! Database migrations

use rusqlite::Connection;
use tracing::{debug, info};

use ghost_common::error::{GhostError, GhostResult};

/// Current schema version
const SCHEMA_VERSION: u32 = 9;

/// Run all pending migrations
pub fn run_migrations(conn: &Connection) -> GhostResult<()> {
    let current_version = get_schema_version(conn)?;

    if current_version >= SCHEMA_VERSION {
        debug!(version = current_version, "Database schema up to date");
        return Ok(());
    }

    info!(
        from = current_version,
        to = SCHEMA_VERSION,
        "Running database migrations"
    );

    // Run migrations sequentially
    if current_version < 1 {
        migrate_v1(conn)?;
    }

    if current_version < 2 {
        migrate_v2(conn)?;
    }

    if current_version < 3 {
        migrate_v3(conn)?;
    }

    if current_version < 4 {
        migrate_v4(conn)?;
    }

    if current_version < 5 {
        migrate_v5(conn)?;
    }

    if current_version < 6 {
        migrate_v6(conn)?;
    }

    if current_version < 7 {
        migrate_v7(conn)?;
    }

    if current_version < 8 {
        migrate_v8(conn)?;
    }

    if current_version < 9 {
        migrate_v9(conn)?;
    }

    set_schema_version(conn, SCHEMA_VERSION)?;

    info!("Database migrations complete");
    Ok(())
}

/// Get current schema version
fn get_schema_version(conn: &Connection) -> GhostResult<u32> {
    let version: u32 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|e| GhostError::Database(e.to_string()))?;
    Ok(version)
}

/// Set schema version
fn set_schema_version(conn: &Connection, version: u32) -> GhostResult<()> {
    conn.execute(&format!("PRAGMA user_version = {};", version), [])
        .map_err(|e| GhostError::Database(e.to_string()))?;
    Ok(())
}

/// Migration to v1: Initial schema
fn migrate_v1(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v1");

    conn.execute_batch(
        r#"
        -- Shares table
        CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            miner_id TEXT NOT NULL,
            difficulty REAL NOT NULL,
            work REAL NOT NULL,
            share_hash TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            received_by TEXT NOT NULL,
            valid INTEGER NOT NULL DEFAULT 1,
            UNIQUE(share_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_shares_round ON shares(round_id);
        CREATE INDEX IF NOT EXISTS idx_shares_miner ON shares(miner_id);
        CREATE INDEX IF NOT EXISTS idx_shares_timestamp ON shares(timestamp);

        -- Rounds table
        CREATE TABLE IF NOT EXISTS rounds (
            round_id INTEGER PRIMARY KEY,
            block_height INTEGER NOT NULL,
            block_hash TEXT,
            start_time INTEGER NOT NULL,
            end_time INTEGER,
            total_shares INTEGER NOT NULL DEFAULT 0,
            total_work REAL NOT NULL DEFAULT 0,
            winning_miner TEXT,
            found_by_node TEXT,
            payout_status TEXT NOT NULL DEFAULT 'active',
            subsidy_sats INTEGER,
            tx_fees_sats INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_rounds_height ON rounds(block_height);
        CREATE INDEX IF NOT EXISTS idx_rounds_status ON rounds(payout_status);

        -- Nodes table
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            public_address TEXT,
            display_name TEXT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            is_elder INTEGER NOT NULL DEFAULT 0,
            elder_order INTEGER,
            capabilities TEXT NOT NULL DEFAULT '{}',
            total_uptime_secs INTEGER NOT NULL DEFAULT 0,
            uptime_7d_percent REAL NOT NULL DEFAULT 0,
            verification_pass_rate REAL NOT NULL DEFAULT 0,
            total_shares_received INTEGER NOT NULL DEFAULT 0,
            total_blocks_found INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_elder ON nodes(is_elder, elder_order);
        CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);

        -- Miners table
        CREATE TABLE IF NOT EXISTS miners (
            miner_id TEXT PRIMARY KEY,
            payout_address TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            connected_node TEXT,
            total_shares INTEGER NOT NULL DEFAULT 0,
            total_work REAL NOT NULL DEFAULT 0,
            blocks_won INTEGER NOT NULL DEFAULT 0,
            total_payouts_sats INTEGER NOT NULL DEFAULT 0,
            avg_hashrate_ths REAL NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_miners_last_seen ON miners(last_seen);

        -- Payouts table
        CREATE TABLE IF NOT EXISTS payouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            recipient_id TEXT NOT NULL,
            recipient_type TEXT NOT NULL,
            address TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            txid TEXT,
            vout INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            confirmed_at INTEGER,
            FOREIGN KEY (round_id) REFERENCES rounds(round_id)
        );
        CREATE INDEX IF NOT EXISTS idx_payouts_round ON payouts(round_id);
        CREATE INDEX IF NOT EXISTS idx_payouts_recipient ON payouts(recipient_id);
        CREATE INDEX IF NOT EXISTS idx_payouts_status ON payouts(status);

        -- Node reward ledger
        CREATE TABLE IF NOT EXISTS node_rewards (
            node_id TEXT PRIMARY KEY,
            balance_sats INTEGER NOT NULL DEFAULT 0,
            last_credited_round INTEGER NOT NULL DEFAULT 0,
            total_credits_sats INTEGER NOT NULL DEFAULT 0,
            total_withdrawals_sats INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        -- Verifications table
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            capability TEXT NOT NULL,
            challenge_type TEXT NOT NULL,
            challenge_data TEXT NOT NULL,
            response_data TEXT,
            result TEXT NOT NULL DEFAULT 'pending',
            started_at INTEGER NOT NULL,
            completed_at INTEGER,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_verifications_node ON verifications(node_id);
        CREATE INDEX IF NOT EXISTS idx_verifications_result ON verifications(result);

        -- Health pings table
        CREATE TABLE IF NOT EXISTS health_pings (
            node_id TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            round_id INTEGER NOT NULL,
            miner_count INTEGER NOT NULL,
            capabilities TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            PRIMARY KEY (node_id, timestamp)
        );
        CREATE INDEX IF NOT EXISTS idx_health_pings_timestamp ON health_pings(timestamp);

        -- Votes table
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            proposal_hash TEXT NOT NULL,
            voter_id TEXT NOT NULL,
            vote INTEGER NOT NULL,
            signature TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            UNIQUE(round_id, proposal_hash, voter_id)
        );
        CREATE INDEX IF NOT EXISTS idx_votes_round ON votes(round_id, proposal_hash);

        -- Key-value store for misc data
        CREATE TABLE IF NOT EXISTS kv_store (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v2: Ghost Pay L2 tables (locks, wraith, reconciliation, peers)
fn migrate_v2(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v2");

    conn.execute_batch(
        r#"
        -- Ghost Locks table for P2TR timelocked UTXOs
        CREATE TABLE IF NOT EXISTS ghost_locks (
            lock_id TEXT PRIMARY KEY,
            owner_ghost_id TEXT NOT NULL,
            lock_pubkey TEXT NOT NULL,
            recovery_pubkey TEXT NOT NULL,
            denomination TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            timelock_tier TEXT NOT NULL,
            creation_height INTEGER NOT NULL,
            recovery_height INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending',
            funding_txid TEXT,
            funding_vout INTEGER,
            spend_txid TEXT,
            output_script TEXT NOT NULL,
            jump_risk_tier TEXT NOT NULL,
            next_jump_height INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_owner ON ghost_locks(owner_ghost_id);
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_state ON ghost_locks(state);
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_recovery ON ghost_locks(recovery_height);
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_jump ON ghost_locks(next_jump_height);

        -- Peers table for P2P network tracking
        CREATE TABLE IF NOT EXISTS peers (
            peer_id TEXT PRIMARY KEY,
            address TEXT NOT NULL,
            port INTEGER NOT NULL,
            node_id TEXT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            last_success INTEGER,
            last_failure INTEGER,
            connection_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            ban_until INTEGER,
            capabilities TEXT,
            protocol_version INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers(last_seen);
        CREATE INDEX IF NOT EXISTS idx_peers_node ON peers(node_id);

        -- Peer reputation tracking
        CREATE TABLE IF NOT EXISTS peer_reputation (
            peer_id TEXT PRIMARY KEY,
            reputation_score REAL NOT NULL DEFAULT 100.0,
            shares_relayed INTEGER NOT NULL DEFAULT 0,
            shares_invalid INTEGER NOT NULL DEFAULT 0,
            blocks_relayed INTEGER NOT NULL DEFAULT 0,
            latency_avg_ms REAL NOT NULL DEFAULT 0,
            uptime_percent REAL NOT NULL DEFAULT 0,
            last_calculated INTEGER NOT NULL,
            FOREIGN KEY (peer_id) REFERENCES peers(peer_id)
        );

        -- Wraith mixing rounds
        CREATE TABLE IF NOT EXISTS wraith_rounds (
            round_id TEXT PRIMARY KEY,
            coordinator_id TEXT NOT NULL,
            denomination TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            phase TEXT NOT NULL DEFAULT 'registration',
            participant_count INTEGER NOT NULL DEFAULT 0,
            min_participants INTEGER NOT NULL,
            max_participants INTEGER NOT NULL,
            registration_deadline INTEGER NOT NULL,
            execution_deadline INTEGER,
            split_txid TEXT,
            merge_txid TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_wraith_rounds_status ON wraith_rounds(status);
        CREATE INDEX IF NOT EXISTS idx_wraith_rounds_phase ON wraith_rounds(phase);
        CREATE INDEX IF NOT EXISTS idx_wraith_rounds_deadline ON wraith_rounds(registration_deadline);

        -- Wraith round participants
        CREATE TABLE IF NOT EXISTS wraith_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id TEXT NOT NULL,
            ghost_id TEXT NOT NULL,
            blinded_output TEXT NOT NULL,
            unblinded_output TEXT,
            input_txid TEXT,
            input_vout INTEGER,
            status TEXT NOT NULL DEFAULT 'registered',
            joined_at INTEGER NOT NULL,
            FOREIGN KEY (round_id) REFERENCES wraith_rounds(round_id),
            UNIQUE(round_id, ghost_id)
        );
        CREATE INDEX IF NOT EXISTS idx_wraith_participants_round ON wraith_participants(round_id);

        -- L2 reconciliation state
        CREATE TABLE IF NOT EXISTS reconciliation_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL UNIQUE,
            settlement_class TEXT NOT NULL,
            participant_count INTEGER NOT NULL,
            total_amount_sats INTEGER NOT NULL,
            merkle_root TEXT NOT NULL,
            l1_txid TEXT,
            l1_block_height INTEGER,
            dispute_deadline INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            finalized_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_reconciliation_status ON reconciliation_state(status);
        CREATE INDEX IF NOT EXISTS idx_reconciliation_deadline ON reconciliation_state(dispute_deadline);

        -- Reconciliation participants (individual settlements in a batch)
        CREATE TABLE IF NOT EXISTS reconciliation_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ghost_id TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            direction TEXT NOT NULL,
            merkle_proof TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY (batch_id) REFERENCES reconciliation_state(batch_id)
        );
        CREATE INDEX IF NOT EXISTS idx_reconciliation_entries_batch ON reconciliation_entries(batch_id);
        CREATE INDEX IF NOT EXISTS idx_reconciliation_entries_ghost ON reconciliation_entries(ghost_id);

        -- Uptime samples for 7-day tracking (moved from v1 if not exists)
        CREATE TABLE IF NOT EXISTS uptime_samples (
            node_id TEXT NOT NULL,
            sample_time INTEGER NOT NULL,
            was_online INTEGER NOT NULL,
            PRIMARY KEY (node_id, sample_time)
        );

        -- Archive challenge results
        CREATE TABLE IF NOT EXISTS archive_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            expected_hash TEXT NOT NULL,
            response_hash TEXT,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_archive_challenges_node ON archive_challenges(node_id);

        -- Policy challenge results
        CREATE TABLE IF NOT EXISTS policy_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            txid TEXT NOT NULL,
            expected_tier INTEGER NOT NULL,
            response_tier INTEGER,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_policy_challenges_node ON policy_challenges(node_id);

        -- Stratum challenge results
        CREATE TABLE IF NOT EXISTS stratum_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            connected INTEGER,
            latency_ms INTEGER,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_stratum_challenges_node ON stratum_challenges(node_id);

        -- Ghost Pay challenge results
        CREATE TABLE IF NOT EXISTS ghostpay_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            response_valid INTEGER,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ghostpay_challenges_node ON ghostpay_challenges(node_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v3: Withdrawal requests table
fn migrate_v3(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v3");

    conn.execute_batch(
        r#"
        -- Withdrawal requests for L1 settlement
        CREATE TABLE IF NOT EXISTS withdrawal_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ghost_id TEXT NOT NULL,
            lock_id TEXT NOT NULL,
            destination_address TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            fee_sats INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            batch_id TEXT,
            l1_txid TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (lock_id) REFERENCES ghost_locks(lock_id)
        );
        CREATE INDEX IF NOT EXISTS idx_withdrawal_ghost ON withdrawal_requests(ghost_id);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_lock ON withdrawal_requests(lock_id);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_status ON withdrawal_requests(status);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_batch ON withdrawal_requests(batch_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v4: Add Sybil resistance (PoW proof) and elder bond columns
fn migrate_v4(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v4: Adding Sybil resistance and elder bond columns");

    conn.execute_batch(
        r#"
        -- Add proof-of-work column for Sybil resistance
        -- The pow_proof is a hex-encoded 12-byte value: 8-byte nonce + 4-byte difficulty
        ALTER TABLE nodes ADD COLUMN pow_proof TEXT;

        -- Add elder bond column for nothing-at-stake prevention
        -- Elder candidates must demonstrate economic commitment
        ALTER TABLE nodes ADD COLUMN elder_bond_sats INTEGER NOT NULL DEFAULT 0;

        -- Add column to track if elder bond has been verified on-chain
        ALTER TABLE nodes ADD COLUMN elder_bond_txid TEXT;

        -- Add column to track slashing events
        ALTER TABLE nodes ADD COLUMN slashed_at INTEGER;

        -- Create table for tracking elder bond UTXOs
        CREATE TABLE IF NOT EXISTS elder_bonds (
            node_id TEXT PRIMARY KEY,
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            amount_sats INTEGER NOT NULL,
            script_pubkey TEXT NOT NULL,
            confirmation_height INTEGER,
            spent_txid TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_bonds_status ON elder_bonds(status);
        CREATE INDEX IF NOT EXISTS idx_elder_bonds_txid ON elder_bonds(txid);

        -- Create table for tracking slashing events
        CREATE TABLE IF NOT EXISTS elder_slashing (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            slashed_amount_sats INTEGER NOT NULL,
            slashing_txid TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_slashing_node ON elder_slashing(node_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v5: Add payout_address to nodes for mainnet payouts
fn migrate_v5(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v5: Adding node payout_address");

    conn.execute_batch(
        r#"
        -- Add payout_address column for node operator rewards
        -- This is the Bitcoin address where nodes receive their 5% share reward
        ALTER TABLE nodes ADD COLUMN payout_address TEXT;

        -- Create index for efficient payout lookups
        CREATE INDEX IF NOT EXISTS idx_nodes_payout ON nodes(payout_address) WHERE payout_address IS NOT NULL;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v6: ZK-BFT state management tables
fn migrate_v6(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v6: Adding ZK-BFT state management tables");

    conn.execute_batch(
        r#"
        -- State snapshots for L2 rollback capability
        -- Snapshots are taken at intervals (every N blocks) and pruned to keep last M
        CREATE TABLE IF NOT EXISTS state_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            height INTEGER NOT NULL UNIQUE,
            state_root TEXT NOT NULL,
            balances_json TEXT NOT NULL,
            nonces_json TEXT,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_height ON state_snapshots(height);

        -- Block proposers for epoch settler selection
        -- The proposer of the last block in an epoch becomes the settler
        CREATE TABLE IF NOT EXISTS block_proposers (
            height INTEGER PRIMARY KEY,
            proposer_id TEXT NOT NULL,
            state_root TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_proposers_epoch ON block_proposers((height / 2160));

        -- Epoch settlement tracking
        -- Tracks which node is responsible for settling each epoch
        CREATE TABLE IF NOT EXISTS epoch_settlements (
            epoch_id INTEGER PRIMARY KEY,
            settler_id TEXT NOT NULL,
            fallback_settler_id TEXT,
            batch_id TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            settlement_deadline INTEGER NOT NULL,
            started_at INTEGER,
            completed_at INTEGER,
            failure_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_epoch_status ON epoch_settlements(status);
        CREATE INDEX IF NOT EXISTS idx_epoch_deadline ON epoch_settlements(settlement_deadline);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v7: Key rotation with elder status transfer
///
/// Adds tables to securely track node identity rotations, preventing:
/// - Reuse of retired node_ids
/// - Unauthorized elder status claims
/// - Replay of old rotation proofs
fn migrate_v7(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v7: Adding key rotation tables");

    conn.execute_batch(
        r#"
        -- Retired node_ids table
        -- Once a node_id is retired (rotated away from), it can never be reused.
        -- This prevents replay attacks and identity resurrection.
        CREATE TABLE IF NOT EXISTS retired_nodes (
            old_node_id TEXT PRIMARY KEY,
            new_node_id TEXT NOT NULL,
            rotation_timestamp INTEGER NOT NULL,
            rotation_proof BLOB NOT NULL,
            FOREIGN KEY (new_node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_retired_new ON retired_nodes(new_node_id);

        -- Rotation history for audit trail
        -- Tracks all rotations including revoked ones for forensic analysis.
        CREATE TABLE IF NOT EXISTS rotation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_node_id TEXT NOT NULL,
            new_node_id TEXT NOT NULL,
            rotation_timestamp INTEGER NOT NULL,
            finalized_timestamp INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            rotation_proof BLOB NOT NULL,
            revocation_proof BLOB,
            elder_transferred INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_rotation_old ON rotation_history(old_node_id);
        CREATE INDEX IF NOT EXISTS idx_rotation_new ON rotation_history(new_node_id);
        CREATE INDEX IF NOT EXISTS idx_rotation_status ON rotation_history(status);

        -- Add rotation tracking column to nodes
        -- Points to the new node_id if this identity was rotated
        -- NULL means active identity, non-NULL means retired
        ALTER TABLE nodes ADD COLUMN rotated_to TEXT;

        -- Add rotation source column to nodes
        -- Points to the old node_id if this identity was rotated from another
        -- Allows tracing the full identity chain
        ALTER TABLE nodes ADD COLUMN rotated_from TEXT;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v8: Equivocation proof persistence (P2P4-L7)
///
/// Stores equivocation proofs when Byzantine behavior is detected.
/// These proofs serve as evidence for slashing and forensic analysis.
fn migrate_v8(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v8: Adding equivocation proofs table");

    conn.execute_batch(
        r#"
        -- Equivocation proofs for Byzantine behavior evidence (P2P4-L7)
        -- Stores cryptographic proof when a node signs conflicting votes
        CREATE TABLE IF NOT EXISTS equivocation_proofs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id BLOB NOT NULL,
            proof_data BLOB NOT NULL,
            detected_at INTEGER NOT NULL,
            round_number INTEGER,
            vote_type TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_equivocation_proofs_node ON equivocation_proofs(node_id);
        CREATE INDEX IF NOT EXISTS idx_equivocation_proofs_round ON equivocation_proofs(round_number);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v9: Prevent double-spend race condition on withdrawals (C-PAY-3)
///
/// Adds a partial unique index to prevent concurrent withdrawal requests for the same lock.
/// Only one pending or batched withdrawal can exist per lock at any time.
fn migrate_v9(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v9: Adding partial unique index for withdrawal race condition prevention");

    conn.execute_batch(
        r#"
        -- Partial unique index to prevent double-withdrawal race condition (C-PAY-3)
        -- Ensures only one pending/batched withdrawal can exist per lock_id
        -- This provides defense-in-depth at the database level
        CREATE UNIQUE INDEX IF NOT EXISTS idx_withdrawals_pending_lock
        ON withdrawal_requests(lock_id)
        WHERE status IN ('pending', 'batched');
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_migrations() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_idempotent_migrations() {
        let conn = Connection::open_in_memory().unwrap();

        // Run migrations twice
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap();

        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
