//! Ghost network types and data structures
//!
//! Defines Ghost-specific types for Wraith Protocol, Jump Locks, etc.

use serde::{Deserialize, Serialize};

/// Ghost transaction type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxType {
    /// Standard public transaction
    Public,
    /// Private/anonymous transaction (Wraith)
    Private,
    /// Coinbase (mining reward)
    Coinbase,
}

/// Wraith Protocol mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WraithMode {
    /// Public ledger - transactions visible on blockchain
    #[default]
    Public,
    /// Private ledger - stealth addresses, RingCT
    Private,
}

/// Ghost Lock status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockStatus {
    /// Lock is active
    Active,
    /// Lock is pending activation
    Pending,
    /// Lock has matured/expired
    Matured,
    /// Lock was cancelled
    Cancelled,
}

/// Jump Lock type (cross-chain or time-locked)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpLock {
    /// Lock identifier
    pub id: String,
    /// Amount locked
    pub amount: u64,
    /// Source chain/address
    pub source: String,
    /// Destination chain/address
    pub destination: String,
    /// Hash lock (for HTLC-style locks)
    pub hash_lock: Option<String>,
    /// Time lock (unix timestamp)
    pub time_lock: Option<u64>,
    /// Current status
    pub status: LockStatus,
    /// Transaction ID
    pub txid: String,
}

/// Stealth address for Wraith Protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAddress {
    /// The one-time stealth address
    pub address: String,
    /// Scan public key (for detecting incoming payments)
    pub scan_pubkey: String,
    /// Spend public key
    pub spend_pubkey: String,
    /// Ephemeral public key (included in transaction)
    pub ephemeral_pubkey: Option<String>,
}

/// Ring signature member (for RingCT)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingMember {
    /// Public key
    pub pubkey: String,
    /// Key image
    pub key_image: String,
    /// Commitment
    pub commitment: String,
}

/// Ghost UTXO with privacy metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostUtxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount (may be hidden for private UTXOs)
    pub amount: Option<u64>,
    /// Number of confirmations
    pub confirmations: u32,
    /// Address (public) or stealth address info (private)
    pub address: String,
    /// Transaction type
    pub tx_type: TxType,
    /// Whether this UTXO is spendable
    pub spendable: bool,
    /// For private UTXOs: the blinding factor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blinding_factor: Option<String>,
    /// Ring size used (for private transactions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_size: Option<u32>,
}

/// Ghost transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostTransaction {
    /// Transaction ID
    pub txid: String,
    /// Block hash (None if unconfirmed)
    pub blockhash: Option<String>,
    /// Block height (None if unconfirmed)
    pub blockheight: Option<u64>,
    /// Number of confirmations
    pub confirmations: u32,
    /// Transaction type
    pub tx_type: TxType,
    /// Timestamp
    pub time: u64,
    /// Total input amount (hidden for private)
    pub total_input: Option<u64>,
    /// Total output amount (hidden for private)
    pub total_output: Option<u64>,
    /// Fee paid
    pub fee: Option<u64>,
    /// Inputs
    pub inputs: Vec<GhostTxInput>,
    /// Outputs
    pub outputs: Vec<GhostTxOutput>,
}

/// Ghost transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostTxInput {
    /// Previous txid
    pub txid: String,
    /// Previous output index
    pub vout: u32,
    /// Address (if public)
    pub address: Option<String>,
    /// Amount (if public)
    pub amount: Option<u64>,
    /// Key image (for private inputs)
    pub key_image: Option<String>,
}

/// Ghost transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostTxOutput {
    /// Output index
    pub n: u32,
    /// Address (public) or stealth info
    pub address: String,
    /// Amount (hidden for private)
    pub amount: Option<u64>,
    /// Whether this is a stealth output
    pub is_stealth: bool,
    /// Range proof (for private outputs)
    pub range_proof: Option<String>,
}

/// Blockchain info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    /// Current block height
    pub blocks: u64,
    /// Header count (may be ahead of blocks during sync)
    #[serde(default)]
    pub headers: u64,
    /// Best block hash
    pub bestblockhash: String,
    /// Current difficulty
    pub difficulty: f64,
    /// Network hashrate
    pub networkhashps: f64,
    /// Verification progress 0.0 – 1.0
    #[serde(default = "default_progress")]
    pub verificationprogress: f64,
    /// Whether initial block download is complete
    pub initialblockdownload: bool,
    /// Chain name (main, test, regtest)
    pub chain: String,
}

fn default_progress() -> f64 {
    1.0
}

/// Address balance info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBalance {
    /// Address
    pub address: String,
    /// Confirmed balance
    pub confirmed: u64,
    /// Unconfirmed balance
    pub unconfirmed: u64,
    /// Immature balance (coinbase rewards not yet mature)
    pub immature: u64,
}

/// Fee estimation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Estimated fee rate (satoshis per byte)
    pub feerate: f64,
    /// Number of blocks for confirmation
    pub blocks: u32,
}

/// Wraith Protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithConfig {
    /// Default ring size for private transactions
    pub default_ring_size: u32,
    /// Minimum ring size
    pub min_ring_size: u32,
    /// Maximum ring size
    pub max_ring_size: u32,
    /// Whether Wraith is enabled on the network
    pub enabled: bool,
}

impl Default for WraithConfig {
    fn default() -> Self {
        Self {
            default_ring_size: 12,
            min_ring_size: 3,
            max_ring_size: 32,
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wraith_mode_default() {
        assert_eq!(WraithMode::default(), WraithMode::Public);
    }

    #[test]
    fn test_wraith_mode_serde_roundtrip() {
        let mode = WraithMode::Private;
        let json = serde_json::to_string(&mode).unwrap();
        let restored: WraithMode = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, WraithMode::Private);
    }

    #[test]
    fn test_tx_type_serde() {
        for ty in [TxType::Public, TxType::Private, TxType::Coinbase] {
            let json = serde_json::to_string(&ty).unwrap();
            let restored: TxType = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, ty);
        }
    }

    #[test]
    fn test_lock_status_serde() {
        for status in [
            LockStatus::Active,
            LockStatus::Pending,
            LockStatus::Matured,
            LockStatus::Cancelled,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let restored: LockStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, status);
        }
    }

    #[test]
    fn test_wraith_config_default() {
        let config = WraithConfig::default();
        assert_eq!(config.default_ring_size, 12);
        assert_eq!(config.min_ring_size, 3);
        assert_eq!(config.max_ring_size, 32);
        assert!(config.enabled);
    }

    #[test]
    fn test_wraith_config_serde() {
        let config = WraithConfig {
            default_ring_size: 8,
            min_ring_size: 4,
            max_ring_size: 16,
            enabled: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let restored: WraithConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.default_ring_size, 8);
        assert!(!restored.enabled);
    }

    #[test]
    fn test_jump_lock_serde() {
        let lock = JumpLock {
            id: "jump1".into(),
            amount: 50_000,
            source: "ghost_addr".into(),
            destination: "btc_addr".into(),
            hash_lock: Some("deadbeef".into()),
            time_lock: Some(1700000000),
            status: LockStatus::Pending,
            txid: "tx123".into(),
        };
        let json = serde_json::to_string(&lock).unwrap();
        let restored: JumpLock = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.hash_lock.as_deref(), Some("deadbeef"));
        assert_eq!(restored.time_lock, Some(1700000000));
    }

    #[test]
    fn test_stealth_address_serde() {
        let addr = StealthAddress {
            address: "stealth1".into(),
            scan_pubkey: "scan".into(),
            spend_pubkey: "spend".into(),
            ephemeral_pubkey: None,
        };
        let json = serde_json::to_string(&addr).unwrap();
        let restored: StealthAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.address, "stealth1");
        assert!(restored.ephemeral_pubkey.is_none());
    }

    #[test]
    fn test_ghost_utxo_private_fields_skipped() {
        let utxo = GhostUtxo {
            txid: "tx".into(),
            vout: 0,
            amount: Some(1000),
            confirmations: 6,
            address: "addr".into(),
            tx_type: TxType::Public,
            spendable: true,
            blinding_factor: None,
            ring_size: None,
        };
        let json = serde_json::to_string(&utxo).unwrap();
        // blinding_factor and ring_size should not be in the JSON
        assert!(!json.contains("blinding_factor"));
        assert!(!json.contains("ring_size"));
    }

    #[test]
    fn test_fee_estimate_serde() {
        let fee = FeeEstimate {
            feerate: 1.5,
            blocks: 6,
        };
        let json = serde_json::to_string(&fee).unwrap();
        let restored: FeeEstimate = serde_json::from_str(&json).unwrap();
        assert!((restored.feerate - 1.5).abs() < f64::EPSILON);
        assert_eq!(restored.blocks, 6);
    }

    #[test]
    fn test_address_balance_serde() {
        let bal = AddressBalance {
            address: "gAddr".into(),
            confirmed: 100,
            unconfirmed: 50,
            immature: 10,
        };
        let json = serde_json::to_string(&bal).unwrap();
        let restored: AddressBalance = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.confirmed, 100);
        assert_eq!(restored.unconfirmed, 50);
        assert_eq!(restored.immature, 10);
    }

    #[test]
    fn test_sync_result_default() {
        let sr = crate::network::SyncResult::default();
        assert_eq!(sr.height, 0);
        assert_eq!(sr.addresses_scanned, 0);
        assert_eq!(sr.new_utxos_count, 0);
    }
}
