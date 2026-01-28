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
//| FILE: merkle.rs                                                                                                      |
//|======================================================================================================================|

//! Merkle tree computation for block templates

use sha2::{Digest, Sha256};

/// Compute double SHA256 hash
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Compute merkle root from transaction IDs
///
/// Bitcoin merkle trees use double SHA256 and duplicate the last
/// element if the number of elements is odd.
pub fn compute_merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }

    if txids.len() == 1 {
        return txids[0];
    }

    let mut level: Vec<[u8; 32]> = txids.to_vec();

    while level.len() > 1 {
        level = compute_next_level(&level);
    }

    level[0]
}

/// Compute the next level of the merkle tree
fn compute_next_level(hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next_level = Vec::with_capacity((hashes.len() + 1) / 2);

    let mut i = 0;
    while i < hashes.len() {
        let left = &hashes[i];
        let right = if i + 1 < hashes.len() {
            &hashes[i + 1]
        } else {
            // Duplicate last element if odd number
            left
        };

        // Concatenate and hash
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(left);
        combined[32..].copy_from_slice(right);

        next_level.push(double_sha256(&combined));
        i += 2;
    }

    next_level
}

/// Compute merkle branch (proof) for a transaction at given index
pub fn compute_merkle_branch(txids: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if txids.is_empty() || index >= txids.len() {
        return Vec::new();
    }

    let mut branch = Vec::new();
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        // Sibling index
        let sibling_idx = if idx % 2 == 0 {
            if idx + 1 < level.len() {
                idx + 1
            } else {
                idx // Duplicate self if last
            }
        } else {
            idx - 1
        };

        branch.push(level[sibling_idx]);

        // Move to next level
        level = compute_next_level(&level);
        idx /= 2;
    }

    branch
}

/// Verify a merkle branch
pub fn verify_merkle_branch(
    txid: &[u8; 32],
    merkle_root: &[u8; 32],
    branch: &[[u8; 32]],
    index: usize,
) -> bool {
    let mut current = *txid;
    let mut idx = index;

    for sibling in branch {
        let mut combined = [0u8; 64];

        if idx % 2 == 0 {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current);
        }

        current = double_sha256(&combined);
        idx /= 2;
    }

    current == *merkle_root
}

/// Merkle tree builder for incremental construction
#[derive(Debug, Clone)]
pub struct MerkleTreeBuilder {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTreeBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Create with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            leaves: Vec::with_capacity(capacity),
        }
    }

    /// Add a leaf (transaction ID)
    pub fn add_leaf(&mut self, txid: [u8; 32]) {
        self.leaves.push(txid);
    }

    /// Add multiple leaves
    pub fn add_leaves(&mut self, txids: &[[u8; 32]]) {
        self.leaves.extend_from_slice(txids);
    }

    /// Get the number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Compute the merkle root
    pub fn root(&self) -> [u8; 32] {
        compute_merkle_root(&self.leaves)
    }

    /// Get branch for a leaf
    pub fn branch(&self, index: usize) -> Vec<[u8; 32]> {
        compute_merkle_branch(&self.leaves, index)
    }

    /// Clear all leaves
    pub fn clear(&mut self) {
        self.leaves.clear();
    }
}

impl Default for MerkleTreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the txid (double SHA256) of a serialized transaction.
///
/// Note: Bitcoin txids are displayed in reverse byte order, but we return
/// the natural byte order here for consistency with merkle tree operations.
pub fn compute_txid(tx_bytes: &[u8]) -> [u8; 32] {
    double_sha256(tx_bytes)
}

/// Hash two 32-byte nodes together for merkle tree construction.
/// The hashes are concatenated (left || right) and double SHA256'd.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    double_sha256(&combined)
}

/// Build a merkle path for the coinbase transaction (always at index 0).
///
/// # Arguments
/// * `txids` - All transaction IDs including coinbase at index 0
///
/// # Returns
/// The merkle path (list of sibling hashes from leaf to root) for the coinbase.
/// If there's only one transaction (coinbase-only), returns an empty path.
pub fn build_merkle_path_for_coinbase(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    compute_merkle_branch(txids, 0)
}

/// Rebuild merkle tree with filtered transactions and return the new merkle path.
///
/// This is used after filtering transactions from a template - we need to
/// rebuild the merkle tree and compute a new path for the coinbase.
///
/// # Arguments
/// * `coinbase_txid` - The txid of the coinbase transaction
/// * `filtered_txids` - TXIDs of filtered transactions (NOT including coinbase)
///
/// # Returns
/// The merkle path for the coinbase transaction in the new tree.
pub fn rebuild_merkle_tree(coinbase_txid: [u8; 32], filtered_txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    // Prepend coinbase to get all txids
    let mut all_txids = Vec::with_capacity(filtered_txids.len() + 1);
    all_txids.push(coinbase_txid);
    all_txids.extend_from_slice(filtered_txids);

    build_merkle_path_for_coinbase(&all_txids)
}

/// Compute the merkle root from a coinbase txid and its merkle path.
/// This can be used to verify the path is correct.
pub fn compute_root_from_path(coinbase_txid: &[u8; 32], merkle_path: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *coinbase_txid;

    for sibling in merkle_path {
        // Coinbase is always at index 0, so it's always on the left at each level
        current = hash_pair(&current, sibling);
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_tx_merkle() {
        let txid = [1u8; 32];
        let root = compute_merkle_root(&[txid]);
        assert_eq!(root, txid);
    }

    #[test]
    fn test_two_tx_merkle() {
        let tx1 = [1u8; 32];
        let tx2 = [2u8; 32];

        let root = compute_merkle_root(&[tx1, tx2]);

        // Manually compute expected root
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&tx1);
        combined[32..].copy_from_slice(&tx2);
        let expected = double_sha256(&combined);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_odd_tx_merkle() {
        let tx1 = [1u8; 32];
        let tx2 = [2u8; 32];
        let tx3 = [3u8; 32];

        let root = compute_merkle_root(&[tx1, tx2, tx3]);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_branch_verification() {
        let txids: Vec<[u8; 32]> = (0..8).map(|i| [i as u8; 32]).collect();

        let root = compute_merkle_root(&txids);

        // Verify branch for each transaction
        for (i, txid) in txids.iter().enumerate() {
            let branch = compute_merkle_branch(&txids, i);
            assert!(verify_merkle_branch(txid, &root, &branch, i));
        }
    }

    #[test]
    fn test_builder() {
        let mut builder = MerkleTreeBuilder::new();

        builder.add_leaf([1u8; 32]);
        builder.add_leaf([2u8; 32]);
        builder.add_leaf([3u8; 32]);

        assert_eq!(builder.len(), 3);

        let root = builder.root();
        let branch = builder.branch(0);

        assert!(verify_merkle_branch(&[1u8; 32], &root, &branch, 0));
    }

    #[test]
    fn test_rebuild_merkle_tree() {
        let coinbase = [0xaa; 32];
        let filtered = [[0xbb; 32], [0xcc; 32]];

        let path = rebuild_merkle_tree(coinbase, &filtered);

        // Should be same as building with all txids
        let all = [coinbase, [0xbb; 32], [0xcc; 32]];
        let expected_path = build_merkle_path_for_coinbase(&all);

        assert_eq!(path, expected_path);
    }

    #[test]
    fn test_empty_filtered_txs() {
        let coinbase = [0xaa; 32];
        let path = rebuild_merkle_tree(coinbase, &[]);

        // Coinbase-only block
        assert!(path.is_empty());
    }

    #[test]
    fn test_compute_root_from_path() {
        let coinbase = [0xaa; 32];
        let tx1 = [0xbb; 32];
        let tx2 = [0xcc; 32];
        let txids = [coinbase, tx1, tx2];

        let root = compute_merkle_root(&txids);
        let path = build_merkle_path_for_coinbase(&txids);

        // Verify we can compute the same root from coinbase + path
        let computed_root = compute_root_from_path(&coinbase, &path);
        assert_eq!(computed_root, root);
    }

    #[test]
    fn test_hash_pair() {
        let left = [0u8; 32];
        let right = [1u8; 32];
        let result = hash_pair(&left, &right);
        // Result should be deterministic
        assert_ne!(result, [0u8; 32]);
        assert_ne!(result, left);
        assert_ne!(result, right);
    }
}
