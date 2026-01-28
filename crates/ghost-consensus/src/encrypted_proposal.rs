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
//| FILE: encrypted_proposal.rs                                                                                          |
//|======================================================================================================================|

//! Encrypted payout proposals with threshold reveal
//!
//! Provides privacy-preserving payout proposals that are only revealed
//! when sufficient consensus is reached. This prevents:
//!
//! - Early leakage of payout addresses
//! - Targeted attacks based on payout amounts
//! - Correlation of addresses before finalization
//!
//! # Architecture
//!
//! 1. Proposer encrypts payout proposal with random symmetric key
//! 2. Key is split using Shamir's Secret Sharing (k-of-n threshold)
//! 3. Each share is encrypted to a specific voting node
//! 4. Nodes vote without seeing full proposal content
//! 5. When k shares are collected, proposal is revealed
//!
//! # Threshold Selection
//!
//! Uses 67% threshold (BFT-compatible):
//! - n = total voting nodes
//! - k = ceil(n * 2/3) required shares
//!
//! This ensures proposals are only revealed after BFT consensus.

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use ghost_common::types::{NodeId, PayoutEntry};

/// Maximum number of shares (voting nodes)
pub const MAX_SHARES: usize = 256;

/// Minimum shares required (at least 3 for any meaningful threshold)
pub const MIN_SHARES: usize = 3;

/// Encrypted proposal errors
#[derive(Debug, Error)]
pub enum ProposalError {
    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid share: {0}")]
    InvalidShare(String),

    #[error("Insufficient shares: have {0}, need {1}")]
    InsufficientShares(usize, usize),

    #[error("Too many shares: {0} > {MAX_SHARES}")]
    TooManyShares(usize),

    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),

    #[error("Proposal not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Shamir share for secret reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    /// Share index (1-based, x-coordinate in polynomial)
    pub index: u8,
    /// Share value (y-coordinate, 32 bytes for 256-bit key)
    pub value: [u8; 32],
    /// Node ID this share belongs to
    pub node_id: NodeId,
}

impl SecretShare {
    /// Verify share is well-formed
    pub fn verify(&self) -> bool {
        // index must be non-zero (Shamir uses 1-indexed x values)
        // MAX_SHARES is 256, so any u8 value (1-255) is valid
        self.index > 0
    }
}

/// Encrypted payout proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedProposal {
    /// Unique proposal ID (hash of encrypted content)
    pub id: [u8; 32],
    /// Round ID this proposal is for
    pub round_id: u64,
    /// Block height this proposal is for
    pub block_height: u64,
    /// Encrypted proposal content (AES-256-GCM)
    pub ciphertext: Vec<u8>,
    /// Nonce for AES-GCM
    pub nonce: [u8; 12],
    /// Total number of shares (n)
    pub total_shares: u8,
    /// Threshold required (k)
    pub threshold: u8,
    /// Proposer's node ID
    pub proposer: NodeId,
    /// Timestamp of proposal creation
    pub created_at: u64,
    /// Commitment to the plaintext (for verification after reveal)
    pub content_hash: [u8; 32],
}

impl EncryptedProposal {
    /// Calculate proposal ID from ciphertext
    fn calculate_id(ciphertext: &[u8], round_id: u64, block_height: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        hasher.update(round_id.to_le_bytes());
        hasher.update(block_height.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Decrypted proposal content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalContent {
    /// Round ID
    pub round_id: u64,
    /// Block height
    pub block_height: u64,
    /// Payout entries
    pub payouts: Vec<PayoutEntry>,
    /// Total amount in satoshis
    pub total_sats: u64,
    /// Treasury address
    pub treasury_address: Vec<u8>,
    /// Random padding to obscure size
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub padding: Vec<u8>,
}

impl ProposalContent {
    /// Calculate content hash for commitment
    pub fn content_hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }

    /// Add random padding to obscure proposal size
    pub fn add_padding(&mut self, target_size: usize) {
        let current_size = serde_json::to_vec(self).map(|v| v.len()).unwrap_or(0);
        if current_size < target_size {
            let padding_size = target_size - current_size;
            self.padding = vec![0u8; padding_size];
            // Fill with random-looking but deterministic data
            for (i, byte) in self.padding.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(0x5D).wrapping_add(0x3A);
            }
        }
    }
}

/// Proposal encryption/decryption manager
pub struct ProposalCrypto {
    /// Pending proposals awaiting reveal (id -> (proposal, collected_shares))
    pending: RwLock<HashMap<[u8; 32], (EncryptedProposal, Vec<SecretShare>)>>,
    /// Revealed proposals
    revealed: RwLock<HashMap<[u8; 32], ProposalContent>>,
}

impl ProposalCrypto {
    /// Create a new proposal crypto manager
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            revealed: RwLock::new(HashMap::new()),
        }
    }

    /// Encrypt a proposal and generate shares
    ///
    /// Returns the encrypted proposal and a map of node_id -> share
    pub fn encrypt_proposal(
        &self,
        content: &ProposalContent,
        voting_nodes: &[NodeId],
        threshold_percent: u8,
    ) -> Result<(EncryptedProposal, HashMap<NodeId, SecretShare>), ProposalError> {
        let n = voting_nodes.len();

        if n < MIN_SHARES {
            return Err(ProposalError::InvalidThreshold(format!(
                "Need at least {} voting nodes, got {}",
                MIN_SHARES, n
            )));
        }

        if n > MAX_SHARES {
            return Err(ProposalError::TooManyShares(n));
        }

        // Calculate threshold (e.g., 67% of n)
        let k = ((n as f64) * (threshold_percent as f64) / 100.0).ceil() as usize;
        let k = k.max(MIN_SHARES).min(n);

        // Generate random 256-bit key
        let key = generate_random_key();

        // Encrypt content with AES-256-GCM
        let plaintext = serde_json::to_vec(content)
            .map_err(|e| ProposalError::Serialization(e.to_string()))?;

        let nonce = generate_random_nonce();
        let ciphertext = aes_gcm_encrypt(&key, &nonce, &plaintext)?;

        // Split key using Shamir's Secret Sharing
        let shares = shamir_split(&key, k, n)?;

        // Map shares to nodes
        let mut node_shares = HashMap::new();
        for (i, node_id) in voting_nodes.iter().enumerate() {
            node_shares.insert(*node_id, SecretShare {
                index: shares[i].0,
                value: shares[i].1,
                node_id: *node_id,
            });
        }

        let content_hash = content.content_hash();

        let proposal = EncryptedProposal {
            id: EncryptedProposal::calculate_id(&ciphertext, content.round_id, content.block_height),
            round_id: content.round_id,
            block_height: content.block_height,
            ciphertext,
            nonce,
            total_shares: n as u8,
            threshold: k as u8,
            proposer: [0u8; 32], // Set by caller
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            content_hash,
        };

        info!(
            id = %hex::encode(&proposal.id[..8]),
            round = content.round_id,
            threshold = k,
            total = n,
            "Created encrypted proposal"
        );

        Ok((proposal, node_shares))
    }

    /// Register a proposal as pending
    pub fn register_proposal(&self, proposal: EncryptedProposal) -> Result<(), ProposalError> {
        let mut pending = self.pending.write();

        if pending.contains_key(&proposal.id) {
            return Ok(()); // Already registered
        }

        debug!(
            id = %hex::encode(&proposal.id[..8]),
            "Registered pending proposal"
        );

        pending.insert(proposal.id, (proposal, Vec::new()));
        Ok(())
    }

    /// Submit a share for a proposal
    ///
    /// Returns Some(content) if threshold is reached and proposal is revealed
    pub fn submit_share(
        &self,
        proposal_id: &[u8; 32],
        share: SecretShare,
    ) -> Result<Option<ProposalContent>, ProposalError> {
        if !share.verify() {
            return Err(ProposalError::InvalidShare("Invalid share format".into()));
        }

        let mut pending = self.pending.write();

        let (proposal, shares) = pending.get_mut(proposal_id)
            .ok_or_else(|| ProposalError::NotFound(hex::encode(&proposal_id[..8])))?;

        // Check if share already submitted from this node
        if shares.iter().any(|s| s.node_id == share.node_id) {
            debug!(
                node = %hex::encode(&share.node_id[..8]),
                "Ignoring duplicate share"
            );
            return Ok(None);
        }

        // Check if share index is valid
        if share.index as usize > proposal.total_shares as usize {
            return Err(ProposalError::InvalidShare(format!(
                "Share index {} > total {}",
                share.index, proposal.total_shares
            )));
        }

        shares.push(share);

        info!(
            id = %hex::encode(&proposal_id[..8]),
            shares = shares.len(),
            threshold = proposal.threshold,
            "Share submitted"
        );

        // Check if we have enough shares
        if shares.len() >= proposal.threshold as usize {
            // Attempt reconstruction
            match self.reveal_proposal(proposal, shares) {
                Ok(content) => {
                    info!(
                        id = %hex::encode(&proposal_id[..8]),
                        "Proposal revealed"
                    );

                    // Move to revealed
                    let id = proposal.id;
                    drop(pending);

                    self.revealed.write().insert(id, content.clone());
                    self.pending.write().remove(&id);

                    return Ok(Some(content));
                }
                Err(e) => {
                    warn!(
                        id = %hex::encode(&proposal_id[..8]),
                        error = %e,
                        "Failed to reveal proposal, waiting for more shares"
                    );
                    // Don't return error - might just need more shares
                }
            }
        }

        Ok(None)
    }

    /// Attempt to reveal a proposal by reconstructing the key
    fn reveal_proposal(
        &self,
        proposal: &EncryptedProposal,
        shares: &[SecretShare],
    ) -> Result<ProposalContent, ProposalError> {
        if shares.len() < proposal.threshold as usize {
            return Err(ProposalError::InsufficientShares(
                shares.len(),
                proposal.threshold as usize,
            ));
        }

        // Reconstruct key from shares
        let share_data: Vec<(u8, [u8; 32])> = shares.iter()
            .map(|s| (s.index, s.value))
            .collect();

        let key = shamir_combine(&share_data, proposal.threshold as usize)?;

        // Decrypt content
        let plaintext = aes_gcm_decrypt(&key, &proposal.nonce, &proposal.ciphertext)?;

        // Deserialize
        let content: ProposalContent = serde_json::from_slice(&plaintext)
            .map_err(|e| ProposalError::Serialization(e.to_string()))?;

        // Verify content hash
        let actual_hash = content.content_hash();
        if actual_hash != proposal.content_hash {
            return Err(ProposalError::Decryption(
                "Content hash mismatch - proposal may be corrupted".into()
            ));
        }

        Ok(content)
    }

    /// Get a revealed proposal
    pub fn get_revealed(&self, proposal_id: &[u8; 32]) -> Option<ProposalContent> {
        self.revealed.read().get(proposal_id).cloned()
    }

    /// Check if proposal is revealed
    pub fn is_revealed(&self, proposal_id: &[u8; 32]) -> bool {
        self.revealed.read().contains_key(proposal_id)
    }

    /// Get pending proposal status
    pub fn get_pending_status(&self, proposal_id: &[u8; 32]) -> Option<(u8, u8)> {
        self.pending.read().get(proposal_id)
            .map(|(p, s)| (s.len() as u8, p.threshold))
    }

    /// Clean up old proposals
    pub fn cleanup_old(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cutoff = now.saturating_sub(max_age_secs);

        let mut pending = self.pending.write();
        pending.retain(|_, (p, _)| p.created_at > cutoff);

        let mut revealed = self.revealed.write();
        // Keep revealed longer - they're useful for verification
        // This is a simplified cleanup; production would track reveal time
        if revealed.len() > 1000 {
            // Just keep recent ones
            revealed.clear();
        }
    }
}

impl Default for ProposalCrypto {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Cryptographic primitives
// ============================================================================

/// Generate a random 256-bit key
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).expect("Failed to generate random key");
    key
}

/// Generate a random 96-bit nonce for AES-GCM
fn generate_random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).expect("Failed to generate random nonce");
    nonce
}

/// AES-256-GCM encryption
fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, ProposalError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ProposalError::Encryption(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher.encrypt(nonce, plaintext)
        .map_err(|e| ProposalError::Encryption(e.to_string()))
}

/// AES-256-GCM decryption
fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, ProposalError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ProposalError::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| ProposalError::Decryption(e.to_string()))
}

// ============================================================================
// Shamir's Secret Sharing (over GF(2^8))
// ============================================================================

/// GF(2^8) field for Shamir's Secret Sharing
mod gf256 {
    /// Multiplication in GF(2^8) with AES polynomial (x^8 + x^4 + x^3 + x + 1)
    pub fn mul(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut a = a;
        let mut b = b;

        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a;
            }
            let high_bit = a & 0x80;
            a <<= 1;
            if high_bit != 0 {
                a ^= 0x1b; // AES polynomial
            }
            b >>= 1;
        }
        result
    }

    /// Multiplicative inverse in GF(2^8)
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        // Use extended Euclidean algorithm or lookup table
        // For simplicity, use exponentiation: a^254 = a^(-1) in GF(2^8)
        let mut result = a;
        for _ in 0..6 {
            result = mul(result, result);
            result = mul(result, a);
        }
        mul(result, result)
    }

    /// Evaluate polynomial at point x
    pub fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        let mut x_pow = 1u8;

        for &coeff in coeffs {
            result ^= mul(coeff, x_pow);
            x_pow = mul(x_pow, x);
        }
        result
    }

    /// Lagrange interpolation to find f(0)
    pub fn lagrange_interpolate(points: &[(u8, u8)]) -> u8 {
        let mut result = 0u8;

        for (i, &(xi, yi)) in points.iter().enumerate() {
            let mut term = yi;

            for (j, &(xj, _)) in points.iter().enumerate() {
                if i != j {
                    // term *= xj / (xj - xi)
                    // In GF(2^8): subtraction is XOR
                    let diff = xj ^ xi;
                    term = mul(term, mul(xj, inv(diff)));
                }
            }

            result ^= term;
        }
        result
    }
}

/// Split a 256-bit secret into n shares with threshold k
fn shamir_split(secret: &[u8; 32], k: usize, n: usize) -> Result<Vec<(u8, [u8; 32])>, ProposalError> {
    if k < 2 || k > n || n > MAX_SHARES {
        return Err(ProposalError::InvalidThreshold(format!(
            "Invalid k={}, n={}",
            k, n
        )));
    }

    let mut shares = vec![(0u8, [0u8; 32]); n];

    // Process each byte of the secret independently
    for byte_idx in 0..32 {
        // Generate random polynomial coefficients (degree k-1)
        // coeffs[0] = secret byte, others are random
        let mut coeffs = vec![0u8; k];
        coeffs[0] = secret[byte_idx];

        // Generate random coefficients for higher degrees
        for coeff in coeffs.iter_mut().skip(1) {
            let mut rand = [0u8; 1];
            getrandom::getrandom(&mut rand).expect("Random generation failed");
            *coeff = rand[0];
        }

        // Evaluate polynomial at points 1, 2, ..., n
        for (i, share) in shares.iter_mut().enumerate() {
            let x = (i + 1) as u8; // x values are 1-indexed
            share.0 = x;
            share.1[byte_idx] = gf256::eval_poly(&coeffs, x);
        }
    }

    Ok(shares)
}

/// Combine k shares to reconstruct the secret
fn shamir_combine(shares: &[(u8, [u8; 32])], k: usize) -> Result<[u8; 32], ProposalError> {
    if shares.len() < k {
        return Err(ProposalError::InsufficientShares(shares.len(), k));
    }

    let mut secret = [0u8; 32];

    // Use only the first k shares
    let shares = &shares[..k];

    // Reconstruct each byte independently
    for byte_idx in 0..32 {
        let points: Vec<(u8, u8)> = shares.iter()
            .map(|(x, y)| (*x, y[byte_idx]))
            .collect();

        secret[byte_idx] = gf256::lagrange_interpolate(&points);
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_mul() {
        // a * 1 = a
        assert_eq!(gf256::mul(0x53, 1), 0x53);
        // a * 0 = 0
        assert_eq!(gf256::mul(0x53, 0), 0);
        // Commutativity
        assert_eq!(gf256::mul(0x53, 0xca), gf256::mul(0xca, 0x53));
    }

    #[test]
    fn test_gf256_inv() {
        // a * a^(-1) = 1
        for a in 1..=255u8 {
            let inv = gf256::inv(a);
            assert_eq!(gf256::mul(a, inv), 1, "Failed for a={}", a);
        }
    }

    #[test]
    fn test_shamir_split_combine() {
        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        // 3-of-5 sharing
        let shares = shamir_split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with any 3 shares
        let recovered = shamir_combine(&shares[0..3], 3).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with different 3 shares
        let recovered = shamir_combine(&shares[2..5], 3).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with all 5 shares
        let recovered = shamir_combine(&shares, 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_shamir_insufficient_shares() {
        let secret = [0x42u8; 32];
        let shares = shamir_split(&secret, 3, 5).unwrap();

        // Should fail with only 2 shares when threshold is 3
        let result = shamir_combine(&shares[0..2], 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = generate_random_key();
        let nonce = generate_random_nonce();
        let plaintext = b"Hello, encrypted world!";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key = generate_random_key();
        let wrong_key = generate_random_key();
        let nonce = generate_random_nonce();
        let plaintext = b"Secret data";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let result = aes_gcm_decrypt(&wrong_key, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_proposal_content_hash() {
        let content = ProposalContent {
            round_id: 123,
            block_height: 800000,
            payouts: vec![],
            total_sats: 1000000,
            treasury_address: vec![0x00, 0x14],
            padding: vec![],
        };

        let hash1 = content.content_hash();
        let hash2 = content.content_hash();
        assert_eq!(hash1, hash2);

        let mut different = content.clone();
        different.round_id = 124;
        let hash3 = different.content_hash();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_encrypted_proposal_roundtrip() {
        let crypto = ProposalCrypto::new();

        let content = ProposalContent {
            round_id: 100,
            block_height: 800000,
            payouts: vec![
                PayoutEntry {
                    address: vec![0x00, 0x14, 0xab, 0xcd],
                    amount: 500000,
                    recipient_id: [1u8; 32],
                    payout_type: ghost_common::types::PayoutType::Mining,
                },
            ],
            total_sats: 1000000,
            treasury_address: vec![0x00, 0x14, 0xef],
            padding: vec![],
        };

        // Create 5 voting nodes
        let nodes: Vec<NodeId> = (1..=5).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            id
        }).collect();

        // Encrypt with 67% threshold (4 of 5)
        let (proposal, shares) = crypto.encrypt_proposal(&content, &nodes, 67).unwrap();

        assert_eq!(proposal.threshold, 4);
        assert_eq!(proposal.total_shares, 5);
        assert_eq!(shares.len(), 5);

        // Register proposal
        crypto.register_proposal(proposal.clone()).unwrap();

        // Submit shares
        for (i, (node_id, share)) in shares.iter().enumerate() {
            let result = crypto.submit_share(&proposal.id, share.clone()).unwrap();

            if i < 3 {
                // Not enough shares yet
                assert!(result.is_none());
            } else {
                // 4th share should reveal
                assert!(result.is_some());
                let revealed = result.unwrap();
                assert_eq!(revealed.round_id, content.round_id);
                assert_eq!(revealed.total_sats, content.total_sats);
                assert_eq!(revealed.payouts.len(), 1);
                break;
            }
        }

        // Verify proposal is now revealed
        assert!(crypto.is_revealed(&proposal.id));
    }

    #[test]
    fn test_duplicate_share_ignored() {
        let crypto = ProposalCrypto::new();

        let content = ProposalContent {
            round_id: 1,
            block_height: 1,
            payouts: vec![],
            total_sats: 1000,
            treasury_address: vec![],
            padding: vec![],
        };

        let nodes: Vec<NodeId> = (1..=5).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            id
        }).collect();

        let (proposal, shares) = crypto.encrypt_proposal(&content, &nodes, 60).unwrap();
        crypto.register_proposal(proposal.clone()).unwrap();

        // Submit first share
        let share = shares.get(&nodes[0]).unwrap().clone();
        crypto.submit_share(&proposal.id, share.clone()).unwrap();

        // Try to submit same share again
        crypto.submit_share(&proposal.id, share).unwrap();

        // Should still only have 1 share counted
        let status = crypto.get_pending_status(&proposal.id).unwrap();
        assert_eq!(status.0, 1);
    }
}
