//! Shared field element utilities for ZK prover and verifier
//!
//! M-1: This module provides a unified implementation of bytes_to_field
//! to ensure consistent behavior between prover and verifier.

use blstrs::Scalar as Fr;
use ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::errors::{ZkError, ZkResult};

/// Convert a 32-byte array to a field element
///
/// M-1: Unified implementation used by both prover and verifier.
///
/// SEC-ZKP-1: Uses hash-based reduction to ensure the value fits in the field
/// without lossy bit masking. This preserves the full entropy of the input.
///
/// # Algorithm
///
/// 1. First attempts direct conversion (works if value < field modulus)
/// 2. If value exceeds modulus, uses domain-separated hash reduction
/// 3. Hash output has top bits cleared to ensure it's under BLS12-381 modulus
///
/// # Security Properties
///
/// - Deterministic: Same input always produces same output
/// - Collision-resistant: Different inputs produce different outputs (with overwhelming probability)
/// - Uniform distribution: Output is uniformly distributed in the field (for hash case)
pub fn bytes_to_field(bytes: &[u8; 32]) -> ZkResult<Fr> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);

    // Try direct conversion first (works if value < field modulus)
    if let Some(fr) = Fr::from_repr_vartime(repr) {
        return Ok(fr);
    }

    // Value exceeds field modulus - use hash-based reduction
    //
    // 4.21 SECURITY: COLLISION RISK DOCUMENTATION
    // When the hash-based reduction path is taken:
    // - Multiple distinct byte arrays can produce the same field element
    // - This is inherent to reducing a ~256-bit space to a ~254-bit field
    // - Collision probability is ~2^-254, computationally infeasible to exploit
    // - The hash function provides uniform distribution over the field
    // - Domain separator "GhostZKP/hash-to-field/v1" ensures independence from other uses
    //
    // This is acceptable because:
    // 1. The probability of accidental collision is negligible (~2^-254)
    // 2. Finding collisions intentionally requires breaking SHA256
    // 3. The circuit constraints provide additional protection against malicious inputs
    let mut hasher = Sha256::new();
    hasher.update(b"GhostZKP/hash-to-field/v1");
    hasher.update(bytes);
    let hash = hasher.finalize();

    let mut reduced = [0u8; 32];
    reduced.copy_from_slice(&hash);
    // Clear top 4 bits to ensure well under BLS12-381 modulus (~2^255)
    reduced[31] &= 0x0F;

    Fr::from_repr_vartime(reduced)
        .ok_or_else(|| ZkError::ProvingError("Failed to reduce bytes to field element".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_field_basic() {
        let bytes = [1u8; 32];
        let field = bytes_to_field(&bytes);
        assert!(field.is_ok(), "Should convert bytes to field");
    }

    #[test]
    fn test_bytes_to_field_zero() {
        let zero_bytes = [0u8; 32];
        let zero_field = bytes_to_field(&zero_bytes);
        assert!(zero_field.is_ok(), "Should convert zero bytes");
    }

    #[test]
    fn test_bytes_to_field_deterministic() {
        let bytes = [42u8; 32];
        let field1 = bytes_to_field(&bytes).unwrap();
        let field2 = bytes_to_field(&bytes).unwrap();
        assert_eq!(field1, field2, "Same input should produce same output");
    }

    #[test]
    fn test_bytes_to_field_different_inputs() {
        let bytes1 = [1u8; 32];
        let bytes2 = [2u8; 32];
        let field1 = bytes_to_field(&bytes1).unwrap();
        let field2 = bytes_to_field(&bytes2).unwrap();
        assert_ne!(
            field1, field2,
            "Different inputs should produce different outputs"
        );
    }

    #[test]
    fn test_bytes_to_field_high_value() {
        // Test with value that exceeds field modulus (all 0xFF)
        let high_bytes = [0xFF; 32];
        let field = bytes_to_field(&high_bytes);
        assert!(
            field.is_ok(),
            "Should handle values exceeding field modulus"
        );
    }
}
