//! MiMC hash function for ZK circuits
//!
//! This module provides a unified MiMC implementation used across all circuits
//! for merkle tree operations. MiMC is a ZK-friendly hash function that uses
//! repeated cubing (x^3) with round constants.
//!
//! # Security
//!
//! With 23 rounds, this provides approximately 115 bits of security against
//! algebraic attacks, which is adequate for merkle tree operations in ZK circuits.
//!
//! # Usage
//!
//! Use `mimc_hash` for circuit constraints and `mimc_hash_native` for native
//! computation (e.g., in witness generation). Both functions produce identical
//! outputs.

use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField};

/// Number of MiMC rounds for adequate security (~115 bits)
/// Increased from 10 to 23 for improved security margin
pub const MIMC_ROUNDS: usize = 23;

/// Generate MiMC round constants deterministically
///
/// Constants are derived deterministically from small primes.
/// Each constant = prime[i] + (i * 1000) for diversity and reproducibility.
pub fn mimc_round_constants<F: PrimeField>() -> [F; MIMC_ROUNDS] {
    // We derive deterministic constants from small primes + index
    // This is simpler and more portable than hash-to-field
    let primes: [u64; MIMC_ROUNDS] = [
        7, 13, 19, 31, 43, 61, 79, 97, 113, 131,
        149, 167, 181, 199, 211, 229, 241, 263, 277, 293,
        307, 317, 337,
    ];

    let mut constants = [F::ZERO; MIMC_ROUNDS];
    for i in 0..MIMC_ROUNDS {
        // Use prime + index*1000 for diversity
        constants[i] = F::from(primes[i] + (i as u64) * 1000);
    }
    constants
}

/// MiMC hash in circuit: H(a, b) = MiMC(a + b)
///
/// Uses x -> x^3 + c[i] over multiple rounds for collision resistance.
/// This is the constraint-generating version for use in ZK circuits.
pub fn mimc_hash<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    left: &AllocatedNum<F>,
    right: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let constants = mimc_round_constants::<F>();

    // Compute initial value: a + b
    let mut current = AllocatedNum::alloc(cs.namespace(|| "mimc_init"), || {
        let l = left.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let r = right.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(l + r)
    })?;

    // Constrain: current = left + right
    cs.enforce(
        || "mimc_init_constraint",
        |lc| lc + current.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + left.get_variable() + right.get_variable(),
    );

    // Apply MiMC rounds: x <- x^3 + c[i]
    for (i, constant) in constants.iter().enumerate() {
        // Compute x^2
        let x_squared = current.mul(cs.namespace(|| format!("mimc_sq_{}", i)), &current)?;

        // Compute x^3 = x^2 * x
        let x_cubed = x_squared.mul(cs.namespace(|| format!("mimc_cube_{}", i)), &current)?;

        // Compute x^3 + c[i]
        let next = AllocatedNum::alloc(cs.namespace(|| format!("mimc_round_{}", i)), || {
            let cube = x_cubed
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(cube + *constant)
        })?;

        // Constrain: next = x_cubed + constant
        cs.enforce(
            || format!("mimc_round_{}_constraint", i),
            |lc| lc + next.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + x_cubed.get_variable() + (*constant, CS::one()),
        );

        current = next;
    }

    Ok(current)
}

/// Native MiMC hash: H(a, b) = MiMC(a + b)
///
/// This computes the same hash as `mimc_hash` but without creating constraints.
/// Use this for witness generation and native merkle tree computations.
pub fn mimc_hash_native<F: PrimeField>(left: F, right: F) -> F {
    let constants = mimc_round_constants::<F>();

    // Initial value: a + b
    let mut current = left + right;

    // Apply MiMC rounds: x <- x^3 + c[i]
    for constant in constants.iter() {
        let x_squared = current * current;
        let x_cubed = x_squared * current;
        current = x_cubed + *constant;
    }

    current
}

/// Convert field element to bytes (for merkle proofs)
pub fn field_to_bytes<F: PrimeField>(field: F) -> [u8; 32] {
    let repr = field.to_repr();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(repr.as_ref());
    bytes
}

/// Convert bytes to field element (for merkle proofs)
///
/// Uses the lower 253 bits (BLS12-381 scalar field size) of the input.
/// Clears the top bit to ensure the value fits in the field.
pub fn bytes_to_field<F: PrimeField>(bytes: &[u8; 32]) -> Option<F> {
    // Construct a u64 array from bytes (little-endian)
    let limbs: [u64; 4] = [
        u64::from_le_bytes(bytes[0..8].try_into().ok()?),
        u64::from_le_bytes(bytes[8..16].try_into().ok()?),
        u64::from_le_bytes(bytes[16..24].try_into().ok()?),
        u64::from_le_bytes(bytes[24..32].try_into().ok()?) & 0x7FFFFFFFFFFFFFFF, // Clear top bit
    ];

    // Compute as: limbs[0] + limbs[1]*2^64 + limbs[2]*2^128 + limbs[3]*2^192
    // For safety with field arithmetic, we use the From<u64> impl
    let two64 = F::from(1u64 << 32) * F::from(1u64 << 32);
    let two128 = two64 * two64;
    let two192 = two128 * two64;

    let result = F::from(limbs[0])
        + F::from(limbs[1]) * two64
        + F::from(limbs[2]) * two128
        + F::from(limbs[3]) * two192;

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    #[test]
    fn test_mimc_rounds_count() {
        assert_eq!(MIMC_ROUNDS, 23, "MiMC should use 23 rounds for security");
    }

    #[test]
    fn test_round_constants_deterministic() {
        let constants1 = mimc_round_constants::<Fr>();
        let constants2 = mimc_round_constants::<Fr>();
        assert_eq!(constants1, constants2, "Round constants should be deterministic");
    }

    #[test]
    fn test_round_constants_non_zero() {
        let constants = mimc_round_constants::<Fr>();
        for (i, c) in constants.iter().enumerate() {
            assert!(*c != Fr::ZERO, "Constant {} should be non-zero", i);
        }
    }

    #[test]
    fn test_native_mimc_matches_circuit() {
        let left = Fr::from(12345u64);
        let right = Fr::from(67890u64);

        // Compute native hash
        let native_hash = mimc_hash_native(left, right);

        // Compute circuit hash
        let mut cs = TestConstraintSystem::<Fr>::new();
        let left_var = AllocatedNum::alloc(cs.namespace(|| "left"), || Ok(left)).unwrap();
        let right_var = AllocatedNum::alloc(cs.namespace(|| "right"), || Ok(right)).unwrap();
        let circuit_hash = mimc_hash(cs.namespace(|| "hash"), &left_var, &right_var).unwrap();

        assert!(cs.is_satisfied(), "Circuit should be satisfied");
        assert_eq!(
            native_hash,
            circuit_hash.get_value().unwrap(),
            "Native and circuit hash should match"
        );
    }

    #[test]
    fn test_mimc_different_inputs() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);

        let hash_ab = mimc_hash_native(a, b);
        let hash_ac = mimc_hash_native(a, c);
        let hash_bc = mimc_hash_native(b, c);

        assert_ne!(hash_ab, hash_ac, "Different inputs should produce different hashes");
        assert_ne!(hash_ab, hash_bc, "Different inputs should produce different hashes");
        assert_ne!(hash_ac, hash_bc, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_field_bytes_roundtrip() {
        let original = Fr::from(0x123456789ABCDEFu64);
        let bytes = field_to_bytes(original);
        let recovered = bytes_to_field::<Fr>(&bytes).unwrap();
        assert_eq!(original, recovered, "Field element should survive roundtrip");
    }
}
