//! Range proof gadget for ZK circuits
//!
//! Proves that a value lies in `[0, 2^num_bits)` without revealing it.
//! Uses bit decomposition: decomposes the value into boolean-constrained
//! bits and verifies reconstruction matches the original value.
//!
//! ~64 constraints for a 64-bit range proof (one per bit + reconstruction).

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

/// Prove that `value` lies in `[0, 2^num_bits)` without revealing it.
///
/// Returns the decomposed bits, which can be reused by other constraints.
///
/// # Arguments
/// * `cs` - Constraint system namespace
/// * `value` - The allocated number to range-check
/// * `num_bits` - Number of bits (e.g., 64 for u64 range)
///
/// # Constraints
/// * `num_bits` boolean constraints (one per bit via AllocatedBit)
/// * 1 reconstruction constraint: `sum(bit_i * 2^i) == value`
pub fn enforce_range<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    num_bits: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    // Extract the u64 representation for witness generation
    let value_bits = value.get_value().map(|v| {
        let bytes = v.to_repr();
        let mut result = 0u64;
        for (i, byte) in bytes.as_ref().iter().take(8).enumerate() {
            result |= (*byte as u64) << (i * 8);
        }
        result
    });

    // Decompose into bits using AllocatedBit (each has built-in boolean constraint)
    let mut bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let bit_value = value_bits.map(|v| ((v >> i) & 1) == 1);
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit_{}", i)), bit_value)?;
        bits.push(Boolean::from(bit));
    }

    // Reconstruct from bits and constrain equality
    let mut coeff = F::ONE;
    let mut lc_sum = LinearCombination::<F>::zero();

    for bit in bits.iter() {
        match bit {
            Boolean::Is(ref b) => {
                lc_sum = lc_sum + (coeff, b.get_variable());
            }
            Boolean::Not(ref b) => {
                lc_sum = lc_sum + (coeff, CS::one()) - (coeff, b.get_variable());
            }
            Boolean::Constant(c) => {
                if *c {
                    lc_sum = lc_sum + (coeff, CS::one());
                }
            }
        }
        coeff = coeff.double();
    }

    // Enforce: sum(bit_i * 2^i) == value
    cs.enforce(
        || "reconstructed equals value",
        |_| lc_sum,
        |lc| lc + CS::one(),
        |lc| lc + value.get_variable(),
    );

    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    #[test]
    fn test_range_proof_zero() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Fr::from(0u64))).unwrap();
        let bits = enforce_range(cs.namespace(|| "range"), &value, 64).unwrap();

        assert!(cs.is_satisfied(), "Zero should satisfy 64-bit range proof");
        assert_eq!(bits.len(), 64);
    }

    #[test]
    fn test_range_proof_one() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Fr::from(1u64))).unwrap();
        let bits = enforce_range(cs.namespace(|| "range"), &value, 64).unwrap();

        assert!(cs.is_satisfied(), "1 should satisfy 64-bit range proof");
        // First bit should be true
        assert_eq!(bits[0].get_value(), Some(true));
        for bit in &bits[1..] {
            assert_eq!(bit.get_value(), Some(false));
        }
    }

    #[test]
    fn test_range_proof_max_u64() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value =
            AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Fr::from(u64::MAX))).unwrap();
        let bits = enforce_range(cs.namespace(|| "range"), &value, 64).unwrap();

        assert!(
            cs.is_satisfied(),
            "u64::MAX should satisfy 64-bit range proof"
        );
        // All bits should be true
        for bit in &bits {
            assert_eq!(bit.get_value(), Some(true));
        }
    }

    #[test]
    fn test_range_proof_boundary() {
        // 2^64 - 1 should pass 64-bit range proof (it's u64::MAX)
        let mut cs = TestConstraintSystem::<Fr>::new();
        let max_val = (1u128 << 64) - 1;
        let value =
            AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Fr::from(max_val as u64))).unwrap();
        enforce_range(cs.namespace(|| "range"), &value, 64).unwrap();
        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_range_proof_exceeds_fails() {
        // A value that requires more than 8 bits should fail an 8-bit range proof
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Fr::from(256u64))).unwrap();
        enforce_range(cs.namespace(|| "range"), &value, 8).unwrap();

        assert!(
            !cs.is_satisfied(),
            "256 should NOT satisfy 8-bit range proof (max is 255)"
        );
    }

    #[test]
    fn test_range_proof_8bit_max() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Fr::from(255u64))).unwrap();
        enforce_range(cs.namespace(|| "range"), &value, 8).unwrap();

        assert!(cs.is_satisfied(), "255 should satisfy 8-bit range proof");
    }

    #[test]
    fn test_range_proof_constraint_count() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Fr::from(42u64))).unwrap();
        enforce_range(cs.namespace(|| "range"), &value, 64).unwrap();

        // 64 boolean constraints (AllocatedBit) + 1 reconstruction = 65
        assert_eq!(cs.num_constraints(), 65);
    }

    #[test]
    fn test_range_proof_small_bit_width() {
        // 1-bit range proof: value must be 0 or 1
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "v0"), || Ok(Fr::from(0u64))).unwrap();
        enforce_range(cs.namespace(|| "r0"), &value, 1).unwrap();
        assert!(cs.is_satisfied());

        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "v1"), || Ok(Fr::from(1u64))).unwrap();
        enforce_range(cs.namespace(|| "r1"), &value, 1).unwrap();
        assert!(cs.is_satisfied());

        let mut cs = TestConstraintSystem::<Fr>::new();
        let value = AllocatedNum::alloc(cs.namespace(|| "v2"), || Ok(Fr::from(2u64))).unwrap();
        enforce_range(cs.namespace(|| "r2"), &value, 1).unwrap();
        assert!(!cs.is_satisfied(), "2 should fail 1-bit range proof");
    }
}
