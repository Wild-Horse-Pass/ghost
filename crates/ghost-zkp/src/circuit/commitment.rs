//! Pedersen-style commitments and nullifiers for confidential transfers
//!
//! Uses MiMC hash to create binding commitments:
//! - Commitment: `C = MiMC(MiMC(value, blinding), domain_sep)`
//! - Nullifier: `N = MiMC(MiMC(spending_key, note_id), domain_sep)`
//!
//! Domain separators ensure commitment hashes never collide with merkle tree hashes
//! or nullifier hashes, even for identical inputs.

use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

use super::mimc::{mimc_hash, mimc_hash_native};

/// Domain separator for commitments: "COMT" = 0x434f4d54
pub const COMMITMENT_DOMAIN_SEPARATOR: u64 = 0x434f4d54;

/// Domain separator for nullifiers: "NULL" = 0x4e554c4c
pub const NULLIFIER_DOMAIN_SEPARATOR: u64 = 0x4e554c4c;

// ============================================================================
// Native (witness generation) functions
// ============================================================================

/// Compute a Pedersen-style commitment using MiMC
///
/// `C = MiMC(MiMC(value, blinding), domain_sep)`
///
/// Two rounds of MiMC: inner hash binds value+blinding, outer hash binds to domain.
/// The domain separator ensures these hashes cannot collide with merkle tree leaf
/// hashes (which use domain 0x4c454146 "LEAF") or nullifier hashes.
pub fn pedersen_commit_native<F: PrimeField>(value: F, blinding: F) -> F {
    let domain = F::from(COMMITMENT_DOMAIN_SEPARATOR);
    mimc_hash_native(mimc_hash_native(value, blinding), domain)
}

/// Compute a nullifier for double-spend prevention
///
/// `N = MiMC(MiMC(spending_key, note_id), domain_sep)`
///
/// - `spending_key`: private key of the note owner
/// - `note_id`: unique identifier (e.g., `MiMC(account_index, commitment)`)
///
/// The nullifier reveals which note is spent without revealing its value.
pub fn compute_nullifier_native<F: PrimeField>(spending_key: F, note_id: F) -> F {
    let domain = F::from(NULLIFIER_DOMAIN_SEPARATOR);
    mimc_hash_native(mimc_hash_native(spending_key, note_id), domain)
}

/// Compute a note ID from an account index and commitment
///
/// `note_id = MiMC(index_as_field, commitment)`
pub fn compute_note_id_native<F: PrimeField>(index: u64, commitment: F) -> F {
    mimc_hash_native(F::from(index), commitment)
}

// ============================================================================
// Circuit (constraint generation) functions
// ============================================================================

/// Compute a Pedersen-style commitment in-circuit
///
/// `C = MiMC(MiMC(value, blinding), domain_sep)`
///
/// Generates constraints proving the commitment is correctly formed.
pub fn pedersen_commit<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    blinding: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let domain_value = F::from(COMMITMENT_DOMAIN_SEPARATOR);

    // Allocate domain separator
    let domain = AllocatedNum::alloc(cs.namespace(|| "commitment_domain_sep"), || {
        Ok(domain_value)
    })?;

    // Constrain domain separator to the constant
    cs.enforce(
        || "commitment_domain_sep_equals_constant",
        |lc| lc + domain.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (domain_value, CS::one()),
    );

    // Inner hash: MiMC(value, blinding)
    let inner = mimc_hash(cs.namespace(|| "commitment_inner_hash"), value, blinding)?;

    // Outer hash: MiMC(inner, domain_sep)
    mimc_hash(cs.namespace(|| "commitment_outer_hash"), &inner, &domain)
}

/// Compute a nullifier in-circuit
///
/// `N = MiMC(MiMC(spending_key, note_id), domain_sep)`
pub fn compute_nullifier<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    spending_key: &AllocatedNum<F>,
    note_id: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let domain_value = F::from(NULLIFIER_DOMAIN_SEPARATOR);

    // Allocate domain separator
    let domain = AllocatedNum::alloc(cs.namespace(|| "nullifier_domain_sep"), || {
        Ok(domain_value)
    })?;

    // Constrain domain separator to the constant
    cs.enforce(
        || "nullifier_domain_sep_equals_constant",
        |lc| lc + domain.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (domain_value, CS::one()),
    );

    // Inner hash: MiMC(spending_key, note_id)
    let inner = mimc_hash(
        cs.namespace(|| "nullifier_inner_hash"),
        spending_key,
        note_id,
    )?;

    // Outer hash: MiMC(inner, domain_sep)
    mimc_hash(cs.namespace(|| "nullifier_outer_hash"), &inner, &domain)
}

/// Compute a note ID in-circuit
///
/// `note_id = MiMC(index_as_field, commitment)`
pub fn compute_note_id<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: CS,
    index: &AllocatedNum<F>,
    commitment: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    mimc_hash(cs, index, commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use ff::Field;

    #[test]
    fn test_commitment_roundtrip() {
        let value = Fr::from(1000u64);
        let blinding = Fr::from(42u64);

        // Native computation
        let native_commit = pedersen_commit_native(value, blinding);

        // Circuit computation
        let mut cs = TestConstraintSystem::<Fr>::new();
        let value_var = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(value)).unwrap();
        let blinding_var =
            AllocatedNum::alloc(cs.namespace(|| "blinding"), || Ok(blinding)).unwrap();
        let circuit_commit =
            pedersen_commit(cs.namespace(|| "commit"), &value_var, &blinding_var).unwrap();

        assert!(cs.is_satisfied(), "Commitment circuit should be satisfied");
        assert_eq!(
            native_commit,
            circuit_commit.get_value().unwrap(),
            "Native and circuit commitment should match"
        );
    }

    #[test]
    fn test_nullifier_roundtrip() {
        let spending_key = Fr::from(12345u64);
        let note_id = Fr::from(67890u64);

        // Native computation
        let native_nullifier = compute_nullifier_native(spending_key, note_id);

        // Circuit computation
        let mut cs = TestConstraintSystem::<Fr>::new();
        let key_var =
            AllocatedNum::alloc(cs.namespace(|| "spending_key"), || Ok(spending_key)).unwrap();
        let note_var =
            AllocatedNum::alloc(cs.namespace(|| "note_id"), || Ok(note_id)).unwrap();
        let circuit_nullifier =
            compute_nullifier(cs.namespace(|| "nullifier"), &key_var, &note_var).unwrap();

        assert!(cs.is_satisfied(), "Nullifier circuit should be satisfied");
        assert_eq!(
            native_nullifier,
            circuit_nullifier.get_value().unwrap(),
            "Native and circuit nullifier should match"
        );
    }

    #[test]
    fn test_nullifier_uniqueness() {
        // Different spending keys produce different nullifiers
        let key1 = Fr::from(100u64);
        let key2 = Fr::from(200u64);
        let note_id = Fr::from(42u64);

        let null1 = compute_nullifier_native(key1, note_id);
        let null2 = compute_nullifier_native(key2, note_id);
        assert_ne!(null1, null2, "Different keys must produce different nullifiers");

        // Different note IDs produce different nullifiers
        let note1 = Fr::from(1u64);
        let note2 = Fr::from(2u64);
        let null3 = compute_nullifier_native(key1, note1);
        let null4 = compute_nullifier_native(key1, note2);
        assert_ne!(
            null3, null4,
            "Different note IDs must produce different nullifiers"
        );
    }

    #[test]
    fn test_domain_separation() {
        // Commitment and merkle leaf hash must differ for same numeric inputs
        let value = Fr::from(1000u64);
        let other = Fr::from(42u64);

        // Commitment hash
        let commit = pedersen_commit_native(value, other);

        // Merkle leaf hash (uses domain 0x4c454146 = "LEAF")
        let leaf_domain = Fr::from(0x4c454146u64);
        let merkle_leaf = mimc_hash_native(value, leaf_domain);

        assert_ne!(
            commit, merkle_leaf,
            "Commitment hash and merkle leaf hash must differ"
        );

        // Commitment and nullifier must also differ for same inputs
        let nullifier = compute_nullifier_native(value, other);
        assert_ne!(
            commit, nullifier,
            "Commitment and nullifier must differ for same inputs"
        );
    }

    #[test]
    fn test_commitment_hiding() {
        // Same value with different blinding factors produces different commitments
        let value = Fr::from(1000u64);
        let blind1 = Fr::from(111u64);
        let blind2 = Fr::from(222u64);

        let c1 = pedersen_commit_native(value, blind1);
        let c2 = pedersen_commit_native(value, blind2);
        assert_ne!(
            c1, c2,
            "Same value with different blindings must produce different commitments"
        );
    }

    #[test]
    fn test_commitment_binding() {
        // Different values with same blinding produce different commitments
        let v1 = Fr::from(1000u64);
        let v2 = Fr::from(2000u64);
        let blinding = Fr::from(42u64);

        let c1 = pedersen_commit_native(v1, blinding);
        let c2 = pedersen_commit_native(v2, blinding);
        assert_ne!(
            c1, c2,
            "Different values with same blinding must produce different commitments"
        );
    }

    #[test]
    fn test_note_id_computation() {
        let index = 5u64;
        let commitment = Fr::from(999u64);

        // Native
        let native_id = compute_note_id_native(index, commitment);

        // Circuit
        let mut cs = TestConstraintSystem::<Fr>::new();
        let index_var =
            AllocatedNum::alloc(cs.namespace(|| "index"), || Ok(Fr::from(index))).unwrap();
        let commit_var =
            AllocatedNum::alloc(cs.namespace(|| "commitment"), || Ok(commitment)).unwrap();
        let circuit_id =
            compute_note_id(cs.namespace(|| "note_id"), &index_var, &commit_var).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(native_id, circuit_id.get_value().unwrap());
    }

    #[test]
    fn test_commitment_zero_value() {
        // Zero value commitment should still be valid and unique per blinding
        let zero = Fr::ZERO;
        let blind1 = Fr::from(1u64);
        let blind2 = Fr::from(2u64);

        let c1 = pedersen_commit_native(zero, blind1);
        let c2 = pedersen_commit_native(zero, blind2);
        assert_ne!(c1, c2, "Zero-value commitments should differ by blinding");
        assert_ne!(c1, Fr::ZERO, "Commitment of zero should not be zero");
    }
}
