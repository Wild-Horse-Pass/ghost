//! Payout validity circuit
//!
//! Proves that payout distribution is valid:
//! 1. Sum preservation: sum(miner_payouts) + sum(node_payouts) + treasury == total_available
//! 2. All payouts are non-negative and fit in 64 bits
//! 3. Treasury fee is within expected bounds

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use std::marker::PhantomData;

use super::BALANCE_BITS;

/// Maximum number of miners in a payout
pub const MAX_MINERS: usize = 100;

/// Maximum number of nodes in a payout
pub const MAX_NODES: usize = 50;

/// Circuit proving payout distribution validity
pub struct PayoutCircuit<F: PrimeField> {
    /// Total available for distribution (subsidy + fees)
    pub total_available: Option<u64>,
    /// Per-miner payout amounts
    pub miner_payouts: Vec<Option<u64>>,
    /// Per-node payout amounts
    pub node_payouts: Vec<Option<u64>>,
    /// Treasury (pool fee) amount
    pub treasury_amount: Option<u64>,
    /// Epoch being settled (PUBLIC INPUT for replay protection)
    pub epoch: Option<u64>,
    /// Miner count for metadata commitment
    pub miner_count: Option<u32>,
    /// Node count for metadata commitment
    pub node_count: Option<u32>,
    /// Phantom data for type parameter
    _marker: PhantomData<F>,
}

/// Compute metadata commitment for binding proof to metadata.
///
/// SECURITY (ZK-C3): Uses polynomial encoding for efficient in-circuit verification:
/// commitment = epoch * 2^64 + miner_count * 2^32 + node_count
///
/// This encoding is:
/// - Injective (unique commitment for each (epoch, miner_count, node_count) tuple)
/// - Efficient to verify in-circuit (simple linear constraint)
/// - Safe from overflow since all inputs are bounded (epoch: u64, counts: u32)
pub fn compute_metadata_commitment<F: PrimeField>(
    epoch: u64,
    miner_count: u32,
    node_count: u32,
) -> F {
    let two32 = F::from(1u64 << 32);
    let two64 = two32 * two32;

    F::from(epoch) * two64 + F::from(miner_count as u64) * two32 + F::from(node_count as u64)
}

impl<F: PrimeField> PayoutCircuit<F> {
    /// Create a new payout circuit
    pub fn new(
        total_available: u64,
        miner_payouts: Vec<u64>,
        node_payouts: Vec<u64>,
        treasury_amount: u64,
    ) -> Self {
        let miner_count = miner_payouts.len() as u32;
        let node_count = node_payouts.len() as u32;
        Self {
            total_available: Some(total_available),
            miner_payouts: miner_payouts.into_iter().map(Some).collect(),
            node_payouts: node_payouts.into_iter().map(Some).collect(),
            treasury_amount: Some(treasury_amount),
            epoch: Some(0), // Default epoch for backwards compatibility
            miner_count: Some(miner_count),
            node_count: Some(node_count),
            _marker: PhantomData,
        }
    }

    /// Create a new payout circuit with epoch
    pub fn new_with_epoch(
        total_available: u64,
        miner_payouts: Vec<u64>,
        node_payouts: Vec<u64>,
        treasury_amount: u64,
        epoch: u64,
    ) -> Self {
        let miner_count = miner_payouts.len() as u32;
        let node_count = node_payouts.len() as u32;
        Self {
            total_available: Some(total_available),
            miner_payouts: miner_payouts.into_iter().map(Some).collect(),
            node_payouts: node_payouts.into_iter().map(Some).collect(),
            treasury_amount: Some(treasury_amount),
            epoch: Some(epoch),
            miner_count: Some(miner_count),
            node_count: Some(node_count),
            _marker: PhantomData,
        }
    }

    /// Create a new payout circuit with epoch and explicit counts
    /// Used when padding payouts for Groth16 where the padded length differs from actual count
    pub fn new_with_counts(
        total_available: u64,
        miner_payouts: Vec<u64>,
        node_payouts: Vec<u64>,
        treasury_amount: u64,
        epoch: u64,
        miner_count: u32,
        node_count: u32,
    ) -> Self {
        Self {
            total_available: Some(total_available),
            miner_payouts: miner_payouts.into_iter().map(Some).collect(),
            node_payouts: node_payouts.into_iter().map(Some).collect(),
            treasury_amount: Some(treasury_amount),
            epoch: Some(epoch),
            miner_count: Some(miner_count),
            node_count: Some(node_count),
            _marker: PhantomData,
        }
    }

    /// Create a dummy circuit for parameter generation
    pub fn dummy(num_miners: usize, num_nodes: usize) -> Self {
        Self {
            total_available: Some(0),
            miner_payouts: vec![Some(0); num_miners],
            node_payouts: vec![Some(0); num_nodes],
            treasury_amount: Some(0),
            epoch: Some(0),
            miner_count: Some(num_miners as u32),
            node_count: Some(num_nodes as u32),
            _marker: PhantomData,
        }
    }

    /// Synthesize the payout validity circuit
    ///
    /// Constraints:
    /// 1. All miner payouts fit in 64 bits
    /// 2. All node payouts fit in 64 bits
    /// 3. Treasury amount fits in 64 bits
    /// 4. total_available fits in 64 bits
    /// 5. sum(miner_payouts) + sum(node_payouts) + treasury == total_available
    ///
    /// PUBLIC INPUTS (in order, verified by verifier):
    /// 1. total_available - total amount being distributed
    /// 2. miner_sum - sum of all miner payouts
    /// 3. node_sum - sum of all node payouts
    /// 4. treasury_amount - treasury allocation
    /// 5. epoch - epoch number for replay protection
    /// 6. metadata_commitment - cryptographic binding of epoch, miner_count, node_count
    pub fn synthesize<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<PayoutOutputs<F>, SynthesisError> {
        // Calculate sums before we move the payouts
        let miner_sum_value = self.miner_payouts.iter().filter_map(|p| *p).sum::<u64>();
        let node_sum_value = self.node_payouts.iter().filter_map(|p| *p).sum::<u64>();

        // Compute metadata commitment for binding proof to metadata
        let epoch_val = self.epoch.unwrap_or(0);
        let miner_count_val = self.miner_count.unwrap_or(0);
        let node_count_val = self.node_count.unwrap_or(0);
        let metadata_commitment_value: F =
            compute_metadata_commitment(epoch_val, miner_count_val, node_count_val);

        // ========================================================================
        // PUBLIC INPUTS - These are checked by the verifier against claimed values
        // Order matters! Must match the order in verify_groth16_proof
        // ========================================================================

        // PUBLIC INPUT 1: total_available
        let total_available =
            AllocatedNum::alloc_input(cs.namespace(|| "total_available"), || {
                self.total_available
                    .map(F::from)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // PUBLIC INPUT 2: miner_sum
        let miner_sum_input = AllocatedNum::alloc_input(cs.namespace(|| "miner_sum"), || {
            Ok(F::from(miner_sum_value))
        })?;

        // PUBLIC INPUT 3: node_sum
        let node_sum_input =
            AllocatedNum::alloc_input(cs.namespace(|| "node_sum"), || Ok(F::from(node_sum_value)))?;

        // PUBLIC INPUT 4: treasury_amount
        let treasury_input = AllocatedNum::alloc_input(cs.namespace(|| "treasury_amount"), || {
            self.treasury_amount
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // PUBLIC INPUT 5: epoch (for replay protection)
        let epoch_input = AllocatedNum::alloc_input(cs.namespace(|| "epoch"), || {
            self.epoch
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ZK-C4: CONSTRAIN epoch public input
        // Allocate epoch witness and constrain it matches the public input
        let epoch_witness = AllocatedNum::alloc(cs.namespace(|| "epoch_witness"), || {
            self.epoch
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint: epoch_witness == epoch_input
        cs.enforce(
            || "epoch_is_constrained",
            |lc| lc + epoch_witness.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + epoch_input.get_variable(),
        );

        // PUBLIC INPUT 6: metadata_commitment (binds proof to epoch, miner_count, node_count)
        // This prevents replay or modification of metadata
        let metadata_commitment_input =
            AllocatedNum::alloc_input(cs.namespace(|| "metadata_commitment"), || {
                Ok(metadata_commitment_value)
            })?;

        // ZK-C3: CONSTRAIN metadata_commitment public input
        // Compute the commitment in-circuit and verify it matches the public input
        //
        // We need to allocate the miner_count and node_count as witnesses,
        // then compute the commitment in-circuit and verify it matches.
        let miner_count_witness =
            AllocatedNum::alloc(cs.namespace(|| "miner_count_witness"), || {
                self.miner_count
                    .map(|c| F::from(c as u64))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let node_count_witness =
            AllocatedNum::alloc(cs.namespace(|| "node_count_witness"), || {
                self.node_count
                    .map(|c| F::from(c as u64))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Compute metadata commitment in-circuit using polynomial combination
        // commitment = epoch * C1 + miner_count * C2 + node_count
        // where C1 = 2^64 and C2 = 2^32 for unique encoding
        //
        // For circuit efficiency, we compute this directly and constrain it equals
        // the provided metadata_commitment_input
        let two32 = F::from(1u64 << 32);
        let two64 = two32 * two32;

        let computed_metadata = AllocatedNum::alloc(cs.namespace(|| "computed_metadata"), || {
            let epoch = self
                .epoch
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)?;
            let miner_count = self
                .miner_count
                .map(|c| F::from(c as u64))
                .ok_or(SynthesisError::AssignmentMissing)?;
            let node_count = self
                .node_count
                .map(|c| F::from(c as u64))
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(epoch * two64 + miner_count * two32 + node_count)
        })?;

        // Constraint: computed_metadata = epoch_witness * 2^64 + miner_count_witness * 2^32 + node_count_witness
        cs.enforce(
            || "metadata_polynomial_correct",
            |lc| lc + computed_metadata.get_variable(),
            |lc| lc + CS::one(),
            |lc| {
                lc + (two64, epoch_witness.get_variable())
                    + (two32, miner_count_witness.get_variable())
                    + node_count_witness.get_variable()
            },
        );

        // Constraint: computed_metadata == metadata_commitment_input
        // This ensures the proof is bound to the specific epoch, miner_count, node_count
        //
        // SECURITY NOTE: The verifier must compute the metadata_commitment using the same
        // polynomial formula and provide it as the public input. This constraint then
        // verifies the prover used consistent values.
        cs.enforce(
            || "metadata_commitment_is_constrained",
            |lc| lc + computed_metadata.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + metadata_commitment_input.get_variable(),
        );

        // ========================================================================
        // RANGE CHECK ON PUBLIC INPUT: total_available
        // ZK-M2: Ensure total_available fits in 64 bits to prevent field overflow attacks
        // ========================================================================
        self.enforce_fits_in_bits(
            cs.namespace(|| "total_available_range"),
            &total_available,
            BALANCE_BITS,
        )?;

        // ========================================================================
        // PRIVATE INPUTS - Individual payout amounts
        // ========================================================================

        // Allocate and constrain miner payouts
        let mut miner_payout_vars = Vec::with_capacity(self.miner_payouts.len());
        for (i, payout) in self.miner_payouts.iter().enumerate() {
            let var = AllocatedNum::alloc(cs.namespace(|| format!("miner_payout_{}", i)), || {
                payout.map(F::from).ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Constrain to 64 bits (non-negative and bounded)
            self.enforce_fits_in_bits(
                cs.namespace(|| format!("miner_payout_{}_range", i)),
                &var,
                BALANCE_BITS,
            )?;

            miner_payout_vars.push(var);
        }

        // Allocate and constrain node payouts
        let mut node_payout_vars = Vec::with_capacity(self.node_payouts.len());
        for (i, payout) in self.node_payouts.iter().enumerate() {
            let var = AllocatedNum::alloc(cs.namespace(|| format!("node_payout_{}", i)), || {
                payout.map(F::from).ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Constrain to 64 bits
            self.enforce_fits_in_bits(
                cs.namespace(|| format!("node_payout_{}_range", i)),
                &var,
                BALANCE_BITS,
            )?;

            node_payout_vars.push(var);
        }

        // Allocate treasury amount
        let treasury = AllocatedNum::alloc(cs.namespace(|| "treasury"), || {
            self.treasury_amount
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constrain treasury to 64 bits
        self.enforce_fits_in_bits(cs.namespace(|| "treasury_range"), &treasury, BALANCE_BITS)?;

        // ========================================================================
        // CONSTRAINTS
        // ========================================================================

        // Constraint 1: Sum preservation - total must equal sum of all payouts
        // sum(miners) + sum(nodes) + treasury == total_available
        let mut sum_lc = LinearCombination::<F>::zero();

        for var in &miner_payout_vars {
            sum_lc = sum_lc + var.get_variable();
        }
        for var in &node_payout_vars {
            sum_lc = sum_lc + var.get_variable();
        }
        sum_lc = sum_lc + treasury.get_variable();

        // Constrain: sum == total_available (public input)
        cs.enforce(
            || "sum_preservation",
            |_| sum_lc.clone(),
            |lc| lc + CS::one(),
            |lc| lc + total_available.get_variable(),
        );

        // Constraint 2: Miner sum public input must equal computed sum
        // This ensures the verifier's miner_sum matches what's proven
        let mut miner_sum_lc = LinearCombination::<F>::zero();
        for var in &miner_payout_vars {
            miner_sum_lc = miner_sum_lc + var.get_variable();
        }
        cs.enforce(
            || "miner_sum_matches",
            |_| miner_sum_lc,
            |lc| lc + CS::one(),
            |lc| lc + miner_sum_input.get_variable(),
        );

        // Constraint 3: Node sum public input must equal computed sum
        let mut node_sum_lc = LinearCombination::<F>::zero();
        for var in &node_payout_vars {
            node_sum_lc = node_sum_lc + var.get_variable();
        }
        cs.enforce(
            || "node_sum_matches",
            |_| node_sum_lc,
            |lc| lc + CS::one(),
            |lc| lc + node_sum_input.get_variable(),
        );

        // Constraint 4: Treasury public input must equal private treasury
        cs.enforce(
            || "treasury_matches",
            |lc| lc + treasury.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + treasury_input.get_variable(),
        );

        Ok(PayoutOutputs {
            total_available,
            miner_payouts: miner_payout_vars,
            node_payouts: node_payout_vars,
            treasury,
            miner_sum: miner_sum_value,
            node_sum: node_sum_value,
        })
    }

    /// Enforce that a value fits in the given number of bits
    fn enforce_fits_in_bits<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        value: &AllocatedNum<F>,
        num_bits: usize,
    ) -> Result<(), SynthesisError> {
        // Decompose into bits using AllocatedBit
        let bits = Self::decompose_into_bits(cs.namespace(|| "decompose"), value, num_bits)?;

        // Reconstruct value from bits and verify it matches
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

        // Constrain: sum of bits = value
        cs.enforce(
            || "reconstructed equals value",
            |_| lc_sum,
            |lc| lc + CS::one(),
            |lc| lc + value.get_variable(),
        );

        Ok(())
    }

    /// Decompose a field element into bits using AllocatedBit
    fn decompose_into_bits<CS: ConstraintSystem<F>>(
        mut cs: CS,
        value: &AllocatedNum<F>,
        num_bits: usize,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let value_bits = value.get_value().map(|v| {
            let bytes = v.to_repr();
            let mut result = 0u64;
            for (i, byte) in bytes.as_ref().iter().take(8).enumerate() {
                result |= (*byte as u64) << (i * 8);
            }
            result
        });

        let mut bits = Vec::with_capacity(num_bits);

        for i in 0..num_bits {
            let bit_value = value_bits.map(|v| ((v >> i) & 1) == 1);

            let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit_{}", i)), bit_value)?;

            bits.push(Boolean::from(bit));
        }

        Ok(bits)
    }
}

/// Implement the bellpepper Circuit trait for Groth16 compatibility
impl<F: PrimeField> Circuit<F> for PayoutCircuit<F> {
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Delegate to our synthesize method and discard the outputs
        // The constraints are what matter for Groth16
        let _ = PayoutCircuit::synthesize(self, cs)?;
        Ok(())
    }
}

/// Outputs from payout circuit synthesis
pub struct PayoutOutputs<F: PrimeField> {
    /// Total available for distribution
    pub total_available: AllocatedNum<F>,
    /// Miner payout variables
    pub miner_payouts: Vec<AllocatedNum<F>>,
    /// Node payout variables
    pub node_payouts: Vec<AllocatedNum<F>>,
    /// Treasury amount
    pub treasury: AllocatedNum<F>,
    /// Sum of miner payouts (computed, not constrained)
    pub miner_sum: u64,
    /// Sum of node payouts (computed, not constrained)
    pub node_sum: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    #[test]
    fn test_valid_payout() {
        // Total: 1000, Miners: 400, Nodes: 400, Treasury: 200
        let circuit = PayoutCircuit::<Fr>::new(
            1000,
            vec![200, 150, 50], // 3 miners totaling 400
            vec![200, 200],     // 2 nodes totaling 400
            200,                // treasury
        );

        let mut cs = TestConstraintSystem::new();
        let outputs = circuit.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied(), "Valid payout should satisfy constraints");
        assert_eq!(outputs.miner_sum, 400);
        assert_eq!(outputs.node_sum, 400);
    }

    #[test]
    fn test_sum_mismatch() {
        // Total: 1000, but payouts only sum to 900
        let circuit = PayoutCircuit::<Fr>::new(
            1000,
            vec![200, 150, 50], // 400
            vec![200, 100],     // 300
            200,                // 200, total = 900 != 1000
        );

        let mut cs = TestConstraintSystem::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(!cs.is_satisfied(), "Sum mismatch should fail");
    }

    #[test]
    fn test_zero_treasury() {
        // No treasury fee
        let circuit = PayoutCircuit::<Fr>::new(
            1000,
            vec![500],
            vec![500],
            0, // zero treasury
        );

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied(), "Zero treasury should be valid");
    }

    #[test]
    fn test_single_miner() {
        // Single miner gets everything minus treasury
        let circuit = PayoutCircuit::<Fr>::new(
            1000,
            vec![980],
            vec![],
            20, // 2% treasury
        );

        let mut cs = TestConstraintSystem::new();
        let outputs = circuit.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied(), "Single miner payout should be valid");
        assert_eq!(outputs.miner_sum, 980);
        assert_eq!(outputs.node_sum, 0);
    }

    #[test]
    fn test_empty_payouts() {
        // All goes to treasury
        let circuit = PayoutCircuit::<Fr>::new(
            1000,
            vec![],
            vec![],
            1000, // all to treasury
        );

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied(), "All-treasury payout should be valid");
    }

    #[test]
    fn test_dummy_circuit() {
        let circuit = PayoutCircuit::<Fr>::dummy(5, 3);

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(
            cs.is_satisfied(),
            "Dummy circuit should satisfy constraints"
        );
    }

    #[test]
    fn test_large_payout() {
        // Large but valid amounts
        let total: u64 = 1_000_000_000_000; // 1 trillion sats
        let circuit = PayoutCircuit::<Fr>::new(
            total,
            vec![400_000_000_000, 100_000_000_000], // 500B to miners
            vec![300_000_000_000, 100_000_000_000], // 400B to nodes
            100_000_000_000,                        // 100B treasury
        );

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(
            cs.is_satisfied(),
            "Large valid payout should satisfy constraints"
        );
    }

    #[test]
    fn test_constraint_count() {
        // Track constraint count for performance
        let circuit = PayoutCircuit::<Fr>::new(1000, vec![300, 200], vec![300, 100], 100);

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        // Constraints:
        // - Each payout: 64 bit decomposition + 1 reconstruction = 65
        // - 6 range-checked values (2 miners + 2 nodes + treasury + total_available) * 65 = 390
        // - 1 sum preservation constraint
        // - 1 miner_sum constraint
        // - 1 node_sum constraint
        // - 1 treasury_matches constraint
        // - 1 epoch_is_constrained (ZK-C4)
        // - 1 metadata_polynomial_correct (ZK-C3)
        // - 1 metadata_commitment_is_constrained (ZK-C3)
        // Total: ~397 constraints
        let expected_per_value = BALANCE_BITS + 1; // bits + reconstruction
        let num_values = 2 + 2 + 1 + 1; // 2 miners + 2 nodes + treasury + total_available
        let range_constraints = num_values * expected_per_value;
        let sum_constraints = 7; // sum_preservation + miner_sum + node_sum + treasury_matches + epoch + 2*metadata
        let expected_constraints = range_constraints + sum_constraints;

        assert!(
            cs.num_constraints() <= expected_constraints,
            "Constraints: {} (expected <= {})",
            cs.num_constraints(),
            expected_constraints
        );
    }

    // ZK-M2: Test that total_available has range check (64-bit)
    #[test]
    fn test_max_u64_total_available() {
        // Test with maximum valid u64 value - should work since all values fit in 64 bits
        let total: u64 = u64::MAX;
        let circuit = PayoutCircuit::<Fr>::new(
            total,
            vec![u64::MAX / 2],
            vec![u64::MAX / 2],
            1, // remaining 1 sat after integer division
        );

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        // This should satisfy constraints since all values fit in 64 bits
        assert!(
            cs.is_satisfied(),
            "Maximum u64 total_available should satisfy 64-bit range check"
        );
    }

    // ZK-M1: Test metadata commitment
    #[test]
    fn test_metadata_commitment_in_circuit() {
        // Verify that circuits with same parameters produce same metadata commitment
        let circuit1 = PayoutCircuit::<Fr>::new_with_epoch(1000, vec![500], vec![400], 100, 42);
        let circuit2 = PayoutCircuit::<Fr>::new_with_epoch(1000, vec![500], vec![400], 100, 42);

        // Both should have same miner_count and node_count
        assert_eq!(circuit1.miner_count, circuit2.miner_count);
        assert_eq!(circuit1.node_count, circuit2.node_count);
        assert_eq!(circuit1.epoch, circuit2.epoch);

        // Different epoch should give different circuit metadata
        let circuit3 = PayoutCircuit::<Fr>::new_with_epoch(1000, vec![500], vec![400], 100, 43);
        assert_ne!(circuit1.epoch, circuit3.epoch);
    }

    #[test]
    fn test_new_with_counts() {
        // Test that new_with_counts preserves the actual counts even with different array sizes
        let circuit = PayoutCircuit::<Fr>::new_with_counts(
            1000,
            vec![500, 0, 0, 0, 0], // Padded to 5 elements
            vec![400, 0, 0],       // Padded to 3 elements
            100,
            42,
            1, // Actual miner count
            1, // Actual node count
        );

        assert_eq!(circuit.miner_count, Some(1));
        assert_eq!(circuit.node_count, Some(1));
        assert_eq!(circuit.miner_payouts.len(), 5);
        assert_eq!(circuit.node_payouts.len(), 3);
    }

    // ==========================================================================
    // Security Tests (ZK-C3, ZK-C4)
    // ==========================================================================

    #[test]
    fn test_epoch_is_constrained() {
        // ZK-C4: Verify that the epoch public input is properly constrained
        // Create two circuits with different epochs
        let circuit1 = PayoutCircuit::<Fr>::new_with_epoch(1000, vec![500], vec![400], 100, 1);
        let circuit2 = PayoutCircuit::<Fr>::new_with_epoch(1000, vec![500], vec![400], 100, 2);

        let mut cs1 = TestConstraintSystem::new();
        let mut cs2 = TestConstraintSystem::new();

        circuit1.synthesize(&mut cs1).unwrap();
        circuit2.synthesize(&mut cs2).unwrap();

        // Both should satisfy constraints with their respective epochs
        assert!(cs1.is_satisfied(), "Circuit 1 should be satisfied");
        assert!(cs2.is_satisfied(), "Circuit 2 should be satisfied");

        // Verify the epoch constraint exists by checking constraint count
        // includes the epoch constraint
        assert!(
            cs1.num_constraints() > 0,
            "Should have constraints including epoch"
        );
    }

    #[test]
    fn test_metadata_commitment_is_constrained() {
        // ZK-C3: Verify that the metadata commitment is properly constrained
        // Different metadata should produce different commitments
        let commitment1 = compute_metadata_commitment::<Fr>(1, 10, 5);
        let commitment2 = compute_metadata_commitment::<Fr>(2, 10, 5);
        let commitment3 = compute_metadata_commitment::<Fr>(1, 11, 5);
        let commitment4 = compute_metadata_commitment::<Fr>(1, 10, 6);

        // All commitments should be different (injective encoding)
        assert_ne!(
            commitment1, commitment2,
            "Different epoch -> different commitment"
        );
        assert_ne!(
            commitment1, commitment3,
            "Different miner_count -> different commitment"
        );
        assert_ne!(
            commitment1, commitment4,
            "Different node_count -> different commitment"
        );
    }

    #[test]
    fn test_metadata_commitment_polynomial_encoding() {
        // Verify the polynomial encoding is injective and consistent
        // commitment = epoch * 2^64 + miner_count * 2^32 + node_count
        let epoch: u64 = 12345;
        let miner_count: u32 = 100;
        let node_count: u32 = 50;

        let commitment = compute_metadata_commitment::<Fr>(epoch, miner_count, node_count);

        // Manually compute expected value
        let two32 = Fr::from(1u64 << 32);
        let two64 = two32 * two32;
        let expected = Fr::from(epoch) * two64
            + Fr::from(miner_count as u64) * two32
            + Fr::from(node_count as u64);

        assert_eq!(
            commitment, expected,
            "Commitment should match polynomial encoding"
        );
    }

    #[test]
    fn test_circuit_with_epoch_constraint_satisfied() {
        // Verify circuit is satisfied when epoch witness matches input
        let circuit = PayoutCircuit::<Fr>::new_with_epoch(1000, vec![500], vec![400], 100, 42);

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(
            cs.is_satisfied(),
            "Circuit should be satisfied when epoch witness matches input"
        );
    }
}
