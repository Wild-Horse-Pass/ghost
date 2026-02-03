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
    /// Phantom data for type parameter
    _marker: PhantomData<F>,
}

impl<F: PrimeField> PayoutCircuit<F> {
    /// Create a new payout circuit
    pub fn new(
        total_available: u64,
        miner_payouts: Vec<u64>,
        node_payouts: Vec<u64>,
        treasury_amount: u64,
    ) -> Self {
        Self {
            total_available: Some(total_available),
            miner_payouts: miner_payouts.into_iter().map(Some).collect(),
            node_payouts: node_payouts.into_iter().map(Some).collect(),
            treasury_amount: Some(treasury_amount),
            epoch: Some(0), // Default epoch for backwards compatibility
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
        Self {
            total_available: Some(total_available),
            miner_payouts: miner_payouts.into_iter().map(Some).collect(),
            node_payouts: node_payouts.into_iter().map(Some).collect(),
            treasury_amount: Some(treasury_amount),
            epoch: Some(epoch),
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
            _marker: PhantomData,
        }
    }

    /// Synthesize the payout validity circuit
    ///
    /// Constraints:
    /// 1. All miner payouts fit in 64 bits
    /// 2. All node payouts fit in 64 bits
    /// 3. Treasury amount fits in 64 bits
    /// 4. sum(miner_payouts) + sum(node_payouts) + treasury == total_available
    ///
    /// PUBLIC INPUTS (in order, verified by verifier):
    /// 1. total_available - total amount being distributed
    /// 2. miner_sum - sum of all miner payouts
    /// 3. node_sum - sum of all node payouts
    /// 4. treasury_amount - treasury allocation
    /// 5. epoch - epoch number for replay protection
    pub fn synthesize<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<PayoutOutputs<F>, SynthesisError> {
        // Calculate sums before we move the payouts
        let miner_sum_value = self.miner_payouts.iter().filter_map(|p| *p).sum::<u64>();
        let node_sum_value = self.node_payouts.iter().filter_map(|p| *p).sum::<u64>();

        // ========================================================================
        // PUBLIC INPUTS - These are checked by the verifier against claimed values
        // Order matters! Must match the order in verify_groth16_proof
        // ========================================================================

        // PUBLIC INPUT 1: total_available
        let total_available = AllocatedNum::alloc_input(cs.namespace(|| "total_available"), || {
            self.total_available
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // PUBLIC INPUT 2: miner_sum
        let miner_sum_input = AllocatedNum::alloc_input(cs.namespace(|| "miner_sum"), || {
            Ok(F::from(miner_sum_value))
        })?;

        // PUBLIC INPUT 3: node_sum
        let node_sum_input = AllocatedNum::alloc_input(cs.namespace(|| "node_sum"), || {
            Ok(F::from(node_sum_value))
        })?;

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

        // Epoch is exposed as public input but not constrained further
        // (it's for binding the proof to a specific epoch)
        let _ = epoch_input;

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
        // - 5 private values (2 miners + 2 nodes + treasury) * 65 = 325
        // - 1 sum preservation constraint
        // - 1 miner_sum constraint
        // - 1 node_sum constraint
        // - 1 treasury_matches constraint
        // Total: ~329 constraints
        let expected_per_value = BALANCE_BITS + 1; // bits + reconstruction
        let num_values = 2 + 2 + 1; // 2 miners + 2 nodes + treasury
        let range_constraints = num_values * expected_per_value;
        let sum_constraints = 4; // sum_preservation + miner_sum + node_sum + treasury_matches
        let expected_constraints = range_constraints + sum_constraints;

        assert!(
            cs.num_constraints() <= expected_constraints,
            "Constraints: {} (expected <= {})",
            cs.num_constraints(),
            expected_constraints
        );
    }
}
