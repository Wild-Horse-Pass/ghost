//! Payment validity circuit
//!
//! Proves that a single payment is valid:
//! 1. Sender has sufficient balance
//! 2. Balance updates are correct (sender -= amount, recipient += amount)
//! 3. No overflow in recipient balance

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use std::marker::PhantomData;

use super::BALANCE_BITS;

/// Circuit proving a single payment is valid
pub struct PaymentCircuit<F: PrimeField> {
    /// Sender's balance before payment (private)
    pub sender_balance_before: Option<u64>,
    /// Recipient's balance before payment (private)
    pub recipient_balance_before: Option<u64>,
    /// Payment amount (private)
    pub amount: Option<u64>,
    /// Sender's balance after payment (private, computed)
    pub sender_balance_after: Option<u64>,
    /// Recipient's balance after payment (private, computed)
    pub recipient_balance_after: Option<u64>,
    /// Phantom data to satisfy the type parameter
    _marker: PhantomData<F>,
}

/// Error type for payment circuit creation
#[derive(Debug, Clone)]
pub enum PaymentCircuitError {
    /// Sender has insufficient balance (underflow)
    SenderBalanceUnderflow { balance: u64, amount: u64 },
    /// Recipient balance would overflow
    RecipientBalanceOverflow { balance: u64, amount: u64 },
}

impl std::fmt::Display for PaymentCircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SenderBalanceUnderflow { balance, amount } => {
                write!(f, "Sender balance underflow: {} - {} would be negative", balance, amount)
            }
            Self::RecipientBalanceOverflow { balance, amount } => {
                write!(f, "Recipient balance overflow: {} + {} exceeds u64::MAX", balance, amount)
            }
        }
    }
}

impl std::error::Error for PaymentCircuitError {}

impl<F: PrimeField> PaymentCircuit<F> {
    /// Create a new payment circuit
    /// Returns an error if the payment would cause overflow or underflow
    pub fn new(
        sender_balance_before: Option<u64>,
        recipient_balance_before: Option<u64>,
        amount: Option<u64>,
    ) -> Result<Self, PaymentCircuitError> {
        let sender_balance_after = match (sender_balance_before, amount) {
            (Some(b), Some(a)) => Some(b.checked_sub(a).ok_or(
                PaymentCircuitError::SenderBalanceUnderflow { balance: b, amount: a }
            )?),
            _ => None,
        };

        let recipient_balance_after = match (recipient_balance_before, amount) {
            (Some(b), Some(a)) => Some(b.checked_add(a).ok_or(
                PaymentCircuitError::RecipientBalanceOverflow { balance: b, amount: a }
            )?),
            _ => None,
        };

        Ok(Self {
            sender_balance_before,
            recipient_balance_before,
            amount,
            sender_balance_after,
            recipient_balance_after,
            _marker: PhantomData,
        })
    }

    /// Create a dummy circuit for parameter generation
    /// Uses zero values to allow synthesis without errors
    pub fn dummy() -> Self {
        Self {
            sender_balance_before: Some(0),
            recipient_balance_before: Some(0),
            amount: Some(0),
            sender_balance_after: Some(0),
            recipient_balance_after: Some(0),
            _marker: PhantomData,
        }
    }

    /// Synthesize the payment validity circuit
    ///
    /// Constraints:
    /// 1. sender_balance_before >= amount (sufficient balance)
    /// 2. sender_balance_after = sender_balance_before - amount
    /// 3. recipient_balance_after = recipient_balance_before + amount
    /// 4. recipient_balance_after >= recipient_balance_before (no overflow)
    pub fn synthesize<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<PaymentOutputs<F>, SynthesisError> {
        // Allocate private inputs
        let sender_before = AllocatedNum::alloc(cs.namespace(|| "sender_balance_before"), || {
            self.sender_balance_before
                .map(|b| F::from(b))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let recipient_before =
            AllocatedNum::alloc(cs.namespace(|| "recipient_balance_before"), || {
                self.recipient_balance_before
                    .map(|b| F::from(b))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let amount = AllocatedNum::alloc(cs.namespace(|| "amount"), || {
            self.amount
                .map(|a| F::from(a))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate computed outputs
        let sender_after = AllocatedNum::alloc(cs.namespace(|| "sender_balance_after"), || {
            self.sender_balance_after
                .map(|b| F::from(b))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let recipient_after =
            AllocatedNum::alloc(cs.namespace(|| "recipient_balance_after"), || {
                self.recipient_balance_after
                    .map(|b| F::from(b))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Constraint 1: sender_balance_before >= amount
        // Proved by showing (sender_balance_before - amount) is non-negative
        // We do this via range proof on sender_after
        self.enforce_non_negative(cs.namespace(|| "sender_has_funds"), &sender_after)?;

        // Constraint 2: sender_after = sender_before - amount
        // Rearranged: sender_before = sender_after + amount
        cs.enforce(
            || "sender_subtraction",
            |lc| lc + sender_after.get_variable() + amount.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + sender_before.get_variable(),
        );

        // Constraint 3: recipient_after = recipient_before + amount
        cs.enforce(
            || "recipient_addition",
            |lc| lc + recipient_before.get_variable() + amount.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + recipient_after.get_variable(),
        );

        // Constraint 4: No overflow - recipient_after >= recipient_before
        // Proved by showing (recipient_after - recipient_before) = amount is non-negative
        // Since amount is already constrained to be <= sender_before (which is bounded),
        // and we're adding to recipient, we need to ensure recipient_after fits in BALANCE_BITS
        self.enforce_fits_in_bits(
            cs.namespace(|| "recipient_no_overflow"),
            &recipient_after,
            BALANCE_BITS,
        )?;

        Ok(PaymentOutputs {
            sender_after,
            recipient_after,
        })
    }

    /// Enforce that a value is non-negative by decomposing into bits
    fn enforce_non_negative<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        value: &AllocatedNum<F>,
    ) -> Result<(), SynthesisError> {
        self.enforce_fits_in_bits(cs.namespace(|| "non_negative"), value, BALANCE_BITS)
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
        // sum = sum(bit_i * 2^i) for i in 0..num_bits
        // We build this incrementally using linear combinations

        let mut coeff = F::ONE;
        let mut lc_sum = LinearCombination::<F>::zero();

        for bit in bits.iter() {
            match bit {
                Boolean::Is(ref b) => {
                    lc_sum = lc_sum + (coeff, b.get_variable());
                }
                Boolean::Not(ref b) => {
                    // Not(b) = 1 - b, so contribution is coeff * (1 - b) = coeff - coeff * b
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
            // Convert field element to u64 (assuming it fits)
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

            // Use AllocatedBit which has built-in boolean constraint
            let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit_{}", i)), bit_value)?;

            bits.push(Boolean::from(bit));
        }

        Ok(bits)
    }
}

/// Outputs from payment circuit synthesis
pub struct PaymentOutputs<F: PrimeField> {
    /// Sender's balance after payment
    pub sender_after: AllocatedNum<F>,
    /// Recipient's balance after payment
    pub recipient_after: AllocatedNum<F>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    #[test]
    fn test_valid_payment() {
        let circuit = PaymentCircuit::<Fr>::new(
            Some(100), // sender has 100
            Some(50),  // recipient has 50
            Some(30),  // sending 30
        ).expect("Valid payment should create circuit");

        let mut cs = TestConstraintSystem::new();
        let outputs = circuit.synthesize(&mut cs).unwrap();

        assert!(
            cs.is_satisfied(),
            "Valid payment should satisfy constraints"
        );

        // Check computed values
        let sender_after = outputs.sender_after.get_value().unwrap();
        let recipient_after = outputs.recipient_after.get_value().unwrap();

        assert_eq!(sender_after, Fr::from(70u64)); // 100 - 30
        assert_eq!(recipient_after, Fr::from(80u64)); // 50 + 30
    }

    #[test]
    fn test_sender_underflow_detection() {
        // Circuit creation should fail with insufficient balance
        let result = PaymentCircuit::<Fr>::new(
            Some(20), // sender only has 20
            Some(50),
            Some(30), // trying to send 30
        );

        assert!(
            matches!(result, Err(PaymentCircuitError::SenderBalanceUnderflow { .. })),
            "Insufficient balance should return SenderBalanceUnderflow error"
        );
    }

    #[test]
    fn test_recipient_overflow_detection() {
        // Circuit creation should fail when recipient balance would overflow
        let result = PaymentCircuit::<Fr>::new(
            Some(u64::MAX),
            Some(1),      // recipient has 1
            Some(u64::MAX), // trying to add u64::MAX would overflow
        );

        assert!(
            matches!(result, Err(PaymentCircuitError::RecipientBalanceOverflow { .. })),
            "Overflow should return RecipientBalanceOverflow error"
        );
    }

    #[test]
    fn test_exact_balance() {
        let circuit = PaymentCircuit::<Fr>::new(
            Some(100), // sender has exactly 100
            Some(0),
            Some(100), // sending all 100
        ).expect("Exact balance should create circuit");

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(
            cs.is_satisfied(),
            "Exact balance payment should satisfy constraints"
        );
    }

    #[test]
    fn test_zero_amount() {
        let circuit = PaymentCircuit::<Fr>::new(
            Some(100),
            Some(50),
            Some(0), // zero amount
        ).expect("Zero amount should create circuit");

        let mut cs = TestConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied(), "Zero amount should satisfy constraints");
    }
}
