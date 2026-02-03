# Ghost ZKP Trusted Setup Requirements

## Overview

Ghost's zero-knowledge proof system uses Groth16, which requires a **trusted setup ceremony**. This document explains why this matters and how to conduct a secure setup.

## Why Trusted Setup Matters

Groth16 proofs require circuit-specific parameters generated through a process called "trusted setup". During setup, random values (called "toxic waste") are used to generate the proving and verifying keys.

**CRITICAL SECURITY PROPERTY**: If anyone knows the toxic waste, they can forge proofs for any statement, completely breaking the ZK system's security.

## The Problem with Random Setup

The function `generate_random_parameters()` in bellperson:
1. Generates toxic waste in memory
2. Uses it to create parameters
3. The toxic waste may persist in memory, swap, or core dumps

This is **acceptable for testing** but **catastrophic for production**:
- Memory could be read by other processes
- Core dumps could expose the values
- The toxic waste could be extracted through side channels

## Multi-Party Computation (MPC) Ceremony

The solution is a **Multi-Party Computation ceremony** where:

1. **Multiple independent parties** each contribute randomness
2. Each party's contribution is **combined cryptographically**
3. The toxic waste is **never reconstructed** by any single party
4. As long as **at least one party is honest**, the setup is secure

### Ceremony Requirements

For Ghost's payout verification circuit:

1. **Minimum Participants**: At least 10 independent parties
2. **Geographic Distribution**: Participants from different jurisdictions
3. **Hardware Diversity**: Different hardware to prevent correlated failures
4. **Transcript Publication**: Full ceremony transcript must be public
5. **Verification**: Anyone can verify the transcript is valid

### Ceremony Process

1. **Phase 1 (Powers of Tau)**
   - Universal ceremony for BLS12-381 curve
   - Can reuse existing ceremonies (e.g., Filecoin, Zcash)
   - Produces curve-wide parameters

2. **Phase 2 (Circuit-Specific)**
   - Specific to Ghost's PayoutCircuit
   - Must be conducted for each circuit version
   - Produces proving and verifying keys

### Using Existing Ceremonies

Ghost can leverage existing Powers of Tau ceremonies:

- **Filecoin**: Large-scale ceremony with 100+ participants
- **Hermez**: Well-audited ceremony process
- **Perpetual Powers of Tau**: Ongoing ceremony accepting contributions

## Implementation Checklist

### Before Production Deployment

- [ ] Conduct or adopt a Phase 1 ceremony
- [ ] Conduct Phase 2 ceremony for PayoutCircuit
- [ ] Publish full ceremony transcript
- [ ] Have transcript independently verified
- [ ] Store parameters in version control with checksums
- [ ] Remove all `new_with_setup()` calls from production code
- [ ] Use `new_with_params()` with ceremony-generated parameters

### Parameter Distribution

Verifying keys should be:
1. Embedded in validator binaries
2. Distributed via secure channels
3. Verified against known checksums
4. Pinned in configuration files

## Code Changes for Production

Replace testing code:
```rust
// TESTING ONLY - DO NOT USE IN PRODUCTION
let prover = PayoutProver::new_with_setup(100, 50)?;
```

With production code:
```rust
// Load MPC-generated parameters
let params = load_mpc_parameters("path/to/params")?;
let prover = PayoutProver::new_with_params(params)?;
```

## Verification

After setup, verify:

1. **Transcript completeness**: All contributions recorded
2. **Cryptographic validity**: Each contribution is valid
3. **Randomness quality**: Contributions contain sufficient entropy
4. **No tampering**: Hash chain is unbroken

## References

- [Groth16 Paper](https://eprint.iacr.org/2016/260)
- [Zcash Ceremony](https://www.zfnd.org/blog/conclusion-of-powers-of-tau/)
- [Filecoin Ceremony](https://github.com/filecoin-project/phase2-attestations)
- [Perpetual Powers of Tau](https://github.com/weijiekoh/perpetualpowersoftau)

## Contact

For questions about Ghost's trusted setup ceremony, contact the core team.
