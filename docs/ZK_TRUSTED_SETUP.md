```
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
//| FILE: ZK_TRUSTED_SETUP.md                                                                                            |
//|======================================================================================================================|
```

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

For Ghost's ZK circuits (GhostNoteSpendCircuit, NoteConsolidateCircuit, and GhostUnshieldCircuit):

1. **Minimum Participants**: At least 10 independent parties (Ghost supports up to 101)
2. **Geographic Distribution**: Participants from different jurisdictions
3. **Hardware Diversity**: Different hardware to prevent correlated failures
4. **Transcript Publication**: Full ceremony transcript must be public
5. **Verification**: Anyone can verify the transcript is valid

### Ceremony Process

Ghost implements a **rolling MPC ceremony** (not a one-time event):

1. **Phase 1 (Powers of Tau)**
   - Universal ceremony for BLS12-381 curve
   - Can reuse existing ceremonies (e.g., Filecoin, Zcash)
   - Produces curve-wide parameters

2. **Phase 2 (Circuit-Specific)**
   - Covers all 3 circuits: GhostNoteSpendCircuit (~12,675 constraints), NoteConsolidateCircuit (~2,500 constraints), and GhostUnshieldCircuit (~6,300 constraints)
   - Uses dummy circuit instantiation for parameter generation (~3-4 seconds per contribution)
   - The first 101 contributors become Elders (+1 share)
   - Parameters ossify permanently after 101 contributions

### Using Existing Ceremonies

Ghost can leverage existing Powers of Tau ceremonies:

- **Filecoin**: Large-scale ceremony with 100+ participants
- **Hermez**: Well-audited ceremony process
- **Perpetual Powers of Tau**: Ongoing ceremony accepting contributions

## Implementation Checklist

### Before Production Deployment

- [x] Rolling MPC ceremony implemented (up to 101 contributors)
- [x] All 3 circuit dummies with depth 20:
  - [x] Slot 1: `GhostNoteSpendCircuit::dummy(20)` — ~12,675 constraints → `note_spend_vk.bin`
  - [x] Slot 2: `NoteConsolidateCircuit::dummy(20)` — ~2,500 constraints → `payout_vk.bin`
  - [x] Slot 3: `GhostUnshieldCircuit::dummy(20)` — ~6,300 constraints → `unshield_vk.bin`
- [x] Toxic waste zeroed automatically via `ZeroizeOnDrop`
- [x] Parameters stored in `~/.ghost/mpc_params/` with versioned files
- [x] P2P contributor sync via `/api/v1/mpc/contributors`
- [ ] Publish full ceremony transcript for mainnet
- [ ] Have transcript independently verified

### Parameter Distribution

Verifying keys should be:
1. Embedded in validator binaries
2. Distributed via secure channels
3. Verified against known checksums
4. Pinned in configuration files

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
