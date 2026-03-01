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
//| FILE: ZK_PROOFS.md                                                                                                   |
//|======================================================================================================================|
```

# ZK Proofs

Zero-knowledge proofs in Ghost Pay for privacy-preserving validation.

## Overview

Ghost Pay uses Zero-Knowledge proofs to enable:
- Private transfers (prove validity without revealing amounts)
- Balance verification (prove sufficient funds without revealing total)
- Settlement batching (prove batch correctness without revealing individual transactions)
- Wraith mixing (additional privacy layer)

## What is a ZK Proof?

A zero-knowledge proof allows someone to prove a statement is true without revealing any information beyond the statement's validity.

**Example**: Prove you have ≥1 BTC without revealing your exact balance.

```
Statement: "I have at least 1 BTC"
Proof: ZK proof that validates this statement
Verifier: Can confirm statement is true
          BUT learns nothing about actual balance
```

## ZK System: Groth16 SNARKs

Ghost Pay uses **Groth16** SNARKs (Succinct Non-interactive ARguments of Knowledge):

| Property | Value |
|----------|-------|
| Proof size | 192 bytes (constant) |
| Verification time | ~5ms (GhostNoteSpendCircuit) |
| Proving time | ~170ms (GhostNoteSpendCircuit, sender-side) |
| Hash function | MiMC (82 rounds, ≥128-bit security) |
| Setup | Rolling MPC ceremony (up to 101 contributors) |

### Why Groth16?

- **Succinct**: Small proof size regardless of computation complexity
- **Non-interactive**: No back-and-forth between prover and verifier
- **Constant verification**: Fast verification regardless of statement complexity
- **Battle-tested**: Used in Zcash, Filecoin, other production systems

## Use Cases in Ghost Pay

### 1. Balance Verification (Legacy — ConfidentialTransfer)

> **Deprecation Notice:** Use Cases 1-2 describe the legacy ConfidentialTransfer account-model
> approach. The current L2 uses the NoteSpend/UTXO model (GhostNoteSpendCircuit). See
> "Circuit Design" section below for the current approach.

Prove you have sufficient balance for a transfer without revealing your total balance.

```
Public inputs:
├── Transfer amount: 0.1 BTC
├── Fee: 100 sats
└── Balance commitment: H(balance || randomness)

Private inputs (witness):
├── Actual balance: 1.5 BTC
└── Randomness used in commitment

Statement proven:
├── balance ≥ amount + fee
└── Balance commitment is valid
```

### 2. Transfer Validity

Prove a transfer is valid without revealing sender, recipient, or amount.

```
Public inputs:
├── Sender balance commitment (before)
├── Sender balance commitment (after)
├── Recipient balance commitment (before)
├── Recipient balance commitment (after)
└── State transition hash

Private inputs (witness):
├── Sender actual balance (before/after)
├── Recipient actual balance (before/after)
├── Transfer amount
├── Valid signatures
└── Randomness values

Statement proven:
├── sender_balance_after = sender_balance_before - amount - fee
├── recipient_balance_after = recipient_balance_before + amount
├── All signatures are valid
└── No double-spend
```

### 3. Settlement Batching

Prove a batch settlement is correct without revealing individual transactions.

```
Public inputs:
├── Previous state root
├── New state root
├── Batch commitment
└── Total fees collected

Private inputs (witness):
├── All individual transactions in batch
├── All intermediate state transitions
└── Merkle proofs for each update

Statement proven:
├── Each transaction in batch is valid
├── State transitions are correct
├── New state root is correctly computed
└── Fee calculation is accurate
```

### 4. Wraith Mixing Enhancement

ZK proofs provide additional privacy guarantees beyond blind signatures.

```
Public inputs:
├── Input commitment (sum of all inputs)
├── Output commitment (sum of all outputs)
└── Session ID

Private inputs (witness):
├── Individual input amounts
├── Individual output amounts
├── Blinding factors

Statement proven:
├── Total inputs = Total outputs + fee
├── No negative amounts
└── All amounts are valid denominations
```

## Circuit Design

### GhostNoteSpendCircuit (Current — February 2026 L2 Redesign)

The L2 uses a **note/UTXO model** with **sender-side proofs**. Senders generate Groth16 proofs locally; validators only verify.

```rust
pub struct GhostNoteSpendCircuit<F: PrimeField> {
    // Private inputs (witness)
    pub note_value: Option<F>,         // Value of the note being spent
    pub spending_key: Option<F>,       // Proves ownership
    pub randomness: Option<F>,         // Commitment randomness
    pub note_index: Option<u64>,       // Position in commitment tree
    pub epoch: Option<F>,              // Epoch of note creation
    pub amount: Option<F>,             // Transfer amount
    pub recipient_pubkey: Option<F>,   // Recipient's public key
    pub change_randomness: Option<F>,  // Randomness for change note
    pub recipient_randomness: Option<F>, // Randomness for recipient note
    pub merkle_siblings: Vec<Option<F>>, // Merkle path (20 levels)
    pub commitment_root: Option<F>,    // Public: tree root
    pub tree_depth: usize,             // 20 (default)
}
```

**Constraints (~12,675 at depth-20):**
1. Spent note commitment correctly formed (MiMC Pedersen)
2. Note ID incorporates index, epoch, and commitment
3. Nullifier proves ownership via spending key
4. Merkle inclusion in commitment tree (20 levels)
5. Balance conservation: change = note_value - amount
6. Change and recipient commitments correctly formed
7. Range proofs: amount in [0, 2^64), change in [0, 2^64)

**Public inputs (4):**
- `commitment_root` — Merkle root of the commitment tree at time of spend
- `nullifier` — prevents double-spend, deterministically routes to validator
- `change_commitment` — sender's new note (remaining balance)
- `recipient_commitment` — recipient's new note (transfer amount)

## Trusted Setup

Groth16 requires a trusted setup ceremony:

### What is Trusted Setup?

A one-time process to generate proving/verification keys:
- If setup is compromised, fake proofs could be created
- Ceremony uses multi-party computation (MPC)
- As long as ONE participant is honest, setup is secure

### Ghost Pay Setup

```
Phase 1: Powers of Tau
├── Universal ceremony (not circuit-specific)
├── 1000+ participants worldwide
└── Produces generic parameters

Phase 2: Circuit-Specific
├── Transform Phase 1 output for our circuits
├── 100+ participants
└── Produces proving/verification keys
```

### Verification

Anyone can verify the setup was performed correctly:
- Check all participants' contributions
- Verify mathematical properties of keys
- Audit ceremony transcripts

## Performance

### Proof Generation (Sender-Side)

| Circuit | Constraints | Proving Time | Params Size |
|---------|-------------|--------------|-------------|
| GhostNoteSpendCircuit (depth=20) | ~12,675 | ~170ms | ~1.4 MB |
| PayoutCircuit | ~2,500 | ~1 second | ~200 KB |

### Proof Verification (Validator-Side)

| Circuit | Verification Time | Proof Size |
|---------|-------------------|------------|
| NoteSpend | ~5ms | 192 bytes |
| Payout | ~10ms | 192 bytes |

## Privacy Guarantees

### What is Hidden (from validators and public)

- Exact balances (hidden in commitments)
- Transfer amounts (proven valid without revealing)
- Sender/recipient mapping in batches
- Individual transaction details
- Historical transaction records (deleted after consensus)

### What is Revealed

- Transaction occurred (state changed)
- Fees collected (aggregate)
- Batch size (number of transactions)
- Timing (when proofs submitted)

### Proposer Visibility (ephemeral + unlinkable)

The block proposer temporarily sees transaction details during block construction (~2-3 seconds):
- Sender and recipient addresses
- Transaction amounts
- Signatures

**However, Ghost Keys make this harmless:**

Ghost Keys (Silent Payment-style, BIP-352) derive a **unique one-time address** for every payment. The proposer sees:

```
Transaction: Send 0.5 BTC to 7a3f9c8b...
```

But the proposer **cannot determine**:
- Who owns that one-time address
- How to link it to any Ghost ID
- How to connect multiple payments to the same recipient
- The recipient's real identity

Only the recipient (with their scan key) can detect that a payment is theirs.

**Result: Full privacy even from the proposer**

| What Proposer Sees | Can They Link It? |
|--------------------|-------------------|
| One-time recipient address | No - unlinkable |
| Payment amount | Yes - but to unknown recipient |
| Sender address | One-time address (also unlinkable) |

**Additional mitigations**:
- Data discarded immediately after 67% consensus
- Proposers rotate each block (no single observer)
- Cannot build persistent records
- Wraith mixing breaks deposit→L2 link

## Integration with Ghost Pay

### Transfer Flow (Sender-Side Proofs)

```
1. Sender wants to transfer 0.1 BTC from their note

2. Sender's wallet generates GhostNoteSpendCircuit proof locally (~170ms):
   ├── Proves ownership of note via spending key → nullifier
   ├── Proves note is in commitment tree via Merkle path (depth 20)
   ├── Proves balance conservation: change = note_value - amount
   └── Creates change + recipient commitments

3. Submit to NullifierRouteHandler:
   ├── Proof (192 bytes) + public inputs
   └── Routed by nullifier prefix to deterministic validator

4. Validator verifies:
   ├── Check GhostNoteSpendCircuit proof (~5ms)
   ├── Check nullifier not already spent (double-spend prevention)
   └── Add new commitments to tree, record nullifier

5. BFT checkpoint (every 10s, all-node, 67% threshold):
   └── Transaction finalized, commitment tree root updated
```

### Settlement

```
1. Epoch ends, reconciliation triggered

2. EpochManager compacts commitment tree and computes new root

3. On-chain settlement:
   ├── Submit state root in OP_RETURN (GPRC marker)
   ├── Process withdrawal outputs for users exiting L2
   └── Batch for fee efficiency

4. L1 transaction:
   └── Contains state commitment + withdrawal outputs
```

## Security Considerations

### Soundness

If the discrete log problem is hard, no one can create fake proofs.

### Zero-Knowledge

Proofs reveal nothing beyond the statement being proven.

### Trusted Setup Risk

If ALL setup participants collude, fake proofs are possible.
Mitigation: Many independent participants from diverse backgrounds.

## Ephemeral Proof Architecture

Ghost Pay uses an **ephemeral proof model** - proofs and transaction details are discarded immediately after consensus, not stored persistently.

### Design Principles

```
1. Proofs are ephemeral (verified once, then discarded)
2. State is truth (no proof history needed)
3. Math guarantees validity (no re-execution needed)
```

### Why No Proof History?

Traditional ZK rollups (Citrea, zkSync) store transaction data for:
- Data availability (reconstruct state from L1)
- Historical queries
- Proof aggregation/folding

Ghost Pay doesn't need this because:
- **Balance settlement, not tx history**: We settle NET balance changes to L1, not individual transactions
- **No data availability requirement**: L2 state lives on validators, not reconstructed from L1
- **Privacy by deletion**: What doesn't exist can't be leaked

### Block Finalization Flow

```
1. Senders generate GhostNoteSpendCircuit proofs locally (~170ms each)
2. Submit transaction + proof to NullifierRouteHandler
3. NullifierRouteHandler verifies proof (~5ms) and routes by nullifier prefix
4. All-node BFT checkpoint every 10 seconds (67% threshold)
5. Once checkpoint reaches consensus → transactions finalized
6. IMMEDIATELY DISCARDED:
   ├── ZK proof data
   ├── Individual transaction details
   ├── Sender/recipient/amount data
   └── All witness data
7. PERMANENTLY STORED:
   ├── Block height
   ├── State root (merkle root of balances)
   ├── Block hash
   └── Proposer signature
```

### What This Means for Security

A malicious proposer **cannot**:

| Attack | Why It Fails |
|--------|--------------|
| Forge invalid transaction | ZK proof verification fails |
| Create money from nothing | Balance arithmetic proven in ZK |
| Double spend | State root tracking prevents |
| Steal funds | Can't produce valid signature |
| Keep transaction records | Data discarded after consensus |

A malicious proposer **can only**:

| Action | Impact | Mitigation |
|--------|--------|------------|
| Reorder transactions | Minimal (payments, not DeFi) | Low MEV value |
| Temporarily censor | Next block, different proposer | Proposer rotation |
| See tx details briefly | ~seconds during block creation | Ephemeral, no persistence |

### Privacy Model

| Observer | What They See | Privacy Level |
|----------|---------------|---------------|
| **Validators** | Only ZK proofs, state roots | Full privacy |
| **L1/Public** | Only balance settlements | Full privacy |
| **Proposer** | Unlinkable one-time addresses | Full privacy |
| **Historical queries** | Nothing (data deleted) | Full privacy |

**Key insight**: Ghost Keys (Silent Payment-style) make even proposer exposure harmless:

1. **Unlinkable addresses**: Each payment uses a one-time derived address
2. **No identity link**: Proposer cannot map addresses to Ghost IDs
3. **No persistence**: Data discarded after 67% consensus
4. **Proposer rotation**: Different node proposes each block

### Why Not Proof Folding (SuperNova/Nova)?

Proof folding (IVC) is useful when you need to:
- Aggregate proofs of many transactions over time
- Post compressed proof history to L1
- Enable L1 to reconstruct full transaction history

Ghost Pay doesn't need this because:
- We settle **balances**, not **transaction histories**
- L1 only needs to know "Alice's balance changed from X to Y"
- No need to prove "here are the 1000 txs that caused that change"
- Single Groth16 proofs per block are sufficient

This is a deliberate design choice for privacy - the less history that exists, the less can be leaked.

## Future Improvements

### Potential Upgrades

| Technology | Benefit | Trade-off |
|------------|---------|-----------|
| PLONK | Universal setup | Larger proofs |
| STARKs | No trusted setup | Much larger proofs |
| Halo 2 | Recursive proofs | Higher complexity |

### Recursive Proofs

Future versions may use recursive proofs:
- Prove "this proof is valid" inside another proof
- Enables unlimited batching
- Constant verification regardless of batch size

## Implementation Notes

### Libraries Used

- `bellperson` - Groth16 implementation (GPU-ready fork of bellman)
- `bls12_381` - BLS12-381 elliptic curve operations
- `ff` - Finite field arithmetic

### Circuit Testing

```rust
#[test]
fn test_note_spend_circuit() {
    let circuit = GhostNoteSpendCircuit::<Fr>::dummy(20);
    let cs = TestConstraintSystem::<Fr>::new();
    circuit.synthesize(&mut cs).unwrap();
    // ~12,675 constraints at depth-20
    assert!(cs.num_constraints() > 5000);
    assert!(cs.num_constraints() < 20000);
}
```

## Deprecated Types

The following types remain in the codebase for backward compatibility but are deprecated.
New code must use the NoteSpend equivalents:

| Deprecated Type | Replacement | Notes |
|----------------|-------------|-------|
| `ConfidentialTransferCircuit` | `GhostNoteSpendCircuit` | Account-model → UTXO model |
| `ConfidentialProver` | `GhostNoteProver` | Server-side → sender-side proofs |
| `ConfidentialVerifier` | `GhostNoteVerifier` | Verify NoteSpend proofs (~5ms) |
| `ClientProver` | `NoteSpendClientProver` | Wallet-side proof generation |
| `ConfidentialTransferResult` | `NoteSpendTransferResult` | Proof output with nullifier + commitments |

All deprecated types carry `#[deprecated]` attributes and will emit compiler warnings.

## Related Documentation

- [Ghost Pay](GHOST_PAY.md) - L2 network using ZK proofs
- [Wraith Protocol](WRAITH_PROTOCOL.md) - Mixing with ZK enhancement
- [Reconciliation](RECONCILIATION.md) - Batch settlement with ZK proofs
