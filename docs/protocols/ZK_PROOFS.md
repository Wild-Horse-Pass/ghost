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
| Proof size | ~200 bytes (constant) |
| Verification time | ~10ms |
| Proving time | ~1 second |
| Setup | Trusted setup required |

### Why Groth16?

- **Succinct**: Small proof size regardless of computation complexity
- **Non-interactive**: No back-and-forth between prover and verifier
- **Constant verification**: Fast verification regardless of statement complexity
- **Battle-tested**: Used in Zcash, Filecoin, other production systems

## Use Cases in Ghost Pay

### 1. Balance Verification

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

### Transfer Circuit

```rust
// Simplified representation
fn transfer_circuit(
    // Public inputs
    sender_commitment_before: Field,
    sender_commitment_after: Field,
    recipient_commitment_before: Field,
    recipient_commitment_after: Field,
    fee: Field,

    // Private inputs (witness)
    sender_balance_before: Field,
    sender_balance_after: Field,
    recipient_balance_before: Field,
    recipient_balance_after: Field,
    amount: Field,
    sender_randomness_before: Field,
    sender_randomness_after: Field,
    recipient_randomness_before: Field,
    recipient_randomness_after: Field,
    sender_signature: Signature,
) {
    // 1. Verify commitments
    assert_eq!(
        hash(sender_balance_before, sender_randomness_before),
        sender_commitment_before
    );
    assert_eq!(
        hash(sender_balance_after, sender_randomness_after),
        sender_commitment_after
    );
    // ... same for recipient

    // 2. Verify balance updates
    assert_eq!(
        sender_balance_after,
        sender_balance_before - amount - fee
    );
    assert_eq!(
        recipient_balance_after,
        recipient_balance_before + amount
    );

    // 3. Verify signature
    assert!(verify_signature(sender_signature, transfer_hash));

    // 4. Range checks (no negative balances)
    assert!(sender_balance_after >= 0);
    assert!(recipient_balance_after >= 0);
}
```

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

### Proof Generation

| Circuit | Constraints | Proving Time | Memory |
|---------|-------------|--------------|--------|
| Transfer | ~10,000 | ~500ms | ~1GB |
| Balance Check | ~5,000 | ~200ms | ~500MB |
| Batch (100 tx) | ~500,000 | ~30s | ~8GB |

### Proof Verification

| Circuit | Verification Time | Proof Size |
|---------|-------------------|------------|
| Transfer | ~10ms | 192 bytes |
| Balance Check | ~5ms | 192 bytes |
| Batch | ~10ms | 192 bytes |

## Privacy Guarantees

### What is Hidden

- Exact balances
- Transfer amounts
- Sender/recipient mapping in batches
- Individual transaction details

### What is Revealed

- Transaction occurred (state changed)
- Fees collected (aggregate)
- Batch size (number of transactions)
- Timing (when proofs submitted)

## Integration with Ghost Pay

### Transfer Flow with ZK

```
1. User wants to transfer 0.1 BTC

2. Wallet generates ZK proof:
   ├── Proves balance ≥ 0.1 BTC + fee
   ├── Proves new balances are correctly computed
   └── Proves valid signature

3. Submit to L2 network:
   ├── Encrypted transfer details
   └── ZK proof

4. Validators verify:
   ├── Check ZK proof (fast, ~10ms)
   ├── Don't see amounts or balances
   └── Update state commitments

5. Transfer complete:
   └── Privacy preserved throughout
```

### Settlement with ZK

```
1. Epoch ends, batch settlement needed

2. Coordinator generates batch proof:
   ├── Proves all N transactions valid
   ├── Proves state transition correct
   └── Single proof for entire batch

3. On-chain settlement:
   ├── Submit batch proof (192 bytes)
   ├── Submit new state root
   └── Anyone can verify

4. L1 transaction:
   └── Contains proof, not transaction details
```

## Security Considerations

### Soundness

If the discrete log problem is hard, no one can create fake proofs.

### Zero-Knowledge

Proofs reveal nothing beyond the statement being proven.

### Trusted Setup Risk

If ALL setup participants collude, fake proofs are possible.
Mitigation: Many independent participants from diverse backgrounds.

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

- `bellman` - Groth16 implementation
- `bls12_381` - Elliptic curve operations
- `ff` - Finite field arithmetic

### Circuit Testing

```rust
#[test]
fn test_transfer_circuit() {
    let circuit = TransferCircuit {
        sender_balance_before: 1_000_000,
        sender_balance_after: 900_000,
        amount: 90_000,
        fee: 10_000,
        // ... other fields
    };

    let proof = create_proof(&circuit, &proving_key);
    assert!(verify_proof(&proof, &verification_key, &public_inputs));
}
```

## Related Documentation

- [Ghost Pay](GHOST_PAY.md) - L2 network using ZK proofs
- [Wraith Protocol](WRAITH_PROTOCOL.md) - Mixing with ZK enhancement
- [Reconciliation](RECONCILIATION.md) - Batch settlement with ZK proofs
