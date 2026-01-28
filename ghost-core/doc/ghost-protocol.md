# Ghost Protocol - Technical Specification

This document describes the Ghost Protocol extensions to Bitcoin Core, including
consensus compatibility, policy changes, and implementation details.

## Executive Summary

Ghost Core is **100% consensus-compatible** with Bitcoin Core. All Ghost features
are implemented using standard Bitcoin script primitives (P2TR, OP_CHECKSIG,
OP_CHECKSEQUENCEVERIFY) and require no consensus changes or soft forks.

## Table of Contents

1. [Consensus Compatibility](#consensus-compatibility)
2. [Ghost Lock](#ghost-lock)
3. [Silent Payments (Ghost ID)](#silent-payments-ghost-id)
4. [Wraith Protocol](#wraith-protocol)
5. [Policy Changes](#policy-changes)
6. [RPC Commands](#rpc-commands)

---

## Consensus Compatibility

### No Consensus Changes

Ghost Core makes **zero modifications** to Bitcoin consensus rules:

| Component | Modified? | Details |
|-----------|-----------|---------|
| validation.cpp | No | Standard validation unchanged |
| consensus/tx_verify.cpp | No | No Ghost-specific validations |
| script/interpreter.cpp | No | No custom opcodes |
| Difficulty adjustment | No | Standard Bitcoin rules |
| Block size/weight | No | Standard limits apply |
| Coin supply | No | 21M cap unchanged |

### Standard Script Usage

All Ghost features use standard Bitcoin script types:

- **P2TR (Taproot)**: Ghost Lock and Silent Payment outputs
- **OP_CHECKSIG**: Key verification in Ghost Lock scripts
- **OP_CHECKSEQUENCEVERIFY**: Timelock enforcement in recovery paths
- **OP_RETURN**: Metadata storage for protocol markers

### BIP Compliance

Ghost Protocol follows these BIPs without modification:

- **BIP-340**: Schnorr signatures
- **BIP-341**: Taproot (witness v1)
- **BIP-342**: Tapscript
- **BIP-352**: Silent Payments (reference implementation)

---

## Ghost Lock

Ghost Lock is a P2TR (Taproot) output structure enabling time-locked recovery.

### Script Structure

```
Internal Key: lock_pubkey (tweaked with merkle root)

Taproot Tree (2-leaf balanced):
├── Leaf 0 (Normal spend):     <lock_pubkey> OP_CHECKSIG
└── Leaf 1 (Recovery path):    <timelock> OP_CSV OP_DROP <recovery_pubkey> OP_CHECKSIG
```

### Spending Paths

1. **Key-path spend**: Sign with tweaked lock_pubkey (most efficient)
2. **Script-path normal**: Reveal Leaf 0, sign with lock_pubkey
3. **Script-path recovery**: After timelock expires, sign with recovery_pubkey

### Standard Denominations (Policy)

| Name | Satoshis | BTC |
|------|----------|-----|
| MICRO | 10,000 | 0.0001 |
| TINY | 100,000 | 0.001 |
| SMALL | 1,000,000 | 0.01 |
| MEDIUM | 10,000,000 | 0.1 |
| LARGE | 100,000,000 | 1.0 |
| XL | 1,000,000,000 | 10.0 |

### Recovery Timelock Parameters (Policy)

| Parameter | Blocks | Approximate Time |
|-----------|--------|------------------|
| Default | 26,280 | ~6 months |
| Minimum | 1,008 | ~1 week |
| Maximum | 52,560 | ~1 year |

**Note**: Denominations and timelock ranges are policy-level constraints, not
consensus-enforced. Non-standard values are valid but may not be relayed.

### Files

- `src/ghostlock.h` - Constants and declarations
- `src/ghostlock.cpp` - Taproot tree construction

---

## Silent Payments (Ghost ID)

Silent Payments enable receiver privacy through ECDH-derived addresses.

### Ghost ID Format

```
Format:  ghost1<bech32m encoded 66 bytes>
Example: ghost1qv8e...
```

The 66-byte payload contains:
- **Scan pubkey** (33 bytes): Used for ECDH key exchange
- **Spend pubkey** (33 bytes): Used for deriving output addresses

### Key Derivation

```
1. Sender computes: shared_secret = ECDH(sender_privkey, recipient_scan_pubkey)
2. Tweak derived:   tweak = SHA256(shared_secret || index || nonce)
3. Output pubkey:   P_output = P_spend + tweak*G
4. Receiver scans:  shared_secret = ECDH(scan_privkey, sender_pubkey)
                    Checks if any P2TR output matches P_spend + tweak*G
```

### OP_RETURN Marker

Ghost Lock transactions include an OP_RETURN with:

```
Marker: 0x47 0x48 0x4F 0x53 ("GHOS")
Data:   33-byte ephemeral pubkey (compressed)
Total:  37+ bytes
```

### Files

- `src/silentpayments.h` - Protocol constants
- `src/silentpayments.cpp` - ECDH and key derivation
- `src/addresstype.h` - SilentPaymentDestination type
- `src/key_io.cpp` - Ghost ID encoding/decoding

---

## Wraith Protocol

Wraith Protocol provides transaction unlinkability through a two-phase mixing process.

### Phase 1: Split Transaction

Creates intermediate Ghost Lock outputs from participant inputs.

```
Inputs:  N UTXOs from participants
Outputs:
  - 10N intermediate Ghost Lock outputs (denomination/10 each)
  - 1 treasury fee output (1% of total - mining fee)
  - 1 OP_RETURN with "GPW1" marker + 32-byte session_id
```

### Phase 2: Merge Transaction

Combines intermediate outputs into final destinations.

```
Inputs:  10 intermediate Ghost Lock outputs (from Phase 1)
Outputs:
  - 1 final P2TR output (full denomination)
  - 1 OP_RETURN with "GPW2" marker + session data
```

### OP_RETURN Markers

| Phase | Marker | Hex |
|-------|--------|-----|
| Phase 1 | "GPW1" | 0x47 0x50 0x57 0x31 |
| Phase 2 | "GPW2" | 0x47 0x50 0x57 0x32 |

### Fee Structure (Policy)

- Protocol fee: 1% of denomination per participant
- Formula: `treasury_amount = (denomination / 100) * input_count - mining_fee`

### Privacy Properties

- **Output shuffling**: Random output ordering (OP_RETURN always last)
- **Denomination matching**: All outputs same value for anonymity set
- **Session isolation**: Independent mixing sessions via session_id

### Files

- `src/wallet/rpc/wraith.cpp` - RPC implementation

---

## Policy Changes

### New Address Type

| Type | Prefix | Length | Encoding |
|------|--------|--------|----------|
| Ghost ID | ghost1 | 66 bytes | bech32m |

Ghost IDs are recognized as valid destinations but don't generate scripts directly
(outputs are derived P2TR addresses).

### Transaction Relay

No changes to mempool or relay policy:
- Ghost transactions use standard P2TR outputs
- Standard OP_RETURN size limits apply
- Standard transaction weight limits apply

### Standardness

Ghost Lock outputs are treated as standard P2TR (WITNESS_V1_TAPROOT) outputs:
- Pass IsStandard() validation
- Benefit from witness discount (1/4 weight)
- No special handling required

---

## RPC Commands

### Silent Payments

#### getsilentpaymentaddress

Returns the wallet's Ghost ID for receiving Silent Payments.

```json
{
  "address": "ghost1...",
  "ghost_id": "ghost1...",
  "scan_pubkey": "<33 bytes hex>",
  "spend_pubkey": "<33 bytes hex>"
}
```

#### checksilentpayment

Checks if an output belongs to the wallet.

```
Parameters: ephemeral_pubkey, output_pubkey, index, nonce
Returns: { "is_mine": true/false }
```

#### derivesilentpaymentaddress

Derives a specific Silent Payment address.

```
Parameters: ghost_id, index, nonce
Returns: { "address": "bcrt1p...", "ephemeral_pubkey": "..." }
```

### Wraith Protocol

#### createwraithtx

Creates a Phase 1 (split) transaction.

```
Parameters: inputs, intermediate_outputs, session_id, denomination, treasury_address
Returns: { "hex": "...", "session_id": "...", "denomination": "..." }
```

#### createwraithfinaltx

Creates a Phase 2 (merge) transaction.

```
Parameters: inputs, outputs, session_id, denomination
Returns: { "hex": "...", "session_id": "...", "denomination": "..." }
```

### Utility

#### estimatebatchfee

Estimates fees for batch transactions.

```
Parameters: num_inputs, num_outputs, has_opreturn, conf_target
Returns: { "estimated_vsize": N, "estimated_fee": N, ... }
```

#### shuffleoutputs

Randomizes transaction output order.

```
Parameters: tx_hex, preserve_opreturn_position
Returns: { "hex": "...", "original_outputs": N, "shuffled_outputs": N }
```

---

## Implementation Notes

### Backwards Compatibility

- All Ghost features are opt-in at the application layer
- Standard Bitcoin wallets can receive Ghost payments (as P2TR outputs)
- Standard Bitcoin nodes can relay Ghost transactions
- No fork or consensus change required

### Cryptographic Operations

| Operation | Implementation |
|-----------|----------------|
| ECDH | Standard secp256k1 |
| Hashing | SHA256 |
| Signatures | Schnorr (BIP-340) |
| Taproot | BIP-341/342 |

### Security Considerations

1. **Key isolation**: Scan and spend keys are separate
2. **Deterministic derivation**: Outputs derived from shared secrets
3. **Timelock security**: Recovery requires CSV expiry
4. **No consensus trust**: All features enforced by standard Bitcoin scripts

---

## References

- [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP-342: Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
