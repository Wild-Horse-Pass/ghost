# Silent Payment v2: Counter-Based k Protocol

## Overview

Silent Payment v2 replaces position-based output indexing with a counter-based k approach. This eliminates fund loss risk when transaction outputs are shuffled, which is critical for Wraith Protocol mixing.

## Problem Statement

The original Silent Payment implementation used output position in the tweak calculation:

```
tweak_v1 = SHA256(shared_secret || output_index || nonce)
```

This is problematic because:
1. **Shuffling breaks detection**: If outputs are reordered (e.g., for privacy), the receiver cannot find their payments
2. **Wraith Protocol incompatibility**: Wraith shuffles outputs for unlinkability, which would cause fund loss
3. **No recovery mechanism**: Lost funds cannot be recovered by re-scanning

## Solution

Counter-based k uses a sequential counter independent of output position:

```
tweak_v2 = SHA256(domain_separator || shared_secret || k)
```

Where:
- `domain_separator = "ghost/silent-payment/v2"` (prevents v1/v2 collision)
- `shared_secret` = ECDH shared secret (32 bytes)
- `k` = sequential counter (0, 1, 2, ...) as little-endian u32

## Key Properties

| Property | Description |
|----------|-------------|
| Position-independent | Outputs can be shuffled freely without affecting detection |
| Recoverable | Increase max_k and re-scan to find missed payments |
| Configurable | Users set scan depth (default 10, max 10,000) |
| Backward compatible | v1 functions deprecated but kept; v1/v2 tweaks never collide |

## Protocol Specification

### Constants

```rust
pub const DEFAULT_MAX_K: u32 = 10;
pub const MAX_MAX_K: u32 = 10_000;
pub const DOMAIN_SEPARATOR_V2: &[u8] = b"ghost/silent-payment/v2";
```

### Sender Protocol

1. Generate ephemeral keypair: `(e, E = e*G)`
2. Compute shared secret: `S = SHA256(e * scan_pubkey)`
3. For each output to this recipient (k = 0, 1, 2, ...):
   - Compute tweak: `t = SHA256(DOMAIN_SEPARATOR_V2 || S || k.to_le_bytes())`
   - Derive output pubkey: `P = spend_pubkey + t*G`
4. Include ephemeral pubkey `E` in OP_RETURN

### Receiver Protocol

1. Extract ephemeral pubkey `E` from OP_RETURN
2. Compute shared secret: `S = SHA256(scan_secret * E)`
3. For each output in transaction:
   - For k = 0 to max_k:
     - Compute tweak: `t = SHA256(DOMAIN_SEPARATOR_V2 || S || k.to_le_bytes())`
     - Compute expected pubkey: `P = spend_pubkey + t*G`
     - If output matches P, record (k, output_index, spend_key = spend_secret + t)
4. Return all matched payments

### Recovery Scanning

If payments are missed (sender used higher k than receiver's max_k):

1. Increase max_k (e.g., to 1000 or 10000)
2. Re-scan historical transactions
3. Missed payments will be found

## Test Vectors

### Vector 1: Basic k=0

```
shared_secret: 4242424242424242424242424242424242424242424242424242424242424242
k: 0
expected_tweak: [computed from SHA256(domain || shared_secret || 0x00000000)]
```

### Vector 2: k=1

```
shared_secret: 4242424242424242424242424242424242424242424242424242424242424242
k: 1
expected_tweak: [computed from SHA256(domain || shared_secret || 0x01000000)]
```

### Vector 3: High k (255)

```
shared_secret: 4242424242424242424242424242424242424242424242424242424242424242
k: 255
expected_tweak: [computed from SHA256(domain || shared_secret || 0xff000000)]
```

### Vector 4: High k (1000)

```
shared_secret: 4242424242424242424242424242424242424242424242424242424242424242
k: 1000
expected_tweak: [computed from SHA256(domain || shared_secret || 0xe8030000)]
```

### Vector 5: v1 vs v2 Non-Collision

```
shared_secret: 4242424242424242424242424242424242424242424242424242424242424242
v1_tweak (index=0, nonce=0): [some value X]
v2_tweak (k=0): [some value Y]
assert: X != Y (domain separator ensures non-collision)
```

## Security Analysis

### Threat: Timing Attack on Scanning

**Mitigation**: Constant-time comparison using `subtle::ConstantTimeEq` prevents timing side-channels.

### Threat: k Value Exhaustion

**Mitigation**: MAX_MAX_K = 10,000 provides sufficient headroom. Normal usage is k < 10.

### Threat: Denial of Service via High k

**Mitigation**: Receivers configure their own max_k. Senders using unreasonably high k values only affect their own recipient's ability to find payments.

### Threat: Privacy Leak via k Value

**Analysis**: k values are not transmitted on-chain. They are implicit in the derived address. An observer cannot determine k from the transaction.

## Migration Notes

### For Senders

- Update to use `derive_payment_address_v2(k)` instead of `derive_payment_address(index)`
- Assign k values sequentially (0, 1, 2, ...) for multiple outputs to same recipient
- k is independent of output position in transaction

### For Receivers

- Update to use `PaymentDetector::new(keys)` which uses v2 by default
- Configure max_k via `ScanConfig` if needed
- Use `ScanConfig::recovery()` for recovery scanning
- Both k and output_index are now available in `ScannedPayment`

### Backward Compatibility

- v1 functions are deprecated but still available
- v1 and v2 tweaks never collide (different domain)
- Wallets should migrate to v2 for new transactions

## API Reference

### ScanConfig

```rust
// Default scanning (max_k = 10)
let config = ScanConfig::default();

// Custom max_k
let config = ScanConfig::new(100);

// Recovery preset (max_k = 1000)
let config = ScanConfig::recovery();

// Deep recovery (max_k = 10000)
let config = ScanConfig::deep_recovery();
```

### PaymentDetector

```rust
// Create detector with default config
let detector = PaymentDetector::new(&keys);

// Create with custom config
let detector = PaymentDetector::with_config(&keys, ScanConfig::recovery());

// Scan transaction
let payments = detector.scan_transaction(&ephemeral_pubkey, &outputs);

// Quick check (k=0 only, for filtering)
let might_be_ours = detector.quick_check(&ephemeral_pubkey, &output_pubkey);
```

### GhostId

```rust
// Derive payment address
let (output_pubkey, ephemeral_pubkey) = ghost_id.derive_payment_address_v2(k)?;

// With full details (includes tweak)
let (output_pubkey, ephemeral_pubkey, tweak) = ghost_id.derive_payment_address_v2_full(k)?;
```

## Implementation Status

| Component | Status |
|-----------|--------|
| Core tweak function | Complete |
| Address derivation | Complete |
| Payment detection | Complete |
| Scanning | Complete |
| ScanConfig | Complete |
| Unit tests | Complete (63 tests) |
| Integration tests | Complete (25+ tests) |
| CLI integration | Partial |
| Documentation | Complete |

## References

- BIP-352: Silent Payments
- Ghost Whitepaper: Section 4.2 (Ghost Pay)
- Wraith Protocol Specification
