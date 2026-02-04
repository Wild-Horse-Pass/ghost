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
//| FILE: GHOST_LABELS.md                                                                                                |
//|======================================================================================================================|

# Ghost Labels

Recipient-local payment categorization for Ghost Pay.

## Overview

Ghost Labels provide a privacy-preserving way for recipients to categorize incoming payments without weakening Silent Payment unlinkability. Labels are:

- **Recipient-specific**: The number `1` means different things to different recipients
- **Metadata-only**: Not part of cryptographic address derivation
- **Universal**: All payments include a label field (no fingerprinting)
- **Local**: Label-to-name mappings never leave the recipient's device

## Design Principles

### 1. No Cryptographic Involvement

Labels are **purely metadata**. They do not affect:
- Address derivation
- Spend key computation
- One-time address generation
- Any cryptographic operation

This preserves full Silent Payment privacy.

### 2. Universal Inclusion

**Every payment includes a label field.** This prevents fingerprinting attacks where an observer could distinguish "labeled" from "unlabeled" payments.

Default label: `0` (used when sender doesn't specify)

### 3. Recipient-Local Semantics

The label index (a number) has no global meaning. Each recipient maintains their own local dictionary:

```
Alice's dictionary:          Bob's dictionary:
1 → "Donations"              1 → "Salary"
2 → "Freelance"              2 → "Refunds"
3 → "Family"                 3 → "Investments"
```

An observer seeing `label: 1` learns nothing - it could mean anything.

### 4. Deletion Safety

Recipients can delete labels at any time. Old payments retain their numeric label but lose the human-readable name. No data corruption occurs.

## Data Structures

### PaymentMetadata

Encrypted in every transaction using the ECDH shared secret.

```rust
struct PaymentMetadata {
    /// Label index (required, default 0)
    label: u32,
    /// Memo length (0-59)
    memo_len: u8,
    /// Optional sender memo (max 59 bytes UTF-8)
    memo: [u8; 59],
}
```

**Fixed size**: 80 bytes total (always)
- 64 bytes plaintext (4 label + 1 length + 59 memo/padding)
- 16 bytes auth tag (Poly1305)
- Nonce derived deterministically (not transmitted)

### LabelDictionary

Stored locally on recipient's device. Never transmitted.

```rust
struct LabelDictionary {
    /// Map of index → human-readable name
    labels: HashMap<u32, String>,
    /// Next available index for new labels
    next_index: u32,
}
```

### LabeledAddress

Shared with senders (e.g., QR code, URL, verbal).

```
Format: ghost1<scan_pubkey><spend_pubkey>?l=<label_index>

Example: ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...?l=5
```

The `?l=` parameter is a hint telling the sender which label index to include in the encrypted metadata.

## Protocol Flow

### Recipient Setup

```
1. Recipient creates local label:
   dictionary.create("Donations") → index 7

2. Recipient generates labeled address:
   ghost1<scan><spend>?l=7

3. Recipient shares address (website, invoice, verbally)
```

### Sender Payment

```
1. Sender receives address: ghost1...?l=7

2. Sender parses label hint: l=7

3. Sender creates payment:
   a. Derive one-time address (standard Ghost Keys, UNCHANGED)
   b. Create metadata: PaymentMetadata { label: 7, memo: "Monthly donation" }
   c. Encrypt metadata with shared_secret (ChaCha20-Poly1305)
   d. Include encrypted_metadata in transaction

4. Sender submits transaction to L2
```

### Recipient Detection

```
1. Recipient scans transactions (standard O(n) ECDH scan)

2. For each potential match:
   a. Compute shared_secret = ECDH(scan_secret, ephemeral_pubkey)
   b. Attempt to decrypt encrypted_metadata
   c. If decryption succeeds → payment is ours

3. Extract label and memo:
   metadata = decrypt(encrypted_metadata, shared_secret)
   label_index = metadata.label  // e.g., 7
   label_name = dictionary.lookup(7)  // e.g., "Donations"
   memo = metadata.memo  // e.g., "Monthly donation"

4. Display to user:
   "Received 0.1 BTC [Donations]: Monthly donation"
```

## Encryption Specification

### Algorithm

ChaCha20-Poly1305 (AEAD)

### Key Derivation

```
encryption_key = HKDF-SHA256(
    ikm: shared_secret,
    salt: "ghost/label/v1",
    info: ephemeral_pubkey,
    length: 32
)
```

### Nonce

12 bytes, derived deterministically (not transmitted):
```
nonce = HKDF-SHA256(
    ikm: shared_secret,
    salt: "ghost/label/nonce/v1",
    info: ephemeral_pubkey,
    length: 12
)
```

Since each payment has a unique ephemeral key, nonces are never reused.
Both sender and recipient can compute the nonce from the shared secret,
so it does not need to be included in the ciphertext.

### Plaintext Format (64 bytes, fixed)

```
Bytes 0-3:   label (u32, little-endian)
Byte 4:     memo_length (u8, 0-59)
Bytes 5-63: memo bytes (UTF-8) + random padding
```

Padding MUST use cryptographically random bytes (not zeros) to fill
the remaining space after the memo. This prevents compression-based attacks.

### Ciphertext Format (80 bytes, fixed)

```
encrypted_metadata = ciphertext (64) || tag (16)
```

Nonce is derived, not transmitted. Total size is always exactly 80 bytes.

## Address Encoding

### With Label

```
ghost1<bech32_data>?l=<index>

Where:
- ghost1 = human-readable prefix
- bech32_data = scan_pubkey (33) || spend_pubkey (33)
- ?l=<index> = label hint (query parameter)
```

### Without Label (Default)

```
ghost1<bech32_data>

Equivalent to ?l=0
```

### QR Code

For QR codes, encode the full URI including label parameter.

## Label Management

### Creating Labels

```rust
impl LabelDictionary {
    /// Create a new label, returns assigned index
    pub fn create(&mut self, name: &str) -> u32 {
        let index = self.next_index;
        self.next_index += 1;
        self.labels.insert(index, name.to_string());
        index
    }
}
```

### Renaming Labels

```rust
impl LabelDictionary {
    /// Rename existing label (index unchanged)
    pub fn rename(&mut self, index: u32, new_name: &str) -> bool {
        if let Some(entry) = self.labels.get_mut(&index) {
            *entry = new_name.to_string();
            true
        } else {
            false
        }
    }
}
```

### Deleting Labels

```rust
impl LabelDictionary {
    /// Delete label (old payments show orphaned index)
    pub fn delete(&mut self, index: u32) -> bool {
        self.labels.remove(&index).is_some()
    }
}
```

### Listing Orphaned Payments

```rust
impl LabelDictionary {
    /// Check if a label index is orphaned (deleted)
    pub fn is_orphaned(&self, index: u32) -> bool {
        index != 0 && !self.labels.contains_key(&index)
    }
}
```

## Backup and Recovery

### What to Backup

```rust
struct LabelBackup {
    /// Full dictionary state
    labels: HashMap<u32, String>,
    /// Next index to prevent collisions
    next_index: u32,
    /// Backup timestamp
    created_at: u64,
}
```

### Recovery Without Backup

If label dictionary is lost:
- Payments are still detectable (labels don't affect crypto)
- Payments display numeric labels instead of names
- User can manually re-create labels and associate old indices

### Recommended Backup Strategy

Include `LabelDictionary` in wallet backup alongside:
- Seed phrase
- Ghost Keys
- Transaction history

## Privacy Analysis

### What Observers See

| Observer | Sees | Learns |
|----------|------|--------|
| Proposer | `encrypted_metadata` blob | Nothing (encrypted) |
| Validators | `encrypted_metadata` blob | Nothing (encrypted) |
| L1/Public | Settlement transactions | Nothing (no labels on L1) |
| Network analyst | All transactions have metadata | Nothing (universal, encrypted) |

### What Recipients See

- Label index (numeric)
- Label name (from local dictionary)
- Memo (from sender)

### Unlinkability

| Scenario | Linkable? | Reason |
|----------|-----------|--------|
| Two payments to same label | No | Different one-time addresses |
| Two payments to different labels | No | Same Ghost ID, different addresses |
| Payments across recipients | No | Same label number means different things |

### Fingerprinting Prevention

Because ALL payments include a label field (defaulting to 0), an observer cannot distinguish:
- Payments with intentional labels
- Payments without labels (using default)
- Payments to label-aware vs legacy wallets

## Compatibility

### Existing Ghost Keys

No changes to:
- `GhostId` structure
- `GhostKeys` structure
- Address derivation
- Spend key derivation
- ECDH shared secret computation

Labels are purely additive - old wallets ignore the `?l=` parameter and use default label 0.

### Existing Transactions

Transactions without `encrypted_metadata` field are treated as:
- Label: 0 (default)
- Memo: None

### Version Negotiation

None required. Labels are backward compatible.

## Constants

```rust
/// Default label for payments without explicit label
pub const DEFAULT_LABEL: u32 = 0;

/// Maximum memo length in bytes (59 bytes = 64 - 4 label - 1 length)
pub const MAX_MEMO_LENGTH: usize = 59;

/// Fixed plaintext size before encryption
pub const METADATA_PLAINTEXT_SIZE: usize = 64;

/// Fixed ciphertext size (plaintext + 16 byte tag)
pub const METADATA_CIPHERTEXT_SIZE: usize = 80;

/// Label dictionary version for backup format
pub const LABEL_BACKUP_VERSION: u32 = 1;
```

## Error Handling

| Error | Cause | Handling |
|-------|-------|----------|
| Decryption failure | Not our payment or corrupted | Skip transaction |
| Unknown label index | Label was deleted | Display numeric index |
| Memo too long | Sender exceeded 59 bytes | Truncate at send time |
| Invalid UTF-8 in memo | Corrupted or malicious | Skip transaction |
| Wrong ciphertext size | Not 80 bytes | Skip transaction |

### Uniform Error Behavior

Implementations MUST NOT distinguish between different failure modes in timing
or error messages. All of the following MUST produce identical "skip transaction"
behavior:
- Authentication tag verification failure
- Invalid plaintext format after decryption
- Invalid UTF-8 in memo field
- Unexpected ciphertext size

This prevents side-channel attacks that could leak information about partial
decryption success.

## Security Considerations

### Encryption

- ChaCha20-Poly1305 provides authenticated encryption (CCA2 secure)
- Shared secret is unique per payment (unique ephemeral key)
- Nonce derived deterministically - no reuse possible
- Fixed 80-byte ciphertext prevents size-based fingerprinting

### Denial of Service

- Metadata decryption is fast (~microseconds)
- Failed decryption is constant-time (AEAD property)
- Fixed 80-byte size limits amplification surface
- 59-byte memo cap prevents bloat

### Label Index Guessing

- Attacker could guess label indices (0, 1, 2...)
- But indices have no global meaning
- Guessing reveals nothing without recipient's dictionary

### Dictionary Theft

- If attacker steals recipient's label dictionary:
  - They learn label names (local UX data)
  - They still cannot detect payments (need scan_secret)
  - They cannot spend funds (need spend_secret)

## Security Requirements

### MUST Requirements

1. **Fixed-size metadata**: All encrypted metadata MUST be exactly 80 bytes.
   Variable sizes leak information about memo presence/length.

2. **Random padding**: Unused memo bytes MUST be filled with cryptographically
   random data, not zeros. This prevents compression-based attacks.

3. **UTF-8 validation**: Memos MUST be valid UTF-8. Invalid UTF-8 after
   decryption MUST be treated as decryption failure.

4. **Constant-time operations**: Implementations SHOULD use constant-time
   HKDF and ChaCha20-Poly1305 to prevent timing side channels.

5. **Ephemeral key uniqueness**: Implementations MUST use a CSPRNG for
   ephemeral key generation. Implementations SHOULD verify ephemeral keys
   are not reused (defense in depth).

6. **Uniform error handling**: All decryption/parsing failures MUST be
   indistinguishable in timing and error messages.

### SHOULD Requirements

1. **Backup encryption**: LabelDictionary backups SHOULD be encrypted with
   the same key material protecting the wallet seed.

2. **Privacy guidance**: Wallets SHOULD warn users that memo content is
   visible to recipients and could be extracted if recipient device is
   compromised.

3. **Separate Ghost IDs**: Users who want to prevent organizational
   fingerprinting SHOULD use separate Ghost IDs for different contexts
   rather than relying solely on labels.

### Privacy Warnings

**For senders**: Memos are visible to recipients. Avoid including personally
identifiable information that could link your identity to payments.

**For recipients**: If you share multiple labeled addresses publicly
(e.g., different labels on website, invoices, etc.), observers may infer
you have multiple payment categories, though they cannot see the category
names or link specific payments.

## Implementation Checklist

### Required Changes

1. **ghost-gsp-proto**: Add `encrypted_metadata` field to payment messages
2. **ghost-keys**: Add `PaymentMetadata` struct and encryption/decryption
3. **ghost-keys**: Add `LabelDictionary` struct
4. **ghost-light-wallet**: Add label management UI
5. **ghost-gsp**: Handle encrypted metadata in payment processing

### Optional Changes

1. **ghost-light-wallet-cli**: Label commands (create, list, delete)
2. **ghost-light-wallet-tui**: Label management screen
3. **Address parsing**: Support `?l=` query parameter

## Test Cases

### Unit Tests

1. Create label, verify index assignment
2. Encrypt/decrypt metadata roundtrip
3. Delete label, verify orphan detection
4. Backup/restore dictionary
5. Parse address with label parameter

### Integration Tests

1. Send payment with label, receive and categorize
2. Send payment without label, receive with default
3. Multiple payments to same label, verify unlinkability
4. Payment to deleted label, verify graceful handling

### Privacy Tests

1. Verify label not in address derivation
2. Verify encrypted metadata is indistinguishable
3. Verify scanning is O(n), not O(n × labels)

## Related Documentation

- [Ghost Keys](GHOST_KEYS.md) - Silent Payment-style addresses
- [Ghost Pay](GHOST_PAY.md) - L2 payment system
- [ZK Proofs](ZK_PROOFS.md) - Privacy-preserving validation

## Changelog

- v1.0 (2026-02): Initial specification
  - Fixed 80-byte metadata size (prevents fingerprinting)
  - 59-byte max memo (compact, sufficient for most use cases)
  - Derived nonce (not transmitted, saves 12 bytes)
  - Random padding requirement (prevents compression attacks)
  - Comprehensive security requirements section
  - Uniform error handling mandate
