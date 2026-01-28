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
//| FILE: GHOST_KEYS.md                                                                                                  |
//|======================================================================================================================|

# Ghost Keys

Silent Payment-style addresses for receiver privacy.

## Overview

Ghost Keys are the identity foundation of Ghost Pay, based on BIP-352 Silent Payments. They enable **unlinkable stealth addresses** where each payment creates a unique address that only the recipient can detect.

**Key property**: A single Ghost ID can receive unlimited payments, each to a different address, with no on-chain link between them.

## Why Ghost Keys?

Traditional Bitcoin addresses have privacy problems:

| Problem | Description |
|---------|-------------|
| Address reuse | Same address links all payments |
| Public addresses | Anyone can see all incoming payments |
| Donation tracking | Posted addresses reveal full history |

Ghost Keys solve this:
- Single ID, unlimited unique addresses
- No address reuse ever
- Only recipient can detect their payments

## Key Structure

### Private Keys (Secret)

```rust
struct GhostKeys {
    scan_secret: SecretKey,   // Used to detect incoming payments
    spend_secret: SecretKey,  // Used to spend received funds
}
```

- **Scan secret**: Needed to find payments addressed to you
- **Spend secret**: Needed to actually spend the funds

### Public Keys (Shareable)

```rust
struct GhostId {
    scan_pubkey: PublicKey,   // Shared publicly for receiving
    spend_pubkey: PublicKey,  // Shared publicly for receiving
}
```

## Ghost ID Format

Ghost IDs use bech32 encoding with the `ghost` human-readable part:

```
ghost1<bech32_encoded_scan_pubkey_spend_pubkey>

Example: ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
```

The encoded data is:
```
scan_pubkey (33 bytes) || spend_pubkey (33 bytes) = 66 bytes
```

### Comparison to Other Formats

| Format | Example | Privacy |
|--------|---------|---------|
| Legacy | 1BvBMSE... | Low (reused) |
| SegWit | bc1qw508... | Low (reused) |
| Ghost ID | ghost1qpzry... | High (unique each time) |

## Payment Derivation

When sending to a Ghost ID:

### Sender's Process

```
1. Generate ephemeral keypair (e, E = e*G)
   - Fresh random keypair for this payment only

2. Compute shared secret
   S = SHA256(e * scan_pubkey)
   - Only sender and recipient can compute this

3. Compute tweak
   t = SHA256(S || output_index || nonce)
   - Unique per output

4. Compute output pubkey
   P = spend_pubkey + t*G
   - This is the actual address

5. Create P2TR output to P
   - Standard Taproot output

6. Include ephemeral pubkey in OP_RETURN
   - GPGL marker + E (33 bytes)
```

### Why This Works

- Sender knows `e` (ephemeral secret), can compute `e * scan_pubkey`
- Recipient knows `scan_secret`, can compute `scan_secret * E`
- These are equal due to ECDH: `e * scan_pubkey = scan_secret * E`
- No one else can compute the shared secret

## Payment Detection (Scanning)

Recipient scans transactions to find payments:

### Scanning Process

```
1. Find OP_RETURN with GPGL marker
   - Look for Ghost Pay Ghost Lock marker

2. Extract ephemeral pubkey E

3. Compute shared secret
   S = SHA256(scan_secret * E)

4. For each output index:
   a. Compute tweak: t = SHA256(S || index || nonce)
   b. Compute expected pubkey: P = spend_pubkey + t*G
   c. Check if any output matches P

5. If match found:
   - Payment belongs to us
   - Derive spend key: spend_key = spend_secret + t
```

### Scanning Efficiency

| Method | Speed | Privacy |
|--------|-------|---------|
| Full node scan | Slow | Maximum |
| Light client hints | Fast | Reduced |
| Server-assisted | Fastest | Trust required |

## Spending Received Funds

Once a payment is detected:

```rust
// Derive the spend key for this specific output
fn derive_spend_key(
    spend_secret: &SecretKey,
    shared_secret: &[u8; 32],
    output_index: u32,
    nonce: &[u8],
) -> SecretKey {
    let tweak = tagged_hash("GhostPay/tweak",
        shared_secret || output_index || nonce);
    spend_secret + tweak
}

// Sign transaction with derived key
let spend_key = derive_spend_key(&keys.spend_secret, &S, index, &nonce);
let signature = spend_key.sign_schnorr(sighash);
```

## Unlinkability

Ghost Keys provide strong unlinkability:

### What's Hidden

| Property | Protected |
|----------|-----------|
| Recipient identity | Yes |
| Payment amount | No (visible on-chain) |
| Link between payments | Yes |
| Total received | Yes |

### What's Visible

- OP_RETURN with ephemeral key (common pattern)
- P2TR output (looks like any other Taproot)
- Transaction structure

### Why Unlinkable?

1. Each payment uses fresh ephemeral key
2. Derived address is unique each time
3. No correlation between payments to same Ghost ID
4. OP_RETURN pattern is common (not identifying)

## OP_RETURN Marker

Payments include an OP_RETURN for the ephemeral key:

```
OP_RETURN GPGL <version> <ephemeral_pubkey>

Where:
- GPGL: Ghost Pay Ghost Lock marker (4 bytes)
- version: Protocol version (1 byte)
- ephemeral_pubkey: Sender's ephemeral pubkey (33 bytes)
```

Total: 38 bytes (well under 80 byte limit)

## Multiple Outputs

A single transaction can pay multiple Ghost IDs:

```
Transaction:
├── Input: Sender's funds
├── Output 0: Payment to Ghost ID A (derived address A)
├── Output 1: Payment to Ghost ID B (derived address B)
├── Output 2: Change
└── OP_RETURN: GPGL + E (same ephemeral key for all)
```

Each recipient:
- Uses same ephemeral key E
- Computes their own shared secret
- Derives their specific output address
- Can only detect and spend their own output

## Key Backup

### Critical: Back Up Both Keys

```
Ghost Keys Backup:
├── scan_secret: Needed to FIND payments
└── spend_secret: Needed to SPEND funds

If you lose scan_secret:
└── Cannot detect new payments (funds may be unrecoverable)

If you lose spend_secret:
└── Can see payments but cannot spend them
```

### Backup Methods

| Method | Security | Convenience |
|--------|----------|-------------|
| Hardware wallet | High | Medium |
| Paper backup | High | Low |
| Encrypted file | Medium | High |
| Brain wallet | Low | High |

## View Keys (Advanced)

For accounting purposes, you can share the scan key:

```rust
struct ViewOnlyGhostKeys {
    scan_secret: SecretKey,   // Can detect payments
    spend_pubkey: PublicKey,  // Cannot spend (no secret)
}
```

Use cases:
- Accountant needs to see incoming payments
- Watch-only wallet
- Payment notification service

**Warning**: Anyone with scan_secret can see ALL your incoming payments.

## Integration Examples

### Receiving a Payment

```rust
// Generate Ghost Keys
let keys = GhostKeys::generate();
let ghost_id = keys.to_ghost_id();

println!("Send payments to: {}", ghost_id);
// ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...

// Scan for payments
for block in blockchain.blocks() {
    for tx in block.transactions() {
        if let Some(payment) = keys.scan_transaction(&tx) {
            println!("Received {} sats", payment.amount);
        }
    }
}
```

### Sending a Payment

```rust
// Parse recipient's Ghost ID
let recipient = GhostId::from_str("ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...")?;

// Create payment
let tx = TransactionBuilder::new()
    .add_ghost_output(&recipient, 100_000) // 100k sats
    .add_change_output(&my_address)
    .build()?;

broadcast(tx);
```

## Comparison to Other Privacy Tech

| Feature | Ghost Keys | Monero | Zcash |
|---------|------------|--------|-------|
| Receiver privacy | Yes | Yes | Yes |
| Amount hidden | No | Yes | Yes |
| Bitcoin compatible | Yes | No | No |
| Scanning required | Yes | Yes | No |
| Trusted setup | No | No | Yes |

## Related Documentation

- [Ghost Locks](GHOST_LOCKS.md) - UTXO format using Ghost Keys
- [Ghost Pay](GHOST_PAY.md) - L2 network with Ghost Keys
- [Wraith Protocol](WRAITH_PROTOCOL.md) - Mixing for entry privacy
