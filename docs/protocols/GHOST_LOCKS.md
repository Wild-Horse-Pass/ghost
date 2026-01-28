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
//| FILE: GHOST_LOCKS.md                                                                                                 |
//|======================================================================================================================|

# Ghost Locks

P2TR UTXOs with timelocked recovery paths for secure fund custody.

## Overview

Ghost Locks are the on-chain representation of funds in Ghost Pay. They use Taproot (P2TR) outputs with two spending paths:

1. **Key Path**: Efficient, private normal spending using the lock key
2. **Script Path**: Timelocked recovery using a backup key

This design ensures funds can always be recovered even if the primary key is lost, while maintaining privacy and efficiency for normal operations.

## Structure

```rust
struct GhostLock {
    lock_pubkey: XOnlyPublicKey,      // Key path spending (normal use)
    recovery_pubkey: XOnlyPublicKey,  // Script path recovery (emergencies)
    denomination: Denomination,        // Standard denomination tier
    timelock_tier: TimelockTier,      // Recovery timelock duration
    creation_height: u32,             // Block height when created
}
```

## P2TR Script Structure

```
Taproot Output:
├── Key Path: lock_pubkey (efficient, private normal spending)
└── Script Path:
    └── Recovery Leaf:
        <recovery_height> OP_CLTV OP_DROP
        <recovery_pubkey> OP_CHECKSIG
```

### Key Path (Normal Use)

- Single signature with `lock_pubkey`
- Most efficient spending (smallest witness)
- Reveals nothing about script structure
- Indistinguishable from regular P2TR spend

### Script Path (Recovery)

- Available after timelock expires
- Requires signature with `recovery_pubkey`
- Reveals the recovery script (but only when used)
- Emergency backup for lost keys

## Standard Denominations

Ghost Locks use standard denominations for privacy (all locks of the same tier look identical):

| Tier | Name | Amount | Use Case |
|------|------|--------|----------|
| Micro | Micro | 10,000 sats | Tiny payments |
| Tiny | Tiny | 100,000 sats | Small payments |
| Small | Small | 1,000,000 sats (0.01 BTC) | Regular payments |
| Medium | Medium | 10,000,000 sats (0.1 BTC) | Larger payments |
| Large | Large | 100,000,000 sats (1 BTC) | Big transfers |
| XL | Extra Large | 1,000,000,000 sats (10 BTC) | Whale transfers |

### Why Standard Denominations?

1. **Privacy**: All locks of the same denomination are indistinguishable
2. **Efficient Mixing**: Wraith protocol can batch same-denomination locks
3. **Predictable Fees**: Known sizes enable accurate fee estimation
4. **Anonymity Set**: More users at each tier = larger anonymity set

## Timelock Tiers

Recovery timelocks balance security vs. recovery time:

| Tier | Duration | Blocks | Use Case |
|------|----------|--------|----------|
| Short | 6 months | ~26,280 | Active users, frequent rotation |
| Standard | 1 year | ~52,560 | Default, balanced security |
| Long | 2 years | ~105,120 | Cold storage, maximum security |

Recovery becomes available at: `creation_height + timelock_blocks`

### Choosing a Timelock

- **Short (6 months)**: For actively used funds that you rotate frequently
- **Standard (1 year)**: Good default for most users
- **Long (2 years)**: For cold storage where you won't need emergency recovery soon

## Ghost Lock ID

Deterministic identifier for tracking locks:

```rust
fn ghost_lock_id(
    lock_pubkey: &XOnlyPublicKey,
    recovery_pubkey: &XOnlyPublicKey,
    creation_height: u32,
    denomination_sats: u64,
) -> [u8; 32] {
    tagged_hash("GhostLock/v1",
        lock_pubkey || recovery_pubkey || creation_height || denomination_sats)
}
```

This ID:
- Uniquely identifies each lock
- Deterministically computed by any party
- Used for L2 balance tracking
- Referenced in settlement transactions

## Creating a Ghost Lock

### From Public Bitcoin (via Wraith)

1. Enter Wraith mixing session with public UTXO
2. Complete two-phase mixing
3. Receive clean Ghost Lock as output

### From Existing Ghost Lock (Transfer)

1. Spend existing lock via key path
2. Create new lock with recipient's keys
3. Single transaction, instant on L2

### Key Generation

```rust
// Generate fresh keys for a new lock
let lock_keypair = KeyPair::generate();
let recovery_keypair = KeyPair::generate();  // Store securely offline

let lock = GhostLock {
    lock_pubkey: lock_keypair.x_only_public_key(),
    recovery_pubkey: recovery_keypair.x_only_public_key(),
    denomination: Denomination::Small,
    timelock_tier: TimelockTier::Standard,
    creation_height: current_height,
};
```

## Spending a Ghost Lock

### Normal Spending (Key Path)

```rust
// Create signature with lock key
let sighash = transaction.sighash_taproot(input_index);
let signature = lock_keypair.sign_schnorr(sighash);

// Witness: just the signature (64 bytes)
witness = [signature]
```

### Recovery Spending (Script Path)

```rust
// Only available after timelock expires
assert!(current_height >= creation_height + timelock_blocks);

// Create signature with recovery key
let sighash = transaction.sighash_taproot_script(input_index, recovery_script);
let signature = recovery_keypair.sign_schnorr(sighash);

// Witness: signature + script + control block
witness = [signature, recovery_script, control_block]
```

## Security Considerations

### Key Management

- **Lock key**: Can be hot (for active funds) or warm
- **Recovery key**: Should be cold storage (hardware wallet, paper backup)
- **Never reuse keys**: Each Ghost Lock should have fresh keys

### Recovery Key Best Practices

1. Generate offline on air-gapped device
2. Store in multiple secure locations
3. Test recovery process before depositing large amounts
4. Consider multisig for high-value recovery keys

### Timelock Considerations

- Shorter timelocks = faster recovery if lock key lost
- Longer timelocks = attacker has longer to crack your keys
- Balance based on your threat model and usage patterns

## Integration with Ghost Pay

Ghost Locks are the native unit of value in Ghost Pay L2:

1. **Deposits**: Create Ghost Lock on L1, register on L2
2. **Transfers**: Update L2 state, no L1 transaction needed
3. **Withdrawals**: Reconciliation batches L2 state to L1

### L2 Balance Tracking

```
L2 State:
├── Ghost Lock ID → Balance
├── Ghost Lock ID → Balance
└── ...
```

The L2 tracks ownership by Ghost Lock ID. Transfers update the state without touching L1 until reconciliation.

## Comparison with Other Approaches

| Feature | Ghost Lock | Lightning Channel | Liquid Peg |
|---------|------------|-------------------|------------|
| Recovery | Timelocked self-custody | Requires counterparty | Federation |
| Privacy | High (P2TR) | Medium | Medium |
| Denomination | Fixed tiers | Any amount | Any amount |
| Settlement | Batched | Per-channel | 2-way peg |
| Custody | Non-custodial | Non-custodial | Federated |

## Related Documentation

- [Jump Locks](JUMP_LOCKS.md) - Automatic key rotation for Ghost Locks
- [Wraith Protocol](WRAITH_PROTOCOL.md) - Private entry into Ghost Locks
- [Ghost Pay](GHOST_PAY.md) - L2 network using Ghost Locks
- [Reconciliation](RECONCILIATION.md) - L1 settlement of Ghost Locks
