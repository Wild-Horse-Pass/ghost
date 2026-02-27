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
//| FILE: JUMP_LOCKS.md                                                                                                  |
//|======================================================================================================================|
```

# Jump Locks

Risk-tiered automatic key rotation for proactive security.

## Overview

Jump Locks extend Ghost Locks with automatic key rotation based on the balance at risk. Higher-value locks rotate more frequently, reducing the window of opportunity for key compromise attacks.

```
Before Jump:  GhostLock(old_keys, balance)
              ↓
Jump TX:      old_lock → new_lock (atomic)
              ↓
After Jump:   GhostLock(fresh_keys, same_balance)
```

## Why Key Rotation?

The longer a key exists, the more opportunities for compromise:
- Side-channel attacks accumulate information over time
- Malware might capture keys gradually
- Physical access risks increase with time

Jump Locks provide **proactive security** by regularly refreshing keys before any compromise window grows too large.

## Risk Tiers

Rotation frequency is based on the balance at risk:

| Tier | Balance Threshold | Rotation Period | Rationale |
|------|-------------------|-----------------|-----------|
| Low | < 0.1 BTC | 30 days | Minimal risk, infrequent rotation |
| Medium | 0.1 - 1 BTC | 14 days | Moderate risk, regular rotation |
| High | > 1 BTC | 7 days | High risk, frequent rotation |

### Tier Selection Logic

```rust
fn risk_tier_from_balance(sats: u64) -> JumpRiskTier {
    match sats {
        0..=9_999_999 => JumpRiskTier::Low,        // < 0.1 BTC
        10_000_000..=99_999_999 => JumpRiskTier::Medium,  // 0.1 - 1 BTC
        _ => JumpRiskTier::High,                   // > 1 BTC
    }
}
```

## Jump Process

### Step-by-Step

```
1. Check if approaching jump deadline
   - deadline = creation_height + rotation_blocks

2. Generate fresh Ghost Lock
   - New lock_pubkey (fresh keypair)
   - Same or new recovery_pubkey (optional refresh)
   - Same denomination
   - Reset creation_height to current

3. Create atomic swap transaction
   - Input: old Ghost Lock (key path spend)
   - Output: new Ghost Lock
   - Single transaction = atomic

4. Broadcast and confirm
   - Old lock spent via key path (efficient, private)
   - New lock created with fresh keys

5. Update wallet state
   - Archive old keys
   - Activate new keys
   - Reset rotation timer
```

### Transaction Structure

```
Jump Transaction:
├── Input: old_ghost_lock (key path spend)
├── Output: new_ghost_lock (fresh keys)
└── Fee: Paid from lock balance (minimal for P2TR)
```

## Scheduling

### Deadline Calculation

```rust
fn calculate_jump_deadline(lock: &GhostLock, current_height: u32) -> u32 {
    let tier = JumpRiskTier::from_sats(lock.denomination.sats());
    lock.creation_height + tier.rotation_blocks()
}

impl JumpRiskTier {
    fn rotation_blocks(&self) -> u32 {
        match self {
            JumpRiskTier::Low => 144 * 30,    // 30 days (~4,320 blocks)
            JumpRiskTier::Medium => 144 * 14, // 14 days (~2,016 blocks)
            JumpRiskTier::High => 144 * 7,    // 7 days (~1,008 blocks)
        }
    }
}
```

### Grace Period

Jumps should be executed **before** the deadline:

| Timing | Action |
|--------|--------|
| > 7 days before deadline | No action needed |
| 3-7 days before | Start preparing jump |
| 1-3 days before | Execute jump (recommended) |
| At deadline | Jump urgently |
| Past deadline | Jump immediately (degraded security) |

## Wallet Integration

### Automatic Jumps

Wallet software handles jumps automatically:

```rust
async fn background_jump_checker(wallet: &Wallet) {
    loop {
        let current_height = get_block_height().await;

        for lock in wallet.active_locks() {
            let deadline = calculate_jump_deadline(&lock, current_height);
            let grace_period = 144 * 3; // 3 days

            if current_height + grace_period >= deadline {
                execute_jump(wallet, &lock).await;
            }
        }

        sleep(Duration::from_secs(600)).await; // Check every 10 minutes
    }
}
```

### Manual Jumps

Users can also trigger jumps manually:
- Suspected key compromise
- Moving to new hardware wallet
- Upgrading security practices

## Benefits

### Security

1. **Proactive**: Keys rotate before compromise window grows
2. **Balance-aware**: Higher stakes get more frequent rotation
3. **Automatic**: No user intervention required
4. **Atomic**: Old → New is single transaction, no fund exposure

### Privacy

1. **Fresh keys**: Each jump creates unlinkable new lock
2. **Indistinguishable**: Jump tx looks like normal P2TR spend
3. **No metadata**: Chain observers can't identify jumps
4. **Wraith Jump sessions**: For maximum unlinkability, key rotation can be performed through a Wraith mixing session (SessionType::Jump) at mining cost only — no service fee. This breaks any chain analysis linking old and new keys through the CoinJoin anonymity set (140-500 participants).

### Usability

1. **Transparent**: Wallet handles everything
2. **Non-interactive**: No coordination with others required
3. **Predictable**: Known rotation schedule

## Fee Considerations

Jump transactions have minimal fees:
- P2TR key path spend: ~1 input vbyte
- P2TR output: ~43 output vbytes
- Total: ~110 vbytes typical

At 10 sat/vbyte: ~1,100 sats per jump

### Wraith Jump Sessions

For maximum privacy, jumps can be routed through a Wraith mixing session instead of a direct on-chain transaction. Wraith Jump sessions charge **zero service fee** — only the mining cost share (~3,000-7,000 sats depending on tier and fee rate). This provides CoinJoin-level unlinkability for key rotation at near-cost.

| Method | Fee | Privacy |
|---|---|---|
| Direct jump (on-chain) | ~1,100 sats | Good (looks like normal P2TR spend) |
| Wraith Jump session | ~3,000-7,000 sats | Maximum (CoinJoin anonymity set) |

### Fee Budgeting

For a 1 BTC lock with 7-day rotation:
- ~52 jumps per year
- ~57,200 sats/year in fees
- ~0.06% annual cost

## Edge Cases

### Insufficient Balance for Fee

If lock balance is too low for jump fee:
- Wallet warns user
- User must either:
  - Add funds to cover fee
  - Accept reduced security (delayed jump)
  - Consolidate with other locks

### Network Congestion

During high-fee periods:
- Extend grace period
- Jump anyway if deadline imminent
- Use RBF to bump fee if stuck

### Offline Wallet

If wallet is offline when jump is due:
- Recovery timelock provides safety net
- Jump immediately upon reconnection
- Consider longer rotation period if frequently offline

## Comparison: Jump vs Regular Ghost Lock

| Feature | Ghost Lock | Jump Lock |
|---------|------------|-----------|
| Key rotation | Manual | Automatic |
| Security model | Static keys | Rotating keys |
| Fees | One-time | Periodic |
| Privacy | Good | Better (fresh keys regularly) |
| Complexity | Simple | Slightly more complex |

## Implementation Notes

### Key Archival

After a jump, old keys should be:
1. Archived (not deleted) for historical signing if needed
2. Marked as spent in wallet
3. Eventually purged after sufficient confirmations

### Recovery Key Handling

Options for recovery key during jumps:
1. **Keep same**: Simpler, recovery key is truly cold
2. **Rotate too**: Maximum security, more key management

Recommended: Rotate recovery key annually, not with every jump.

## Related Documentation

- [Ghost Locks](GHOST_LOCKS.md) - The underlying lock structure
- [Ghost Pay](GHOST_PAY.md) - L2 network where jumps occur
- [Reconciliation](RECONCILIATION.md) - How jumps interact with settlement
