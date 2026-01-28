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
//| FILE: PRUNING.md                                                                                                     |
//|======================================================================================================================|

# Pruning

Data retention and cleanup policies for Ghost nodes.

## Overview

Ghost nodes accumulate significant data over time:
- Share submissions
- Challenge results
- Round history
- L2 state (if running Ghost Pay)

Pruning policies ensure nodes don't grow unbounded while preserving data needed for:
- Dispute resolution
- Audit trails
- Verification challenges

## Retention Tiers

| Data Type | Retention | Rationale |
|-----------|-----------|-----------|
| Active round data | Until confirmed | Needed for block building |
| Recent shares | 144 blocks (~1 day) | Dispute window |
| Round summaries | 1,008 blocks (~1 week) | Audit period |
| Challenge results | 4,320 blocks (~1 month) | Capability history |
| Payout records | 52,560 blocks (~1 year) | Tax/legal requirements |
| Archive blocks | Forever (if archive mode) | Full node capability |

## Share Data

### Active Shares

During a round, all share data is retained:

```
Active Round:
├── Full share proof (hash, nonce, difficulty)
├── Miner identity
├── Timestamp
├── Verification status
└── Propagation metadata
```

### Post-Confirmation

After a block is confirmed:

```
Confirmed Round (keep 144 blocks):
├── Share count per miner
├── Difficulty-weighted work
├── Block hash
└── Payout snapshot

Old Rounds (>144 blocks):
├── Round summary only
│   ├── Total shares
│   ├── Block hash
│   ├── Payout merkle root
│   └── Timestamp
└── Individual share data deleted
```

### Why 144 Blocks?

- Covers potential reorgs (extremely rare beyond 6 blocks)
- Allows dispute resolution
- ~1 day of history
- Reasonable storage overhead

## Challenge Results

Challenge data is needed for:
- Verifying node capabilities
- Historical pass rates
- Dispute resolution

### Retention Policy

```
Challenge Results:
├── Last 30 days: Full detail
│   ├── Challenge request
│   ├── Response data
│   ├── Pass/fail status
│   ├── Timing information
│   └── Verifier identity
│
└── Older than 30 days: Summary only
    ├── Pass rate
    ├── Challenge count
    └── Capability status
```

### Pass Rate Calculation

Only recent challenges count for capability qualification:

```rust
const CHALLENGE_WINDOW: u32 = 4320; // ~30 days in blocks

fn calculate_pass_rate(node_id: &[u8; 32], capability: Capability) -> f64 {
    let recent_challenges = db.query(
        "SELECT passed, total FROM challenges
         WHERE node_id = ? AND capability = ? AND height > ?",
        node_id, capability, current_height - CHALLENGE_WINDOW
    );

    recent_challenges.passed as f64 / recent_challenges.total as f64
}
```

## Round History

### Full Round Data

Retained for 1 week (1,008 blocks):

```
Round Record:
├── Block header
├── Coinbase transaction
├── All payout outputs
├── Share distribution
├── Node participation
└── Consensus votes
```

### Summary Data

Retained for 1 year:

```
Round Summary:
├── Round ID
├── Block hash
├── Height
├── Timestamp
├── Total subsidy
├── Total fees
├── Payout merkle root
└── Winner node ID
```

### Archive Data

If running archive mode, full blocks retained forever.

## L2 State (Ghost Pay)

Ghost Pay nodes have additional pruning requirements:

### Virtual Blocks

```
L2 Virtual Blocks:
├── Current epoch: Full state
├── Previous epoch: Full state (for verification)
├── Older epochs: State root only
└── Settlement TXs: Keep forever (on L1)
```

### Ghost Locks

```
Active Locks: Full detail
├── Lock pubkey
├── Recovery pubkey
├── Denomination
├── Creation height
├── Last activity

Spent Locks: Pruned after 144 L1 blocks
├── Keep TXID only
└── Delete key material
```

### Wraith Sessions

```
Active Sessions: Full state
├── Participants
├── Phase status
├── Blind signatures
└── Intermediate outputs

Completed Sessions: Summary after 7 days
├── Session ID
├── Participant count
├── Denomination
├── Completion status

Failed/Refunded Sessions: Delete after 30 days
```

## Database Maintenance

### Automatic Pruning

Pruning runs automatically:

```rust
// Run every 144 blocks (~1 day)
async fn prune_task(db: &Database) {
    let current_height = get_block_height().await;

    // Prune old shares
    db.execute(
        "DELETE FROM shares WHERE round_height < ?",
        current_height - SHARE_RETENTION_BLOCKS
    );

    // Prune old challenges (keep summaries)
    db.execute(
        "DELETE FROM challenge_details WHERE height < ?",
        current_height - CHALLENGE_DETAIL_RETENTION_BLOCKS
    );

    // Vacuum database
    db.execute("VACUUM");
}
```

### Manual Maintenance

Operators can trigger maintenance:

```bash
# Check database size
ghost-cli db stats

# Trigger pruning
ghost-cli db prune

# Vacuum (reclaim space)
ghost-cli db vacuum

# Export audit data before pruning
ghost-cli db export --from-height 800000 --to-height 810000
```

## Storage Requirements

### Minimum Node

Without archive mode:

| Component | Growth Rate | 1 Year Total |
|-----------|-------------|--------------|
| Share data | ~10 MB/day | ~1 GB (pruned) |
| Challenges | ~1 MB/day | ~12 MB (pruned) |
| Rounds | ~5 MB/day | ~100 MB (pruned) |
| **Total** | | **~1.5 GB** |

### Archive Node

With full archive mode:

| Component | Growth Rate | 1 Year Total |
|-----------|-------------|--------------|
| Blockchain | ~60 GB/year | ~650 GB total |
| Share data | Same as above | ~1 GB |
| Full history | ~50 MB/day | ~18 GB |
| **Total** | | **~670 GB** |

### Ghost Pay Node

With L2 enabled:

| Component | Growth Rate | 1 Year Total |
|-----------|-------------|--------------|
| Base node | | ~1.5 GB |
| L2 state | ~5 MB/day | ~2 GB |
| Wraith sessions | ~2 MB/day | ~100 MB (pruned) |
| **Total** | | **~4 GB** |

## Configuration

```toml
[pruning]
# Share retention (blocks)
share_retention = 144

# Challenge detail retention (blocks)
challenge_retention = 4320

# Round detail retention (blocks)
round_retention = 1008

# Payout record retention (blocks)
payout_retention = 52560

# Auto-prune interval (blocks)
prune_interval = 144

# Vacuum after pruning
auto_vacuum = true
```

## Compliance Considerations

### Audit Trail

For regulatory compliance:
- Payout records kept for 1 year minimum
- Can extend retention in config
- Export function for auditors

### Data Export

```bash
# Export all payouts for address
ghost-cli export payouts --address bc1q... --format csv

# Export round history
ghost-cli export rounds --from 2024-01-01 --to 2024-12-31

# Full audit export
ghost-cli export audit --year 2024
```

### GDPR Considerations

- Share data is pseudonymous (address-based)
- No personal information stored
- Miner can request data export
- Pruning naturally removes old data

## Recovery

### Lost Data

If pruned data is needed later:
- Recent data: Request from peer nodes
- Old data: May be unrecoverable
- Archive nodes: Full history available

### Backup Recommendations

```bash
# Daily backup of critical data
ghost-cli db backup --path /backup/ghost-$(date +%Y%m%d).db

# Weekly full backup
ghost-cli db backup --full --path /backup/ghost-full-$(date +%Y%m%d).db
```

## Related Documentation

- [Architecture](ARCHITECTURE.md) - System overview
- [Mining Pool](MINING_POOL.md) - Share handling
- [Node Capabilities](NODE_CAPABILITIES.md) - Archive mode requirements
