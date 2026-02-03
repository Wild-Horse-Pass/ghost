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
//| FILE: NODE_CAPABILITIES.md                                                                                           |
//|======================================================================================================================|

# Node Capabilities

The 5-4-3-2-1 share system for incentivizing valuable services.

## Overview

Nodes earn shares in the node reward pool based on the services they provide. More valuable services earn more shares:

| Capability | Shares | Description |
|------------|--------|-------------|
| Archive Mode | +5 | Full blockchain storage and retrieval |
| Ghost Pay | +4 | L2 payment network operation |
| Public Mining | +3 | Stratum port open to public miners |
| Bitcoin Pure | +2 | Transaction policy enforcement |
| Elder Status | +1 | First 101 nodes, still active |

**Maximum**: 15 shares (5+4+3+2+1)

## Gatekeeper: 95% Uptime

**Before any shares count, nodes must maintain 95% uptime over trailing 7 days.**

```
Uptime Calculation:
├── Expected heartbeats: 1 per 10 seconds = 60,480/week
├── Minimum received: 57,456 (95%)
└── Below 95%: No shares, no rewards
```

This prevents nodes from:
- Only running during profitable periods
- Gaming the share system
- Providing unreliable service

## Archive Mode (+5 Shares)

### What It Means

Store and serve the full Bitcoin blockchain:
- All blocks from genesis
- All transaction data
- Quick retrieval for any historical block

### Requirements

| Requirement | Value |
|-------------|-------|
| Storage | ~600GB+ (and growing) |
| Pruning | Disabled |
| Response time | <5 seconds per block |

### Verification

Random block retrieval challenges:

```
Challenge:
├── Verifier selects random block height
├── Requests block from target node
├── Target must return full block data
├── Verifier validates block hash

Pass Criteria:
├── Correct block returned
├── Response within timeout (10s)
└── 95% pass rate required
```

### Verification Endpoint

```
GET /api/v1/verify/archive?height=500000

Response:
{
    "block_hash": "000000000000000...",
    "block_data": "<hex>",
    "merkle_root": "...",
    "timestamp": 1234567890,
    "verified": true
}
```

## Ghost Pay (+4 Shares)

### What It Means

Run a Ghost Pay L2 node:
- Process L2 transfers
- Participate in reconciliation
- Maintain L2 state

### Requirements

| Requirement | Value |
|-------------|-------|
| Software | ghost-pay daemon |
| Network | L2 P2P connectivity |
| State | Current L2 state synced |

### Verification

L2 block lookup challenges:

```
Challenge:
├── Verifier requests L2 state at epoch N
├── Target returns state root and proof
├── Verifier validates against L1 anchor

Pass Criteria:
├── Correct state returned
├── Valid Merkle proof
├── Response within timeout
└── 90% pass rate required
```

### Verification Endpoint

```
GET /api/v1/verify/ghostpay

Response:
{
    "l2_running": true,
    "l2_height": 50000,
    "l2_synced": true,
    "active_locks": 10,
    "verified": true
}
```

## Public Mining (+3 Shares)

### What It Means

Accept connections from public miners:
- Stratum port accessible from internet
- Actually serving work to miners
- Not just localhost

### Requirements

| Requirement | Value |
|-------------|-------|
| Port | 3333 open to public |
| Protocol | SV1 Stratum |
| Capacity | Accept new connections |

### Verification

TCP probe and Stratum handshake:

```
Challenge:
├── Verifier connects to stratum port
├── Sends mining.subscribe
├── Expects valid response
├── Optionally sends mining.authorize

Pass Criteria:
├── Connection accepted
├── Valid Stratum response
├── <5 second response time
└── 95% pass rate required
```

### Verification Endpoint

```
GET /api/v1/verify/stratum

Response:
{
    "port_open": true,
    "stratum_port": 3333,
    "connected_miners": 50,
    "protocol": "SV1",
    "verified": true
}
```

## Bitcoin Pure (+2 Shares)

### What It Means

Enforce a BUDS policy (transaction filtering):
- Run with a policy profile
- Correctly classify transactions
- Reject policy-violating transactions

### Requirements

| Requirement | Value |
|-------------|-------|
| Policy | bitcoin_pure, permissive, or custom |
| Classification | Accurate BUDS labeling |
| Consistency | Same result for same transaction |

### Verification

Policy classification challenges:

```
Challenge:
├── Verifier sends test transaction
├── Transaction designed to test policy
├── Target must correctly accept/reject
├── Must identify correct BUDS labels

Pass Criteria:
├── Correct accept/reject decision
├── Correct label identification
├── Consistent with claimed policy
└── 95% pass rate required
```

### Verification Endpoint

```
POST /api/v1/verify/policy
Content-Type: application/json

{
    "test_tx": "0100000001...",
    "policy": "bitcoin_pure"
}

Response:
{
    "accepted": false,
    "rejected_labels": ["meta.inscription"],
    "arbda_score": 2,
    "policy_matched": true,
    "verified": true
}
```

## Elder Status (+1 Share)

### What It Means

Be among the first 101 nodes to register:
- Historical significance
- Network bootstrapping reward
- Limited availability (only 101 ever)

### Requirements

| Requirement | Value |
|-------------|-------|
| Registration | Among first 101 |
| Status | Still active |
| Uptime | Meet gatekeeper (95%) |

### Verification

No active verification needed - status is historical:

```
Verification:
├── Check elder registry
├── Confirm node ID matches
├── Confirm still meeting uptime
└── No challenges required
```

### Revocation

Elders can lose status:
- 67% BFT vote required
- Must be offline ≥7 continuous days
- **Burned slots**: Revoked elder numbers are NEVER reassigned

## Challenge Verification Parameters

| Parameter | Value |
|-----------|-------|
| Verification Interval | 300 seconds (5 minutes) |
| Challenge Timeout | 10 seconds |
| Nodes Verified Per Round | 2 nodes |
| Min Challenges for Qualification | 3 |

| Capability | Pass Rate Required |
|------------|-------------------|
| Archive Mode (+5) | 95% |
| Ghost Pay (+4) | 90% |
| Public Mining (+3) | 95% |
| Bitcoin Pure (+2) | 95% |

## Challenge Process

```
Every 5 minutes:
1. Node selects 3 random peers to verify
2. For each peer:
   a. Check which capabilities they claim
   b. Issue appropriate challenges
   c. Record pass/fail result
3. Results shared across pool
4. After 10 challenges, capability qualified if pass rate met
```

## Share Calculation Example

```
Node A:
├── Archive Mode: Yes (+5)
├── Ghost Pay: Yes (+4)
├── Public Mining: Yes (+3)
├── Bitcoin Pure: Yes (+2)
├── Elder #42: Yes (+1)
└── Total: 15 shares

Node B:
├── Archive Mode: No (0)
├── Ghost Pay: Yes (+4)
├── Public Mining: Yes (+3)
├── Bitcoin Pure: No (0)
├── Elder: No (0)
└── Total: 7 shares

Node C:
├── Archive Mode: Yes (+5)
├── Ghost Pay: No (0)
├── Public Mining: Yes (+3)
├── Bitcoin Pure: Yes (+2)
├── Elder: No (0)
└── Total: 10 shares
```

## Reward Distribution

Top 100 nodes by total shares receive rewards:

```
Node Reward Pool: 1,562,500 sats (0.5% of subsidy)

Total Shares in Top 100: 1,000 shares

Distribution:
├── Node A (15 shares): 23,437 sats (15/1000 × 1,562,500)
├── Node B (7 shares): 10,937 sats (7/1000 × 1,562,500)
├── Node C (10 shares): 15,625 sats (10/1000 × 1,562,500)
└── ...
```

## Capability Stacking

Capabilities stack multiplicatively with economics:

| Shares | % of 15 Max | Reward Multiple |
|--------|-------------|-----------------|
| 1 | 6.7% | 1x |
| 5 | 33% | 5x |
| 10 | 67% | 10x |
| 15 | 100% | 15x |

Running more services = more shares = more rewards.

## Configuration

```toml
[capabilities]
# Enable archive mode
archive_mode = true

# Enable Ghost Pay L2
ghost_pay = true

# Enable public mining (open stratum port)
public_mining = true

# Enable BUDS policy
policy_enabled = true
policy_profile = "bitcoin_pure"

# Elder status (cannot be configured, assigned at registration)
# elder_number = 42  # Read-only
```

## Monitoring

```bash
# Check capability status
ghost-cli capabilities status

# View challenge history
ghost-cli capabilities challenges

# Check current shares
ghost-cli capabilities shares

# View ranking
ghost-cli capabilities rank
```

## Troubleshooting

### Failing Archive Challenges

```
Symptom: Archive pass rate <95%
Causes:
├── Slow disk I/O
├── Database corruption
├── Network timeouts
Solutions:
├── Use SSD storage
├── Reindex blockchain
├── Increase timeout tolerance
```

### Failing Stratum Challenges

```
Symptom: Public Mining pass rate <95%
Causes:
├── Firewall blocking port
├── Too many connections
├── Stratum daemon issues
Solutions:
├── Check firewall rules
├── Increase connection limits
├── Restart stratum service
```

### Not Earning Shares

```
Symptom: 0 shares despite capabilities
Causes:
├── Uptime <95%
├── <10 challenges completed
├── Capability verification failing
Solutions:
├── Improve uptime
├── Wait for more challenges
├── Check verification endpoints
```

## Related Documentation

- [Economics](ECONOMICS.md) - How rewards are calculated
- [Consensus](CONSENSUS.md) - How challenges are coordinated
- [BUDS Policy](BUDS_POLICY.md) - Policy verification details
- [Pruning](PRUNING.md) - Archive mode requirements
