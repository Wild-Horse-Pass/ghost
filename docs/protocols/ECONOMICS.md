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
//| FILE: ECONOMICS.md                                                                                                   |
//|======================================================================================================================|

# Economics

Fee structure, treasury management, and reward distribution.

## Overview

Bitcoin Ghost uses a carefully designed economic model that:
- Rewards miners proportionally to work submitted
- Incentivizes node operators to run valuable infrastructure
- Funds ongoing development via a decaying treasury
- Distributes L2 fees to nodes running Ghost Pay

## Block Reward Distribution

When a block is found:

```
Block Reward = Subsidy + TX Fees

Subsidy Distribution:
├── Pool Fee (1% of subsidy)
│   ├── Treasury Allocation (0.5% of subsidy)
│   └── Node Reward Pool (0.5% of subsidy)
└── Miner Pool (99% of subsidy)
    └── Distributed to miners proportional to work

TX Fees:
└── 100% to node operator (whoever built the block)
```

### Example (3.125 BTC Block)

```
Subsidy:           312,500,000 sats (3.125 BTC)
TX Fees:            10,000,000 sats (0.1 BTC)

Pool Fee (1%):       3,125,000 sats
├── Treasury:        1,562,500 sats (0.5%)
└── Node Rewards:    1,562,500 sats (0.5%)

Miner Pool (99%): 309,375,000 sats

Coinbase Outputs:
├── Node Operator:   10,000,000 sats (TX fees)
├── Treasury:         1,562,500 sats
├── Top 100 Nodes:    1,562,500 sats (divided by shares)
└── Top 200 Miners: 309,375,000 sats (divided by work)
```

## Treasury

The treasury funds ongoing development and maintenance.

### Parameters

| Parameter | Value |
|-----------|-------|
| Address | Controlled by Bitcoin Ghost team |
| Threshold | 21 BTC |
| Pre-threshold rate | 0.5% of block subsidy |
| Decay period | 5 years |

### Treasury Decay

Once the treasury reaches 21 BTC, allocation begins decreasing:

| Year | Treasury Rate | Node Rate | Total Pool Fee |
|------|---------------|-----------|----------------|
| Pre-threshold | 0.5% | 0.5% | 1.0% |
| Year 1 | 0.4% | 0.6% | 1.0% |
| Year 2 | 0.3% | 0.7% | 1.0% |
| Year 3 | 0.2% | 0.8% | 1.0% |
| Year 4 | 0.1% | 0.9% | 1.0% |
| Year 5+ | 0.0% | 1.0% | 1.0% |

After 5 years, the full 1% pool fee goes to node rewards.

### Rationale

- Early stage: Treasury funds development
- Mature stage: Nodes are rewarded for infrastructure
- 21 BTC cap: Prevents excessive accumulation
- 5-year decay: Gradual transition to decentralized funding

## Node Reward Pool (5-4-3-2-1 System)

Nodes earn shares based on the services they provide:

| Capability | Shares | Verification Method |
|------------|--------|---------------------|
| Archive Mode | +5 | Random block retrieval challenges |
| Ghost Pay | +4 | L2 block lookup challenges |
| Public Mining | +3 | Stratum port accessibility |
| Bitcoin Pure | +2 | Policy challenge (tx classification) |
| Elder Status | +1 | First 101 nodes, still active |

**Maximum shares**: 15 (5+4+3+2+1)

### Gatekeeper Requirement

**95% uptime over trailing 7 days required for ANY shares.**

This prevents nodes from gaming the system by only being online during profitable periods.

### Distribution

- Top 100 nodes by total shares get paid in each block's coinbase
- Payment is proportional to shares held
- Example: Node with 15 shares gets 15/total_shares of pool

```
Example Distribution:
├── Total node pool: 1,562,500 sats
├── Total shares in top 100: 1,200 shares
├── Node A (15 shares): 19,531 sats (15/1200 × 1,562,500)
├── Node B (10 shares): 13,021 sats (10/1200 × 1,562,500)
└── Node C (8 shares):  10,417 sats (8/1200 × 1,562,500)
```

### Node Reward Ledger

Nodes not in the top 100 still accumulate balances:

```
Each Block:
├── Top 100 nodes: Paid in coinbase (balance zeroed)
└── Nodes 101+: Balance accumulates in ledger

Accumulating Balance Payout:
├── When node enters top 100: Full balance paid
└── When balance > dust threshold: Included in periodic batch
```

## Miner Payouts

### Work-Proportional Distribution

Miners receive 99% of block subsidy, distributed by shares submitted:

```
miner_payout = (miner_shares / total_shares) × miner_pool
```

### Coinbase Limits

| Output Type | Max Count |
|-------------|-----------|
| TX Fees | 1 |
| Treasury | 1 |
| Node Rewards | 100 |
| Miner Payouts | 200 |
| **Total** | **301** |

### Miner Ledger

Similar to nodes, miners outside top 200 accumulate:

```
Each Block:
├── Top 200 miners: Paid in coinbase (balance zeroed)
└── Miners 201+: Balance accumulates in ledger

Example:
├── Miner A: 5% of work, rank #50 → Paid every block
├── Miner B: 0.01% of work, rank #300 → Accumulates
├── Miner B accumulates 50,000 sats over 100 blocks
└── Miner B enters top 200 → Gets full accumulated balance
```

## Dust Threshold

**Minimum payout: 546 satoshis**

- Below dust: Balance accumulates in ledger
- Above dust: Paid in next block coinbase (if in top 200/100)

This prevents creating uneconomical UTXOs.

## L2 Fee Distribution

Ghost Pay L2 generates fees from:
- Transfers: 10 sats + 0.1%
- Wraith mixing: 1% (L1 tx fees deducted)
- Reconciliation: Batch settlement fees

### L2 Fee Split

```
L2 Fee Income
     │
     ├──► Ghost Pay Node Reward Pool
     │    Pre-threshold: 50%
     │    Post-decay: 100%
     │
     └──► Treasury
          Pre-threshold: 50%
          Post-decay: 0%
```

**Important**: Only nodes with Ghost Pay capability (+4 shares) receive L2 fee distributions.

### Example (Pre-threshold)

```
Wraith fees collected: 100,000 sats
├── Ghost Pay nodes: 50,000 sats (split among +4 nodes)
└── Treasury: 50,000 sats
```

### Example (Post-decay)

```
Wraith fees collected: 100,000 sats
└── Ghost Pay nodes: 100,000 sats (treasury gets nothing)
```

## Elder System

The first 101 nodes to register get Elder status (+1 share).

### Rules

| Parameter | Value |
|-----------|-------|
| Max Elders | 101 |
| Assignment | FIFO by registration timestamp |
| Ordering | SHA256(timestamp \|\| node_id) |
| Revocation | 67% BFT vote if offline ≥7 days |
| Burned Slots | Revoked numbers NEVER reassigned |

### Purpose

- Rewards early adopters who bootstrap the network
- Creates incentive to run nodes from day one
- Limited supply (only 101 ever) creates scarcity

## Challenge Verification

Nodes verify each other's capabilities:

| Parameter | Value |
|-----------|-------|
| Verification Interval | 300 seconds (5 minutes) |
| Challenge Timeout | 10 seconds |
| Nodes Verified Per Round | 3 nodes |
| Min Challenges for Qualification | 10 |

| Capability | Pass Rate Required |
|------------|-------------------|
| Archive Mode (+5) | 95% |
| Ghost Pay (+4) | 90% |
| Public Mining (+3) | 95% |
| Bitcoin Pure (+2) | 95% |

Failing challenges = losing shares = losing income.

## Economic Incentives Summary

| Actor | Incentive | How Earned |
|-------|-----------|------------|
| Miners | 99% of subsidy | Submit valid shares |
| Node operators | TX fees | Build blocks with transactions |
| Service providers | Node shares | Run Archive/GhostPay/etc |
| Early adopters | Elder bonus | Be among first 101 nodes |
| Treasury | Development funding | 0.5% (decaying) of subsidy |

## Related Documentation

- [Mining Pool](MINING_POOL.md) - How mining and shares work
- [Node Capabilities](NODE_CAPABILITIES.md) - Detailed capability requirements
- [Consensus](CONSENSUS.md) - How nodes agree on payouts
