# Economics Deep-Dive

*Complete breakdown of Ghost's economic model — share formulas, payout math, treasury mechanics, and the path to ossification.*

## Overview

Ghost economics are designed around three principles:

1. **Miners first** — 99% of subsidy + 100% of fees go to miners
2. **Sustainable node incentives** — Behavior-based rewards, not speculation
3. **Path to zero governance** — Treasury decays to 0%, system ossifies

:::info No New Token
Ghost introduces no new token. All rewards come from Bitcoin block subsidies and transaction fees. There's no inflation, no pre-mine, no ICO.
:::

## Pool Fee Structure

Ghost Pool charges a **fixed 1% fee on the block subsidy only**. Transaction fees are never touched.

### Fee Distribution

```text
pool_fee = block_subsidy × 0.01
Currently: 3.125 BTC × 0.01 = 0.03125 BTC per block
```

The 1% fee is split between Treasury and Node Reward Pool:

| Phase | Treasury | Node Reward Pool |
| --- | --- | --- |
| Before 21 BTC threshold | 0.5% | 0.5% |
| Year 1 of decay | 0.4% | 0.6% |
| Year 2 of decay | 0.3% | 0.7% |
| Year 3 of decay | 0.2% | 0.8% |
| Year 4 of decay | 0.1% | 0.9% |
| Year 5+ (ossified) | 0% | 1.0% |

## Miner Payouts

### Subsidy Distribution

Miners receive 99% of the block subsidy, distributed by hashrate contribution:

```text
miner_subsidy = (miner_shares / total_round_shares) × (block_subsidy × 0.99)
Where miner_shares = shares submitted by this miner this round
```

### Transaction Fees

The miner whose share found the block receives **100% of transaction fees**:

```text
winning_miner_total = miner_subsidy + block_tx_fees
Only the block-finding miner gets block_tx_fees
```

:::info Why TX fees to winning miner?
The node that builds the template chooses which transactions to include. Giving them 100% of fees incentivizes building high-fee templates. This is unlike traditional pools that split fees across all miners.
:::

## Node Share System

Nodes earn 0-15 shares based on behavior. Shares determine your portion of the Node Reward Pool. The Gatekeeper prerequisite (95% uptime over 7 days) must be met before any shares are awarded.

### Share Types

| Share Type | Points | Requirement |
| --- | --- | --- |
| Archive Mode | +5 | Store full blockchain history |
| Ghost Pay | +4 | Process Ghost Pay settlements |
| Public Mining | +3 | Accept public Stratum connections |
| Reaper | +2 | Run Reaper dead-code policy: reject excess witness data, oversized OP_RETURNs, drop-script abuse, and other non-financial bloat — verified by random policy challenges |
| Elder Status | +1 | One of first 101 nodes |
| **Maximum** | **15** | |

### Node Reward Formula

```text
node_reward = (your_shares / total_network_shares) × node_reward_pool
Where node_reward_pool = block_subsidy × (0.005 to 0.01)
```

### Example Calculation

If you have 12 shares and the network has 1000 total shares:

```text
node_reward = (12 / 1000) × 0.015625 BTC = 0.0001875 BTC
Per block, assuming 0.5% pool fee allocation to nodes
```

## Treasury & Decay

### Treasury Threshold

The Treasury accumulates until it reaches **21 BTC**. This is a hard cap — once reached, the decay begins automatically.

```text
treasury_allocation = block_subsidy × 0.005 (until 21 BTC reached)
At current subsidy: 0.015625 BTC per block → ~134 blocks/day → ~42 days to 1 BTC
```

### 5-Year Decay

Once 21 BTC is reached, Treasury allocation decays over 5 years:

- Y1: 0.4%
- Y2: 0.3%
- Y3: 0.2%
- Y4: 0.1%
- Y5+: 0%

- Treasury allocation
- Ossified (no treasury)

### Treasury Usage

Treasury funds can only be used for:

- Development and engineering
- Security audits
- Infrastructure costs
- Legal and operational requirements

There is no governance voting or political mechanism. Treasury usage is pre-defined and transparent.

## Ossification

After the 5-year decay completes, Ghost enters its **final state**:

| Parameter | Final Value |
| --- | --- |
| Pool Fee | 1% (unchanged) |
| Treasury Allocation | 0% |
| Node Reward Pool | 1% |
| Governance | Dissolved |

In the ossified state:

- No more development funding
- No more governance decisions
- No more changes to economic parameters
- Ghost becomes permanent, neutral infrastructure

:::info Why Ossification?
Governance is a liability. By designing Ghost to become governance-free, we eliminate the risk of capture, politics, and drift from original principles. The system simply runs, forever, as designed.
:::

## Worked Examples

### Example 1: Block Found

A block is found with 3.125 BTC subsidy and 0.5 BTC in fees. The round had 10,000 miner shares.

```text
Pool fee:         3.125 × 0.01     = 0.03125 BTC
Treasury:         0.03125 × 0.5    = 0.015625 BTC  
Node Reward Pool: 0.03125 × 0.5    = 0.015625 BTC
Miner Pool:       3.125 × 0.99     = 3.09375 BTC

Miner A (1000 shares, block finder):
  Subsidy: (1000/10000) × 3.09375  = 0.309375 BTC
  TX Fees: 0.5 BTC
  Total:   0.809375 BTC

Miner B (500 shares):
  Subsidy: (500/10000) × 3.09375   = 0.1546875 BTC
  TX Fees: 0 (not block finder)
  Total:   0.1546875 BTC
```

### Example 2: Node Rewards

Network has 100 nodes with total 1200 shares. Your node has 14 shares.

```text
Node Reward Pool: 0.015625 BTC (per block)

Your reward: (14/1200) × 0.015625 = 0.000182 BTC per block

At 144 blocks/day:
  Daily:   0.000182 × 144 = 0.0262 BTC
  Monthly: 0.0262 × 30    = 0.786 BTC
```

### Example 3: Elder Advantage

Comparing Elder vs non-Elder node with same configuration (14 shares vs 15 shares):

```text
Network: 100 nodes, 1400 total shares

Non-Elder (14 shares): (14/1400) × 0.015625 = 0.00015625 BTC/block
Elder (15 shares):     (15/1400) × 0.015625 = 0.00016741 BTC/block

Elder advantage: ~7.1% more per block
```
