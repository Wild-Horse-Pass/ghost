# Consensus & Protocol

*How Ghost nodes reach agreement on shares, payouts, and Elder status without centralization.*

## Overview

Ghost uses a decentralized consensus mechanism to coordinate mining pool operations across all nodes. Key consensus types:

- **Share Consensus** — Agreement on valid shares during a round
- **Payout Consensus** — Agreement on reward distribution when block found
- **Elder Consensus** — Agreement on Elder status and revocation
- **Treasury Consensus** — Agreement on treasury threshold and decay state

:::info Byzantine Fault Tolerant
Ghost consensus tolerates up to 33% malicious nodes. The system requires 67% supermajority for critical decisions, ensuring honest nodes always win.
:::

## Network Topology

Ghost uses a **full mesh network** where every node connects to every other node:

```text
Ghost Network (Full Mesh)

    Node A ◄────► Node B
       ▲            ▲
       │            │
       ▼            ▼
    Node D ◄────► Node C
```

### Port Assignments

| Port | Purpose | Pattern |
| --- | --- | --- |
| 8555 | Share Propagation | PUB/SUB |
| 8556 | Block Announcements | PUB/SUB |
| 8557 | Consensus Voting | DEALER/ROUTER |
| 8558 | Health Monitoring | PUB/SUB |
| 8559 | Discovery Service | REQ/REP |
| 8560 | Elder Management | PUB/SUB |

## ZMQ Protocol

Ghost uses ZeroMQ for low-latency peer-to-peer communication:

### Why ZMQ?

- **Low latency** — 1-50ms vs 50-200ms for libp2p
- **Proven reliability** — Used by Bitcoin Core
- **Multiple patterns** — PUB-SUB, DEALER-ROUTER, REQ-REP
- **Simple implementation** — Easy to debug

### Message Format

```bash
GhostMessage {
  version: u8,              // Protocol version
  msg_type: MessageType,    // Share, Block, Vote, etc.
  timestamp: u64,           // Unix timestamp (ms)
  sender_id: [u8; 32],      // Node ID
  payload: Vec<u8>,         // Serialized message
  signature: Vec<u8>,       // secp256k1 signature
}
```

All messages are signed with secp256k1 signatures to prevent forgery.

## Share Consensus

How nodes agree on valid shares:

### Share Validation Rules

1. Hash meets pool difficulty target
2. Derived from valid block template
3. Timestamp within 30 seconds
4. Node signature valid
5. Not a duplicate

### Propagation Flow

```bash
Miner submits share to Node A
        ↓
Node A validates locally
        ↓
Node A broadcasts ShareProof (port 8555)
        ↓ (1-50ms)
All nodes receive via SUB socket
        ↓
Each node validates independently
        ↓
Each node adds to local share ledger
```

### Merkle Commitment

Every 60 seconds, nodes broadcast a commitment of their share ledger:

```bash
ShareCommitment {
  node_id: [u8; 32],
  round_id: [u8; 32],
  merkle_root: [u8; 32],    // Root of share tree
  share_count: u64,
  signature: Vec<u8>,
}
```

If merkle roots don't match, nodes sync their differences.

## Payout Consensus

When a block is found, nodes must agree on payouts:

### Consensus Flow

```bash
Block found by Node A
        ↓
Node A submits block to Bitcoin network (immediate)
        ↓
Node A broadcasts BlockFound (port 8556)
        ↓
All nodes freeze share ledgers
        ↓
All nodes calculate PayoutProposal
        ↓ (1-2 seconds)
All nodes broadcast proposals (port 8561)
        ↓
All nodes vote on proposals (port 8557)
        ↓ (5 second timeout)
67% consensus reached → PayoutTransaction created
        ↓
OR no 67% → median calculation used
```

### 67% Supermajority

Payout proposals require 67% agreement. If achieved:

- Winning proposal is accepted
- Finding node creates payout transaction
- All nodes verify and relay to Bitcoin network

### Median Fallback

If no proposal gets 67%, nodes calculate the median:

- For each miner, take median of all proposed amounts
- For each node, take median of all proposed rewards
- Use median values as the consensus payout

This ensures payouts always happen, even without perfect agreement.

## Byzantine Fault Tolerance

Ghost consensus is designed to resist Byzantine (malicious) nodes:

### Safety Guarantees

| Property | Guarantee |
| --- | --- |
| Share Consensus | All honest nodes agree on valid shares if 67% are honest |
| Payout Consensus | Correct payouts enforced by honest majority |
| Elder Consensus | Elder list immutable, revocation requires 67% witness |
| Liveness | System never deadlocks (median fallback) |

### Cryptographic Security

- **secp256k1 signatures** — All messages authenticated
- **Merkle proofs** — Share inclusion verifiable
- **Hash chains** — State history tamper-proof

## Attack Resistance

### Fake Shares Attack

**Attack:** Malicious node broadcasts invalid shares.

**Defense:** All nodes validate shares independently. Invalid shares are rejected. Repeated violations → peer banned.

### Payout Manipulation Attack

**Attack:** Malicious nodes propose inflated payouts for themselves.

**Defense:** 67% honest majority overrules bad proposals. Median fallback prevents deadlock.

### Elder Sybil Attack

**Attack:** Attacker registers many nodes to dominate Elder slots.

**Defense:** Only first 101 nodes become Elders. One-time event at launch. Deterministic ordering by (timestamp, hash) prevents manipulation.

### Network Partition Attack

**Attack:** Attacker splits network to cause disagreement.

**Defense:** Full mesh topology with multiple connection paths. Periodic state verification. Self-healing when partition heals.

:::warning 33% Limit
If more than 33% of nodes are malicious, consensus guarantees break down. This is a fundamental limit of BFT systems. Ghost relies on economic incentives (node rewards) to keep the majority honest.
:::
