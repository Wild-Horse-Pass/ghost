# Elder System

*The first 101 nodes to register become Elders — with permanent bonus rewards and recognition.*

## Overview

The Elder System rewards early adopters who help bootstrap the Ghost network. It's simple:

:::highlight 101
Elder slots — first come, first served
:::

Elders receive a permanent +1 share bonus in the node reward system. This bonus lasts forever, as long as you maintain your node.

:::info Why 101?
101 is enough to establish a robust initial network while remaining exclusive enough to reward true early adopters. It's also a prime number, which has a nice aesthetic quality.
:::

## Selection Process

Elder selection happens automatically during the network launch:

1. **Node Registration** — You install Ghost Node and it generates your unique 32-byte Node ID. Your node registers with the network.
2. **Timestamp Recording** — Your registration timestamp is cryptographically signed and broadcast to all nodes.
3. **Ordering** — Nodes are ordered by (timestamp, hash(node_id)) for deterministic tie-breaking.
4. **Elder Assignment** — Once 101 nodes have registered, the Elder list is frozen. Positions 1-101 are assigned.

### Deterministic Selection

The selection is fully deterministic — all nodes calculate the same Elder list from the same data. There's no central authority deciding who becomes an Elder.

### One-Time Event

Elder selection happens only once, at network launch. Once 101 Elders are assigned, the list is permanent. New nodes cannot become Elders.

## Benefits

Elders receive a permanent +1 share in the node reward system:

| Share Type | Regular Node | Elder Node |
| --- | --- | --- |
| Archive Mode | +5 | +5 |
| Ghost Pay | +4 | +4 |
| Public Mining | +3 | +3 |
| Reaper | +2 | +2 |
| Elder Status | — | +1 |
| **Maximum Total** | **14** | **15** |

### Economic Impact

The +1 Elder share means ~7.1% more rewards compared to an identical non-Elder node (assuming max shares). Over time, this adds up significantly.

### Recognition

Elders are visible on the network dashboard with their rank (1-101). It's a permanent mark of being an early supporter.

## Requirements

To become an Elder, you must:

1. **Register early** — Be one of the first 101 nodes to register
2. **Stay online** — Maintain uptime after registration
3. **Run a valid node** — Full sync, passing health checks

There's no payment, no application, no approval process. Just be early and run a good node.

:::callout Current Status
The Elder Genesis Event has occurred. 4 Elder nodes are currently active (out of 101 maximum). 97 slots remain for new Elders. Check the [Network page](/pool.html) for the latest status.
:::

## Revocation

Elder status can be **permanently lost** if you fail to maintain your node:

:::warning 7-Day Rule
If your Elder node is offline for **7 continuous days**, your Elder status is permanently revoked. No exceptions. No appeals.
:::

### How Revocation Works

1. Your node stops sending health pings
2. Other nodes track your downtime
3. After 7 days, any node can propose revocation
4. 67% of active nodes must witness/confirm
5. Revocation is recorded permanently

### Slots Are Not Refilled

When an Elder is revoked, their slot is **not** given to someone else. The total number of Elders decreases permanently. This means:

- Starting with 101 Elders
- If 5 are revoked → 96 Elders remain
- Those 96 share the Elder pool among fewer nodes
- Remaining Elders get slightly more

### Why So Strict?

The 7-day rule ensures Elders are active participants, not just early claimers who abandon the network. It also creates urgency — if you want Elder status, you must commit to running infrastructure.

## FAQ

### Can I buy Elder status?

No. Elder status is non-transferable and non-purchasable. It's tied to a specific Node ID that you generate.

### What if I need to migrate my node?

You can migrate your node to new hardware as long as you preserve your Node ID and the keypair that signed your Elder registration. Back up your node's data directory (the SQLite database under `~/.ghost/` and any key material in your config). If you lose those keys, you lose your Elder status — there is no recovery path.

:::info "ghostnode.dat"
The dashboard UI sometimes refers to a `ghostnode.dat` label, but the node itself does not write a single file by that name. The authoritative state lives in the node's SQLite database and config directory.
:::

### Can I run multiple Elder nodes?

Technically yes, if you register multiple nodes in the first 101. But each node requires separate infrastructure and must maintain uptime independently.

### What if I'm offline for 6 days?

You're fine. The rule is 7 *continuous* days. If you come back online after 6 days, the counter resets.

### How do I check my Elder status?

Your node dashboard shows your Elder status, rank, and current uptime. You can also check the [Network page](/pool.html) for the full Elder registry.

### Is Elder status really permanent?

Yes, barring revocation for the 7-day downtime rule. There's no expiration, no renewal, no governance vote that can remove you.
