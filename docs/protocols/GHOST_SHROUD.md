# Ghost Shroud

## Overview

Ghost Shroud adds a random delay (0-5 seconds) before relaying transactions to peers, preventing timing-based origin detection. When a node receives or creates a transaction, instead of relaying it immediately, the transaction is queued with a random future relay time. This breaks the timing correlation that network observers use to identify which node originated a transaction.

**Key properties:**
- Enabled by default on all Ghost Core nodes
- Mining is unaffected (transactions enter the mempool immediately)
- Configurable via `-shroud=0` to disable
- Zero impact on transaction validity or confirmation time

## How It Works

### Transaction Flow

```
Without Shroud:
  Node receives/creates tx → Relay immediately to all peers
  ↳ Observer sees: Node A relayed first → Node A is likely the origin

With Shroud:
  Node receives/creates tx → Add to mempool immediately
                            → Queue relay with random 0-5s delay
                            → Relay when delay expires
  ↳ Observer sees: Multiple nodes relay at similar times → Origin unclear
```

### Implementation

Ghost Shroud is implemented in `net_processing.cpp` with three components:

**1. Shroud Queue**

When shroud is enabled, `RelayTransaction()` queues transactions instead of relaying them directly:

```cpp
struct ShroudEntry {
    Txid txid;
    Wtxid wtxid;
    std::chrono::microseconds relay_at;  // When to actually relay
};

std::vector<ShroudEntry> m_shroud_queue;
```

Each entry gets a random delay between 0 and 5000 milliseconds:

```cpp
auto delay = FastRandomContext().randrange<std::chrono::milliseconds>(
    std::chrono::milliseconds{5000});
```

**2. Queue Drain**

`DrainShroudQueue()` checks the queue each message-processing cycle and relays any transactions whose delay has elapsed:

```cpp
void DrainShroudQueue() {
    // Collect entries where relay_at <= now
    // Release shroud mutex before acquiring peer mutex (deadlock prevention)
    // Relay each ready transaction directly
}
```

This is called from `SendMessages()`, which runs for each connected peer during the message processing loop.

**3. Direct Relay Bypass**

When shroud is disabled (`-shroud=0`), transactions bypass the queue entirely and use `RelayTransactionDirect()` for immediate relay, matching standard Bitcoin Core behavior.

### Mining Behavior

Transactions enter the local mempool immediately regardless of shroud status. The delay only applies to P2P relay to other nodes. This means:

- Block templates include the transaction with zero delay
- Mining hashrate is never wasted on stale templates
- The node operator's own miners see transactions instantly
- Only outbound relay to peers is delayed

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `-shroud` | `1` (enabled) | Enable random relay delay for origin protection |
| `-shroud=0` | — | Disable shroud (standard Bitcoin Core relay behavior) |

Add to `ghost.conf`:

```ini
# Disable shroud (not recommended)
shroud=0
```

Or via command line:

```bash
ghostd -shroud=0
```

## Privacy Guarantees

### What Shroud Protects Against

- **Timing analysis**: Network observers monitoring relay timestamps cannot determine which node originated a transaction based on "first seen" timing
- **Topology mapping**: The random delay makes it harder to map the network topology by observing propagation patterns
- **Transaction graph correlation**: Combined with Ghost Keys and Wraith Protocol, shroud adds another layer of unlinkability

### Limitations

- **Does not hide participation**: Nodes still relay transactions; shroud only obscures *when* relative to other nodes
- **Does not encrypt**: Transaction content is still visible to peers (use Wraith Protocol for transaction privacy)
- **Statistical analysis**: A well-resourced observer monitoring many nodes over long periods may still extract some timing signal, though the random delay significantly raises the cost and reduces accuracy
- **Local mempool**: The transaction is in the local mempool immediately, so an observer with direct access to a node's mempool can see it before relay

### Threat Model

| Threat | Protection Level |
|--------|-----------------|
| Passive network observer (single vantage point) | Strong |
| Multi-node observer (several vantage points) | Moderate |
| Global observer (monitors all relay links) | Weak (but raises cost significantly) |
| Local mempool inspection | None (transaction is local immediately) |

## Relationship to Other Privacy Features

Ghost Shroud is one layer in Bitcoin Ghost's defense-in-depth privacy architecture:

| Layer | Feature | Protects |
|-------|---------|----------|
| **Network** | Ghost Shroud | Transaction origin timing |
| **Address** | Ghost Keys (BIP-352) | Recipient address linkability |
| **Transaction** | Wraith Protocol | Input-output graph linkability |
| **Payment** | Ghost Pay L2 | On-chain transaction visibility |

Each layer operates independently. Shroud provides network-level protection regardless of whether the transaction uses Ghost Keys, Wraith mixing, or standard Bitcoin addresses.

## Source Files

| File | Purpose |
|------|---------|
| `ghost-core/src/net_processing.cpp` | Shroud queue, `DrainShroudQueue()`, `RelayTransaction()` |
| `ghost-core/src/net_processing.h` | `shroud` option declaration |
| `ghost-core/src/node/peerman_args.cpp` | CLI argument parsing |
| `ghost-core/src/init.cpp` | Argument registration and help text |
