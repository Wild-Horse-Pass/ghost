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
//| FILE: README.md                                                                                                      |
//|======================================================================================================================|
```

# Bitcoin Ghost Protocol Documentation

Comprehensive protocol specifications for Bitcoin Ghost -- a full Bitcoin node implementation with incentivized operation, decentralized mining, and Ghost Pay L2.

---

## Core

| Document | Description |
|----------|-------------|
| [Architecture](ARCHITECTURE.md) | System design and component overview |
| [Consensus](CONSENSUS.md) | BFT consensus between nodes (67% threshold) |
| [Economics](ECONOMICS.md) | Fee structure, treasury, and reward distribution |
| [Node Capabilities](NODE_CAPABILITIES.md) | 5-4-3-2-1 verified capability share system |

## Mining

| Document | Description |
|----------|-------------|
| [Mining Pool](MINING_POOL.md) | Decentralized mining coordination |
| [BUDS Policy](BUDS_POLICY.md) | Transaction classification (T0-T3 tiers) |
| [Ghost Reaper](GHOST_REAPER.md) | Dead code detection engine for witness scripts |
| [Pruning](PRUNING.md) | Chain data retention policies |

## Privacy

| Document | Description |
|----------|-------------|
| [Ghost Keys](GHOST_KEYS.md) | Silent Payment addresses (BIP-352 style) |
| [Ghost Locks](GHOST_LOCKS.md) | P2TR UTXOs with timelocked recovery |
| [Wraith Protocol](WRAITH_PROTOCOL.md) | Two-phase CoinJoin mixing |
| [Ghost Shroud](GHOST_SHROUD.md) | Transaction relay origin protection |
| [Jump Locks](JUMP_LOCKS.md) | Risk-tiered automatic key rotation |
| [Ghost Labels](GHOST_LABELS.md) | Encrypted payment metadata |
| [Silent Payment v2](SILENT_PAYMENT_V2.md) | Payment derivation specification |
| [ZK Proofs](ZK_PROOFS.md) | Groth16 zero-knowledge proof system |
| [MPC Ceremony](MPC_CEREMONY.md) | Rolling MPC for ZK parameter generation and Elder system |

## Ghost Core (Bitcoin Core Fork)

| Document | Description |
|----------|-------------|
| [Ghost Haze](GHOST_HAZE.md) | Selective archive stripping and real-time data purification |

## Layer 2

| Document | Description |
|----------|-------------|
| [Ghost Pay](GHOST_PAY.md) | L2 instant payment network (10-second settlement) |
| [Reconciliation](RECONCILIATION.md) | L1 settlement batches |
| [L2 Comparison](L2_COMPARISON.md) | Ghost Pay vs Lightning, Citrea, Liquid, Ark |

## Getting Started

| Document | Description |
|----------|-------------|
| [Getting Started](GETTING_STARTED.md) | Quick start guide for new users |

---

## Reading Order

### For Miners

1. [Mining Pool](MINING_POOL.md) - Understand how to connect and earn
2. [Economics](ECONOMICS.md) - Learn about reward distribution

### For Node Operators

1. [Architecture](ARCHITECTURE.md) - Understand system design
2. [Mining Pool](MINING_POOL.md) - How mining works
3. [Consensus](CONSENSUS.md) - How nodes coordinate
4. [Node Capabilities](NODE_CAPABILITIES.md) - Earning node rewards
5. [MPC Ceremony](MPC_CEREMONY.md) - Elder status and ZK ceremony
6. [BUDS Policy](BUDS_POLICY.md) - Transaction filtering
7. [Ghost Haze](GHOST_HAZE.md) - Archive stripping (Ghost Core)

### For L2 Users

1. [Ghost Pay](GHOST_PAY.md) - L2 overview
2. [Ghost Keys](GHOST_KEYS.md) - Your identity
3. [Wraith Protocol](WRAITH_PROTOCOL.md) - Private entry
4. [Reconciliation](RECONCILIATION.md) - Exiting to L1

### For Developers

1. [Architecture](ARCHITECTURE.md) - System design
2. All protocol docs in detail
3. [ZK Proofs](ZK_PROOFS.md) - Cryptographic details

---

## Key Concepts

### Decentralization

Bitcoin Ghost has no central server:
- Every pool node is equal
- Nodes coordinate via P2P consensus
- Any node can submit blocks
- 67% BFT tolerance

### Privacy

Multiple layers of privacy:
- **Ghost Keys**: Unlinkable stealth addresses
- **Wraith Protocol**: Break link between public BTC and L2
- **Ghost Shroud**: Transaction relay origin protection
- **Ghost Haze**: Embedded content liability protection
- **ZK Proofs**: Prove validity without revealing details

### Incentive Alignment

The 5-4-3-2-1 system rewards valuable services:
- Archive nodes store full blockchain (+5)
- Ghost Pay nodes run L2 (+4)
- Public mining nodes accept miners (+3)
- Policy nodes filter transactions (+2)
- Elder nodes bootstrapped the network (+1)

### Self-Custody

Users always control their funds:
- Ghost Locks have recovery paths
- No trusted third parties
- Exit to L1 always possible

---

## Glossary

| Term | Definition |
|------|------------|
| **ARBDA** | Arbitrary Data score - highest BUDS tier in transaction |
| **BFT** | Byzantine Fault Tolerant - consensus tolerating 33% malicious |
| **BUDS** | Bitcoin Unified Data Standard - transaction classification |
| **Corpse** | Transaction with dead code exceeding Reaper thresholds |
| **Elder** | One of first 101 MPC ceremony contributors |
| **Epoch** | 6-hour period for L2 settlement |
| **Exorcism** | Runtime process stripping hazeable data before disk write |
| **Gatekeeper** | 95% uptime requirement for rewards |
| **Ghost Haze** | Node state with irreversibly stripped archive |
| **Ghost ID** | Public identifier using Ghost Keys |
| **Ghost Lock** | P2TR UTXO with timelocked recovery |
| **Ghost Pay** | Layer 2 instant payment network |
| **GSB** | Ghost Stripped Block - hazed archive file format |
| **Jump Lock** | Automatic key rotation based on risk |
| **MPC** | Multi-Party Computation for ZK parameter generation |
| **Reaper** | Dead code detection engine for witness scripts |
| **Round** | Period between blocks |
| **Share** | Proof of work below pool difficulty |
| **Shroud** | Random relay delay for transaction origin protection |
| **Virtual Block** | 10-second L2 block |
| **Wraith** | Two-phase mixing protocol |

## Version

This documentation covers Bitcoin Ghost v1.5.

## Contributing

Found an error or want to improve the docs? Submit a pull request to the repository.
