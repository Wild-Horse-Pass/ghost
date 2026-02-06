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

# Bitcoin Ghost Protocol Documentation

Comprehensive documentation for Bitcoin Ghost - a full Bitcoin node implementation with incentivized operation, decentralized mining, and Ghost Pay L2. Similar to Bitcoin Core or Bitcoin Knots, but with enhanced features for node operators, miners, and users.

## Quick Links

### Core Concepts

| Document | Description |
|----------|-------------|
| [Architecture](ARCHITECTURE.md) | System design and component overview |
| [Mining Pool](MINING_POOL.md) | How the decentralized pool operates |
| [Economics](ECONOMICS.md) | Fee structure, treasury, and rewards |
| [Consensus](CONSENSUS.md) | BFT consensus between nodes |

### Layer 2 (Ghost Pay)

| Document | Description |
|----------|-------------|
| [Ghost Pay](GHOST_PAY.md) | L2 payment network overview |
| [L2 Comparison](L2_COMPARISON.md) | Ghost Pay vs Lightning, Citrea, Liquid, Ark, etc. |
| [Ghost Keys](GHOST_KEYS.md) | Silent Payment-style addresses |
| [Ghost Locks](GHOST_LOCKS.md) | P2TR UTXOs with timelocked recovery |
| [Jump Locks](JUMP_LOCKS.md) | Automatic key rotation |
| [Wraith Protocol](WRAITH_PROTOCOL.md) | Two-phase CoinJoin mixing |
| [Reconciliation](RECONCILIATION.md) | L1 settlement system |
| [ZK Proofs](ZK_PROOFS.md) | Zero-knowledge proofs for privacy |

### Node Operation

| Document | Description |
|----------|-------------|
| [Node Capabilities](NODE_CAPABILITIES.md) | The 5-4-3-2-1 share system |
| [BUDS Policy](BUDS_POLICY.md) | Transaction classification |
| [Pruning](PRUNING.md) | Data retention policies |

## Reading Order

### For Miners

1. [Mining Pool](MINING_POOL.md) - Understand how to connect and earn
2. [Economics](ECONOMICS.md) - Learn about reward distribution

### For Node Operators

1. [Architecture](ARCHITECTURE.md) - Understand system design
2. [Mining Pool](MINING_POOL.md) - How mining works
3. [Consensus](CONSENSUS.md) - How nodes coordinate
4. [Node Capabilities](NODE_CAPABILITIES.md) - Earning node rewards
5. [BUDS Policy](BUDS_POLICY.md) - Transaction filtering

### For L2 Users

1. [Ghost Pay](GHOST_PAY.md) - L2 overview
2. [Ghost Keys](GHOST_KEYS.md) - Your identity
3. [Wraith Protocol](WRAITH_PROTOCOL.md) - Private entry
4. [Reconciliation](RECONCILIATION.md) - Exiting to L1

### For Developers

1. [Architecture](ARCHITECTURE.md) - System design
2. All protocol docs in detail
3. [ZK Proofs](ZK_PROOFS.md) - Cryptographic details

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

## Glossary

| Term | Definition |
|------|------------|
| **ARBDA** | Arbitrary Data score - highest BUDS tier in transaction |
| **BFT** | Byzantine Fault Tolerant - consensus tolerating 33% malicious |
| **BUDS** | Bitcoin Unified Data Standard - tx classification |
| **Elder** | One of first 101 registered nodes |
| **Epoch** | 6-hour period for L2 settlement |
| **Gatekeeper** | 95% uptime requirement for rewards |
| **Ghost ID** | Public identifier using Ghost Keys |
| **Ghost Lock** | P2TR UTXO with timelocked recovery |
| **Ghost Pay** | Layer 2 instant payment network |
| **Jump Lock** | Automatic key rotation based on risk |
| **Round** | Period between blocks |
| **Share** | Proof of work below pool difficulty |
| **Virtual Block** | 10-second L2 block |
| **Wraith** | Two-phase mixing protocol |

## Version

This documentation covers Bitcoin Ghost v1.4.

## Contributing

Found an error or want to improve the docs? Submit a pull request to the repository.
