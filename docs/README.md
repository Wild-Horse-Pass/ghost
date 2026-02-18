# Bitcoin Ghost Documentation

Bitcoin Ghost is a full Bitcoin node implementation with incentivized operation, decentralized mining, privacy features, and an integrated L2 payment network. A derivative of Bitcoin Core, similar in philosophy to Bitcoin Knots, but with significant enhancements for node operators, miners, and users.

---

## Quick Start

| Document | Description |
|----------|-------------|
| [Getting Started](./protocols/GETTING_STARTED.md) | Quick start guide for new users |
| [Wallet Overview](./wallets/README.md) | Choose the right wallet |
| [Deployment Runbook](./DEPLOYMENT_RUNBOOK.md) | Production deployment guide |

---

## Protocol Documentation

### Core Protocols

| Protocol | Description |
|----------|-------------|
| [Architecture](./protocols/ARCHITECTURE.md) | System design and component overview |
| [Consensus](./protocols/CONSENSUS.md) | BFT voting mechanism |
| [Mining Pool](./protocols/MINING_POOL.md) | Decentralized mining coordination |
| [Economics](./protocols/ECONOMICS.md) | Fee structure, treasury, and reward distribution |
| [Node Capabilities](./protocols/NODE_CAPABILITIES.md) | 5-4-3-2-1 verified capability share system |
| [BUDS Policy](./protocols/BUDS_POLICY.md) | Transaction classification (T0-T3 tiers) |

### Privacy & Security

| Protocol | Description |
|----------|-------------|
| [Ghost Keys](./protocols/GHOST_KEYS.md) | Silent Payment addresses (BIP-352 style) |
| [Ghost Locks](./protocols/GHOST_LOCKS.md) | Timelocked P2TR outputs with recovery paths |
| [Wraith Protocol](./protocols/WRAITH_PROTOCOL.md) | Two-phase CoinJoin mixing |
| [Ghost Shroud](./protocols/GHOST_SHROUD.md) | Transaction relay origin protection |
| [Jump Locks](./protocols/JUMP_LOCKS.md) | Risk-tiered automatic key rotation |
| [ZK Proofs](./protocols/ZK_PROOFS.md) | Groth16 zero-knowledge proof system |
| [MPC Ceremony](./protocols/MPC_CEREMONY.md) | Rolling MPC for ZK parameter generation and Elder system |

### Ghost Core (Bitcoin Core Fork)

| Protocol | Description |
|----------|-------------|
| [Ghost Haze](./protocols/GHOST_HAZE.md) | Selective archive stripping and real-time data purification |
| [Ghost Reaper](./protocols/GHOST_REAPER.md) | Dead code detection engine for witness scripts |

### Layer 2

| Protocol | Description |
|----------|-------------|
| [Ghost Pay](./protocols/GHOST_PAY.md) | L2 instant payment network (10-second settlement) |
| [Reconciliation](./protocols/RECONCILIATION.md) | L1 settlement batches |
| [L2 Comparison](./protocols/L2_COMPARISON.md) | Ghost Pay vs Lightning, Citrea, Liquid, Ark |

### Additional

| Protocol | Description |
|----------|-------------|
| [Silent Payment v2](./protocols/SILENT_PAYMENT_V2.md) | Payment derivation specification |
| [Ghost Labels](./protocols/GHOST_LABELS.md) | Encrypted payment metadata |
| [Pruning](./protocols/PRUNING.md) | Chain data retention policies |

---

## Technical Reference

| Document | Description |
|----------|-------------|
| [Specification](./SPECIFICATION.md) | Canonical technical specification (v1.5) |
| [API Endpoints](./API_ENDPOINTS.md) | HTTP API reference |
| [RPC Commands](./RPC_COMMANDS.md) | Bitcoin Core RPC extensions |
| [Ghost Core Integration](./GHOST_CORE_INTEGRATION.md) | Bitcoin Core modification details |
| [ZK Trusted Setup](./ZK_TRUSTED_SETUP.md) | Trusted setup ceremony requirements |

---

## Wallet Guides

| Guide | Description |
|-------|-------------|
| [Light Wallet](./wallets/LIGHT_WALLET.md) | Quick setup, minimal resources, GSP-connected |
| [Full Node Wallet](./wallets/FULL_NODE_WALLET.md) | Maximum privacy with local blockchain |
| [GSP Server](./wallets/GSP_SERVER.md) | Run your own light wallet backend server |

---

## Operator Guides

| Guide | Description |
|-------|-------------|
| [Deployment Runbook](./DEPLOYMENT_RUNBOOK.md) | Production deployment step-by-step |
| [Troubleshooting](./TROUBLESHOOTING.md) | Common issues and solutions |
| [Key Management](./KEY_MANAGEMENT.md) | Node identity and wallet key management |
| [Key Rotation](./KEY_ROTATION.md) | Key rotation procedures |
| [Mining Load Balancing](./MINING_LOAD_BALANCING.md) | DNS-based miner routing and load distribution |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        BITCOIN GHOST NETWORK                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  USER LAYER                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │  Light Wallet   │  │  Full Node      │  │   Mining        │         │
│  │  (CLI/TUI)      │  │  Wallet         │  │   Dashboard     │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                     │                  │
│  SERVICE LAYER                 │                     │                  │
│  ┌────────┴────────┐           │           ┌────────┴────────┐         │
│  │   GSP Server    │           │           │   Ghost Pool    │         │
│  │  (Light Wallet  │           │           │  (Mining Coord) │         │
│  │   Backend)      │           │           │                 │         │
│  └────────┬────────┘           │           └────────┬────────┘         │
│           │                    │                     │                  │
│  PROTOCOL LAYER               │                     │                  │
│  ┌────────┴────────────────────┴─────────────────────┴────────┐        │
│  │                       ghost-core (ghostd)                   │        │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │        │
│  │  │ Ghost    │  │ Ghost    │  │ Wraith   │  │ Ghost    │   │        │
│  │  │ Keys     │  │ Locks    │  │ Protocol │  │ Haze     │   │        │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │        │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │        │
│  │  │ BIP-157  │  │ P2P      │  │ Mempool  │  │ Chain    │   │        │
│  │  │ Filters  │  │ Network  │  │ +Reaper  │  │ Validation│   │        │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │        │
│  └────────────────────────────────────────────────────────────┘        │
│                                  │                                      │
│  BLOCKCHAIN LAYER               │                                      │
│  ┌──────────────────────────────┴─────────────────────────────┐        │
│  │                      Bitcoin Blockchain                     │        │
│  └─────────────────────────────────────────────────────────────┘        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Reading Order

### For Miners
1. [Mining Pool](./protocols/MINING_POOL.md) - How to connect and mine
2. [Economics](./protocols/ECONOMICS.md) - Reward distribution

### For Node Operators
1. [Architecture](./protocols/ARCHITECTURE.md) - System design
2. [Deployment Runbook](./DEPLOYMENT_RUNBOOK.md) - Production setup
3. [Node Capabilities](./protocols/NODE_CAPABILITIES.md) - Earning node rewards
4. [MPC Ceremony](./protocols/MPC_CEREMONY.md) - Elder status
5. [BUDS Policy](./protocols/BUDS_POLICY.md) - Transaction filtering
6. [Ghost Haze](./protocols/GHOST_HAZE.md) - Archive stripping (Ghost Core)

### For L2 Users
1. [Ghost Pay](./protocols/GHOST_PAY.md) - L2 overview
2. [Ghost Keys](./protocols/GHOST_KEYS.md) - Your identity
3. [Wraith Protocol](./protocols/WRAITH_PROTOCOL.md) - Private entry
4. [Reconciliation](./protocols/RECONCILIATION.md) - Exiting to L1

### For Developers
1. [Specification](./SPECIFICATION.md) - Canonical reference
2. [Architecture](./protocols/ARCHITECTURE.md) - System design
3. Protocol docs (by area of interest)
4. [API Endpoints](./API_ENDPOINTS.md) - HTTP API reference

---

## Glossary

| Term | Definition |
|------|------------|
| **ARBDA** | Arbitrary Data score - highest BUDS tier in transaction |
| **BFT** | Byzantine Fault Tolerant - consensus tolerating 33% malicious |
| **BUDS** | Bitcoin Unified Data Standard - transaction classification |
| **Corpse** | Transaction with dead code exceeding Reaper thresholds |
| **Elder** | One of first 101 MPC ceremony contributors (+1 share) |
| **Epoch** | 6-hour period for L2 settlement |
| **Exorcism** | Runtime process stripping hazeable data before disk write |
| **Gatekeeper** | 95% uptime requirement for rewards |
| **Ghost Haze** | Node state with irreversibly stripped archive |
| **Ghost ID** | Public identifier using Ghost Keys (BIP-352 style) |
| **Ghost Lock** | P2TR UTXO with timelocked recovery |
| **Ghost Pay** | Layer 2 instant payment network |
| **GSB** | Ghost Stripped Block - hazed archive file format |
| **Jump Lock** | Automatic key rotation based on risk tier |
| **MPC** | Multi-Party Computation for ZK parameter generation |
| **Reaper** | Dead code detection engine for witness scripts |
| **Round** | Period between blocks (one block = one round) |
| **Share** | Proof of work below pool difficulty |
| **Shroud** | Random relay delay for transaction origin protection |
| **Virtual Block** | 10-second L2 block |
| **Wraith** | Two-phase CoinJoin mixing protocol |

---

## Version

This documentation covers Bitcoin Ghost v1.5.

## Contributing

Found an error or want to improve the docs? Submit a pull request to the repository.
