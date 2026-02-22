# Bitcoin Ghost

<div align="center">

```
 ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░
 ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░
 ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░
      ░              ░
```

<a href="https://git.io/typing-svg">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=22&duration=3000&pause=1000&color=F7931A&center=true&vCenter=true&width=700&height=80&lines=Your+keys.+Your+node.+Your+pool.;Earn+Bitcoin+by+running+infrastructure.;Private+payments+without+compromise." alt="Typing SVG" />
</a>

<p>
  <img src="https://img.shields.io/badge/Bitcoin-Native-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Bitcoin" />
  <img src="https://img.shields.io/badge/Rust-1.75+-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <a href="https://github.com/bitcoin-ghost/ghost/actions"><img src="https://img.shields.io/github/actions/workflow/status/bitcoin-ghost/ghost/ci.yml?style=for-the-badge&label=CI" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License" /></a>
  <img src="https://img.shields.io/badge/version-1.8.0-green?style=for-the-badge" alt="Version" />
</p>

<p>
  <a href="https://bitcoinghost.org">Website</a> ·
  <a href="https://bitcoinghost.org/whitepaper">Whitepaper</a> ·
  <a href="docs/">Documentation</a> ·
  <a href="docs/protocols/GETTING_STARTED.md">Getting Started</a>
</p>

<p>
  <a href="#the-problem">Problem</a> &bull;
  <a href="#ghost-is-the-correction">Solution</a> &bull;
  <a href="#what-you-can-build">Use Cases</a> &bull;
  <a href="#the-5-4-3-2-1-share-system">Rewards</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#deep-dive">Deep Dive</a>
</p>

</div>

---

## The Problem

Bitcoin mining was designed to be decentralized. A solo miner, a laptop, a CPU — that was the vision. Today, **three mining pools control over 50% of Bitcoin's hashrate.** When you point your miner at a custodial pool, someone else decides which transactions make it into blocks. Someone else holds your rewards until they feel like paying you. Someone else can be subpoenaed, sanctioned, or shut down — and your hashrate goes with them.

That's not the protocol Satoshi described.

Meanwhile, the people who actually secure Bitcoin — full node operators — get nothing. You donate bandwidth, storage, and years of compute to validate every transaction and serve every block. Your reward is a higher electricity bill. The infrastructure Bitcoin depends on runs on goodwill, and goodwill doesn't scale.

And there's a problem nobody talks about: **every full node stores the entire blockchain, including content embedded by third parties that may violate strict liability laws** in your jurisdiction. Under US, UK, and EU statutes, it doesn't matter that you didn't put it there. Running a full archive node carries legal exposure that most operators don't even know about.

---

## Ghost Is the Correction

Ghost is not an altcoin. It is sovereign Bitcoin infrastructure — a fork of Bitcoin Core v30, a decentralized mining pool, an L2 payment layer, and a privacy stack. Every satoshi stays on the Bitcoin blockchain. Every protocol speaks Bitcoin natively.

**It pays node operators.** When the network finds a block, 100% of transaction fees go to the node operator whose template built it. On top of that, the node reward pool — funded by 0.5–1% of every block subsidy — is distributed to the top 100 nodes based on cryptographically verified capabilities. Run valuable infrastructure, get paid. No invoices. No accounts. Bitcoin directly in the coinbase.

**It decentralizes mining.** Any Ghost node can accept miners on its native Stratum V1 port — no central pool server, no custodian, no permission required. Nodes form a P2P mesh and reach consensus through BFT voting backed by zero-knowledge proofs. Pre-computed payouts mean zero delay when a winning share lands. Each node selects its own transactions. Your hashrate. Your transaction selection. Your rules.

**It protects operators.** Ghost Haze strips hazeable content from blocks before it ever touches your disk. Embedded data exists only in volatile RAM during validation — never stored, never recoverable. The Reaper mempool filter detects and rejects dead code using 8 algorithmic detection vectors. This isn't a blacklist — it's structural dead code analysis that catches unknown patterns automatically. Run a full archival Bitcoin node without storing content you didn't ask for.

**It makes payments private.** Wraith Protocol breaks your transaction graph through CoinJoin mixing at L2 entry. Ghost Keys (BIP-352 Silent Payments) derive a unique address for every payment from a single static identifier. Ghost Shroud defeats network-level timing analysis. Ghost Pay settles in ~10-second virtual blocks with ZK-proven validity. No payment graph. No address reuse. No metadata leakage.

---

## What You Can Build

> [!TIP]
> **Already running a Bitcoin full node?** Switch from `bitcoind` to `ghostd` — same Bitcoin Core v30 base, same RPC interface, same data directory structure. Enable Archive mode in your config, and start earning from the node reward pool for every block the network finds. You're already donating the bandwidth and storage to serve blocks. Ghost just pays you for it.

<table>
<tr>
<td width="50%" valign="top">

### Start a Pool with Your Friends

You and three friends each have a BitAxe. Instead of pointing them at Foundry, each of you runs a Ghost node. Your miners connect to your own nodes over Stratum V1. The nodes form a P2P mesh, share work, reach BFT consensus on payouts, and submit blocks to Bitcoin. No middleman. No account. No custodian. When you find a block, rewards distribute automatically — every node can verify the math. As more people join your network, **it becomes more decentralized, not less.**

</td>
<td width="50%" valign="top">

### Earn Bitcoin Running Infrastructure

No mining hardware? Run a Ghost node with Archive mode (+5 shares) and Reaper strict mode (+2 shares). Keep 95% uptime for 7 days, and you're earning a proportional cut of the node reward pool from every block the network finds. Add Ghost Pay (+4 shares) and open your Stratum port to miners (+3 shares) to reach 14 of 15 possible shares. The node reward pool pays out every single block in the coinbase transaction — transparent, verifiable, automatic.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Send Private Bitcoin Payments

Open your Ghost wallet and send Bitcoin that can't be traced back to you. Wraith Protocol mixes your coins at L2 entry using blind-signature CoinJoin — even the coordinator can't link your input to your output. Ghost Keys generate a unique on-chain address for every payment from a single static identifier. Ghost Pay settles transfers in ~10 seconds with ZK proofs. No channel management. No liquidity routing. No inbound capacity headaches.

</td>
<td width="50%" valign="top">

### Protect Your Node from Legal Exposure

Every Bitcoin archive node stores the complete blockchain — including content embedded by malicious third parties. Ghost Haze irreversibly strips hazeable fields (witness padding, scriptSig data stuffing, OP_RETURN payloads) before writing blocks to disk, reducing archive size from ~718 GB to ~195 GB. What remains is the complete economic graph: every transaction, every UTXO, every balance — with cryptographic proof that the stripped content existed, but without the content itself.

</td>
</tr>
</table>

---

## The 5-4-3-2-1 Share System

Nodes earn shares in the node reward pool by **proving** — not claiming — that they run real infrastructure:

| Capability | Shares | How It's Verified |
|:-----------|:------:|:------------------|
| **Archive Node** | +5 | Random peers request arbitrary historical blocks. Serve them or fail. |
| **Ghost Pay** | +4 | Random L2 state lookup challenges. Prove you're processing payments. |
| **Public Mining** | +3 | Peers probe your Stratum port. Accept real miners or don't claim you do. |
| **Reaper** | +2 | Policy classification challenges. Prove your mempool rejects dead code. |
| **Elder** | +1 | Contributed to the MPC ceremony. First 101 nodes only. Permanent, non-transferable. |

**Maximum: 15 shares.** A full-capability node earns 15x what a minimal node earns from the reward pool.

Every 5 minutes, your node selects 3 random peers and issues cryptographic challenges. Their peers do the same to you. After 10+ challenges, you need a 95% pass rate (90% for Ghost Pay) to qualify. The gatekeeper: **95% uptime over 7 trailing days** before any shares count at all. Fake it and you fail. There are no shortcuts.

> [!IMPORTANT]
> **Where does the money come from?** Every Bitcoin block has a subsidy (currently 3.125 BTC) and transaction fees. The node whose template is used for the winning share keeps **100% of TX fees** — this is the primary incentive and it scales with network activity. The **node reward pool** takes 0.5% of the subsidy and distributes it proportionally to the top 100 nodes by verified shares. The remaining 99% of the subsidy goes to miners based on submitted work. Every payout is on-chain in the coinbase — transparent and verifiable by anyone.

### The Flywheel

Ghost is designed to progressively decentralize over time. The economics reward early adoption:

1. **More nodes join** → more miners connect → more blocks found through Ghost
2. **More blocks** → the treasury reaches its 21 BTC threshold faster
3. **Threshold reached** → a 5-year decay begins, shifting treasury allocation to node operators
4. **Node rewards grow** from 0.5% to **1.0%** of every block subsidy — they double
5. **Better incentives** → more nodes join → the cycle accelerates

The decay schedule is enforced at the protocol level. Year 1: 0.6% nodes / 0.4% treasury. Year 3: 0.8% / 0.2%. **Year 5 onward: 100% of the pool fee goes to node operators. The treasury goes to zero permanently.** The earlier the network reaches critical mass, the sooner every operator's rewards double.

> [!NOTE]
> **101 Elder positions exist.** The MPC ceremony accepts the first 101 contributing nodes. Elder status grants +1 share permanently. Positions are non-transferable — if an elder goes offline, their position is lost forever, not reassigned. This is a consensus parameter, not a marketing decision. Once the 101st node contributes, the window closes.

---

## Architecture

```
                       ┌──────────────────────────────────┐
                       │       P2P MESH NETWORK            │
                       │                                    │
                       │   consensus · shares · payouts     │
                       │   blocks · health · discovery      │
                       └──────────────────────────────────┘
                        ▲              ▲              ▲
                        │              │              │
                  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
                  │  Node A   │  │  Node B   │  │  Node C   │
                  │  (you)    │  │ (friend)  │  │ (anyone)  │
                  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
                        │              │              │
                    ghostd         ghostd         ghostd
                  (Ghost Core)   (Ghost Core)   (Ghost Core)
                        │              │              │
                  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
                  │  Reaper   │  │  Haze     │  │  Ghost    │
                  │  Filter   │  │  Archive  │  │  Pay L2   │
                  └───────────┘  └───────────┘  └───────────┘
                        ▲              ▲              ▲
                        │              │              │
                   Your miners    Their miners    Light wallets
                   (BitAxe, S19)  (Stratum V1)   (CLI / TUI)
```

Every node is a peer. No node is special. Miners connect to whichever node they choose. Nodes reach consensus through BFT voting on a Noise-encrypted ZeroMQ mesh across 8 dedicated ports (8555–8562). Ghost Core (`ghostd`) is a Bitcoin Core v30 fork with integrated Reaper mempool filtering and Ghost Haze block stripping.

<details>
<summary><strong>Network Ports</strong></summary>

| Port | Purpose |
|------|---------|
| 3333 | Stratum V1 — native miner connections |
| 34255 | Stratum V2 — via SRI pool |
| 8080 | REST API |
| 8555 | Share propagation |
| 8556 | Block announcements |
| 8557 | Consensus voting |
| 8558 | Health monitoring (pings every 10s) |
| 8559 | Peer discovery |
| 8560 | Elder management |
| 8561 | Payout proposals |
| 8562 | Payout transactions |
| 8800 | Ghost Pay L2 API |
| 8900 | GSP WebSocket (light wallet backend) |

</details>

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/bitcoin-ghost/ghost.git
cd ghost && git submodule update --init --recursive
cargo build --release

# Start Ghost Core
./ghost-core/bin/ghostd -daemon

# Generate node identity
./target/release/ghost-cli key generate --output ~/.ghost/node.key

# Launch your node — connects to mesh, begins earning
./target/release/ghost-pool --config /etc/ghost/pool.toml
```

**Point a miner at your node:** `stratum+tcp://<your-ip>:3333` — worker name: `<btc_address>.worker1`

**Prerequisites:** Rust 1.75+, Ghost Core (or Bitcoin Core 27.0+), SQLite 3.35+, Linux/macOS (Windows via WSL2)

<details>
<summary><strong>Docker</strong></summary>

```bash
cd docker && cp .env.example .env    # Edit .env with your config
docker-compose up -d

# With monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d
```

</details>

<details>
<summary><strong>Light Wallet</strong></summary>

```bash
./target/release/ghost-light-wallet-cli init
./target/release/ghost-light-wallet-cli receive         # Your Silent Payment address
./target/release/ghost-light-wallet-cli balance --refresh
./target/release/ghost-light-wallet-cli send <address> <amount_sats>
```

</details>

---

## Deep Dive

<details>
<summary><strong>Privacy Stack — Five Independent Layers</strong></summary>

<br/>

Ghost implements defense-in-depth privacy. Each layer operates independently — use any combination.

**1. Wraith Protocol (Entry Privacy)**
Two-phase CoinJoin mixing when depositing Bitcoin into the L2 layer. Phase 1 splits your input into 10 intermediate Ghost Locks across random participants. Phase 2 merges intermediates into final locks. Blind Schnorr signatures ensure the coordinator cannot link any input to any output. Standard denomination sizes (10k to 100M sats) prevent amount-based correlation. Anonymity sets from 25 (express) to 1,000+ (whale).

**2. Ghost Keys — BIP-352 Silent Payments (Receiver Privacy)**
Share a single static Ghost address. Every incoming payment automatically derives a unique on-chain address using an ephemeral shared secret. Only the recipient can detect and spend the payment. No address reuse. No sender-recipient linkage. The scan key detects payments; the spend key authorizes them — these can be separated for watch-only wallets.

**3. Ghost Pay L2 (Transfer Privacy)**
Off-chain transfers use zero-knowledge proofs. Validators verify that balances are correct and no double-spending occurs without seeing amounts, sender, or recipient. Transfers settle in ~10-second virtual blocks. Periodic batch settlement to L1.

**4. Ghost Shroud (Network Privacy)**
Random 0–5 second delay before relaying transactions to peers. Defeats passive network observers attempting timing analysis to identify which node originated a transaction. Default-enabled on all Ghost Core nodes. Your local mempool receives transactions immediately — mining templates are never stale.

**5. Ghost Haze (Archive Privacy)**
Irreversibly strips witness data, scriptSig padding, and OP_RETURN content from blocks before writing to disk. Reduces full archive from ~718 GB to ~195 GB. The complete economic graph is preserved — every txid, UTXO, and balance. Bitcoin's native witness commitments cryptographically prove stripped content existed without retaining it.

**No other Bitcoin L2 combines all five layers.** Lightning has no entry privacy (channel opens are visible on-chain). Liquid is federated. Ark requires trust in service providers. Ghost is the only stack where mixing, stealth addresses, ZK transfers, network obfuscation, and archive stripping all work together.

</details>

<details>
<summary><strong>Ghost Pay — L2 Payments</strong></summary>

<br/>

Ghost Pay is an optional Layer 2 payment network:

- **Deposit** Bitcoin via Ghost Locks (timelocked P2TR scripts on L1)
- **Transfer** instantly to any other Ghost Pay user (~10-second virtual blocks, ZK-proven validity)
- **Withdraw** back to L1 at your pace (Express: 6h, Standard: 24h, Economy: 7 days)
- **Fees:** 10 sats + 0.1%

**Retail payments under 100k sats** use optimistic confirmation — if 8 conditions about the sender's lock are satisfied (active state, 6+ L1 confirmations, sufficient balance, no pending L1 transactions, etc.), the merchant sees "Confirmed" immediately. Full settlement follows on the next virtual block.

**vs. Lightning Network:**

| | Ghost Pay | Lightning |
|---|---|---|
| **Setup** | Fund one Ghost Lock | Open channels, manage liquidity |
| **Routing** | Direct L2 transfer | Multi-hop routing (path finding) |
| **Entry privacy** | Wraith mixing (high) | Channel opens visible on-chain (low) |
| **State model** | ZK-proven (mathematical guarantee) | Channel-based (watch for fraud) |
| **Offline receiving** | Yes (validators store L2 state) | No (must be online) |
| **Maturity** | Active development | Production (5+ years, 14k+ nodes) |

**Self-custody guaranteed.** Ghost Locks include timelocked recovery paths. If the L2 network goes offline permanently, you recover your Bitcoin on L1 after the timelock expires. No federation. No custodian.

</details>

<details>
<summary><strong>Decentralized Mining</strong></summary>

<br/>

**Today's mining pools:**
```
Miner → Central Pool Server → Operator selects transactions
                             → Operator holds your rewards
                             → Operator can censor, delay, refuse
                             → Operator is a regulatory target
```

**Ghost:**
```
Miner → Any Ghost Node → Nodes form P2P mesh (Noise-encrypted ZeroMQ)
                        → BFT consensus on payouts (67% threshold)
                        → Pre-computed payouts (zero block submission delay)
                        → Each node independently selects transactions
```

**Pre-computed payouts** are the key innovation. Traditional pools delay block submission while they calculate and agree on payouts. Ghost maintains continuous rolling consensus on the current reward distribution across the mesh. When a winning share arrives, the block already contains the correct coinbase outputs. Submit immediately. No delay. No wasted time.

**Transaction sovereignty.** Each node runs its own mempool policy via BUDS (Bitcoin Use-case Differentiation System). Nodes running `bitcoin_pure` mode include only financial transactions (T0+T1). Nodes running `full_open` include everything. The miner decides which node — and therefore which policy — to support by choosing where to connect. No central authority decides what gets mined.

**Censorship resistance.** A 67% BFT threshold means up to 33% of nodes can be malicious, offline, or censoring — the remaining honest nodes continue operating. No single entity can control block construction or prevent any transaction from being mined. Contrast this with centralized pools where one operator makes every decision.

</details>

<details>
<summary><strong>Legal Protection — Ghost Haze & Reaper</strong></summary>

<br/>

**The problem nobody talks about.**

Under strict liability statutes — US 18 U.S.C. § 2252, UK Protection of Children Act 1978, EU Directive 2011/93/EU — possession of certain content is a criminal offense regardless of intent. Third parties have embedded such content in the Bitcoin blockchain via witness data, OP_RETURN, and scriptSig fields. **Every full archive node stores it.** A single high-profile prosecution could trigger mass node shutdowns and threaten Bitcoin's decentralization.

**Ghost Haze (Storage Layer):**
- Strips witness data, scriptSig padding, and OP_RETURN payloads before writing blocks to disk
- Content exists only in volatile RAM during block validation — never persisted
- Irreversible: stripped data cannot be reconstructed (SHA-256 is one-way)
- Complete economic graph preserved: all txids, UTXOs, balances, and block headers remain intact
- Bitcoin's native txid and witness commitments cryptographically prove stripped content existed

**Ghost Reaper (Mempool Layer):**
Eight algorithmic detection vectors identify dead code embedded in transactions:
1. Inscription envelopes (Ordinals `OP_FALSE OP_IF ... OP_ENDIF`)
2. Drop stuffing (large data pushed then immediately discarded)
3. Unreachable code (data after `OP_RETURN`)
4. Fake pubkeys (invalid ECDSA prefixes in bare multisig)
5. Oversized OP_RETURN (>83 bytes)
6. Taproot annex (non-standard witness data)
7. Excess witness data (>500 bytes unused by script execution)
8. Legacy scriptSig data stuffing

**This is not a blacklist.** Reaper uses structural dead code analysis — it catches patterns it has never seen before. Two independent layers: Ghost Core filters at the mempool level, Ghost Pool filters during block template construction.

**Three-layer legal defense:**
1. **Physical impossibility** — Hazeable content does not exist on disk and cannot be recovered
2. **No mens rea** — Data was opaque bytes processed by hash functions in RAM, never rendered or accessed as content
3. **Analogous precedent** — Functionally equivalent to a postal carrier handling sealed packages or a router forwarding encrypted packets

</details>

---

## Documentation

| Document | Description |
|----------|-------------|
| **[Getting Started](docs/protocols/GETTING_STARTED.md)** | Step-by-step setup for new operators |
| [Full Specification](docs/SPECIFICATION.md) | Complete protocol specification |
| [Node Capabilities](docs/protocols/NODE_CAPABILITIES.md) | 5-4-3-2-1 verification system |
| [Economics](docs/protocols/ECONOMICS.md) | Reward distribution, treasury decay, dust handling |
| [Consensus](docs/protocols/CONSENSUS.md) | ZK-BFT consensus protocol |
| [Ghost Keys](docs/protocols/GHOST_KEYS.md) | BIP-352 Silent Payment implementation |
| [Ghost Pay](docs/protocols/GHOST_PAY.md) | L2 payment network |
| [Wraith Protocol](docs/protocols/WRAITH_PROTOCOL.md) | CoinJoin mixing |
| [Ghost Haze](docs/protocols/GHOST_HAZE.md) | Stripped block archival |
| [Ghost Reaper](docs/protocols/GHOST_REAPER.md) | Dead code detection and filtering |
| [BUDS Policy](docs/protocols/BUDS_POLICY.md) | Transaction classification (T0–T3) |
| [MPC Ceremony](docs/protocols/MPC_CEREMONY.md) | Elder key generation |
| [Deployment Runbook](docs/DEPLOYMENT_RUNBOOK.md) | Production deployment guide |
| [API Reference](docs/API_ENDPOINTS.md) | HTTP API documentation |
| [Wallets](docs/wallets/README.md) | Wallet options and setup |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |

---

## Security

Ghost has undergone **14 rounds** of comprehensive security auditing with zero critical vulnerabilities in release. The codebase is continuously fuzzed via cargo-fuzz and dependency-audited via cargo-audit in CI.

All P2P mesh communication is encrypted via the Noise Protocol Framework. Sensitive database fields are encrypted at rest. All public-facing APIs are rate-limited with trusted proxy validation. Node identity uses Ed25519 with secure key rotation via dual-signature proofs.

Report vulnerabilities to: **security@bitcoinghost.org**

---

## Development

```bash
cargo build --release                        # Build all binaries
cargo test --workspace                       # Full test suite
cargo test -p ghost-consensus                # Single crate
cargo clippy --workspace -- -D warnings      # Lint (zero warnings)
cargo fmt --all                              # Format
cargo audit                                  # Dependency security audit
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting pull requests.

---

## Acknowledgments

Ghost is built on the work of people and projects we deeply respect:

**[Bitcoin Core](https://github.com/bitcoin/bitcoin)** — Ghost Core is a fork of Bitcoin Core v30. The decades of careful, conservative engineering by hundreds of contributors is the foundation everything here is built on. We are downstream of their work and grateful for it.

**[Stratum V2 / SRI](https://github.com/stratum-mining/stratum)** — The Stratum Reference Implementation team built the modern mining protocol that Ghost's pool infrastructure extends. Their mission to decentralize template selection aligns directly with ours.

**BIP Authors** — Ghost implements or builds upon work from many Bitcoin Improvement Proposals:
- **[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)** (Silent Payments) by Josie Baker and Ruben Somsen — the foundation of Ghost Keys
- **[BIP-340/341](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)** (Schnorr/Taproot) by Pieter Wuille, Jonas Nick, and Tim Ruffing — used throughout for signatures and script paths
- **[BIP-320](https://github.com/bitcoin/bips/blob/master/bip-0320.mediawiki)** (Version Rolling) by Timo Hanke and Sergio Demian Lerner — enables efficient ASIC mining support
- **BIP-141** (Segregated Witness), **BIP-157/158** (Compact Block Filters) by Olaoluwa Osuntokun, Alex Akselrod, and Jim Posen, **BIP-32/39/86** (HD wallets, mnemonics, Taproot derivation)

**[rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) & [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)** — The Rust Bitcoin ecosystem provides the cryptographic and data structure primitives Ghost is built with. The quality of these libraries is exceptional.

**[bellperson](https://github.com/filecoin-project/bellperson)** — Ghost's ZK-BFT consensus uses bellperson (a fork of bellman) for Groth16 proof generation. Thanks to the Zcash and Filecoin teams.

**[snow](https://github.com/mcginty/snow)** — The Noise Protocol Framework implementation that encrypts Ghost's entire P2P mesh.

**The broader open-source community** — Tokio, Axum, ZeroMQ, SQLite, and the countless projects that make building reliable distributed systems possible. We stand on your shoulders.

---

## License

[MIT](LICENSE)

---

<div align="center">

**Your keys. Your node. Your pool.**

<p>
  <a href="https://bitcoinghost.org">Website</a> ·
  <a href="https://github.com/bitcoin-ghost">GitHub</a> ·
  <a href="docs/">Documentation</a> ·
  <a href="https://bitcoinghost.org/whitepaper">Whitepaper</a>
</p>

<sub>Ghost is free, open-source software under the MIT license. It is not financial advice. Run your own node. Verify everything.</sub>

</div>
