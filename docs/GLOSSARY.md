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
//| FILE: GLOSSARY.md                                                                                                    |
//|======================================================================================================================|
```

# Bitcoin Ghost Glossary

Comprehensive reference of Ghost-specific terminology, organized by category with cross-references and implementation pointers.

---

## Table of Contents

- [Core System](#core-system)
- [Node Capabilities and Rewards](#node-capabilities-and-rewards)
- [Mining and Stratum](#mining-and-stratum)
- [Ghost Core (ghostd)](#ghost-core-ghostd)
- [Ghost Haze System](#ghost-haze-system)
- [Ghost Reaper](#ghost-reaper)
- [BUDS Classification](#buds-classification)
- [Ghost Pay L2](#ghost-pay-l2)
- [Privacy and Cryptography](#privacy-and-cryptography)
- [MPC Ceremony and Elders](#mpc-ceremony-and-elders)
- [Consensus and P2P Mesh](#consensus-and-p2p-mesh)
- [Wallet and Client Infrastructure](#wallet-and-client-infrastructure)
- [Economic Model](#economic-model)
- [Network Ports Reference](#network-ports-reference)
- [OP_RETURN Markers](#op_return-markers)

---

## Core System

### Bitcoin Ghost
A full Bitcoin node implementation derived from Bitcoin Core v30.1. Combines complete block validation, decentralized mining coordination, an incentivized node capability system (5-4-3-2-1 shares), Ghost Pay L2 instant payments, and enhanced privacy features (Silent Payments, Wraith mixing, Shroud relay protection). Comparable in philosophy to Bitcoin Knots but with substantially more functionality.
- Spec: `docs/SPECIFICATION.md` Section 1

### ghost-pool
The main pool binary. Accepts miner connections (SV1 Stratum on port 3333), receives templates from Ghost Core via JSON-RPC, filters transactions using BUDS/Reaper policy, participates in P2P consensus, builds the coinbase with all payouts, submits blocks, and responds to verification challenges.
- Binary path: `/opt/ghost/bin/ghost-pool`
- Config: `/etc/ghost/pool.toml`
- Source: `bins/ghost-pool/src/`

### Ghost Core (ghostd)
A fork of Bitcoin Core v30.1 with Ghost-specific modifications including Silent Payments (BIP-352), Ghost Lock P2TR script templates, Wraith Protocol transaction building, Ghost Haze/Exorcism archive stripping, Ghost Reaper mempool filtering, Ghost Shroud relay protection, and the GSP light wallet server. Must not be confused with standard bitcoind -- all Ghost nodes run ghostd.
- Binary: `ghostd`
- Source: `ghost-core/` subdirectory (CMake build)
- Build: `cmake -S . -B build/ && cmake --build build/ --target ghostd`

### Ghost CLI (ghost-cli)
Command-line interface for interacting with a running Ghost node. Provides subcommands for capability status, challenge history, share information, and ranking.
- Binary: `/opt/ghost/bin/ghost-cli`

### Ossification
The permanent freezing of system parameters. In Ghost, this applies primarily to the MPC ceremony: after 101 contributions, parameters are frozen permanently and no further changes are accepted. The broader project philosophy aims to eventually ossify the entire protocol, meaning every code change must be correct and complete.
- Spec: `docs/protocols/MPC_CEREMONY.md` Section 4

---

## Node Capabilities and Rewards

### 5-4-3-2-1 Share System
The incentive mechanism for node operators. Nodes earn shares in the node reward pool based on verified capabilities. Higher-value services earn more shares:

| Capability | Shares | Verification |
|------------|--------|--------------|
| Archive Mode | +5 | Random block retrieval challenges |
| Ghost Pay | +4 | L2 block lookup challenges |
| Public Mining | +3 | Stratum port accessibility check |
| Reaper | +2 | Reaper verification |
| Elder Status | +1 | MPC ceremony contribution (first 101 nodes) |

Maximum: 15 shares. Gatekeeper: 95% uptime over trailing 7 days required for any shares.
- Spec: `docs/protocols/NODE_CAPABILITIES.md`
- Implementation: `crates/ghost-verification/src/`

### Archive Mode (+5 Shares)
A node capability indicating the node stores and serves the full Bitcoin blockchain (all blocks from genesis, no pruning). Verified by random block retrieval challenges where a peer requests a block at a random height and the node must return correct data within 10 seconds. Requires 95% pass rate over 10+ challenges. Nodes running Ghost Core in Hazed mode are automatically excluded from Archive Mode.
- Verification endpoint: `GET /api/v1/verify/archive?height={n}`

### Ghost Pay Capability (+4 Shares)
A node capability indicating the node runs a Ghost Pay L2 node, processes L2 transfers, participates in reconciliation, and maintains current L2 state. Verified by L2 block lookup challenges requiring 90% pass rate.
- Verification endpoint: `GET /api/v1/verify/ghostpay`

### Public Mining (+3 Shares)
A node capability indicating the node accepts public miner connections on its Stratum port. Verified by TCP probe and Stratum handshake (connecting, sending `mining.subscribe`, and checking for a valid response). Requires 95% pass rate.
- Verification endpoint: `GET /api/v1/verify/stratum`

### Reaper Capability (+2 Shares)
A node capability indicating the node runs Ghost Reaper. Verified by sending test transactions containing known dead code patterns and confirming the node correctly rejects them as Corpses. Requires 95% pass rate. Previously called "Bitcoin Pure" in the share system (renamed February 2026). Not to be confused with the `bitcoin_pure` PolicyProfile, which is a separate BUDS policy name.
- Verification endpoint: `POST /api/v1/verify/reaper`
- Config condition: `reaper.enabled`

### Elder Status (+1 Share)
A node capability granted to the first 101 nodes that contribute to the MPC ceremony. Determined by the `mpc_contributions` database table. Positions are permanent and non-transferable; if an elder goes offline, the position is lost forever. Revoked elder numbers are never reassigned ("burned slots"). Elder status does not grant special voting power -- all nodes participate equally in BFT consensus.
- See: [MPC Ceremony](#mpc-ceremony-and-elders)

### Gatekeeper
The uptime requirement that must be met before any shares count toward rewards. Nodes must maintain 95% uptime over a trailing 7-day window (57,456 of 60,480 expected heartbeats). Below this threshold, a node earns zero shares regardless of capabilities.
- Constant: `UPTIME_GATEKEEPER_THRESHOLD = 95.0`

### Node Reward Pool
The portion of each block's subsidy (0.5% pre-threshold, increasing after treasury decay) allocated to qualified nodes. Distributed proportionally to total shares held. Top 100 nodes by shares are paid directly in the coinbase; others accumulate balances in a ledger until they enter the top 100 or exceed the dust threshold.
- Implementation: `bins/ghost-pool/src/payout.rs`

### Node Reward Ledger
A per-node balance tracking system. Each block adds a node's share of the reward pool to its ledger balance. Top 100 nodes have their balance paid out in the coinbase (then zeroed). Nodes outside the top 100 accumulate until they enter the top 100 or meet batch payout criteria.

### Verification Challenge
A challenge-response test used to verify a node's claimed capabilities. Every 5 minutes, each node selects 3 random peers and issues appropriate challenges for each capability the peer claims. Results are stored in database tables (`archive_challenges`, `policy_challenges`, `stratum_challenges`, `ghostpay_challenges`) and shared across the pool via P2P.
- Implementation: `crates/ghost-verification/src/task.rs`

### QualifiedCapabilityProvider
The component that calculates whether a node has passed enough verification challenges to qualify for a given capability. Requires a minimum number of challenges (10) and a capability-specific pass rate (90-95%) over a 7-day window.
- Implementation: `crates/ghost-verification/src/qualification.rs`

### VerificationClient
The HTTP client that issues verification challenges to peer nodes.
- Implementation: `crates/ghost-verification/src/client.rs`

### VerificationTask
The periodic task (spawned in `main.rs`) that selects random peers and issues verification challenges every 5 minutes.
- Implementation: `crates/ghost-verification/src/task.rs`

---

## Mining and Stratum

### Stratum V1 (SV1)
The primary mining protocol used by Ghost. JSON-RPC over TCP on port 3333. Miners connect with worker name format `<bitcoin_address>.<worker_id>`, where the payout address is extracted from the username. Key methods: `mining.subscribe`, `mining.authorize`, `mining.notify`, `mining.submit`.
- Implementation: `bins/ghost-pool/src/stratum/`

### Stratum V2 (SV2)
A binary mining protocol defined by the SRI project. SV2 is supported via the SRI pool binary (`pool_sv2`) on port 34255. Ghost-pool feeds templates via TDP (port 8442); SRI pool distributes SV2 work. Ghost does not support SV2 miner-selected transactions -- nodes have full template sovereignty. The translator binary (`bins/translator/`) bridges SV1 and SV2.
- SRI fork: `sv2-apps/pool-apps/`

### SRI (Stratum Reference Implementation)
The open-source Stratum V2 reference implementation from the stratum-mining project. Ghost's SRI fork lives in `sv2-apps/pool-apps/` and is built as a separate workspace. The SRI pool binary (`pool_sv2`) accepts SV2 connections upstream from the translator.

### Translator
An SV1-to-SV2 protocol translation proxy (`bins/translator/`). Accepts SV1 JSON-RPC connections from miners and can convert to SV2 binary protocol for upstream SV2 pools. Now largely optional since ghost-pool natively supports SV1.

### Vardiff (Variable Difficulty)
Per-miner difficulty adjustment targeting approximately 4 shares per minute. Initial difficulty is 2000. Adjustments are recalculated after 4+ shares in a 30+ second window, with a maximum 4x change factor per adjustment. Sent to miners via `mining.set_difficulty` notification.
- Config: `VardiffConfig` in `stratum/difficulty.rs`
- Constant: target = 4 shares/minute

### Share
A proof of work submitted by a miner that meets the pool's difficulty target (lower than network difficulty). Shares prove the miner is expending hashrate. Each share is validated for job existence, nonce uniqueness, hash correctness, timestamp bounds, and rate limits.

### Round
A period of share accounting between consecutive blocks. When a block is found, the current round's shares are snapshot, payouts are calculated, and a new round begins. Tracked in the `rounds` database table.
- Implementation: `bins/ghost-pool/src/round.rs`

### Pre-Consensus Coinbase
A critical design pattern where coinbase outputs are computed deterministically before a winning share arrives, eliminating consensus delay at block discovery. All nodes calculate the same payouts from the same share state, so when a block is found, it can be submitted immediately with the pre-built coinbase.
- Spec: `docs/SPECIFICATION.md` Section 18.1

### Coinbase Construction
The process of building the coinbase transaction for each block. Ghost provides complete coinbase outputs via TDP, controlling all outputs (miner payouts, node rewards, treasury, TX fees to node operator). Maximum 301 outputs: 1 TX fees + 1 treasury + 100 node rewards + 200 miner payouts.
- Implementation: `bins/ghost-pool/src/payout.rs`

### TDP (Template Distribution Protocol)
The mechanism by which ghost-pool sends block templates (including pre-built coinbase outputs) to miners or to the SRI pool. When `coinbase_tx_value_remaining` is 0, it indicates Ghost controls all outputs.

### CPFP (Child Pays For Parent)
A Bitcoin transaction relay/mining policy where a child transaction with high fees can incentivize mining of its low-fee parent transaction. Ghost's template construction includes CPFP-aware sorting.
- Implementation: `bins/ghost-pool/src/template.rs`

### Block Template
The data structure received from Ghost Core via `getblocktemplate` RPC containing the set of mempool transactions to include in the next block, along with header fields. Ghost Pool filters this template through BUDS/Reaper policy before distributing work to miners.

### BIP320 Version Rolling
A technique where miners can use certain bits of the block header's version field as additional nonce space. The miner sends only the bits within a mask, and ghost-pool combines them: `(template_version & !mask) | (miner_bits & mask)`.

---

## Ghost Core (ghostd)

### Ghost Core
See [Core System](#ghost-core-ghostd).

### ghostd
The daemon binary for Ghost Core. Built from `ghost-core/` using CMake. Runs as the `ghost` user with data directory at `/home/ghost/.ghost/ghost-core/`.

### Ghost Core RPC
JSON-RPC over HTTP for communication between ghost-pool and ghostd. Standard Bitcoin Core RPC methods (`getblocktemplate`, `submitblock`, `getblockchaininfo`) plus Ghost-specific additions for Silent Payments, Wraith Protocol, and Reconciliation.

---

## Ghost Haze System

### Ghost Haze
The state of a Ghost Core node whose historical archive has been irreversibly stripped of all "hazeable" content -- witness data, scriptSig signatures, OP_RETURN payloads, and coinbase arbitrary data. Only the structural economic graph (transaction IDs, amounts, addresses, block headers) remains. Bitcoin's existing cryptographic commitments (txids, witness commitments) serve as proof that the destroyed content existed. Reduces storage from ~718 GB to ~193 GB (compressed). Provides legal protection against liability from arbitrary content (including CSAM) embedded in the blockchain by third parties.
- Spec: `docs/protocols/GHOST_HAZE.md`
- Source: `ghost-core/src/haze/`

### Hazeable Content
Data fields that Ghost Haze strips from the archive: witness data (~200 GB), scriptSig data (~75 GB), OP_RETURN payloads (~3 GB), and coinbase arbitrary data (~0.06 GB). None of these are required for Bitcoin's consensus, transaction graph, balance verification, or wallet operation for historical transactions.

### Ghost Exorcism
The runtime process that protects a Ghost Core node during block processing. Incoming block data is validated entirely in volatile memory (RAM). Only stripped structural data is written to persistent storage. Hazeable content passes through RAM and is purged -- it never takes hold on disk. Implemented as a single code path change in `validation.cpp` after `AcceptBlock()` succeeds.
- Source: `ghost-core/src/haze/exorcism.h/.cpp`

### Ghost Exorcist
The conversion tool that transforms an existing full archive node (Mode B) into a hazed node (Mode A). Walks the existing `blk*.dat` files, strips all hazeable content, writes the structural archive in GSB format, securely zeroes the originals, and generates a Legal Compliance Packet. Conversion is irreversible.
- CLI: `ghost-core --exorcist`
- Source: `ghost-core/src/haze/exorcist.h/.cpp`

### Mode A (Hazed Node)
The default and recommended Ghost Core mode. Ghost Haze and Ghost Exorcism are active from first launch. Storage: ~193 GB (compressed). All hazeable content is stripped; only the structural economic graph is preserved. Legal liability: none.

### Mode B (Full Archive)
The opt-in Ghost Core mode for operators who accept the legal risk. Standard Bitcoin Core behavior with all data stored in plaintext. Storage: ~718 GB. Benefits from daily Ghost Checkpoint for faster IBD.

### GSB Files (Ghost Stripped Block)
The on-disk format for stripped blocks in a hazed node. Files named `gsb?????.dat` with a magic header of `0x47 0x53 0x42 0x00` ("GSB\0"). Contains block headers, transaction structure (versions, inputs/outputs, amounts, scripts), and stored txids for legacy transactions -- but no witness data, scriptSig, OP_RETURN payloads, or coinbase arbitrary data.
- Source: `ghost-core/src/haze/stripped_block.h/.cpp`

### Ghost Checkpoint
A signed data package published daily by the Ghost Core project, bundling everything a new node needs for accelerated sync: pre-built chainstate (LevelDB UTXO database), all block headers, a SwiftSync Bloom filter, archive chunk manifest, and an Ed25519 signature. Enables a hazed node to become usable in ~3 minutes.

### SwiftSync
A Bloom filter (~212 MB) included in Ghost Checkpoints that encodes the ~170 million outpoints remaining unspent at the checkpoint height. During full IBD from genesis, the node checks this filter before writing UTXO entries to LevelDB, eliminating 93% of LevelDB write operations (only the 7% of outputs that survive to the present are written). Reduces UTXO construction from ~2.5 hours to ~15-20 minutes.

### Legal Compliance Packet
A signed JSON document generated by Ghost Core on demand, attesting that the node operates in Haze mode, all hazeable content has been irreversibly destroyed, and Exorcism is active. Suitable for presentation to legal counsel or regulatory authorities.
- CLI: `ghost-core --legal-packet`

### NODE_GHOST_HAZE
A P2P service flag (`1 << 14`) advertised by Mode A nodes. Signals to peers that the node stores structural data only and will respond to full block requests with `GHOST_STRIPPED_BLOCK` messages.

### GHOST_STRIPPED_BLOCK
A P2P message type sent by Mode A nodes in response to `getdata` for a block. Contains the stripped block in GSB format.

### GHOST_REDIRECT
A P2P message type sent by Mode A nodes when a peer requests raw data that has been stripped. Contains the requested txids and a list of known archive peer addresses.

---

## Ghost Reaper

### Ghost Reaper
A dead code detection engine that analyzes Bitcoin transaction witness scripts and outputs to identify bytes that serve no purpose in script execution. Transactions containing excessive dead code are classified as "Corpses" and filtered from block templates. Operates independently from BUDS classification -- BUDS classifies transaction purpose (policy tiers), while Reaper classifies transaction content (dead bytes). Two-layer defense: Layer 1 (C++ in Ghost Core mempool, fast pattern matching) and Layer 2 (Rust in ghost-pool template, full 8-vector analysis).
- Spec: `docs/protocols/GHOST_REAPER.md`
- Layer 2 source: `crates/ghost-reaper/src/`
- Layer 1 source: `ghost-core/src/validation.cpp` (within `PreChecks()`)

### Corpse
A transaction that Ghost Reaper has determined contains dead code exceeding configured thresholds. Corpse transactions are filtered from block templates and not included in blocks built by Ghost nodes.

### Dead Code
Bytes in a transaction's witness data, scripts, or outputs that serve no purpose in script execution. Includes inscription envelopes, drop stuffing, unreachable code, fake pubkeys, oversized OP_RETURN, annex abuse, excess witness data, and legacy scriptSig data stuffing.

### Detection Vectors (Reaper)
The 8 categories of dead code that Reaper detects:
1. **Inscription Envelope** -- `OP_FALSE OP_IF <data> OP_ENDIF` in witness (Ordinals-style)
2. **Drop Stuffing** -- `<push >= 76 bytes> OP_DROP` in witness
3. **Unreachable Code** -- Bytecode after a top-level `OP_RETURN`
4. **Fake Pubkeys** -- Two-tier detection: (1) prefix validation rejects non-0x02/0x03 bytes (`FakePubkey`), (2) full secp256k1 curve point decompression via `PublicKey::from_slice()` catches valid prefixes with off-curve x-coordinates (`FakePubkeyCurvePoint`). Both enabled in strict mode.
5. **Oversized OP_RETURN** -- Data payload exceeding configured limit (default: 83 bytes)
6. **Annex Presence** -- P2TR witness last element starting with `0x50`
7. **Excess Witness Data** -- Witness bytes not consumed by any execution path (taint-tracking analysis)
8. **Legacy scriptSig Data** -- Non-standard large pushes in legacy scriptSig

### ReaperVerdict
The result of analyzing a transaction. Contains the verdict (Accept or Corpse), a list of dead code regions, per-input analyses, total dead/witness byte counts, and dead code ratio.

### Reaper Modes
Binary toggle:
- **Enabled** -- Any dead code results in a Corpse verdict. Zero tolerance. Required for +2 Reaper shares.
- **Disabled** -- No analysis or filtering performed.
- Configuration: `-ghostreaper` (ghostd) or `[reaper] enabled = true` (pool.toml)

### Taint-Tracking Simulator
A symbolic script execution engine within Ghost Reaper (`simulator.rs`) that traces which witness indices contribute to stack values consumed by signature verification opcodes. Witness bytes not consumed by any execution path are flagged as excess. Safety limits: 1000 stack depth, 100 IF depth, 64 branch paths.

---

## BUDS Classification

### BUDS (Bitcoin Unified Data Standard)
A classification system that categorizes transaction data by type and location. Each transaction is assigned labels based on what data it contains and where that data appears. Nodes use BUDS to implement policy-based filtering for mempool acceptance and block building. Each node chooses its own policy -- there is no network-wide mandate.
- Spec: `docs/protocols/BUDS_POLICY.md`
- Source: `crates/ghost-buds/src/`

### BUDS Tiers
Classification hierarchy for transaction data:
- **T0 (Consensus)** -- Required for validation (signatures, scripts, public keys). Always allowed.
- **T1 (Economic)** -- Standard Bitcoin usage (payments, L2 commitments, small OP_RETURN). Generally allowed.
- **T2 (Metadata)** -- Application data (inscriptions, BRC-20, Runes). Policy decision.
- **T3 (Unknown)** -- Unclassified or obfuscated data. Generally rejected.

### BUDS Surfaces
Where data appears in a transaction: `scriptpubkey`, `witness_stack`, `witness_script`, `scriptsig`, `coinbase`.

### BUDS Labels
Hierarchical classification tags assigned to byte ranges in a transaction. Examples: `consensus.sig`, `pay.standard`, `meta.inscription`, `da.op_return_small`, `da.obfuscated`.

### PolicyProfile
A named set of allow/reject rules for BUDS labels, plus numeric thresholds. Built-in profiles:
- **bitcoin_pure** -- "P2P Electronic Cash." Allows consensus, payments, contracts, commitments, small OP_RETURN. Rejects inscriptions, BRC-20, Runes, large OP_RETURN, excessive witness.
- **permissive** -- Allows all known metadata. Rejects only unknown/obfuscated data.
- **full_open** -- Accepts everything.

Operators can also create custom profiles.
- Source: `crates/ghost-policy/src/`

### ARBDA Score
The highest BUDS tier present in a classified transaction (e.g., if a transaction contains T2 metadata labels, its ARBDA score is T2). Used in policy verification responses.

---

## Ghost Pay L2

### Ghost Pay
An optional Layer 2 payment network built on top of Bitcoin Ghost. Provides instant transfers (10-second virtual blocks), low fees (users pay only their share of batch mining costs), privacy (ZK proofs, Ghost Keys), and periodic Bitcoin L1 settlement. Nodes running Ghost Pay earn +4 shares.
- Spec: `docs/protocols/GHOST_PAY.md`
- Source: `crates/ghost-pay/src/`
- Binary: `bins/ghost-pay/`

### Virtual Block
The L2 time unit. Duration: 10 seconds. Provides fast confirmation for Ghost Pay transfers. Finality is instant within L2.

### Epoch
A batch of 2,160 virtual blocks (= 6 hours). Epochs define settlement boundaries for L1 reconciliation. Different settlement classes batch across different numbers of epochs.

### Reconciliation
The process of settling L2 state changes to Bitcoin L1. Batches withdrawal requests and state commitments into L1 transactions. Settlement classes: Express (every epoch, ~6h), Standard (every 4 epochs, ~24h), Economy (weekly, ~7d). Fees contribute to the L2 fee pool.
- Spec: `docs/protocols/RECONCILIATION.md`
- Source: `crates/ghost-reconciliation/src/`

### Settlement Class
One of three tiers for L1 reconciliation batching: Express (every epoch, higher fees), Standard (every 4 epochs, medium fees), Economy (weekly, lower fees). Users choose their class when requesting a withdrawal from L2.

### Ghost Keys
The identity foundation of Ghost Pay, based on BIP-352 Silent Payments. Consist of a scan key pair (for detecting incoming payments) and a spend key pair (for spending received funds). Each payment creates a unique on-chain address that only the recipient can detect, providing receiver privacy with no address reuse.
- Spec: `docs/protocols/GHOST_KEYS.md`
- Source: `crates/ghost-keys/src/`

### Ghost ID
A bech32-encoded address format with the `ghost` human-readable part, encoding a scan pubkey (33 bytes) and spend pubkey (33 bytes). Format: `ghost1<bech32_encoded_data>`. A single Ghost ID can receive unlimited payments, each to a different on-chain address.

### Silent Payments (BIP-352)
A Bitcoin Improvement Proposal for stealth addresses. Ghost Keys are based on this standard. The sender uses ECDH with the recipient's scan pubkey to derive a unique output pubkey for each payment. Only the recipient (with their scan secret) can detect and spend the payment.
- Ghost Core RPC: `getsilentpaymentaddress`, `derivesilentpaymentaddress`, `checksilentpayment`, etc.

### Ghost Locks
The on-chain representation of funds in Ghost Pay. Taproot (P2TR) outputs with two spending paths: key path (efficient, private normal spending) and script path (timelocked recovery using a backup key). Use standard denominations for privacy (Micro: 10k sats, Tiny: 100k, Small: 1M, Medium: 10M, Large: 100M, XL: 1B).
- Spec: `docs/protocols/GHOST_LOCKS.md`
- Source: `crates/ghost-locks/src/`

### Ghost Lock ID
A deterministic 32-byte identifier for a Ghost Lock, computed as `tagged_hash("GhostLock/v1", lock_pubkey || recovery_pubkey || creation_height || denomination_sats)`. Used for L2 balance tracking and settlement transaction references.

### Denomination (Ghost Lock)
Standard value tiers for Ghost Locks ensuring all locks of the same tier look identical on-chain: Micro (10,000 sats), Tiny (100,000), Small (1,000,000), Medium (10,000,000), Large (100,000,000), XL (1,000,000,000). Enables efficient Wraith mixing and privacy through uniformity.

### Timelock Tier
Recovery timelock duration for Ghost Locks: Short (6 months, ~26,280 blocks), Standard (1 year, ~52,560 blocks), Long (2 years, ~105,120 blocks). Recovery spending via the script path becomes available after `creation_height + timelock_blocks`.

### Jump Locks
An extension of Ghost Locks that provides automatic key rotation based on the balance at risk. Higher-value locks rotate more frequently: Low (< 0.1 BTC, 30 days), Medium (0.1-1 BTC, 14 days), High (> 1 BTC, 7 days). Each "jump" is an atomic transaction spending the old lock and creating a new one with fresh keys.
- Spec: `docs/protocols/JUMP_LOCKS.md`

### Wraith Protocol
A two-phase CoinJoin mixing protocol for private entry into Ghost Pay. Phase 1 (Split): N inputs become OPP×N intermediate Ghost Locks (OPP = 2-10 per tier). Phase 2 (Merge): OPP×N intermediates merge back into N final Ghost Locks. Uses Schnorr blind signatures so the coordinator cannot link inputs to outputs. Fixed service fee (500-10,000 sats per denomination) + mining cost share. Denominations: Micro (100K), Small (1M), Medium (10M), Large (100M). Any Ghost node can coordinate sessions.
- Spec: `docs/protocols/WRAITH_PROTOCOL.md`
- Source: `crates/wraith-protocol/src/`

### Blind Signatures (Schnorr)
An interactive signing protocol used in Wraith Protocol where the coordinator signs messages without seeing their content. The participant blinds the message with random factors, the coordinator signs the blinded version, and the participant unblinds to get a valid signature. Provides cryptographic unlinkability between signing sessions and final signatures.

### Wraith Participant Tiers
Anonymity set sizes with corresponding wait times: Express (25 participants, minutes), Quick (50, hours), Small (100, ~1 day), Medium (250, ~2 days), Standard (500, ~3 days), Large (750, ~5 days), Whale (1000, ~7 days).

---

## Privacy and Cryptography

### Ghost Shroud
A network-level privacy feature in Ghost Core that adds a random delay (0-5 seconds) before relaying transactions to peers, preventing timing-based origin detection. Transactions enter the local mempool immediately (mining unaffected); only outbound relay is delayed. Enabled by default (`-shroud=1`).
- Spec: `docs/protocols/GHOST_SHROUD.md`
- Source: `ghost-core/src/net_processing.cpp`

### Noise Protocol
The encryption framework used for sensitive P2P communication between Ghost nodes. Protocol: `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Provides mutual authentication, forward secrecy, identity binding, and anti-replay protection. Used for shares, blocks, votes, payouts, verification, and MPC messages. Port 8563.
- Implementation: `crates/ghost-consensus/src/mesh.rs`

### Ed25519
The digital signature algorithm used for node identity. Each node has a 32-byte Ed25519 public key as its NodeId. All consensus messages are Ed25519-signed with sender, timestamp, and payload.

### Groth16
The zero-knowledge proof system used by Ghost Pay. SNARK (Succinct Non-Interactive Argument of Knowledge) over the BLS12-381 curve. Proof size: 192 bytes (A: 48 G1, B: 96 G2, C: 48 G1). Used for GhostNoteSpendCircuit (note spending / transfer validity) and PayoutCircuit (payout distribution validity). Requires a trusted setup (MPC ceremony) to generate proving and verifying keys.
- Source: `crates/ghost-zkp/src/`

### GhostNoteSpendCircuit
A Groth16 ZK circuit that proves a sender is authorized to spend a note in the L2 commitment tree. ~12,675 constraints at depth-20 merkle tree. Uses MiMC (82 rounds) for hashing. Public inputs: `commitment_root`, `nullifier`, `change_commitment`, `recipient_commitment`. Senders generate proofs locally (~170ms); validators verify in ~5ms. Replaced the earlier BlockCircuit design (February 2026 L2 redesign).
- Source: `crates/ghost-zkp/src/circuit/note_spend.rs`

### NullifierRouteHandler
The L2 transaction validator that replaces the earlier ZkVoteHandler and L2BlockProducer. Validates sender-side Groth16 proofs, routes transactions by nullifier prefix for deterministic validator assignment, manages BFT checkpoints (every 10 seconds, all-node, 67% threshold), and produces epoch transition proposals.
- Source: `crates/ghost-consensus/src/nullifier_route_handler.rs`

### EpochManager
Manages L2 epoch lifecycle: tree compaction, epoch transitions, proposer rotation, and commitment tree maintenance. Each epoch represents a batch of virtual blocks. Provides `current_root()` and `advance_epoch()` for the NullifierRouteHandler.
- Source: `crates/ghost-consensus/src/epoch_manager.rs`

### CommitmentTree
A sparse Merkle tree (depth 20, ~1M leaf capacity) that stores note commitments for the L2 note/UTXO model. Uses `precompute_zero_hashes()` for efficient sparse tree operations — without it, computing the root is O(2^depth). MiMC (82 rounds) is the hash function. Critical implementation detail: `get_node_hash()` short-circuits on zero subtrees.
- Source: `crates/ghost-zkp/src/commitment_tree.rs`

### MiMC
A hash function used in Ghost's ZK circuits. Uses 82 rounds of Feistel-mode hashing with SHA-256-derived round constants over BLS12-381. Provides ≥128-bit security against algebraic attacks. Used for note commitments, nullifier derivation, and Merkle tree construction within GhostNoteSpendCircuit.
- Source: `crates/ghost-zkp/src/circuit/mimc.rs`
- Constant: `MIMC_ROUNDS = 82`

### Sender-Side Proofs
The L2 proof architecture where senders (not validators) generate Groth16 proofs for their transactions. Senders prove they own a note and that the spend is valid (~170ms proof generation). Validators only verify the proof (~5ms). This shifts computational burden to senders and enables parallel transaction processing. Replaced the earlier validator-side block proof model (February 2026 L2 redesign).

### PayoutCircuit
A Groth16 ZK circuit that proves payout distribution validity: sum preservation (miners + nodes + treasury = total), 64-bit amount bounds, and metadata commitment.
- Source: `crates/ghost-zkp/src/payout.rs`

### Toxic Waste
The random secret values (tau, alpha, beta) generated by each MPC ceremony contributor and used to transform the ceremony parameters. If any single contributor honestly destroys their toxic waste, the ceremony is secure. Ghost zeroes these values with volatile writes and memory barriers, never writes them to disk. Deletion is fully automatic via `ZeroizeOnDrop` -- no manual intervention required. Values exist only in stack memory during contribution generation and are zeroized when the function returns.
- Source: `crates/ghost-zkp/src/ceremony.rs`

---

## MPC Ceremony and Elders

### MPC Ceremony (Multi-Party Computation Ceremony)
A rolling trusted setup ceremony for generating Groth16 proving and verifying keys. Contributors apply random values to chain-linked parameters. The first 101 contributors become Elders (+1 share). Security model: 1-of-N (one honest participant sufficient for soundness). Genesis node (position 1) auto-approves locally; subsequent positions require 67% BFT approval from existing contributors. Ossifies after 101 contributions.
- Spec: `docs/protocols/MPC_CEREMONY.md`
- Source: `crates/ghost-mpc/src/`, `bins/ghost-pool/src/mpc_handler.rs`

### CeremonyManager
The component that tracks MPC ceremony state, stores parameter files, and provides access to current proving/verifying keys. Maintains contribution count (0-101), current params hash, ossification status, and ceremony ID.
- Source: `crates/ghost-zkp/src/ceremony.rs`

### Elder
A node that successfully contributed to the MPC ceremony (positions 1-101). Elder status is determined by the `mpc_contributions` database table. Grants +1 share in the 5-4-3-2-1 system. All nodes vote equally in BFT consensus regardless of elder status -- the only context where elder status affects voting is MPC contribution approval.

### Genesis Node
The first node in the network, started with the `--genesis` flag. Auto-approves its own MPC contribution as position 1, bootstrapping the ceremony. Only one node should run with `--genesis`; if multiple do, they each independently generate genesis parameters and conflict. Protected by three layers: (1) network peer check queries seed nodes for existing MPC contributors before allowing genesis, (2) optional password protection via `genesis_password` in config, (3) ceremony ID matching rejects contributions from a conflicting genesis.

### Burned Slot
A revoked elder number that is never reassigned. When an elder is revoked (67% BFT vote after 7+ days offline), their position number is permanently retired. Tracked in the `burned_elder_numbers` database table.

### MPC Parameter Files
Stored in `~/.ghost/mpc_params/`. Each version (`note_spend_params_v{N}.bin`, `payout_params_v{N}.bin`) is a complete parameter set (~200MB). A `_current.bin` symlink points to the latest. Transferred between peers in 1MB chunks.

---

## Consensus and P2P Mesh

### BFT Consensus (Byzantine Fault Tolerant)
The consensus mechanism used for coordinating pool nodes. Requires 67% agreement for share accounting, payout proposal approval, and elder registration/revocation. Tolerates up to 33% malicious or faulty nodes.
- Spec: `docs/protocols/CONSENSUS.md`
- Source: `crates/ghost-consensus/src/`

### ZMQ Mesh Network
The peer-to-peer communication layer using ZeroMQ (ZMQ) sockets. Uses PUB/SUB for broadcasts (shares, blocks, health), DEALER/ROUTER for voting, and REQ/REP for discovery. Ports 8555-8562. Sensitive messages route through Noise Protocol encryption (port 8563) instead of plaintext ZMQ.
- Source: `crates/ghost-consensus/src/mesh.rs`

### Health Ping
A heartbeat message broadcast every 10 seconds on port 8558. Contains node capabilities, uptime, and status. Used for liveness detection and capability advertisement. Missing heartbeats are tracked; 7+ continuous days offline triggers revocation eligibility for elders.

### ConsensusMessage
The enum of all message types in the P2P protocol: `ShareProof`, `BlockFound`, `PayoutProposal`, `PayoutVote`, `PayoutTransaction`, `HealthPing`, `NodeRegistration`, `ElderRevocation`, `DiscoveryRequest`, `DiscoveryResponse`.

### SignedMessage
The envelope for all consensus messages. Contains sender (32-byte Ed25519 pubkey), timestamp (Unix ms), Ed25519 signature (64 bytes), and serialized payload.

### PayoutProposal
A message broadcast when a block is found, proposing the payout distribution. Sent on port 8561. Other nodes validate and vote (approve/reject) on the proposal.

### PayoutVote
A node's vote on a PayoutProposal. Sent on port 8557. At 67% approval, consensus is reached and the payout is executed.

### Share Propagation
The broadcast of share proofs across the mesh network (port 8555, PUB/SUB). When a node validates a miner's share, it broadcasts a `ShareProof` to all peers so all nodes maintain consistent ledger state.

### Block Announcement
The broadcast of a `BlockFound` message (port 8556) after a node submits a winning block to the Bitcoin network.

### Peer Discovery
The process by which nodes find each other. Uses ZMQ REQ/REP on port 8559. Nodes can also be discovered via bootstrap peers in configuration, the `/api/v1/network/public-nodes` HTTP endpoint, or the Node Finder web tool.

### Replay Attack Prevention
Three-layer defense against message replay in the P2P mesh:
1. **Deduplication Window** -- Tracks `(sender_id, sequence_number)` pairs for 60 seconds (100k capacity).
2. **Timestamp Validation** -- Messages must be within 5 minutes of current time.
3. **Sequence Monotonicity** -- Per-sender tracking of highest sequence seen; rejects lower or equal sequences.

### Equivocation
When a node casts conflicting votes (e.g., approving and rejecting the same proposal). Detected and punished with a 24-hour ban (escalating with repeat offenses).

### Ban Management
Automated peer banning for protocol violations. Reasons: Equivocation (24h), RateLimitExceeded (1h), InvalidMessages (30m), ProtocolViolation (24h). Escalation multiplier: `2^(count - 1)`, capped at 16x. Decay: count decreases by 1 per 7-day clean period.

---

## Wallet and Client Infrastructure

### GSP (Ghost Service Provider)
A light wallet backend integrated into ghostd that enables light wallets to interact with the Bitcoin Ghost network without running a full node. Uses BIP-157 compact block filters for privacy (server cannot track specific wallets). Default port: 8900 (HTTP/WebSocket). Authentication via WalletProof + JWT sessions.
- Spec: `docs/wallets/GSP_SERVER.md`
- Source: `crates/ghost-gsp/src/`

### Ghost Node TUI
A Ratatui terminal dashboard for node management. Includes 9 configuration wizards (identity, network, mining, capabilities, treasury, Ghost Pay, Reaper, privacy, advanced), multi-node swarm view, and live status monitoring.
- Source: `bins/ghost-node-tui/src/`

### Ghost Node Dashboard
A Next.js web dashboard for monitoring node status, capabilities, mining activity, and peer connections.
- Deploy path: `/home/ghost/ghost-node-dashboard/`
- Source: `dashboard/`

### Light Wallet TUI
A Ratatui terminal wallet with Ghost Keys, Ghost Locks, L2 payments, and Wraith mixing support. Connects to a GSP server for blockchain data.
- Source: `bins/ghost-light-wallet-tui/src/`

### Light Wallet CLI
A command-line wallet for balance queries, send/receive operations, and lock management. Connects to a GSP server for blockchain data.
- Source: `bins/ghost-light-wallet-cli/src/`

### Ghost Qt Wallet
A desktop GUI wallet built into Ghost Core. Full Qt interface with address book, coin control, PSBT support, Ghost Locks management, and Silent Payment integration.
- Source: `ghost-core/src/qt/`

---

## Economic Model

### Pool Fee
1% of each block's subsidy (not TX fees). Split between treasury (0.5%) and node reward pool (0.5%) pre-threshold.

### Treasury
A fund for ongoing development, controlled by a multisig address. Receives 0.5% of each block subsidy (pre-threshold). After reaching 21 BTC, enters a 5-year linear decay: 0.5% -> 0.4% -> 0.3% -> 0.2% -> 0.1% -> 0%. After decay completes, the full 1% pool fee goes to node rewards.
- Threshold: 21 BTC (2,100,000,000,000 sats)
- Constant: `TREASURY_THRESHOLD_SATS`

### Treasury Decay
The 5-year linear reduction of the treasury allocation after the 21 BTC threshold is reached. Each year reduces the treasury's share by 0.1 percentage points. After 5 years, treasury allocation drops to zero.

### TX Fees
Transaction fees from all transactions in a block. 100% goes to the node operator that built the block (in the coinbase), separate from the subsidy-based pool fee.

### Dust Threshold
The minimum payout amount: 546 satoshis. Payouts below this amount are not included in the coinbase; instead, the balance accumulates in the ledger until it exceeds the threshold.
- Constant: `DUST_THRESHOLD_SATS = 546`

### Dust Redistribution
The system for handling sub-dust amounts. Miner payouts below 546 sats are added to the node reward pool. Node reward dust goes to the top-capability node. TX fee dust goes to the top-capability node. No satoshis are lost to treasury or abandoned.

### Miner Payout
Work-proportional share of 99% of the block subsidy. Top 200 miners by balance are paid directly in the coinbase. Below top 200, balance accumulates in the ledger until above dust threshold.

### Ledger
The internal accounting system tracking miner and node balances. Two ledger states exist:
- **Pending Ledger** -- Updated as shares arrive, used for pre-consensus coinbase calculation.
- **Consensus Ledger** -- The agreed-upon state referenced for payout calculations.

On block found: pending transitions to consensus atomically. Top 200 miners and top 100 nodes are paid (zeroed); others accumulate.

---

## Network Ports Reference

| Port | Protocol | Purpose |
|------|----------|---------|
| 3333 | TCP/JSON-RPC | SV1 Stratum (miners) |
| 8080 | HTTP | Verification API |
| 8333 | TCP | Bitcoin P2P (mainnet) |
| 8555 | ZMQ PUB/SUB | Share propagation |
| 8556 | ZMQ PUB/SUB | Block announcements |
| 8557 | ZMQ DEALER/ROUTER | Consensus voting |
| 8558 | ZMQ PUB/SUB | Health monitoring (heartbeat) |
| 8559 | ZMQ REQ/REP | Peer discovery |
| 8560 | ZMQ PUB/SUB | Elder management / MPC |
| 8561 | ZMQ PUB/SUB | Payout proposals |
| 8562 | ZMQ PUB/SUB | Payout transactions |
| 8563 | TCP/Noise | Encrypted P2P channel |
| 8800 | HTTP | Ghost Pay API |
| 8900 | HTTP/WebSocket | GSP (light wallet backend) |
| 28332 | ZMQ | Ghost Core hashblock notifications (localhost) |
| 28333 | ZMQ | Ghost Core hashtx notifications (localhost) |
| 8442 | TCP/SV2 | TDP (Template Distribution Protocol) |
| 34255 | TCP/SV2 | SV2 Stratum (SRI pool endpoint) |
| 38332 | HTTP/JSON-RPC | Ghost Core RPC (localhost, signet) |
| 38333 | TCP | Bitcoin P2P (signet) |

---

## OP_RETURN Markers

| Marker | Full Name | Purpose |
|--------|-----------|---------|
| GPGL | Ghost Pay Ghost Lock | Ephemeral pubkey for Silent Payment derivation (38 bytes total) |
| GPRC | Ghost Pay Reconciliation | L2 state commitment anchor (version + epoch + state root) |
| WR1 | Wraith Phase 1 | Marks a Wraith Protocol split transaction |
| WR2 | Wraith Phase 2 | Marks a Wraith Protocol merge transaction |

---

## Crate Reference

| Crate | Purpose |
|-------|---------|
| `ghost-accounting` | Economic accounting (ledger, balances) |
| `ghost-buds` | BUDS classification engine |
| `ghost-common` | Shared types and RPC primitives |
| `ghost-consensus` | P2P mesh network, health handler, BFT voting |
| `ghost-gsp` | Ghost Service Provider (light wallet backend) |
| `ghost-gsp-proto` | GSP protocol definitions |
| `ghost-keys` | Silent Payment (BIP-352) key derivation |
| `ghost-light-wallet` | Light wallet client |
| `ghost-locks` | Ghost Lock P2TR output construction |
| `ghost-mpc` | MPC ceremony participation |
| `ghost-policy` | Policy profiles and validation |
| `ghost-reaper` | Dead code detection engine (8-vector analysis) |
| `ghost-reconciliation` | L1 settlement for Ghost Pay |
| `ghost-storage` | SQLite database layer and migrations |
| `ghost-stratum-common` | Shared Stratum protocol types |
| `ghost-template` | Block template construction and filtering |
| `ghost-verification` | Node capability verification (challenges, qualification) |
| `ghost-zkp` | Zero-knowledge proofs (Groth16, circuits, ceremony) |
| `wraith-protocol` | Two-phase CoinJoin mixing |

---

*End of Glossary*
