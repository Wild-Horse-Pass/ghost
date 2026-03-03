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
//| FILE: GHOST_HAZE.md                                                                                                  |
//|======================================================================================================================|
```

# GHOST CORE

## Ghost Haze, Ghost Exorcism & Ghost Exorcist

### Selective Archive Stripping, Real-Time Data Purification & Archive Conversion

**Technical Specification v2.0**
Bitcoin Ghost Project — February 2026

---

## 1. Abstract

Ghost Haze, Ghost Exorcism, and Ghost Exorcist are complementary data protection systems for Bitcoin node operators running Ghost Core.

**Ghost Haze** is the state of a node whose historical archive has been irreversibly stripped of all hazeable content — witness data, scriptSig signatures, OP_RETURN payloads, and coinbase arbitrary data. Only the structural economic graph remains. Bitcoin's existing cryptographic commitments (txids, witness commitments) serve as proof that the destroyed content existed.

**Ghost Exorcism** is the runtime process that protects the node during block processing. Incoming block data is validated entirely in volatile memory. Only stripped structural data is written to persistent storage. Hazeable content passes through RAM and is purged — it never takes hold on disk.

**Ghost Exorcist** is the conversion tool that transforms an existing full archive node into a hazed node. It walks the existing `blk*.dat` files, strips all hazeable content, writes the structural archive, and generates a Legal Compliance Packet proving the conversion.

Together, they provide complete lifecycle protection against the legal liability of arbitrary content embedded in the Bitcoin blockchain by third parties.

---

## 2. Problem Statement

### 2.1 The Embedded Data Liability

The Bitcoin blockchain permits arbitrary data to be embedded in transactions through several vectors: OP_RETURN outputs, witness fields (including Ordinals inscriptions), bare multisig scriptSig outputs, coinbase inputs, and crafted address encodings. These vectors have been exploited to store illegal material including CSAM. Every full archive node operator stores this data in plaintext on their hardware.

### 2.2 The Legal Exposure

Under strict liability statutes in most jurisdictions — including the United States (18 U.S.C. § 2252), United Kingdom (Protection of Children Act 1978), and the European Union (Directive 2011/93/EU) — possession of CSAM is a criminal offense regardless of intent or knowledge. A single high-profile prosecution could trigger mass node shutdowns, threatening Bitcoin's decentralization.

### 2.3 The Two Attack Surfaces

**At rest:** Historical blockchain data on disk contains embedded illegal content in plaintext. Ghost Haze eliminates this by irreversibly stripping hazeable content from the archive.

**In transit:** During block validation and IBD, plaintext illegal content passes through the node. Ghost Exorcism ensures this content exists only in volatile memory during validation and is never written to persistent storage.

### 2.4 Why This Data Is Not Needed

The hazeable content consists of:

- **Witness data (~200 GB):** Signatures and proofs that verified spending authority at the time of the transaction. Once a transaction is buried under 100+ blocks of proof-of-work, these signatures have served their purpose. Bitcoin Core's `assumevalid` (default since 2017) already skips re-verification of old signatures.

- **scriptSig data (~75 GB):** Legacy transaction signatures. Same argument as witness data — the signature proved spending authority, the transaction is confirmed, the job is done.

- **OP_RETURN payloads (~3 GB):** Application-layer data (Runes, Omni, OpenTimestamps). Every protocol that uses OP_RETURN maintains its own index and archive infrastructure. Bitcoin nodes are not required to store application data.

- **Coinbase arbitrary data (~0.06 GB):** Pool identification tags and miner messages. Zero operational value.

No part of Bitcoin's consensus, transaction graph, balance verification, or wallet operation requires this data for historical transactions.

---

## 3. Design Philosophy

**Irreversibility.** Stripped content cannot be reconstructed from the local node. This is destruction, not encryption. The content is gone.

**Zero custom records.** Bitcoin's existing cryptographic structure provides all necessary commitments. The txid commits to scriptSig. The witness commitment commits to all witness data. No per-field or per-transaction haze records are added — Bitcoin's consensus-validated commitments are stronger than any self-generated hash.

**Structural completeness.** The full economic graph is preserved: who paid whom, how much, when, to which address. Transaction IDs, amounts, output scripts, block headers, merkle trees, and the UTXO set are never stripped. A hazed node answers 99.9% of all practical queries locally.

**Minimal divergence.** Ghost Core stays as close to Bitcoin Core as possible. The stripped block format is derived from Bitcoin Core's existing `SERIALIZE_TRANSACTION_NO_WITNESS` serialization. Exorcism is a single code path change in block writing. The checkpoint system extends Bitcoin Core's existing `assumevalid` and `assumeUTXO` infrastructure.

**Opt-in modes.** Ghost Core supports three modes via the `storage.haze_mode` config field: Standard, Hazed, and FullArchive. Both Hazed and FullArchive benefit from the daily checkpoint infrastructure. The operator chooses at first launch.

---

## 4. Node Modes

### Configuration

The haze mode is configured in `pool.toml`:

```toml
[storage]
haze_mode = "Standard"    # Standard | Hazed | FullArchive
```

| Value | Description |
|-------|-------------|
| `Standard` | Default Bitcoin Core behavior with Ghost pool integration. No stripping. |
| `Hazed` | Ghost Haze and Ghost Exorcism active. All hazeable content stripped from archive. |
| `FullArchive` | Full archive retained but with daily checkpoint infrastructure for faster IBD. |

The `HazeMode` enum is defined in `ghost-common` and used by both the TUI wizard and `ghost-setup` CLI.

### 4.1 Mode A: Hazed Node

The default and recommended mode. Ghost Haze and Ghost Exorcism are active from first launch.

- All hazeable content is stripped from the archive
- Incoming blocks are validated in RAM; only structural data is written to disk
- The node stores the structural economic graph with Bitcoin's cryptographic commitments
- Legal Compliance Packet available on demand
- Serves structural data to other Mode A nodes
- Redirects raw data requests to Mode B peers on the network

### 4.2 Mode B: Full Archive

For operators who accept the legal risk in exchange for complete data availability.

- Standard Bitcoin Core behavior — all data stored in plaintext
- Benefits from the daily checkpoint (extended `assumevalid` + `assumeUTXO`)
- Faster IBD than stock Bitcoin Core via daily checkpoints
- Serves full block data to all peers (Bitcoin Core, Mode A, Mode B)
- No stripping, no Exorcism, no Legal Compliance Packet

### 4.3 Comparison

| Attribute | Mode A (Hazed) | Mode B (Full Archive) |
|---|---|---|
| Storage | ~195 GB (compressed) | ~718 GB |
| IBD (snapshot sync) | ~3 minutes to usable | ~15 minutes to usable |
| IBD (full, from genesis) | ~35 minutes | ~3.5 hours |
| Monthly growth | ~2 GB | ~6.5 GB |
| Legal liability | None — content physically absent | Full — all content in plaintext |
| Transaction graph | Complete | Complete |
| UTXO set | Complete | Complete |
| Historical signatures | Absent (committed by txid/wtxid) | Present |
| Historical OP_RETURN data | Absent (committed by txid) | Present |
| Serves Mode A peers | Yes | Yes |
| Serves Bitcoin Core peers | Structural only (redirects raw) | Yes (full blocks) |

---

## 5. Ghost Exorcism: Real-Time Data Purification

### 5.1 Purpose

Ghost Exorcism is the runtime process that ensures hazeable content never touches persistent storage. It protects the node operator during the processing window when incoming block data must be validated.

### 5.2 How It Works

Bitcoin Core's block processing pipeline:

```
1. Receive block from network    → RAM buffer
2. Deserialize and validate      → RAM
3. Write to blk*.dat             → DISK
```

Ghost Exorcism modifies step 3:

```
1. Receive block from network    → RAM buffer
2. Deserialize and validate      → RAM
3. Strip hazeable content        → RAM (structural data extracted)
4. Write stripped block to disk  → DISK (structural only)
5. Zero RAM buffer               → RAM wiped
```

The hazeable content (witness data, scriptSig, OP_RETURN payloads, coinbase scriptSig) exists in volatile memory for the duration of validation — typically milliseconds per transaction. It is never written to any persistent storage. After the stripped structural data is written to disk, the RAM buffer is explicitly zeroed.

### 5.3 Stripping Depth

Exorcism applies to ALL blocks written to disk. There is no 100-block delay for the stripping process. The distinction from the original specification:

- **Original spec:** Store full blocks, strip after 100 confirmations
- **This spec:** Never store full blocks. Strip before writing. Always.

For re-org handling, the last 100 blocks' structural data is sufficient. Re-orgs require re-downloading and re-validating the replacement blocks from the network, which provides fresh full data in RAM for validation. The structural archive on disk provides the UTXO state to roll back to.

### 5.4 Crash Safety

If the node crashes during block processing:

- The RAM buffer is lost (volatile memory) — hazeable content gone
- The last successfully written block on disk is structural-only
- On restart, the node resumes from the last structural block
- No hazeable content survives a crash on disk at any point

### 5.5 Implementation

The core change is in `validation.cpp`, in the block acceptance path:

```cpp
// After AcceptBlock() succeeds:
if (ghost_mode == GhostMode::HAZED) {
    WriteGhostStrippedBlock(block, block_index);
    secure_zero(block_data.data(), block_data.size());
} else {
    // Standard Bitcoin Core write path
    WriteBlockToDisk(block, block_index);
}
```

This is a single code path divergence. No modification to consensus validation, script interpretation, or signature verification. Exorcism operates entirely after validation succeeds.

---

## 6. Ghost Haze: The Stripped Archive

### 6.1 Data Classification

#### 6.1.1 Stripped Fields (Destroyed)

| Field | Typical Size | Content |
|---|---|---|
| Witness data | ~110 bytes/input (SegWit) | Signatures, pubkeys, Taproot proofs, Ordinals inscriptions |
| scriptSig | ~107 bytes/input (legacy) | Legacy signatures, multisig redemption scripts |
| OP_RETURN payload | Up to 4 MB (post Core v30) | Arbitrary application data |
| Coinbase scriptSig | 40-100 bytes/block | Pool tags, miner messages |

#### 6.1.2 Preserved Fields (Never Stripped)

| Field | Purpose |
|---|---|
| Transaction IDs (txid) | Transaction graph, merkle tree, commitment to scriptSig |
| Output amounts (nValue) | Balance verification, economic auditing |
| Output scripts (scriptPubKey) | Addresses, locking conditions (including script hashes for P2SH/P2WSH/P2TR) |
| Block headers (80 bytes each) | Chain structure, proof-of-work, timestamps, merkle roots |
| Witness commitment (in coinbase output) | Commitment to all witness data in the block |
| Transaction version, locktime | Fixed-format integers |
| Input prevout references | Transaction graph linkage (txid + output index) |
| Input sequence numbers | Timelock and RBF signaling |
| UTXO set | Current spendable outputs — required for consensus |

### 6.2 Why No Haze Records

The original specification proposed 39-byte per-field haze records (SHA-256 hash commitments). This revision eliminates them entirely. Bitcoin's existing cryptographic structure already provides the commitments:

| Stripped Field | Existing Commitment | How It Works |
|---|---|---|
| Witness data | Witness commitment in coinbase output (BIP 141) | Merkle root of all wtxids, embedded in a coinbase output scriptPubKey |
| scriptSig | txid | txid = SHA256d(version + inputs(**including scriptSig**) + outputs + locktime) |
| OP_RETURN payload | txid | OP_RETURN scriptPubKey is part of the outputs hashed into the txid |
| Coinbase scriptSig | Coinbase txid | Same as scriptSig — included in txid computation |

These commitments are **consensus-validated** — every node on the network verified them. They are stronger than any self-generated haze record.

**Savings:** Eliminating per-field haze records saves ~90 GB of storage and removes the need for a dedicated haze index database (another ~37 GB). Total savings vs original spec: **~127 GB.**

### 6.3 Verification of Retrieved Data

When a Mode A node retrieves raw data from an archive peer for forwarding:

**Witness verification:**
1. Receive raw witness data for a transaction
2. Reconstruct the full transaction (preserved fields + received witness)
3. Compute the wtxid
4. Verify against the witness commitment merkle tree in the coinbase output

**scriptSig verification:**
1. Receive raw scriptSig for a transaction
2. Insert into the preserved transaction structure
3. Compute the txid
4. Compare against the stored/computed txid

No custom haze records needed. Bitcoin's native commitment structure handles verification.

### 6.4 Stored Transaction IDs

For most transactions, the txid is computable from preserved data:

- **Native SegWit (P2WPKH, P2WSH, P2TR):** scriptSig is always empty. The txid is computed from: version + inputs(prevout + empty scriptSig + sequence) + outputs + locktime. All of this is preserved. **No stored txid needed.**

- **Legacy and P2SH-wrapped SegWit:** scriptSig was non-empty and has been stripped. The txid is no longer computable from preserved data. **The txid must be stored explicitly.**

Approximately 500 million legacy/P2SH-wrapped transactions require stored txids at 32 bytes each = ~16 GB. This is the only storage overhead of the haze system.

---

## 7. Ghost Stripped Block Format

### 7.1 File Format

Hazed blocks are stored in `gsb*.dat` files (Ghost Stripped Block). The format is derived from Bitcoin Core's standard block serialization with hazeable fields removed.

```
[4 bytes]   Magic: 0x47 0x53 0x42 0x00 ("GSB\0")
[4 bytes]   Stripped block data size (uint32 LE)
[80 bytes]  Block header (unchanged)
[varint]    Transaction count
[per transaction]:
    [1 byte]    Flags
                  bit 0: has_stored_txid (1 if original scriptSig was non-empty)
    [if has_stored_txid]:
        [32 bytes]  txid
    [4 bytes]   nVersion
    [varint]    Input count
    [per input]:
        [32 bytes]  prevout txid
        [4 bytes]   prevout index
        [1 byte]    scriptSig length = 0x00 (always empty in stripped format)
        [4 bytes]   nSequence
    [varint]    Output count
    [per output]:
        [8 bytes]   nValue
        [varint]    scriptPubKey length
        [variable]  scriptPubKey
                    (OP_RETURN outputs: scriptPubKey stored as-is but with
                     payload replaced: OP_RETURN [1 byte] + push opcode + 0x00 padding
                     to signal stripped status. Original length preserved in push opcode.)
    [4 bytes]   nLockTime
```

### 7.2 OP_RETURN Handling

OP_RETURN outputs are identified by their scriptPubKey starting with `0x6a` (OP_RETURN opcode). In stripped format:

- The `0x6a` opcode is preserved (identifies it as OP_RETURN)
- The payload is replaced with a single byte `0x00` (empty push)
- The original payload length is lost from the script but committed by the txid

This ensures OP_RETURN outputs remain identifiable as OP_RETURN (not confused with spendable outputs) while destroying the embedded content.

### 7.3 Per-Transaction Size

| Transaction Type | Original | Stripped | Savings |
|---|---|---|---|
| P2WPKH 1-in/2-out (modern, 85%+ of txs) | 226 bytes | ~109 bytes | 52% |
| Legacy P2PKH 1-in/2-out | 226 bytes | ~142 bytes | 37% |
| Ordinals inscription (1 MB witness) | ~1,048,692 bytes | ~141 bytes | 99.99% |
| 2-in/2-out P2TR | ~312 bytes | ~183 bytes | 41% |

### 7.4 Compression

Ghost stripped blocks are optionally compressed with zstd. Structural data compresses significantly better than raw blocks because cryptographic data (signatures, pubkeys) — which is incompressible — has been removed. The remaining data contains highly repetitive patterns:

- `nSequence`: 0xFFFFFFFF in ~95% of inputs
- `nVersion`: 1 or 2 in ~99% of transactions
- Output script prefixes: `0x0014` (P2WPKH), `0x5120` (P2TR), `0x76a914` (P2PKH)
- Prevout indices: small integers (mostly 0 or 1)

Expected compression ratio: ~50% with zstd level 3, yielding compressed `gsb*.dat.zst` files.

---

## 8. Storage Model

### 8.1 Mode A (Hazed)

| Component | Uncompressed | Compressed (zstd) |
|---|---|---|
| Ghost stripped blocks (gsb*.dat) | ~360 GB | ~180 GB |
| UTXO chainstate | ~11 GB | ~11 GB |
| Block index | ~2 GB | ~2 GB |
| Recent blocks (last 100, full in RAM/tmpfs) | ~0.15 GB | ~0.15 GB |
| **Total** | **~373 GB** | **~193 GB** |

No `rev*.dat` (undo data) is needed. Stripped blocks are written once and never "undone" — re-orgs redownload and revalidate replacement blocks from the network.

### 8.2 Mode B (Full Archive)

| Component | Size |
|---|---|
| Raw blocks (blk*.dat) | ~620 GB |
| Undo data (rev*.dat) | ~85 GB |
| UTXO chainstate | ~11 GB |
| Block index | ~2 GB |
| **Total** | **~718 GB** |

### 8.3 Comparison

| Metric | Mode A (compressed) | Mode A (uncompressed) | Mode B |
|---|---|---|---|
| Total storage | **193 GB** | 373 GB | 718 GB |
| Reduction vs full archive | **73%** | 48% | — |
| Monthly growth | ~2 GB | ~3.5 GB | ~6.5 GB |
| Minimum SSD | 256 GB | 512 GB | 1 TB |
| Approximate SSD cost | $25 | $40 | $70 |

---

## 9. Ghost Checkpoint

### 9.1 What Is a Ghost Checkpoint?

A Ghost Checkpoint is a signed data package published daily by the Ghost Core project. It bundles everything a new node needs for accelerated sync:

```
ghost-checkpoint-{height}.tar.zst
├── manifest.json                 // Height, block hash, signatures, metadata
├── chainstate/                   // Pre-built LevelDB UTXO database (~7 GB compressed)
│   ├── CURRENT
│   ├── MANIFEST-*
│   └── *.ldb
├── headers.bin                   // All block headers, sequential (~71 MB)
├── swift_hints.bloom             // SwiftSync Bloom filter (~212 MB)
├── archive_chunks.manifest       // Chunk hashes for parallel archive download
└── signature.ed25519             // Ed25519 signature over all contents
```

### 9.2 Components

**Pre-built chainstate:** A compressed LevelDB directory containing the complete UTXO set at the checkpoint height. Drop into the data directory and the node opens it directly — no deserialization or reinsertion step. This eliminates the ~10 minute snapshot load time of Bitcoin Core's `assumeUTXO`.

**Block headers:** All block headers from genesis to checkpoint height, serialized sequentially. 80 bytes per header, ~71 MB total. Verifiable as a proof-of-work chain.

**SwiftSync Bloom filter:** A 212 MB Bloom filter encoding the ~170 million outpoints (txid + vout) that remain unspent at the checkpoint height. During full IBD from genesis, the node checks this filter before writing UTXO entries to LevelDB — only the 7% of outputs that survive to the present are written. The remaining 93% are tracked in memory only, eliminating 93% of LevelDB write operations.

**Archive chunks manifest:** SHA-256 hashes for 64 MB chunks of the compressed stripped archive. Enables parallel download from multiple peers simultaneously.

**Ed25519 signature:** Signs all checkpoint contents. Ghost Core's project public key is hardcoded in the binary. Multiple trusted keys supported for key rotation.

### 9.3 Trust Model

This is the same trust model as Bitcoin Core's `assumevalid` and `assumeUTXO`. The node operator trusts that the Ghost Core developers correctly computed the UTXO set, the block headers form a valid proof-of-work chain, and the SwiftSync hints are accurate.

The node can optionally perform background verification after syncing — walking the chain and confirming that the UTXO set matches what would be computed from genesis. This background verification runs at low priority and does not affect normal node operation.

### 9.4 Checkpoint Distribution

- Embedded in each Ghost Core release
- Available as a standalone signed file from Ghost Core servers
- Distributed via the Ghost P2P network (nodes share latest checkpoint with peers)
- Available as a pre-built archive torrent (updated weekly)

The checkpoint metadata (manifest + chainstate + headers + Bloom filter) is ~7.3 GB. The full stripped archive is ~180 GB compressed. These are distributed separately — the node becomes usable with just the checkpoint metadata.

---

## 10. Initial Block Download (IBD)

### 10.1 Mode A: Snapshot Sync (Recommended — ~3 minutes to usable)

The fastest path. Uses the Ghost Checkpoint to skip all historical processing.

```
Step 1: Download checkpoint metadata           ~7.3 GB    ~60 seconds (gigabit)
Step 2: Decompress chainstate to data dir                 ~30 seconds
Step 3: Load block headers                     ~71 MB     ~1 second
Step 4: Start node, open existing chainstate              ~5 seconds
Step 5: Download recent blocks (since checkpoint)  ~5 MB  ~1 second
Step 6: Validate recent blocks via Exorcism               ~2 minutes
─────────────────────────────────────────────────────────────────────
NODE IS LIVE                                               ~3 minutes

Step 7: Background — download stripped archive  ~180 GB   ~30 minutes
        (parallel chunk download from peers)
─────────────────────────────────────────────────────────────────────
STRUCTURAL ARCHIVE COMPLETE                                ~33 minutes
```

The node is fully operational after step 6: it validates new blocks, serves the UTXO set, and participates in consensus. The structural archive downloads in the background for historical lookup capability.

### 10.2 Mode A: Full IBD from Genesis (~35 minutes)

For operators who prefer to validate from genesis rather than trust the checkpoint.

```
Step 1: Download checkpoint (headers + SwiftSync bloom)   ~300 MB    ~3 seconds
Step 2: Download compressed stripped archive (parallel)    ~180 GB    ~30 minutes
Step 3: Process blocks with SwiftSync:                                (overlaps step 2)
        - For each block: parse structural data
        - For each output: check SwiftSync Bloom filter
          → In filter (7%): write to LevelDB
          → Not in filter (93%): track in memory only
        - For each input: spend from memory or LevelDB
Step 4: Post-checkpoint blocks: full Exorcism pipeline                ~5 minutes
─────────────────────────────────────────────────────────────────────
NODE IS LIVE + ARCHIVE COMPLETE                            ~35 minutes
```

The SwiftSync Bloom filter eliminates 93% of LevelDB write operations, reducing UTXO construction from ~2.5 hours to ~15-20 minutes. Total IBD time is limited by download speed, not CPU or disk I/O.

### 10.3 Mode B: Checkpoint-Accelerated Full Archive (~3.5 hours)

Mode B downloads the complete blockchain but benefits from the daily checkpoint:

```
Step 1: Download checkpoint (chainstate + headers)         ~7.3 GB    ~60 seconds
Step 2: Load chainstate (optional — or full IBD below)
Step 3: Download full blocks from peers                    ~620 GB    ~1.5 hours
Step 4: Validate with extended assumevalid                            ~2 hours
        (signature verification skipped for pre-checkpoint blocks)
─────────────────────────────────────────────────────────────────────
NODE IS LIVE                                               ~3.5 hours
```

Still faster than stock Bitcoin Core (~4-5 hours) due to the daily checkpoint extending `assumevalid` to yesterday's block rather than the last release's hardcoded block.

### 10.4 Comparison

| Method | Time to Usable | Full Archive/Structural | Download Size |
|---|---|---|---|
| Bitcoin Core (default) | ~4-5 hours | ~4-5 hours | ~620 GB |
| Bitcoin Core + assumeUTXO | ~94 minutes | ~12 hrs (background) | ~620 GB |
| **Ghost Mode A (snapshot)** | **~3 minutes** | **~33 minutes** | **7.3 GB + 180 GB** |
| **Ghost Mode A (full IBD)** | **~35 minutes** | **~35 minutes** | **~180 GB** |
| Ghost Mode B (checkpoint) | ~60 seconds (snapshot) | ~3.5 hours | 7.3 GB + 620 GB |

---

## 11. Ghost Exorcist: Archive Conversion Tool

### 11.1 Purpose

Ghost Exorcist converts an existing full archive node (Bitcoin Core or Ghost Core Mode B) into a Ghost Core Mode A hazed node. It processes the existing `blk*.dat` files, strips all hazeable content, writes the structural archive in `gsb*.dat` format, and securely zeroes the original files.

### 11.2 Usage

```
$ ghost-core --exorcist

Ghost Exorcist v2.0 — Archive Conversion Tool

Scanning existing archive...
  Found: 620 GB in blk*.dat (blocks 0-936,000)
  Found: 85 GB in rev*.dat

Phase 1/4: Stripping witness data        ████████████████████ 100%   -200 GB
Phase 2/4: Stripping scriptSig           ████████████████████ 100%    -75 GB
Phase 3/4: Stripping OP_RETURN/coinbase  ████████████████████ 100%     -3 GB
Phase 4/4: Secure zeroing originals      ████████████████████ 100%

Conversion complete.
  Before:  718 GB (full archive)
  After:   193 GB (structural archive, compressed)
  Freed:   525 GB
  Time:    ~45 minutes

Legal Compliance Packet generated: ~/.ghost/legal_compliance.json
Mode switched to: HAZED (Mode A)
Exorcism enabled for all future blocks.
```

### 11.3 Conversion Process

1. **Read** each block from `blk*.dat`
2. **Extract** structural data (headers, txids, prevouts, amounts, output scripts, version, locktime, sequence)
3. **Store txid** explicitly for legacy transactions with non-empty scriptSig
4. **Write** stripped block to `gsb*.dat` (optionally compressed)
5. **Secure zero** the corresponding region in `blk*.dat` (overwrite with 0x00)
6. **Delete** `rev*.dat` (undo data no longer needed)
7. **Update** block index to point to `gsb*.dat` locations
8. **Generate** Legal Compliance Packet
9. **Set** node mode to HAZED in configuration

### 11.4 Secure Zeroing

The original `blk*.dat` files are overwritten with zeros before deletion, not simply unlinked. This ensures that hazeable content is not recoverable via filesystem forensics. After zeroing, the files are deleted.

### 11.5 Reversibility

Conversion is **irreversible**. Once Exorcist has run, the hazeable content is permanently destroyed on this node. To obtain a full archive again, the operator must re-sync from scratch in Mode B. This is by design — reversibility would undermine the legal protection argument.

---

## 12. Data Retrievability

### 12.1 Locally Available (Both Modes, Instant)

- Complete transaction graph: addresses, amounts, timing
- All transaction IDs and block heights
- All output amounts and locking scripts (scriptPubKey)
- Full UTXO set for balance verification
- Block headers, timestamps, difficulty, proof-of-work
- Merkle proofs for transaction inclusion
- Script hashes for P2SH/P2WSH/P2TR outputs (locking conditions as hashes)

This covers 99.9% of all practical queries.

### 12.2 Network Retrieval (Mode A Only)

For raw stripped content (witness bytes, scriptSig data, OP_RETURN payloads), the Mode A node redirects the requester to Mode B or Bitcoin Core archive peers on the network. The Mode A node:

- Identifies archive peers (nodes advertising `NODE_NETWORK` without `NODE_GHOST_HAZE`)
- Provides the txid for lookup
- Never re-acquires, caches, or stores the raw data
- Can optionally verify retrieved data against Bitcoin's commitments (txid/wtxid) without retaining it

### 12.3 What Scripts Are Preserved

An important clarification for contract-based transactions (timelocks, multisig, HTLCs):

**The locking conditions (scriptPubKey) are always preserved.** For simple scripts (P2PKH), the full locking logic is visible on disk. For hash-locked scripts (P2SH, P2WSH, P2TR), the script hash is visible — the actual script is revealed only at spending time in the witness/scriptSig.

**The unlocking proof (witness/scriptSig) is stripped after the block is written.** This contains the signatures and revealed scripts that proved the conditions were met. Once confirmed, this proof has served its purpose.

For **unspent** outputs with complex scripts: the actual script hasn't been revealed on-chain yet. Only the hash exists in the UTXO set (preserved). When the output is eventually spent, the spending transaction arrives as a new block, is validated in RAM via Exorcism, and the structural data is written. The unlocking proof passes through memory and is never persisted.

---

## 13. P2P Network Compatibility

### 13.1 Service Flags

Mode A nodes advertise the `NODE_GHOST_HAZE` service flag (`1 << 14`). This signals to peers that:

- The node stores structural data only
- Full block requests will be answered with `GHOST_STRIPPED_BLOCK` messages
- Raw data requests will be answered with `GHOST_REDIRECT` messages pointing to archive peers

Mode B nodes do not set this flag and behave as standard Bitcoin Core nodes.

### 13.2 Message Types

**GHOST_STRIPPED_BLOCK:** Sent in response to `getdata` for a block when the node is Mode A. Contains the stripped block in `gsb` format. Mode A peers can parse this directly. Non-Ghost peers treat it as an unknown message (safe — they will request the block from another peer).

**GHOST_REDIRECT:** Sent when a peer requests raw data that has been stripped. Contains the txid(s) requested and a list of known archive peer addresses. The requester can then fetch the raw data from an archive peer.

### 13.3 Compatibility Matrix

| Requesting Peer | Mode A Response | Mode B Response |
|---|---|---|
| Ghost Core Mode A | GHOST_STRIPPED_BLOCK | Full block (peer will strip locally) |
| Ghost Core Mode B | GHOST_STRIPPED_BLOCK + GHOST_REDIRECT | Full block |
| Bitcoin Core | GHOST_REDIRECT to archive peers | Full block |

### 13.4 Network Health

Mode A nodes fully participate in:
- Block relay (headers and structural data)
- Transaction relay (mempool transactions are pre-confirmation, not stripped)
- UTXO-dependent protocols (compact block relay, etc.)
- Addr relay and peer discovery

The Bitcoin P2P network continues to function normally. Mode A nodes are full participants in consensus validation and block propagation. The only limitation is serving raw historical data to Bitcoin Core peers doing full IBD with signature verification.

---

## 14. Legal Framework

### 14.1 Three-Layer Defense (Mode A)

**Layer 1: Physical impossibility of possession.** The content does not exist on disk. It was never written to persistent storage (Exorcism) or has been irreversibly destroyed (Exorcist conversion). SHA-256 is a one-way function — the content cannot be reconstructed from the cryptographic commitments that remain.

**Layer 2: No mens rea.** The operator cannot know what content was embedded. During the brief validation window, the data existed as opaque bytes in volatile memory fed directly into cryptographic verification functions. It was never rendered, displayed, or assembled into viewable form.

**Layer 3: Analogous precedent.** Equivalent to a postal worker handling sealed packages, a network router forwarding encrypted packets, or a bank processing wire transfers that may fund illegal activity. The infrastructure operator processes and forwards; they do not possess.

### 14.2 Legal Compliance Packet

Ghost Core generates a signed Legal Compliance Packet on demand:

```json
{
  "ghost_core_version": "2.0.0",
  "node_mode": "HAZED",
  "node_public_key": "02abc...def",
  "exorcism_active": true,
  "haze_status": "COMPLETE",
  "blocks_stripped": 936000,
  "chain_tip": 936144,
  "structural_archive_size_gb": 193,
  "hazeable_content_on_disk": false,
  "exorcist_conversion_date": "2026-02-14T12:00:00Z",
  "checkpoint_height": 936000,
  "checkpoint_hash": "000000000000000000023a5d...",
  "legal_summary": "This node operates in Ghost Haze mode. All hazeable content (witness data, scriptSig signatures, OP_RETURN payloads, and coinbase arbitrary data) has been irreversibly destroyed from persistent storage. Only the structural economic graph (transaction IDs, amounts, addresses, block headers) is retained. Bitcoin's native cryptographic commitments (txids, witness commitments) serve as proof that the destroyed content existed. The content cannot be reconstructed from this node's storage. Ghost Exorcism is active: incoming block data is validated in volatile memory and only structural data is written to disk.",
  "signature": "3045022100..."
}
```

The packet is signed with the node's identity key, includes a timestamp, and is suitable for presentation to legal counsel or regulatory authorities.

### 14.3 CLI Access

```
$ ghost-core --haze-status
$ ghost-core --legal-packet
$ ghost-core --legal-packet --output /path/to/compliance.json
```

---

## 15. CLI Interface

### 15.1 Mode Selection (First Launch)

On first launch with no existing data directory, Ghost Core presents:

```
Ghost Core — First Launch Setup

Select node mode:

  [1] Hazed Node (Recommended)
      Legal protection. 193 GB storage. Fastest sync.
      All hazeable content stripped. Full economic graph preserved.

  [2] Full Archive
      Standard Bitcoin node. 718 GB storage.
      All data stored including embedded content. Operator accepts legal risk.

Selection (1/2):
```

The selection is stored in `ghost.conf` and a mode lock file. Changing mode requires re-sync.

### 15.2 Commands

```
ghost-core --haze-status          Display mode, storage, sync status, Exorcism state
ghost-core --legal-packet         Generate Legal Compliance Packet
ghost-core --exorcist             Convert existing full archive to hazed (Mode B → Mode A)
ghost-core --checkpoint-update    Download latest daily checkpoint
ghost-core --checkpoint-status    Show checkpoint height, age, signature status
```

### 15.3 RPC Interface

Existing Bitcoin Core RPC calls work with hazed archives. Stripped fields return indicators:

```json
// getrawtransaction on a hazed node (Mode A)
{
  "txid": "abc123...",
  "version": 2,
  "vin": [{
    "txid": "def456...",
    "vout": 0,
    "scriptSig": {"hex": "", "stripped": true},
    "sequence": 4294967295
  }],
  "vout": [{
    "value": 0.001,
    "scriptPubKey": {"hex": "0014abc...", "type": "witness_v0_keyhash", "address": "bc1q..."}
  }],
  "witness": "stripped",
  "haze_status": {
    "stripped": true,
    "committed_by_txid": "abc123...",
    "committed_by_witness_commitment": "block:936000:coinbase:output:3"
  }
}
```

Mode B nodes return full data as normal with no `haze_status` field.

---

## 16. Security Considerations

### 16.1 Consensus Safety

Neither mode modifies Bitcoin's consensus rules. All validation occurs on full plaintext data in RAM before any stripping. The Exorcism process operates entirely after `AcceptBlock()` succeeds. A hazed node and a full archive node produce byte-identical UTXO sets.

### 16.2 Checkpoint Integrity

Checkpoints are signed with the Ghost Core project Ed25519 key. Nodes verify the signature before applying any checkpoint data. A compromised checkpoint would only affect new nodes during IBD — existing nodes would detect discrepancies during optional background verification. Multiple trusted public keys are supported for key rotation.

### 16.3 Re-org Handling

Re-orgs are handled by re-downloading and re-validating the replacement blocks from the network. The structural archive provides the UTXO state for rollback. The last 100 blocks' data remains available in the node's mempool/network cache for fast re-org processing. Deep re-orgs (>100 blocks) require re-downloading blocks from peers, which is the same behavior as Bitcoin Core.

### 16.4 SwiftSync Bloom Filter Security

A malicious Bloom filter could cause the node to skip writing a UTXO that should exist, leading to an incorrect UTXO set. This is mitigated by:

- The Bloom filter is signed as part of the checkpoint
- Optional background verification recomputes the UTXO set from genesis
- The false positive rate (0.1%) means extra writes, not missing writes — false positives cause unnecessary LevelDB writes (slightly slower sync), not missing UTXOs

### 16.5 Archive Peer Trust

Mode A nodes redirect raw data requests to archive peers but do not vouch for the archive peer's data. The requester must verify any received data against Bitcoin's cryptographic commitments (txid, witness commitment). Mode A nodes facilitate discovery, not trust.

---

## 17. Implementation Overview

### 17.1 New Files

```
src/haze/
├── stripped_block.h / .cpp       // Ghost stripped block format (ser/deser)
├── exorcism.h / .cpp             // Strip-before-write in block processing
├── exorcist.h / .cpp             // Archive conversion tool
├── checkpoint.h / .cpp           // Daily checkpoint format, signing, loading
├── checkpoint_db.h / .cpp        // Checkpoint storage
├── swift_sync.h / .cpp           // SwiftSync Bloom filter integration
├── mode_selector.h / .cpp        // First-launch mode selection
├── legal_packet.h / .cpp         // Legal Compliance Packet generator
├── haze_p2p.h / .cpp             // GHOST_STRIPPED_BLOCK and GHOST_REDIRECT messages
└── tests/
    ├── stripped_block_tests.cpp
    ├── exorcism_tests.cpp
    ├── exorcist_tests.cpp
    ├── checkpoint_tests.cpp
    └── swift_sync_tests.cpp

src/rpc/haze.h / .cpp             // RPC interface for haze commands
```

### 17.2 Modified Files

```
src/init.cpp                      // Mode selection at startup
src/validation.cpp                // Exorcism: strip-before-write after AcceptBlock()
src/net_processing.cpp            // GHOST_STRIPPED_BLOCK, GHOST_REDIRECT handling
src/protocol.h                    // New message types, NODE_GHOST_HAZE service flag
src/rpc/blockchain.cpp            // getblock/getrawtransaction haze awareness
src/rpc/rawtransaction.cpp        // decoderawtransaction haze awareness
src/haze/CMakeLists.txt            // CMake build for haze module
```

### 17.3 Task Summary

| Phase | Tasks | Effort | Description | Status |
|---|---|---|---|---|
| 1: Core | 5 | ~100 hrs | Stripped block format, field classifier, block stripper, Exorcism, Exorcist | COMPLETE |
| 2: Checkpoint | 4 | ~80 hrs | Checkpoint format, signing, SwiftSync, parallel download | COMPLETE |
| 3: Integration | 5 | ~60 hrs | Mode selector, CLI/RPC, P2P messages, legal packet, archive peer discovery | COMPLETE |
| 4: Testing | 4 | ~60 hrs | Unit tests, functional tests, UTXO equivalence, cross-mode P2P | COMPLETE |
| 5: Bootstrap | 6 | ~40 hrs | UTXO snapshot loading, hazed node bootstrap without full archive peer | COMPLETE |
| **Total** | **24** | **~340 hrs** | **All phases complete, deployed to signet testnet** | **COMPLETE** |

### 17.4 Critical Acceptance Criteria

1. **UTXO equivalence:** A Mode A node and a Mode B node processing the same chain produce byte-identical UTXO sets. This is the single most important test.

2. **No hazeable content on disk:** After Exorcism processes a block, `grep` of `gsb*.dat` for known embedded payloads returns zero matches.

3. **Crash safety:** Kill the node mid-block-processing, restart. No hazeable content on disk. Node resumes from last structural block.

4. **Checkpoint integrity:** A checkpoint-synced node's UTXO set matches a full-IBD node's UTXO set exactly.

5. **Exorcist completeness:** After conversion, all `blk*.dat` regions containing hazeable content are zeroed. All structural data is present in `gsb*.dat`.

---

## 18. Hazed Node Bootstrap (UTXO Snapshot)

### 18.1 The Problem

A hazed node starting from scratch cannot sync from genesis without a full archive peer — it needs full blocks for validation, but those blocks contain the hazeable content it's designed to avoid. Even with a full archive peer available, downloading and validating the entire chain takes hours.

### 18.2 Snapshot Bootstrap

Ghost Core extends Bitcoin Core's `assumeUTXO` infrastructure to enable hazed-only networks. A hazed node can bootstrap from a UTXO snapshot without ever needing a full archive peer:

```
1. Load UTXO snapshot via -loadtxoutset=<path> or loadtxoutset RPC
2. Snapshot activates — node has complete UTXO set at snapshot height
3. Background IBD is disabled (hazed nodes cannot re-validate historical blocks)
4. Node begins processing new blocks via Exorcism immediately
5. On restart, snapshot chainstate auto-validates (skip UTXO hash verification)
```

### 18.3 Network Independence

With snapshot bootstrap, hazed nodes form self-sufficient networks:

- No full archive peer required for initial sync
- Hazed nodes serve stripped blocks to other hazed peers
- New hazed nodes bootstrap from snapshot + stripped block relay
- The haze block cache ensures batch processing works for P2P block relay

### 18.4 Implementation

Key changes to Bitcoin Core's snapshot infrastructure:

- `ActivateSnapshot()`: Disable background IBD chainstate for hazed nodes
- `MaybeCompleteSnapshotValidation()`: Auto-validate on restart without UTXO hash check
- `NODE_NETWORK` service flag: Not re-enabled after snapshot download (hazed nodes stay `NODE_NETWORK_LIMITED`)
- `-loadtxoutset`: CLI argument for offline snapshot loading without RPC

---

## 19. Implementation Status

Ghost Haze is fully implemented and deployed. All 5 phases (24 tasks) are complete:

- **43 C++ unit tests** covering all components
- **8 Python functional tests** covering all modes and edge cases
- **Deployed to 4-node signet testnet** (3 full_archive + 1 hazed)
- **Exorcist conversion verified** on production signet (29,321 blocks converted)
- **UTXO equivalence verified** across all node modes

---

## 20. Future Work

- **Hardware enclave integration:** SGX/TrustZone for hardware-level Exorcism assurance
- **ZK temporal proofs:** Aggregated zero-knowledge proofs attesting to block validity in a time-based hierarchy (optional extension for enhanced verification)
- **Cross-chain:** Ghost Haze for other UTXO chains (Litecoin, Bitcoin Cash)
- **Ghost Exorcist for pruned nodes:** Convert a pruned node to a partial structural archive (only blocks still on disk)
- **Checkpoint consensus:** Decentralized checkpoint generation by multiple trusted parties rather than a single project key

---

## 21. Conclusion

Ghost Haze, Ghost Exorcism, and Ghost Exorcist together provide complete lifecycle protection against embedded content liability:

- **Exorcism** protects during processing — hazeable content never touches disk
- **Haze** protects at rest — the archive contains only structural data
- **Exorcist** protects existing nodes — convert a full archive to hazed in 45 minutes

The design achieves this with minimal divergence from Bitcoin Core:

- No custom haze records — Bitcoin's existing cryptographic commitments (txids, witness commitments) serve as proof of destroyed content
- No consensus modifications — all stripping occurs after validation
- Single code path change for Exorcism — strip-before-write in `validation.cpp`
- Same UTXO set — a hazed node and a full archive node are economically identical

A hazed node in 193 GB. A full economic graph. Zero illegal content. Synced in 3 minutes.

**The ghosts are exorcised. The haze remains.**

---

*END OF SPECIFICATION*
