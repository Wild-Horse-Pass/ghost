# GHOST CORE

## Ghost Haze, Exorcism & Exorcist
### Implementation Task Breakdown

**24 Tasks — 5 Phases — ~340 Hours**
**v2.1 — February 2026 — ALL PHASES COMPLETE**

---

## Overview

This document breaks the Ghost Haze & Exorcism specification (v2.0) into discrete implementation tasks. Each task is self-contained with clear inputs, outputs, file paths, dependencies, and acceptance criteria.

The design eliminates per-field haze records entirely, using Bitcoin's existing cryptographic commitments (txids, witness commitments) instead. This removes 10 tasks from the original v1.2 breakdown while delivering better storage efficiency and simpler architecture.

---

## Phase Summary

| Phase | Tasks | Effort | Description | Status |
|---|---|---|---|---|
| 1: Core Engine | 5 | ~100 hrs | Field classifier, stripped block format, block stripper, Exorcism, Exorcist | COMPLETE |
| 2: Checkpoint & Sync | 4 | ~80 hrs | Checkpoint format, signing, SwiftSync Bloom filter, parallel chunk download | COMPLETE |
| 3: Integration | 5 | ~60 hrs | Mode selector, CLI/RPC, P2P messages, legal packet, archive peer discovery | COMPLETE |
| 4: Testing | 4 | ~60 hrs | Unit tests, functional tests, UTXO equivalence, cross-mode P2P | COMPLETE |
| 5: Bootstrap | 6 | ~40 hrs | UTXO snapshot loading, hazed node bootstrap, production deployment | COMPLETE |
| **Total** | **24** | **~340 hrs** | **All phases implemented and deployed** | **COMPLETE** |

---

## Repository Structure

All Ghost Haze code lives under `src/haze/`. Minimal modifications to existing Bitcoin Core files.

### New files

```
src/haze/
├── field_classifier.h / .cpp         // Task 1.1: Identify hazeable fields in a transaction
├── stripped_block.h / .cpp           // Task 1.2: GSB format serializer/deserializer
├── block_stripper.h / .cpp           // Task 1.3: Full block → stripped block conversion
├── exorcism.h / .cpp                 // Task 1.4: Strip-before-write integration
├── exorcist.h / .cpp                 // Task 1.5: Archive conversion tool
├── checkpoint.h / .cpp               // Task 2.1: Checkpoint data format
├── checkpoint_signer.h / .cpp        // Task 2.2: Ed25519 signing and verification
├── swift_sync.h / .cpp               // Task 2.3: SwiftSync Bloom filter
├── chunk_download.h / .cpp           // Task 2.4: Parallel chunk download protocol
├── mode_selector.h / .cpp            // Task 3.1: First-launch mode selection
├── legal_packet.h / .cpp             // Task 3.5: Legal Compliance Packet generator
├── haze_p2p.h / .cpp                 // Task 3.4: P2P message handlers
└── tests/
    ├── field_classifier_tests.cpp    // Task 4.1
    ├── stripped_block_tests.cpp      // Task 4.1
    ├── exorcism_tests.cpp            // Task 4.1
    ├── exorcist_tests.cpp            // Task 4.1
    ├── checkpoint_tests.cpp          // Task 4.1
    └── swift_sync_tests.cpp         // Task 4.1

src/rpc/haze.h / .cpp                // Task 3.2/3.3: RPC interface

test/functional/
├── feature_ghost_haze.py             // Task 4.2: Haze mode basic functionality
├── feature_ghost_exorcism.py         // Task 4.2: Archive-to-hazed conversion
├── feature_ghost_utxo_equiv.py       // Task 4.3: UTXO equivalence (critical test)
├── feature_ghost_haze_p2p.py         // Task 4.4: Cross-mode P2P tests
├── feature_ghost_haze_serve.py       // Task 5.6: Block serving tests
├── feature_ghost_exorcist.py         // Task 5.6: Exorcist tool tests
├── feature_ghost_haze_snapshot.py    // Task 5.6: UTXO snapshot bootstrap
└── feature_ghost_checkpoint_sync.py  // Task 5.6: Checkpoint sync protocol
```

### Modified files

```
src/CMakeLists.txt                    // Link haze module to bitcoin_node
src/haze/CMakeLists.txt               // CMake build for haze module (15 source files)
src/init.cpp                          // Mode selection, exorcist, snapshot loading (Task 3.1, 5.3)
src/validation.h                      // Haze block cache, SwiftSync pointer (Task 5.4, 2.3)
src/validation.cpp                    // Exorcism strip-before-write, SwiftSync (Task 1.4, 2.3)
src/node/blockstorage.h               // GSB file sequence, WriteStrippedBlock, ReadStrippedBlock
src/node/blockstorage.cpp             // GSB file I/O implementation
src/net_processing.cpp                // P2P message handling (Task 3.4)
src/protocol.h                        // New message types, NODE_GHOST_HAZE flag (Task 3.4)
src/protocol.cpp                      // Service flag strings, message type list
src/rpc/blockchain.h                  // Haze-aware block JSON (Task 3.3)
src/rpc/blockchain.cpp                // getblock haze awareness (Task 3.3)
src/rpc/rawtransaction.cpp            // getrawtransaction haze awareness (Task 3.3)
src/rpc/register.h                    // RegisterHazeRPCCommands
src/core_io.h                         // is_hazed flag for TxToUniv
src/core_write.cpp                    // TxToUniv haze indicators
src/wallet/sqlite.cpp                 // SQLite init order fix for GSP coexistence
```

---

## Dependency Graph

```
Phase 1 (sequential — each builds on the previous):

  1.1 Field Classifier
       │
       ▼
  1.2 Stripped Block Format
       │
       ├──────────────────┐
       ▼                  ▼
  1.3 Block Stripper    2.1 Checkpoint Format (Phase 2 starts here)
       │                  │
       ├─────┐            ├─────┐
       ▼     ▼            ▼     ▼
  1.4 Exo  1.5 Exo-    2.2   2.3 SwiftSync
  rcism    rcist        Sign    │
       │     │            │     ▼
       │     │            │   2.4 Chunk DL
       │     │            │     │
       ▼     ▼            ▼     ▼
  ┌─── Phase 3 (after 1.4 + 2.2) ───┐
  │ 3.1 Mode Selector               │
  │ 3.2 CLI Interface               │
  │ 3.3 RPC Compatibility           │
  │ 3.4 P2P Messages                │
  │ 3.5 Legal Packet                │
  └──────────────────────────────────┘
                  │
                  ▼
          Phase 4: Testing
```

**Key parallelism opportunity:** Phase 2 (Tasks 2.1-2.4) can begin as soon as Task 1.2 is complete. Phase 2 and the remainder of Phase 1 (Tasks 1.3-1.5) can run in parallel.

---

## Phase 1: Core Engine

The foundation. Builds the stripping engine from data structures up to the full Exorcism pipeline and Exorcist conversion tool. Tasks are sequential within the phase.

---

### TASK 1.1: Field Classifier

**Difficulty:** EASY | **Phase:** 1 | **Depends on:** Nothing | **Est:** 12 hrs

Utility that examines a Bitcoin transaction and identifies all hazeable fields — their type, byte offset, and length. Must handle legacy, SegWit v0, SegWit v1 (Taproot), P2SH-wrapped SegWit, and coinbase transactions.

**Files to create:**
- `src/haze/field_classifier.h` — `HazeableField` struct, `HazeFieldType` enum, classifier function
- `src/haze/field_classifier.cpp` — `ClassifyTransaction()` implementation

**Data structures:**

```cpp
enum class HazeFieldType : uint8_t {
    WITNESS    = 0x01,  // Witness stack data (SegWit inputs)
    SCRIPTSIG  = 0x02,  // scriptSig content (legacy/P2SH-wrapped inputs)
    OP_RETURN  = 0x03,  // OP_RETURN output payload
    COINBASE   = 0x04,  // Coinbase input scriptSig
};

struct HazeableField {
    HazeFieldType type;
    uint32_t tx_index;       // Transaction index within the block
    uint32_t field_index;    // Input/output index within the transaction
    size_t original_size;    // Byte size of the hazeable content
};

// Returns all hazeable fields in a transaction
std::vector<HazeableField> ClassifyTransaction(const CTransaction& tx, bool is_coinbase);

// Returns all hazeable fields in a block
std::vector<HazeableField> ClassifyBlock(const CBlock& block);

// Returns true if the transaction has a non-empty scriptSig on any input
// (determines whether txid must be stored explicitly in stripped format)
bool RequiresStoredTxid(const CTransaction& tx);
```

**Acceptance criteria:**

- [ ] Identifies witness data for all SegWit input types (P2WPKH, P2WSH, P2TR key-path, P2TR script-path)
- [ ] Identifies scriptSig for legacy inputs (P2PKH, P2SH, bare multisig)
- [ ] Identifies scriptSig for P2SH-wrapped SegWit inputs (P2SH-P2WPKH, P2SH-P2WSH)
- [ ] Identifies OP_RETURN outputs by `0x6a` opcode prefix in scriptPubKey
- [ ] Identifies coinbase scriptSig (first input where prevout hash is all zeros)
- [ ] Returns empty vector for transactions with no hazeable fields (if any exist)
- [ ] Does NOT identify preserved fields as hazeable (amounts, output scripts, prevouts, headers)
- [ ] `RequiresStoredTxid()` returns true for legacy and P2SH-wrapped transactions, false for native SegWit
- [ ] Handles edge cases: empty witness stacks, empty scriptSig on non-SegWit, OP_RETURN with no payload
- [ ] All unit tests pass

---

### TASK 1.2: Ghost Stripped Block Format

**Difficulty:** MEDIUM | **Phase:** 1 | **Depends on:** 1.1 | **Est:** 25 hrs

Define and implement the Ghost Stripped Block (GSB) format — the on-disk serialization for hazed blocks. This format stores preserved structural fields with hazeable content removed. Must be readable independently and support optional zstd compression.

**Files to create:**
- `src/haze/stripped_block.h` — Format constants, `CStrippedBlock` class, `CStrippedTransaction` class
- `src/haze/stripped_block.cpp` — Serialization, deserialization, file I/O

**Format (from spec section 7.1):**

```
[4 bytes]   Magic: 0x47 0x53 0x42 0x00 ("GSB\0")
[4 bytes]   Stripped block data size (uint32 LE)
[80 bytes]  Block header (unchanged)
[varint]    Transaction count
[per transaction]:
    [1 byte]    Flags (bit 0: has_stored_txid)
    [32 bytes]  txid (only if has_stored_txid = 1)
    [4 bytes]   nVersion
    [varint]    Input count
    [per input]:
        [32 bytes]  prevout txid
        [4 bytes]   prevout index
        [1 byte]    scriptSig length = 0x00
        [4 bytes]   nSequence
    [varint]    Output count
    [per output]:
        [8 bytes]   nValue
        [varint]    scriptPubKey length
        [variable]  scriptPubKey (OP_RETURN: opcode + 0x00 only)
    [4 bytes]   nLockTime
```

**Key classes:**

```cpp
class CStrippedTransaction {
    bool m_has_stored_txid;
    uint256 m_stored_txid;      // Only if scriptSig was non-empty
    int32_t m_version;
    std::vector<CStrippedInput> m_inputs;   // prevout + sequence only
    std::vector<CStrippedOutput> m_outputs; // value + scriptPubKey (OP_RETURN stripped)
    uint32_t m_locktime;
};

class CStrippedBlock {
    CBlockHeader m_header;
    std::vector<CStrippedTransaction> m_transactions;

    // Serialize to GSB format
    void Serialize(CDataStream& ss) const;
    // Deserialize from GSB format
    void Unserialize(CDataStream& ss);

    // Get the txid for a transaction (computed or stored)
    uint256 GetTxid(size_t tx_index) const;
};

// File I/O
bool WriteStrippedBlockToDisk(const CStrippedBlock& block, FlatFilePos& pos);
bool ReadStrippedBlockFromDisk(CStrippedBlock& block, const FlatFilePos& pos);
```

**Acceptance criteria:**

- [ ] `CStrippedBlock` serializes to exactly the GSB binary format defined in the spec
- [ ] `Serialize()` → `Unserialize()` round-trip produces identical objects
- [ ] Magic bytes are `0x47534200` ("GSB\0")
- [ ] Block header is preserved byte-for-byte
- [ ] Txid stored only when `RequiresStoredTxid()` is true (from Task 1.1)
- [ ] All scriptSig fields are empty (length byte 0x00)
- [ ] No witness data present in serialization
- [ ] OP_RETURN outputs: opcode `0x6a` preserved, payload replaced with single `0x00`
- [ ] Non-OP_RETURN output scripts preserved byte-for-byte
- [ ] `GetTxid()` computes txid from preserved data for native SegWit, returns stored txid for legacy
- [ ] GSB files use `.gsb` extension (naming: `gsb00000.dat`, `gsb00001.dat`, etc.)
- [ ] Optional zstd compression: `WriteCompressedStrippedBlock()` / `ReadCompressedStrippedBlock()`
- [ ] Compressed files use `.gsb.zst` extension
- [ ] File corruption (truncated, bad magic, bad size) returns error, does not crash
- [ ] All unit tests pass

---

### TASK 1.3: Block Stripper

**Difficulty:** MEDIUM | **Phase:** 1 | **Depends on:** 1.1, 1.2 | **Est:** 20 hrs

Core conversion function that takes a fully validated `CBlock` and produces a `CStrippedBlock`. This is the heart of the stripping engine used by both Exorcism (real-time) and Exorcist (batch conversion).

**Files to create:**
- `src/haze/block_stripper.h` — `StripBlock()` function, stripping statistics
- `src/haze/block_stripper.cpp` — Implementation

**Key functions:**

```cpp
struct StripResult {
    CStrippedBlock stripped_block;
    size_t original_size;         // Full block serialized size
    size_t stripped_size;          // Stripped block serialized size
    size_t witness_bytes_removed;
    size_t scriptsig_bytes_removed;
    size_t opreturn_bytes_removed;
    size_t coinbase_bytes_removed;
    uint32_t txids_stored;        // Number of txids stored explicitly
};

// Strip a full block into a stripped block
StripResult StripBlock(const CBlock& block);

// Strip a single transaction (used internally and by Exorcist)
CStrippedTransaction StripTransaction(const CTransaction& tx, bool is_coinbase);

// Verify a stripped block's structural integrity
// (merkle root matches txids, header is valid, etc.)
bool VerifyStrippedBlock(const CStrippedBlock& stripped, const CBlockHeader& expected_header);
```

**Acceptance criteria:**

- [ ] `StripBlock()` produces a valid `CStrippedBlock` for any valid `CBlock`
- [ ] The stripped block's header is byte-identical to the original
- [ ] Merkle root computed from `GetTxid()` for all stripped txs matches the header's merkle root
- [ ] The witness commitment in the coinbase output is preserved (it's a scriptPubKey, not hazeable)
- [ ] `StripResult` statistics are accurate (bytes removed per category)
- [ ] Handles all transaction types: legacy P2PKH, P2SH multisig, P2SH-P2WPKH, P2SH-P2WSH, P2WPKH, P2WSH, P2TR key-path, P2TR script-path
- [ ] Handles blocks with zero hazeable content (empty blocks, blocks with only coinbase)
- [ ] Handles blocks with OP_RETURN outputs of varying sizes (0 bytes to max)
- [ ] `VerifyStrippedBlock()` catches: wrong merkle root, missing stored txids, corrupt header
- [ ] Known test vector: specific regtest block produces expected stripped output byte-for-byte
- [ ] Performance: strips a typical 1.5 MB block in <10ms
- [ ] All unit tests pass

---

### TASK 1.4: Ghost Exorcism

**Difficulty:** HARD | **Phase:** 1 | **Depends on:** 1.3 | **Est:** 30 hrs

Integrate the strip-before-write process into Bitcoin Core's block acceptance pipeline. When Mode A is active, incoming blocks are validated in RAM against full data, then only the stripped structural output is written to disk. The original data is zeroed in memory after writing.

This is the most critical task in the entire project. It modifies `validation.cpp` — the consensus-adjacent code path.

**Files to create:**
- `src/haze/exorcism.h` — `GhostExorcism` class, configuration
- `src/haze/exorcism.cpp` — Strip-before-write logic, secure memory zeroing

**Files to modify:**
- `src/validation.cpp` — Insert Exorcism into the block write path
- `src/Makefile.am` — Add all Phase 1 source files to build

**Key functions:**

```cpp
class GhostExorcism {
public:
    // Initialize with mode and data directory
    void Init(GhostMode mode, const fs::path& datadir);

    // Process a validated block — strip and write to disk
    // Called AFTER AcceptBlock() succeeds, INSTEAD OF standard WriteBlockToDisk
    bool ProcessValidatedBlock(const CBlock& block,
                               const CBlockIndex* pindex,
                               FlatFilePos& pos);

    // Secure zero a memory region (volatile write, not optimizable by compiler)
    static void SecureZero(void* ptr, size_t len);

    // Statistics
    size_t GetTotalBytesStripped() const;
    size_t GetBlocksProcessed() const;
    bool IsActive() const;
};
```

**Integration point in validation.cpp:**

The change is in `BlockManager::SaveBlockToDisk()` (or equivalent in the Bitcoin Core version being forked). After the block has been fully validated and accepted:

```cpp
if (g_ghost_exorcism.IsActive()) {
    // Mode A: strip and write structural only
    success = g_ghost_exorcism.ProcessValidatedBlock(block, pindex, pos);
} else {
    // Mode B / standard: write full block
    success = WriteBlockToDisk(block, pos);
}
```

**Acceptance criteria:**

- [ ] When Exorcism is active, `ProcessValidatedBlock()` writes a GSB file, never a blk*.dat entry
- [ ] When Exorcism is inactive (Mode B), the standard `WriteBlockToDisk()` path is used unchanged
- [ ] After writing, the source block data in memory is zeroed via `SecureZero()`
- [ ] `SecureZero()` uses `volatile` pointer cast or platform-specific secure zero (e.g., `explicit_bzero`, `SecureZeroMemory`) to prevent compiler optimization
- [ ] The UTXO set is updated from the full in-memory block BEFORE stripping (validation is on full data)
- [ ] Block index is updated to point to the GSB file position (not blk*.dat)
- [ ] The node can read back stripped blocks from GSB files via the block index
- [ ] `getblock` RPC on a stripped block returns structural data with haze indicators
- [ ] Crash during `ProcessValidatedBlock()` leaves no partial hazeable data on disk
- [ ] The GSB write is atomic: either the full stripped block is written or nothing is
- [ ] New blocks arriving via P2P are processed through Exorcism seamlessly
- [ ] IBD (Initial Block Download) processes all blocks through Exorcism when Mode A is active
- [ ] Performance: Exorcism adds <5ms overhead per block vs standard write path
- [ ] `GetTotalBytesStripped()` and `GetBlocksProcessed()` report accurate cumulative statistics
- [ ] No modifications to consensus validation code — Exorcism operates AFTER validation only
- [ ] `cargo test` / `make check` passes — no regressions in existing Bitcoin Core tests
- [ ] All unit tests pass

**CRITICAL: This task requires careful review. The modification to validation.cpp must not alter any consensus behavior. The strip-before-write must occur strictly after AcceptBlock() and UpdateTip() succeed.**

---

### TASK 1.5: Ghost Exorcist

**Difficulty:** MEDIUM | **Phase:** 1 | **Depends on:** 1.2, 1.3 | **Est:** 20 hrs

The archive conversion tool. Reads existing `blk*.dat` files, strips all hazeable content, writes the structural archive in GSB format, securely zeroes the original files, and removes `rev*.dat` (undo data). Generates a Legal Compliance Packet upon completion.

**Files to create:**
- `src/haze/exorcist.h` — `GhostExorcist` class
- `src/haze/exorcist.cpp` — Conversion pipeline

**Key functions:**

```cpp
class GhostExorcist {
public:
    struct ConversionResult {
        bool success;
        uint32_t blocks_converted;
        size_t original_size;
        size_t stripped_size;
        size_t bytes_freed;
        std::string error;
    };

    struct Progress {
        uint32_t blocks_processed;
        uint32_t blocks_total;
        double percent;
        std::string eta;
        std::string current_phase;  // "stripping", "zeroing", "cleanup"
    };

    using ProgressCallback = std::function<void(const Progress&)>;

    // Run the full conversion
    ConversionResult Convert(const fs::path& datadir,
                             ProgressCallback progress_cb = nullptr);

    // Resume an interrupted conversion
    ConversionResult Resume(const fs::path& datadir,
                            ProgressCallback progress_cb = nullptr);

private:
    // Phase 1: Read blk*.dat, strip, write gsb*.dat
    bool StripArchive(const fs::path& datadir);

    // Phase 2: Secure zero all blk*.dat files
    bool SecureZeroOriginals(const fs::path& datadir);

    // Phase 3: Delete blk*.dat and rev*.dat
    bool CleanupOriginals(const fs::path& datadir);

    // Phase 4: Update block index to point to GSB files
    bool UpdateBlockIndex(const fs::path& datadir);
};
```

**Acceptance criteria:**

- [ ] Reads all blocks from existing `blk*.dat` files using Bitcoin Core's block file infrastructure
- [ ] Strips each block via `StripBlock()` (Task 1.3)
- [ ] Writes stripped blocks to `gsb*.dat` files
- [ ] Securely zeroes all `blk*.dat` files before deletion (byte-by-byte overwrite with 0x00)
- [ ] Deletes all `rev*.dat` files (undo data not needed for stripped archive)
- [ ] Updates the block index LevelDB to point to GSB file positions
- [ ] Progress callback reports: blocks processed, total, percentage, ETA, current phase
- [ ] Logs every 10,000 blocks: `"Exorcist: 450000/936000 (48.1%) — Phase: stripping — ETA: 22m"`
- [ ] Handles interruption gracefully: tracks last converted block, `Resume()` continues from there
- [ ] After conversion: `getblock <hash>` returns structural data for any historical block
- [ ] After conversion: `gettxout` works normally (UTXO set untouched)
- [ ] After conversion: `grep` of data directory for known OP_RETURN payloads returns zero matches
- [ ] After conversion: all `blk*.dat` files are gone or contain only zeros
- [ ] After conversion: all `rev*.dat` files are deleted
- [ ] After conversion: disk usage matches expected Mode A size
- [ ] Sets mode to HAZED in configuration file
- [ ] Generates Legal Compliance Packet (depends on Task 3.5 — can be stubbed initially)
- [ ] Refuses to run if mode is already HAZED (idempotency protection)
- [ ] Conversion is irreversible — warns user and requires confirmation
- [ ] Performance: converts the full ~620 GB archive in <1 hour on NVMe SSD
- [ ] All unit tests pass

---

## Phase 2: Checkpoint & Sync

The checkpoint system that enables accelerated IBD for both modes. Phase 2 can begin as soon as Task 1.2 (Stripped Block Format) is complete — it runs in parallel with Tasks 1.3-1.5.

---

### TASK 2.1: Checkpoint Data Format

**Difficulty:** EASY | **Phase:** 2 | **Depends on:** 1.2 | **Est:** 15 hrs

Define the Ghost Checkpoint format — the manifest structure, the pre-built chainstate packaging, and the archive chunk manifest. The checkpoint is a tarball containing everything a new node needs for accelerated sync.

**Files to create:**
- `src/haze/checkpoint.h` — `GhostCheckpoint` class, manifest structure, constants
- `src/haze/checkpoint.cpp` — Serialization, deserialization, tarball generation

**Key structures:**

```cpp
struct CheckpointManifest {
    uint16_t version;               // Format version (1)
    uint32_t block_height;          // Checkpoint block height
    uint256 block_hash;             // Checkpoint block hash
    uint64_t total_transactions;    // Total txs up to this height
    uint64_t utxo_count;            // Number of UTXOs in chainstate
    uint64_t creation_timestamp;    // Unix timestamp
    uint256 chainstate_hash;        // SHA-256 of compressed chainstate directory
    uint256 headers_hash;           // SHA-256 of headers.bin
    uint256 bloom_hash;             // SHA-256 of swift_hints.bloom
    uint256 chunks_manifest_hash;   // SHA-256 of archive_chunks.manifest
    std::vector<uint8_t> signature; // Ed25519 signature (64 bytes)
};

struct ChunkManifest {
    uint64_t chunk_size;            // Bytes per chunk (default: 64 MB)
    uint64_t total_chunks;
    uint64_t total_size;            // Total compressed archive size
    struct ChunkEntry {
        uint256 hash;               // SHA-256 of chunk data
        uint64_t offset;            // Byte offset in archive
        uint32_t size;              // Actual chunk size (last chunk may be smaller)
        uint32_t start_height;      // First block in this chunk
        uint32_t end_height;        // Last block in this chunk
    };
    std::vector<ChunkEntry> chunks;
};
```

**Checkpoint tarball structure:**

```
ghost-checkpoint-{height}.tar.zst
├── manifest.json
├── chainstate.tar.zst              // Pre-built LevelDB directory
├── headers.bin                     // Sequential block headers
├── swift_hints.bloom               // SwiftSync Bloom filter
└── archive_chunks.manifest         // Chunk hashes for parallel download
```

**Acceptance criteria:**

- [ ] `CheckpointManifest` serializes to JSON and binary formats
- [ ] Manifest round-trips correctly (serialize → deserialize → compare)
- [ ] `ChunkManifest` correctly describes the archive's chunk layout
- [ ] `headers.bin` is a flat file of sequential 80-byte block headers from genesis to checkpoint height
- [ ] `headers.bin` is verifiable: each header's prev_hash matches the previous header's hash
- [ ] Chainstate tarball contains a valid LevelDB directory that can be opened directly
- [ ] Checkpoint generation from a synced node produces a valid tarball
- [ ] Checkpoint loading validates all hashes before applying
- [ ] Reject checkpoints with invalid hashes, wrong version, or missing components
- [ ] All unit tests pass

---

### TASK 2.2: Checkpoint Signing & Verification

**Difficulty:** MEDIUM | **Phase:** 2 | **Depends on:** 2.1 | **Est:** 20 hrs

Ed25519 signing of checkpoints by the Ghost Core project key, and verification on the client side. Supports multiple trusted keys for key rotation.

**Files to create:**
- `src/haze/checkpoint_signer.h` — Signing and verification functions
- `src/haze/checkpoint_signer.cpp` — Ed25519 implementation

**Key functions:**

```cpp
// Sign a checkpoint manifest with the project private key
bool SignCheckpoint(CheckpointManifest& manifest,
                    const std::array<uint8_t, 32>& private_key);

// Verify a checkpoint signature against trusted public keys
bool VerifyCheckpoint(const CheckpointManifest& manifest,
                      const std::vector<std::array<uint8_t, 32>>& trusted_keys);

// Get the hardcoded trusted public keys
std::vector<std::array<uint8_t, 32>> GetTrustedCheckpointKeys();
```

**Acceptance criteria:**

- [ ] Ed25519 signing produces a 64-byte signature embedded in the manifest
- [ ] Verification succeeds for correctly signed checkpoints
- [ ] Verification fails for tampered checkpoints (modified height, hash, or any component hash)
- [ ] Verification fails for unknown signing keys
- [ ] Multiple trusted keys supported (for key rotation)
- [ ] Ghost Core project public key hardcoded in source, configurable for testing via `-checkpointkey`
- [ ] Uses Bitcoin Core's existing crypto primitives where possible, or libsodium for Ed25519
- [ ] Signing tool is a separate CLI command for checkpoint publishers: `ghost-core --sign-checkpoint`
- [ ] All unit tests pass

---

### TASK 2.3: SwiftSync Bloom Filter

**Difficulty:** HARD | **Phase:** 2 | **Depends on:** 2.1 | **Est:** 25 hrs

Implement the SwiftSync optimization: a Bloom filter encoding all ~170 million outpoints that remain unspent at the checkpoint height. During full IBD from genesis, the node checks this filter before writing UTXO entries to LevelDB — only the 7% of outputs that survive are written to disk. The remaining 93% are tracked in memory only.

**Files to create:**
- `src/haze/swift_sync.h` — `SwiftSyncFilter` class, `SwiftSyncIBDController` class
- `src/haze/swift_sync.cpp` — Bloom filter implementation, IBD integration

**Files to modify:**
- `src/validation.cpp` — Integrate SwiftSync into UTXO update path during IBD

**Key classes:**

```cpp
class SwiftSyncFilter {
public:
    // Generate a filter from the current UTXO set
    static SwiftSyncFilter Generate(const CCoinsViewDB& utxo_db,
                                    std::function<void(double)> progress_cb = nullptr);

    // Load a filter from checkpoint
    static SwiftSyncFilter Load(const fs::path& bloom_file);

    // Save filter to file
    bool Save(const fs::path& bloom_file) const;

    // Check if an outpoint is likely in the surviving UTXO set
    bool MayContain(const COutPoint& outpoint) const;

    // Statistics
    size_t GetSizeBytes() const;        // ~212 MB
    uint64_t GetElementCount() const;   // ~170M
    double GetFalsePositiveRate() const; // ~0.001
};

class SwiftSyncIBDController {
public:
    // Initialize with a loaded filter
    void Init(SwiftSyncFilter&& filter);

    // Called for each output created during IBD
    // Returns true if the output should be written to LevelDB
    // Returns false if it should be tracked in memory only (ephemeral)
    bool ShouldPersistOutput(const COutPoint& outpoint) const;

    // Called for each input spent during IBD
    // Returns true if the spend is against a persisted output (LevelDB delete needed)
    // Returns false if the spend is against an ephemeral output (memory remove only)
    bool IsPersistedOutput(const COutPoint& outpoint) const;

    // Track an ephemeral output (created but expected to be spent before checkpoint)
    void TrackEphemeral(const COutPoint& outpoint, const Coin& coin);

    // Spend an ephemeral output
    bool SpendEphemeral(const COutPoint& outpoint);

    // Statistics
    size_t GetEphemeralCount() const;
    size_t GetPersistedCount() const;
    size_t GetLevelDBWritesSaved() const;
};
```

**Acceptance criteria:**

- [ ] `Generate()` produces a Bloom filter from the UTXO set in <30 minutes
- [ ] Filter size is ~212 MB for ~170M elements at 0.1% false positive rate
- [ ] `MayContain()` returns true for all outpoints in the UTXO set (zero false negatives)
- [ ] `MayContain()` false positive rate is approximately 0.1% on random outpoints
- [ ] During IBD with SwiftSync active, only ~7% of outputs are written to LevelDB
- [ ] The remaining ~93% are tracked in an in-memory hash map
- [ ] Ephemeral outputs are correctly spent from the in-memory map
- [ ] False positives (ephemeral output passes the filter) result in unnecessary LevelDB writes — slower but not incorrect
- [ ] The UTXO set after SwiftSync IBD is **byte-identical** to the UTXO set after standard IBD
- [ ] Memory usage for ephemeral tracking stays under 4 GB (configurable)
- [ ] If memory limit is reached, ephemeral outputs overflow to LevelDB (graceful degradation)
- [ ] IBD with SwiftSync completes in <40 minutes on gigabit + NVMe (vs ~3.5 hours without)
- [ ] `GetLevelDBWritesSaved()` reports accurate statistics
- [ ] Integration with `validation.cpp` is minimal: two decision points (create output, spend output)
- [ ] SwiftSync is automatically disabled after catching up to checkpoint height (normal validation resumes)
- [ ] All unit tests pass

**This is the highest-value single task.** SwiftSync alone takes full IBD from ~3.5 hours to ~35 minutes.

---

### TASK 2.4: Parallel Chunk Download

**Difficulty:** MEDIUM | **Phase:** 2 | **Depends on:** 2.1 | **Est:** 20 hrs

Protocol for downloading the compressed stripped archive in parallel from multiple peers. The archive is split into 64 MB chunks, each identified by SHA-256 hash. Multiple peers serve different chunks simultaneously.

**Files to create:**
- `src/haze/chunk_download.h` — `ChunkDownloader` class
- `src/haze/chunk_download.cpp` — Parallel download orchestration

**Key class:**

```cpp
class ChunkDownloader {
public:
    struct DownloadStats {
        uint64_t chunks_complete;
        uint64_t chunks_total;
        uint64_t bytes_downloaded;
        uint64_t bytes_total;
        double percent;
        double speed_mbps;        // Current aggregate speed
        uint32_t active_peers;
        std::string eta;
    };

    using ProgressCallback = std::function<void(const DownloadStats&)>;

    // Initialize with chunk manifest and available peers
    void Init(const ChunkManifest& manifest,
              const std::vector<CAddress>& peers,
              const fs::path& output_dir);

    // Start parallel download (non-blocking, runs in background)
    void Start(ProgressCallback progress_cb = nullptr);

    // Stop download
    void Stop();

    // Resume interrupted download (checks existing chunks on disk)
    void Resume(ProgressCallback progress_cb = nullptr);

    // Verify all downloaded chunks against manifest hashes
    bool VerifyAll() const;

    // Assemble chunks into sequential gsb*.dat files
    bool Assemble() const;
};
```

**Acceptance criteria:**

- [ ] Downloads chunks from multiple peers simultaneously (up to configurable max, default 20)
- [ ] Each chunk is verified against its SHA-256 hash in the manifest before accepting
- [ ] Failed/corrupted chunks are re-requested from a different peer
- [ ] Slow peers are deprioritized; fast peers get more chunk assignments
- [ ] Progress callback reports: chunks complete, bytes, speed, active peers, ETA
- [ ] Resumable: checks existing chunks on disk, only downloads missing/incomplete ones
- [ ] `Assemble()` combines verified chunks into sequential `gsb*.dat` files
- [ ] Chunks are stored as temporary files until verified, then moved to final location
- [ ] Handles peer disconnection gracefully (reassign chunks to remaining peers)
- [ ] Handles zero available peers (waits for peer discovery, retries)
- [ ] Bandwidth limiting: configurable max download speed to avoid saturating connection
- [ ] All unit tests pass

---

## Phase 3: Integration

Connect everything to the user interface, P2P network, and RPC layer. Begins after Task 1.4 (Exorcism) and Task 2.2 (Checkpoint Signing) are complete.

---

### TASK 3.1: Mode Selector

**Difficulty:** EASY | **Phase:** 3 | **Depends on:** 1.4 | **Est:** 10 hrs

First-launch mode selection. Detects new data directory, presents mode choice, persists selection, and prevents mode changes without re-sync.

**Files to create:**
- `src/haze/mode_selector.h` — `GhostMode` enum, selection logic
- `src/haze/mode_selector.cpp` — First-launch detection, mode persistence

**Files to modify:**
- `src/init.cpp` — Mode selection at startup before IBD

**Key structures:**

```cpp
enum class GhostMode : uint8_t {
    HAZED = 0,          // Mode A: stripped archive + Exorcism
    FULL_ARCHIVE = 1,   // Mode B: standard Bitcoin Core behavior
};

// Detect mode from existing data directory, or prompt for selection
GhostMode DetectOrSelectMode(const fs::path& datadir, bool interactive);

// Read mode from configuration
GhostMode ReadMode(const fs::path& datadir);

// Write mode to configuration (creates lock file)
void WriteMode(const fs::path& datadir, GhostMode mode);

// Check if mode change is attempted with existing data
bool ValidateModeConsistency(const fs::path& datadir, GhostMode requested_mode);
```

**Acceptance criteria:**

- [ ] On first launch (empty data directory): presents mode selection prompt
- [ ] Mode A sets `ghostmode=hazed` in `ghost.conf` and creates `mode.lock` file
- [ ] Mode B sets `ghostmode=full_archive` in `ghost.conf` and creates `mode.lock` file
- [ ] Subsequent launches read mode from `ghost.conf` silently (no prompt)
- [ ] Attempting to start with `ghostmode=hazed` on a data directory containing `blk*.dat` produces a clear error: `"Mode A requires stripped archive. Run --exorcist to convert existing archive, or use a fresh data directory."`
- [ ] Attempting to start with `ghostmode=full_archive` on a data directory containing `gsb*.dat` produces a clear error: `"Mode B requires full archive. Re-sync with a fresh data directory."`
- [ ] `--ghostmode=hazed` and `--ghostmode=full_archive` CLI flags override interactive selection
- [ ] Non-interactive mode (daemon) defaults to HAZED if no config exists
- [ ] All unit tests pass

---

### TASK 3.2: CLI Interface

**Difficulty:** EASY | **Phase:** 3 | **Depends on:** 1.4, 2.2, 3.5 | **Est:** 10 hrs

Command-line interface for Ghost Haze features. All commands map to RPC calls.

**Files to create:**
- `src/rpc/haze.h` — RPC command registration
- `src/rpc/haze.cpp` — RPC handlers

**Commands:**

```
ghost-core --haze-status
ghost-core --legal-packet [--output <path>]
ghost-core --exorcist
ghost-core --checkpoint-update
ghost-core --checkpoint-status
```

**Acceptance criteria:**

- [ ] `--haze-status` returns JSON: `{mode, exorcism_active, blocks_total, storage_gb, stripped_storage_gb, compression_enabled, checkpoint_height, checkpoint_age_hours}`
- [ ] `--legal-packet` generates and outputs the Legal Compliance Packet JSON
- [ ] `--legal-packet --output /path/file.json` writes the packet to a file
- [ ] `--exorcist` invokes the archive conversion tool (Task 1.5)
- [ ] `--checkpoint-update` fetches the latest checkpoint from configured URL or P2P peers
- [ ] `--checkpoint-status` shows: checkpoint height, block hash, age, signature status, SwiftSync filter status
- [ ] Mode B nodes: haze-specific commands return `"Not applicable in Full Archive mode (Mode B)"`
- [ ] All commands have `--help` documentation
- [ ] RPC equivalents: `gethazestatus`, `getlegalpacket`, `getcheckpointstatus`, `updatecheckpoint`
- [ ] All commands return well-formed JSON
- [ ] All unit tests pass

---

### TASK 3.3: RPC Compatibility Layer

**Difficulty:** MEDIUM | **Phase:** 3 | **Depends on:** 1.2 | **Est:** 15 hrs

Modify existing Bitcoin Core RPC calls to work with the stripped archive. Stripped fields return indicators instead of data. Mode B nodes return full data unchanged.

**Files to modify:**
- `src/rpc/blockchain.cpp` — `getblock`, `getblockstats`
- `src/rpc/rawtransaction.cpp` — `getrawtransaction`, `decoderawtransaction`

**Behavior for Mode A nodes:**

For `getrawtransaction` on a stripped block:
```json
{
  "txid": "abc123...",
  "vin": [{
    "txid": "def456...",
    "vout": 0,
    "scriptSig": {"hex": "", "stripped": true},
    "sequence": 4294967295,
    "witness": "stripped"
  }],
  "vout": [{
    "value": 0.001,
    "scriptPubKey": {"hex": "0014abc...", "type": "witness_v0_keyhash", "address": "bc1q..."}
  }, {
    "value": 0.0,
    "scriptPubKey": {"hex": "6a00", "type": "nulldata", "stripped": true}
  }],
  "haze_status": {
    "mode": "hazed",
    "fields_stripped": ["witness", "scriptsig"],
    "committed_by": "txid"
  }
}
```

**Acceptance criteria:**

- [ ] `getblock` on a stripped block returns structural data with `"haze_status"` field
- [ ] `getrawtransaction` returns preserved fields + `"stripped": true` for hazeable fields
- [ ] `gettxout` works normally on both modes (UTXO set is never stripped)
- [ ] `getblockheader` works normally on both modes (headers are preserved)
- [ ] `getblockstats` works for structural stats (txcount, total_size, avg_fee) but returns `null` for witness-dependent stats
- [ ] Mode B nodes: all RPCs return full data with no haze fields (standard Bitcoin Core behavior)
- [ ] No RPC call crashes or errors on stripped data
- [ ] `decoderawtransaction` on hex from a stripped block correctly decodes structural fields
- [ ] The `verbose` parameter on `getblock` respects haze indicators at all verbosity levels
- [ ] All unit tests pass

---

### TASK 3.4: P2P Messages

**Difficulty:** MEDIUM | **Phase:** 3 | **Depends on:** 1.2 | **Est:** 15 hrs

New P2P messages for serving stripped blocks and redirecting raw data requests. Mode A nodes advertise their status via a service flag.

**Files to create:**
- `src/haze/haze_p2p.h` — Message structures
- `src/haze/haze_p2p.cpp` — Message handlers

**Files to modify:**
- `src/protocol.h` — `NODE_GHOST_HAZE` service flag, message type constants
- `src/net_processing.cpp` — Message handling for new types

**New protocol elements:**

```cpp
// Service flag
static const ServiceFlags NODE_GHOST_HAZE = (1 << 26);

// Message types
extern const char* GHOST_STRIPPED_BLOCK;  // "gstripblk"
extern const char* GHOST_REDIRECT;       // "gredirect"
extern const char* GHOST_CHUNK_REQ;      // "gchunkreq"
extern const char* GHOST_CHUNK_RESP;     // "gchunkresp"
```

**Acceptance criteria:**

- [ ] Mode A nodes advertise `NODE_GHOST_HAZE` service flag in version handshake
- [ ] Mode B nodes do not set `NODE_GHOST_HAZE`
- [ ] When a Mode A node receives `getdata` for a block, it responds with `GHOST_STRIPPED_BLOCK` containing the GSB data
- [ ] When a non-Ghost peer requests block data, Mode A responds with `GHOST_REDIRECT` containing the txid(s) and a list of known archive peer addresses
- [ ] `GHOST_CHUNK_REQ` requests a specific chunk by hash (for parallel archive download)
- [ ] `GHOST_CHUNK_RESP` returns the chunk data
- [ ] Archive peers (Mode B or Bitcoin Core) are identified by `NODE_NETWORK` flag without `NODE_GHOST_HAZE`
- [ ] Non-Ghost peers receiving Ghost messages treat them as unknown (safe — Bitcoin Core ignores unknown message types)
- [ ] Peer scoring: don't penalize peers for sending unknown Ghost messages
- [ ] Mode A peers preferentially connect to other Mode A peers for block relay (structural blocks are smaller)
- [ ] All unit tests pass

---

### TASK 3.5: Legal Compliance Packet

**Difficulty:** EASY | **Phase:** 3 | **Depends on:** 1.4 | **Est:** 10 hrs

Generates the machine-verifiable and human-readable legal protection document for Mode A operators.

**Files to create:**
- `src/haze/legal_packet.h` — `LegalPacket` struct
- `src/haze/legal_packet.cpp` — Generation, signing, export

**Output format:**

```json
{
  "ghost_core_version": "2.0.0",
  "specification_version": "2.0",
  "node_mode": "HAZED",
  "node_public_key": "02abc...def",
  "exorcism_active": true,
  "exorcism_since": "2026-02-14T12:00:00Z",
  "haze_status": "COMPLETE",
  "blocks_stripped": 936000,
  "chain_tip": 936144,
  "structural_archive_size_gb": 193.4,
  "hazeable_content_on_disk": false,
  "checkpoint_height": 936000,
  "checkpoint_hash": "000000000000000000023a5d...",
  "conversion_method": "exorcist",
  "conversion_date": "2026-02-14T12:00:00Z",
  "legal_summary": "This node operates in Ghost Haze mode. All hazeable content (witness data, scriptSig signatures, OP_RETURN payloads, and coinbase arbitrary data) has been irreversibly destroyed from persistent storage. Only the structural economic graph (transaction IDs, amounts, addresses, block headers) is retained. Bitcoin's native cryptographic commitments (txids, witness commitments) serve as mathematical proof that the destroyed content existed but cannot be reconstructed. Ghost Exorcism is active: incoming block data is validated in volatile memory and only structural data is written to persistent storage.",
  "generated_at": "2026-02-14T15:30:00Z",
  "signature": "3045022100..."
}
```

**Acceptance criteria:**

- [ ] Generates a complete JSON document with all fields from the spec
- [ ] Signed with the node's identity key
- [ ] `generated_at` reflects the actual generation time
- [ ] `blocks_stripped` matches the actual number of blocks in GSB format on disk
- [ ] `hazeable_content_on_disk` is determined by scanning for blk*.dat files (not just config)
- [ ] `conversion_method` is `"exorcist"` (converted from full archive) or `"exorcism"` (hazed from genesis)
- [ ] `legal_summary` is a clear, court-ready plain English explanation
- [ ] Output as JSON to stdout or to a file path
- [ ] Mode B nodes: command returns error `"Legal Compliance Packet not applicable in Full Archive mode. This node stores all blockchain data including embedded content."`
- [ ] All unit tests pass

---

## Phase 4: Testing

Comprehensive testing across all components. Begins after all implementation tasks are complete.

---

### TASK 4.1: Unit Tests

**Difficulty:** MEDIUM | **Phase:** 4 | **Depends on:** All Phase 1-3 tasks | **Est:** 15 hrs

Unit tests for every data structure, utility function, and component.

**Files to create:**
- `src/haze/tests/field_classifier_tests.cpp`
- `src/haze/tests/stripped_block_tests.cpp`
- `src/haze/tests/exorcism_tests.cpp`
- `src/haze/tests/exorcist_tests.cpp`
- `src/haze/tests/checkpoint_tests.cpp`
- `src/haze/tests/swift_sync_tests.cpp`

**Test coverage required:**

| Component | Tests |
|---|---|
| Field Classifier | All tx types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, coinbase), edge cases (empty witness, no OP_RETURN) |
| Stripped Block Format | Serialize/deserialize round-trip, magic bytes, OP_RETURN handling, stored txid logic, compression |
| Block Stripper | All tx types, merkle root verification, statistics accuracy, known test vectors |
| Exorcism | Strip-before-write, secure zero verification, crash recovery simulation, Mode B passthrough |
| Exorcist | Small archive conversion, progress reporting, interruption/resume, secure zeroing verification |
| Checkpoint | Manifest round-trip, signature verification, tamper detection, key rotation |
| SwiftSync | Bloom filter accuracy (FP rate), UTXO survive/ephemeral classification, memory limits |

**Acceptance criteria:**

- [ ] All tests pass with `make check` or Bitcoin Core's test runner
- [ ] Every public function in `src/haze/` has at least one test
- [ ] Known test vectors: specific regtest transactions produce expected stripped output
- [ ] Edge cases: empty blocks, blocks with only coinbase, maximum-size OP_RETURN, witness-less legacy blocks
- [ ] No memory leaks (Valgrind clean on test suite)

---

### TASK 4.2: Functional Tests

**Difficulty:** MEDIUM | **Phase:** 4 | **Depends on:** All Phase 1-3 tasks | **Est:** 15 hrs

End-to-end functional tests on regtest. Mine blocks with known embedded content, verify stripping, test both modes.

**Files to create:**
- `test/functional/feature_ghost_haze.py`
- `test/functional/feature_ghost_exorcism.py`

**Test scenarios:**

```
feature_ghost_haze.py:
  1. Start Mode A node on regtest
  2. Mine 200 blocks with various tx types:
     - P2WPKH standard transfers
     - P2WSH multisig spends
     - P2TR key-path and script-path spends
     - OP_RETURN outputs with known payloads ("GHOST_TEST_PAYLOAD_123")
     - Legacy P2PKH transactions
  3. Verify all blocks on disk are in GSB format (not blk*.dat)
  4. Verify getblock/getrawtransaction return haze indicators
  5. Verify gettxout works normally
  6. Grep data directory for "GHOST_TEST_PAYLOAD_123" — must NOT be found
  7. Verify merkle roots match for all blocks

feature_ghost_exorcism.py:
  1. Start Mode B node, mine 200 blocks with embedded content
  2. Stop node
  3. Run --exorcist conversion
  4. Restart in Mode A
  5. Verify all blocks now in GSB format
  6. Verify blk*.dat files are gone or zeroed
  7. Verify rev*.dat files are deleted
  8. Grep for known payloads — must NOT be found
  9. Verify getblock still works for all blocks
  10. Mine 10 more blocks — verify Exorcism processes them correctly
```

**Acceptance criteria:**

- [ ] All test scenarios pass on regtest
- [ ] Tests run in <5 minutes total
- [ ] Tests are deterministic (no flaky results)
- [ ] Tests clean up after themselves (no leftover regtest data)

---

### TASK 4.3: UTXO Equivalence Tests

**Difficulty:** HARD | **Phase:** 4 | **Depends on:** All Phase 1-3 tasks | **Est:** 20 hrs

**The single most important test.** A Mode A node and a Mode B node processing the same regtest chain must produce byte-identical UTXO sets. If they don't, something is broken in the stripping or validation pipeline.

**Files to create:**
- `test/functional/feature_ghost_utxo_equiv.py`

**Test procedure:**

```
1. Generate a deterministic regtest chain (500+ blocks) with diverse tx types:
   - Standard transfers (P2WPKH, P2TR)
   - Multisig spends (P2SH, P2WSH)
   - Timelocked transactions (CLTV, CSV)
   - OP_RETURN outputs
   - Large witness transactions (simulated inscriptions)
   - Chain of unconfirmed transactions (CPFP)
   - Coinbase spends (after maturity)

2. Sync this chain on a Mode A node (Exorcism active)
3. Sync the same chain on a Mode B node (standard)
4. Dump both UTXO sets via gettxoutsetinfo
5. Compare:
   - hash_serialized must be identical
   - txouts (count) must be identical
   - total_amount must be identical
6. Spot-check 100 random UTXOs via gettxout on both nodes — must match

7. Repeat with checkpoint-accelerated IBD (Mode A):
   - Generate checkpoint at block 400
   - New Mode A node syncs via checkpoint
   - Compare UTXO set at block 500 — must match Mode B

8. Repeat with SwiftSync IBD:
   - Generate SwiftSync Bloom filter at block 400
   - New Mode A node syncs with SwiftSync from genesis
   - Compare UTXO set — must match Mode B
```

**Acceptance criteria:**

- [ ] `hash_serialized` from `gettxoutsetinfo` is byte-identical between Mode A and Mode B
- [ ] UTXO count matches exactly
- [ ] Total amount matches exactly
- [ ] Checkpoint-synced UTXO set matches standard IBD UTXO set
- [ ] SwiftSync UTXO set matches standard IBD UTXO set
- [ ] Test runs with at least 500 blocks and 5+ transaction types
- [ ] Test includes coinbase maturity edge cases (spending coinbase at exactly 100 confirmations)
- [ ] Test includes re-org scenario (3-block re-org, verify UTXO set correct after)

**If this test fails, do not proceed. Fix the underlying issue first.**

---

### TASK 4.4: Cross-Mode P2P Tests

**Difficulty:** MEDIUM | **Phase:** 4 | **Depends on:** 3.4 | **Est:** 10 hrs

Test P2P interoperability between Mode A nodes, Mode B nodes, and standard Bitcoin Core nodes.

**Files to create:**
- `test/functional/feature_ghost_p2p.py`

**Test scenarios:**

```
1. Mode A ↔ Mode A:
   - Node A mines a block
   - Node B receives it, processes via Exorcism
   - Both nodes have identical chain tips
   - Node B requests historical block from Node A → receives GSB format

2. Mode A ↔ Mode B:
   - Node B (full archive) mines a block
   - Node A receives it, processes via Exorcism, stores stripped
   - Node A requests historical block → receives full block, does NOT store it

3. Mode A ↔ Bitcoin Core:
   - Bitcoin Core node mines a block
   - Mode A node receives it, processes via Exorcism
   - Bitcoin Core requests historical block from Mode A → receives GHOST_REDIRECT

4. Chunk download:
   - Mode A node requests archive chunks from Mode A peer
   - Chunks are verified against manifest hashes
   - Corrupted chunk is rejected, re-requested from different peer

5. Service flag:
   - Mode A nodes advertise NODE_GHOST_HAZE
   - Mode B nodes do not advertise NODE_GHOST_HAZE
   - Peers correctly identify archive peers for redirect
```

**Acceptance criteria:**

- [ ] All five scenarios pass on regtest with 3+ nodes
- [ ] Block propagation works correctly across all mode combinations
- [ ] GHOST_REDIRECT messages contain valid archive peer addresses
- [ ] GHOST_STRIPPED_BLOCK messages are correctly parsed by Mode A peers
- [ ] Bitcoin Core nodes are not disrupted by Ghost messages (treated as unknown)
- [ ] No peer banning or scoring penalties for Ghost messages

---

## Phase 5: Bootstrap & Deployment

Enables hazed-only networks without full archive peers. Added during implementation.

---

### TASK 5.1: Disable Background IBD for Hazed Nodes — COMPLETE

**Difficulty:** MEDIUM | **Phase:** 5 | **Depends on:** 1.4 | **Est:** 8 hrs

Hazed nodes loading a UTXO snapshot should not attempt background IBD — they can't validate historical blocks without full data. Modified `ActivateSnapshot()` to disable the IBD chainstate immediately.

**Modified:** `src/validation.cpp`

---

### TASK 5.2: Prevent NODE_NETWORK Re-enable — COMPLETE

**Difficulty:** EASY | **Phase:** 5 | **Depends on:** 5.1 | **Est:** 4 hrs

After snapshot download completes, Bitcoin Core normally re-enables `NODE_NETWORK`. Hazed nodes must stay `NODE_NETWORK_LIMITED` since they can't serve full blocks.

**Modified:** `src/init.cpp`

---

### TASK 5.3: CLI Snapshot Loading — COMPLETE

**Difficulty:** EASY | **Phase:** 5 | **Depends on:** 5.1 | **Est:** 4 hrs

Added `-loadtxoutset=<path>` CLI argument for offline UTXO snapshot loading without needing RPC. Loads snapshot, prints summary, exits cleanly.

**Modified:** `src/init.cpp`

---

### TASK 5.4: Haze Block Cache — COMPLETE

**Difficulty:** HARD | **Phase:** 5 | **Depends on:** 1.4 | **Est:** 12 hrs

Critical fix for P2P batch block processing. `ActivateBestChain` batch-connects multiple blocks but only passes `pblock` for the tip. Intermediate blocks need disk reads which fail on GSB files. Added `m_haze_block_cache` to ChainstateManager — blocks cached between AcceptBlock and ConnectTip.

**Modified:** `src/validation.h`, `src/validation.cpp`

---

### TASK 5.5: Exorcist Partial-Hazed Support — COMPLETE

**Difficulty:** MEDIUM | **Phase:** 5 | **Depends on:** 1.5 | **Est:** 6 hrs

Exorcist now handles nodes where `hazemode=hazed` was set before running the exorcist. Checks for blk*.dat files with non-zero data before bailing on HAZED lock file. Gracefully skips blocks already in GSB format.

**Modified:** `src/init.cpp`, `src/haze/exorcist.cpp`

---

### TASK 5.6: Functional Tests — COMPLETE

**Difficulty:** MEDIUM | **Phase:** 5 | **Depends on:** All Phase 5 tasks | **Est:** 6 hrs

Additional functional tests:

- `feature_ghost_haze_snapshot.py` — UTXO snapshot bootstrap end-to-end
- `feature_ghost_haze_serve.py` — block serving across modes
- `feature_ghost_exorcist.py` — exorcist tool conversion
- `feature_ghost_checkpoint_sync.py` — checkpoint sync protocol

**Files:** `test/functional/feature_ghost_haze_snapshot.py`, `test/functional/feature_ghost_haze_serve.py`, `test/functional/feature_ghost_exorcist.py`, `test/functional/feature_ghost_checkpoint_sync.py`

---

## Implementation Order

All phases completed. Actual execution order with AI assistance:

```
Phase 1: Core Engine          — Tasks 1.1-1.5 (sequential)
Phase 2: Checkpoint & Sync    — Tasks 2.1-2.4 (parallel with Phase 1.3+)
Phase 3: Integration          — Tasks 3.1-3.5 (after Phase 1.4 + 2.2)
Phase 4: Testing              — Tasks 4.1-4.4 (after all implementation)
Phase 5: Bootstrap & Deploy   — Tasks 5.1-5.6 (production hardening)
```

**All 24 tasks complete. Deployed to 4-node signet testnet.**

---

## Execution Notes

### Build System

Ghost Core uses CMake (not autotools):

```bash
# Build ghostd
cd ghost-core && cmake -S . -B build/ && cmake --build build/ --target ghostd -j4

# Run unit tests
cmake --build build/ --target test_ghost && ./build/bin/test_ghost

# Run functional tests
python3 test/functional/feature_ghost_haze.py
python3 test/functional/feature_ghost_exorcism.py
python3 test/functional/feature_ghost_haze_p2p.py
python3 test/functional/feature_ghost_utxo_equiv.py
python3 test/functional/feature_ghost_haze_serve.py
python3 test/functional/feature_ghost_exorcist.py
python3 test/functional/feature_ghost_haze_snapshot.py
python3 test/functional/feature_ghost_checkpoint_sync.py
```

### Code Style

- Follow Bitcoin Core conventions: 4-space indent, CamelCase classes, snake_case locals, `m_` prefix for members
- Use Bitcoin Core's serialization framework (`DataStream`, `SERIALIZE_METHODS` macro)
- Use Bitcoin Core's logging (`LogPrintLevel` with `BCLog::HAZE` category, bit 29)
- Copyright headers matching Bitcoin Core's format on every new file
- Include guards: `BITCOIN_HAZE_FILENAME_H`

### Key Implementation Notes

- **Haze block cache:** `m_haze_block_cache` in ChainstateManager is critical for P2P batch processing. GSB files cannot be deserialized as CBlock — the cache bridges AcceptBlock to ConnectTip.
- **Exorcist on partially-hazed nodes:** If `hazemode=hazed` is set before running the exorcist, blocks already in GSB format are gracefully skipped.
- **SQLite coexistence:** GSP's `sqlite3_open()` can initialize SQLite before wallet code calls `sqlite3_config()`. The wallet tolerates `SQLITE_MISUSE` from config calls.
- **NODE_GHOST_HAZE:** Service bit `(1 << 14)`. NODE_HAZE_CHECKPOINT: `(1 << 13)`.

### Safety Rules

- **NEVER modify consensus validation logic.** Exorcism operates AFTER validation, never during.
- **UTXO equivalence is non-negotiable.** If Task 4.3 fails, everything stops until it's fixed.
- **Mode selection must be bulletproof.** Wrong mode on wrong data = corrupted node.
- **Secure zero must be verified.** Compiler must not optimize away the memory wipe.

---

*END OF TASK BREAKDOWN — ALL PHASES COMPLETE*
