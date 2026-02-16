# Ghost Haze & Exorcism — Implementation Progress

## Branch: `feature/ghost-haze`

## Phase 1: Core Engine

### Task 1.1: Field Classifier — DONE
- [x] `HazeFieldType` enum (WITNESS, SCRIPTSIG, OP_RETURN, COINBASE)
- [x] `HazeableField` struct
- [x] `ClassifyTransaction()` — identifies all hazeable fields per tx
- [x] `ClassifyBlock()` — classifies all txs in a block
- [x] `RequiresStoredTxid()` — true if legacy/P2SH (non-empty scriptSig)
- [x] `IsOpReturn()` — detects OP_RETURN outputs
- [x] `WitnessDataSize()` — computes witness byte count
- **Files:** `src/haze/field_classifier.h`, `src/haze/field_classifier.cpp`

### Task 1.2: Ghost Stripped Block Format — DONE
- [x] `CStrippedInput` — prevout + sequence only (scriptSig always empty)
- [x] `CStrippedOutput` — value + scriptPubKey (OP_RETURN payload replaced)
- [x] `CStrippedTransaction` — flags + optional stored txid + structural data
- [x] `CStrippedBlock` — header + stripped transactions
- [x] `GetTxid()` — computes from structural data or returns stored txid
- [x] `ComputeMerkleRoot()` — from stripped tx txids
- [x] GSB format: magic `0x47534200` + size + data
- [x] `SerializeGSB()` / `DeserializeGSB()` — envelope serialization
- **Files:** `src/haze/stripped_block.h`, `src/haze/stripped_block.cpp`

### Task 1.3: Block Stripper — DONE
- [x] `StripResult` struct with per-category byte statistics
- [x] `StripBlock()` — full block → stripped block conversion
- [x] `StripTransaction()` — single tx stripping
- [x] `VerifyStrippedBlock()` — merkle root verification
- [x] `MakeStrippedOpReturn()` — OP_RETURN + 0x00
- **Files:** `src/haze/block_stripper.h`, `src/haze/block_stripper.cpp`

### Task 1.4: Ghost Exorcism — DONE
- [x] `GhostMode` enum (HAZED, FULL_ARCHIVE)
- [x] `GhostExorcism` class — Init, StripValidatedBlock, SecureZero, stats
- [x] `BlockManager::WriteStrippedBlock()` — GSB file I/O
- [x] `BlockManager::m_gsb_file_seq` — FlatFileSeq with "gsb" prefix
- [x] `BlockManager::OpenGSBFile()` — open gsb?????.dat files
- [x] `validation.cpp` AcceptBlock integration — Mode A/B branching
- **Files:** `src/haze/exorcism.h`, `src/haze/exorcism.cpp`
- **Modified:** `src/node/blockstorage.h`, `src/node/blockstorage.cpp`, `src/validation.cpp`

### Task 1.5: Ghost Exorcist — DONE
- [x] `GhostExorcist` class with `Convert()` and `Resume()` public methods
- [x] `ConversionResult` struct — success, blocks_converted, sizes, error
- [x] `Progress` struct + `ProgressCallback` — real-time progress reporting
- [x] Phase 1 `StripArchive()` — reads blk, strips, writes gsb, updates block index
- [x] Phase 2 `SecureZeroOriginals()` — overwrites blk*.dat with zeros + `FileCommit()`
- [x] Phase 3 `CleanupOriginals()` — deletes blk*.dat and rev*.dat
- [x] Resume marker file (exorcist_resume.dat) — write/read/delete
- [x] GSB file rotation at 128 MiB boundary
- [x] Batch LevelDB flush every 1000 blocks via `WriteBlockIndexDB()`
- [x] `BlockManager` friend access for `m_dirty_blockindex`
- **Files:** `src/haze/exorcist.h`, `src/haze/exorcist.cpp`
- **Modified:** `src/node/blockstorage.h` (friend declaration + forward decl)

## Build System — DONE
- [x] `src/haze/CMakeLists.txt` — bitcoin_haze static library (5 source files)
- [x] `src/CMakeLists.txt` — add_subdirectory(haze), link to bitcoin_node
- [x] `BCLog::HAZE` logging category (bit 29)
- [x] `ghostd` builds cleanly
- [x] `test_ghost` builds cleanly
- [x] Existing tests pass (no regressions)

## Phase 1 COMPLETE

All five Phase 1 tasks are implemented and building cleanly.

## Phase 2: Checkpoint & Sync

### Task 2.1: Checkpoint Data Format — DONE
- [x] `ChunkInfo` struct — per-chunk metadata (index, hash, offset, size, height range)
- [x] `ChunkManifest` struct — chunk_size, total_chunks, vector of ChunkInfo
- [x] `CheckpointManifest` struct — version, height, block_hash, utxo_count, component hashes, signature
- [x] `GetSigningHash()` — SHA-256 of all fields except signature
- [x] `ToJSON()` — UniValue JSON serialization for RPC/debugging
- [x] `GenerateCheckpoint()` — creates headers.bin and manifest from synced node
- [x] `LoadCheckpoint()` — deserialize manifest from disk with version validation
- [x] `ValidateCheckpoint()` — verify headers/bloom/chunk hashes against manifest
- [x] `HashFile()` — SHA-256 of arbitrary file
- [x] `WriteHeadersFile()` — sequential 80-byte block headers (height N at offset N*80)
- [x] `ReadHeader()` — random-access header read by height
- [x] `HashHeadersFile()` — SHA-256 of headers.bin
- [x] `VerifyHeadersChain()` — verify prev_hash chain continuity
- **Files:** `src/haze/checkpoint.h`, `src/haze/checkpoint.cpp`, `src/haze/headers_file.h`, `src/haze/headers_file.cpp`

### Task 2.2: Checkpoint Signing (Ed25519) — DONE
- [x] Vendored ed25519-donna library (~19 files, public domain)
- [x] `bitcoin_crypto_ed25519` static library via CMake
- [x] Custom hash bridge: ed25519_impl.cpp → CSHA512
- [x] Custom random bridge: ed25519_impl.cpp → GetStrongRandBytes
- [x] `SignCheckpoint()` — Ed25519 sign manifest's signing hash
- [x] `VerifyCheckpoint()` — verify against hardcoded trusted keys
- [x] `VerifyCheckpointWithKey()` — verify against specific public key
- [x] `GetTrustedCheckpointKeys()` — hardcoded key list (supports rotation)
- [x] `DerivePublicKey()` — derive Ed25519 pubkey from secret key
- **Files:** `src/crypto/ed25519/` (vendored), `src/crypto/ed25519/CMakeLists.txt`, `src/crypto/ed25519/ed25519_impl.cpp`, `src/haze/checkpoint_signing.h`, `src/haze/checkpoint_signing.cpp`

### Task 2.3: SwiftSync Bloom Filter — DONE
- [x] `SwiftSyncFilter` class — custom large Bloom filter (~300 MB for mainnet)
- [x] Optimal parameter calculation (m bits, k hashes from element count + FPR)
- [x] SipHash with derived keys per hash function for outpoint hashing
- [x] `Insert()` / `MayContain()` — O(k) per operation
- [x] `Save()` / `Load()` — binary format with magic + parameters + bit array
- [x] `GetFalsePositiveRate()` — theoretical FPR computation
- [x] `SwiftSyncController` class — manages ephemeral coin cache during IBD
- [x] `ShouldPersist()` — Bloom filter check for persist-vs-ephemeral decision
- [x] `TrackEphemeral()` / `GetEphemeral()` / `SpendEphemeral()` — ephemeral cache ops
- [x] `Deactivate()` — cleanup at checkpoint height with statistics logging
- [x] `SwiftSyncUpdateCoins()` — Bloom-filter-aware replacement for UpdateCoins
- [x] `SwiftSyncCoinsView` — CCoinsViewBacked subclass for ephemeral coin lookup
- [x] `validation.cpp` ConnectBlock integration — 10-line intercept at UpdateCoins call
- [x] `validation.cpp` deactivation check — 4-line check after block connection
- [x] `validation.h` — `m_swiftsync` unique_ptr on ChainstateManager
- **Files:** `src/haze/bloom_filter.h`, `src/haze/bloom_filter.cpp`, `src/haze/swiftsync.h`, `src/haze/swiftsync.cpp`, `src/haze/swiftsync_view.h`
- **Modified:** `src/validation.h`, `src/validation.cpp`

### Task 2.4: Parallel Chunk Download — DONE
- [x] `ChunkState` struct — per-chunk status tracking (PENDING → REQUESTED → COMPLETE)
- [x] `DownloadStats` struct — progress reporting (chunks, bytes, percent)
- [x] `ChunkDownloader` class — parallel download orchestration
- [x] `Init()` — setup from ChunkManifest with configurable parallelism
- [x] `CheckExistingChunks()` — resume support (verify existing files on disk)
- [x] `RequestChunks()` — assign pending chunks to peers
- [x] `ReceiveChunk()` — validate SHA-256 hash + write to disk
- [x] `HandlePeerDisconnect()` — re-queue assigned chunks
- [x] `CheckTimeouts()` — timeout detection with retry logic (max 3 retries)
- [x] P2P messages: `getchkpt`, `chkpt`, `getchunk`, `chunk` in protocol.h
- [x] `NODE_HAZE_CHECKPOINT` service bit (1 << 13)
- [x] `serviceFlagToStr` updated for new service bit
- **Files:** `src/haze/chunk_downloader.h`, `src/haze/chunk_downloader.cpp`
- **Modified:** `src/protocol.h`, `src/protocol.cpp`

## Build System — Updated
- [x] `src/haze/CMakeLists.txt` — bitcoin_haze now builds 11 source files + links ed25519
- [x] `src/crypto/CMakeLists.txt` — add_subdirectory(ed25519)
- [x] `src/crypto/ed25519/CMakeLists.txt` — bitcoin_crypto_ed25519 static library
- [x] `ghostd` builds cleanly (no errors, no warnings)
- [x] `test_ghost` builds cleanly
- [x] All 710 existing tests pass (no regressions)

## Phase 2 COMPLETE

All four Phase 2 tasks are implemented and building cleanly.

## Phase 3: Integration

### Task 3.1: Mode Selector — DONE
- [x] `DetectOrSelectMode()` — detect from lock file, CLI arg, or interactive prompt
- [x] `ReadModeLock()` / `WriteModeLock()` — persistent mode in `haze_mode.lock` (single byte)
- [x] `ValidateModeConsistency()` — blk*.dat vs gsb*.dat cross-check
- [x] `--hazemode=hazed|full_archive` CLI argument registered in init.cpp
- [x] `--haze-status`, `--legal-packet`, `--exorcist` CLI arguments registered
- [x] `init.cpp` startup integration — mode detection after ChainstateManager creation
- [x] `NODE_GHOST_HAZE` service bit advertised for Hazed nodes
- [x] Interactive mode selection prompt with ASCII UI for first launch
- [x] "Mode A" → "Hazed" terminology updated across all existing code
- **Files:** `src/haze/mode_selector.h`, `src/haze/mode_selector.cpp`
- **Modified:** `src/init.cpp`, `src/haze/exorcism.h`, `src/node/blockstorage.h`, `src/validation.cpp`

### Task 3.3: RPC Compatibility Layer — DONE
- [x] `BlockManager::ReadStrippedBlock()` — read GSB files (by FlatFilePos and CBlockIndex)
- [x] `BlockManager::IsHazeMode()` — convenience accessor
- [x] `ReconstructPartialBlock()` — CStrippedBlock → partial CBlock for RPC
- [x] `ReconstructPartialBlockWithMeta()` — with metadata about what was stripped
- [x] `getblock` RPC modified — Hazed: reads GSB, reconstructs, adds `haze_status`
- [x] `getrawtransaction` RPC modified — Hazed: adds `haze_status` to output
- [x] `TxToUniv()` modified — `is_hazed` flag adds `"stripped": true` indicators
- [x] `blockToJSON()` modified — `is_hazed` flag adds block-level `haze_status`
- [x] Coinbase `"coinbase_stripped": true`, scriptSig `"stripped": true`
- [x] Witness `"txinwitness": "stripped"`, OP_RETURN `"stripped": true`
- **Files:** `src/haze/block_reconstruct.h`, `src/haze/block_reconstruct.cpp`
- **Modified:** `src/node/blockstorage.h`, `src/node/blockstorage.cpp`, `src/rpc/blockchain.h`, `src/rpc/blockchain.cpp`, `src/rpc/rawtransaction.cpp`, `src/core_io.h`, `src/core_write.cpp`

### Task 3.5: Legal Compliance Packet — DONE
- [x] `LegalPacket` struct — all fields from spec (version, mode, stats, legal summary)
- [x] `LegalPacket::ToJSON()` — UniValue serialization
- [x] `GenerateLegalPacket()` — gathers node state, scans datadir, returns packet
- [x] Court-ready legal summary text covering all stripped content types
- [x] Hazeable content detection (scans for blk*.dat files)
- [x] Conversion method detection (exorcism vs exorcist)
- [x] Returns `std::nullopt` for Full Archive nodes
- **Files:** `src/haze/legal_packet.h`, `src/haze/legal_packet.cpp`

### Task 3.2: CLI/RPC Interface — DONE
- [x] `gethazestatus` RPC — mode, exorcism state, blocks stripped, storage GB
- [x] `getlegalpacket` RPC — generates and returns legal compliance packet JSON
- [x] `getcheckpointstatus` RPC — checkpoint height and state
- [x] `RegisterHazeRPCCommands()` — registered in `RegisterAllCoreRPCCommands()`
- [x] Category: "haze" for all haze RPC commands
- **Files:** `src/rpc/haze.h`, `src/rpc/haze.cpp`
- **Modified:** `src/rpc/register.h`

### Task 3.4: P2P Messages — DONE
- [x] `NODE_GHOST_HAZE` service bit (1 << 14) — Hazed nodes advertise this
- [x] `GHOST_STRIPPED_BLOCK` ("gstripblk") message type — stripped block transfer
- [x] `GHOST_REDIRECT` ("gredirect") message type — redirect to Full Archive peers
- [x] `GhostRedirect` struct — block_hash + list of archive peer addresses (as strings)
- [x] `ProcessGetBlockData()` modified — Hazed nodes serve stripped blocks or redirects
- [x] `GHOST_STRIPPED_BLOCK` handler — deserialize, verify merkle root, log receipt
- [x] `GHOST_REDIRECT` handler — deserialize, log receipt
- [x] `serviceFlagToStr` updated for `NODE_GHOST_HAZE`
- [x] `ALL_NET_MESSAGE_TYPES` updated with new message types
- **Files:** `src/haze/haze_p2p.h`, `src/haze/haze_p2p.cpp`
- **Modified:** `src/protocol.h`, `src/protocol.cpp`, `src/net_processing.cpp`

## Build System — Updated
- [x] `src/haze/CMakeLists.txt` — 15 source files (Phase 1: 5, Phase 2: 6, Phase 3: 4)
- [x] `src/CMakeLists.txt` — `rpc/haze.cpp` added to bitcoin_node sources
- [x] `ghostd` builds cleanly (no errors)
- [x] `test_ghost` builds cleanly
- [x] Existing tests pass (block_tests, serialize_tests, net_tests, rpc_tests, blockchain_tests)

## Phase 3 COMPLETE

All five Phase 3 tasks are implemented and building cleanly.

## Phase 4: Testing

### Task 4.1: Unit Tests — DONE
- [x] `haze_tests.cpp` — 19 test cases covering:
  - Field Classifier: classify_segwit_transaction, classify_legacy_transaction, classify_coinbase, classify_opreturn, classify_block, witness_data_size
  - Stripped Block Format: gsb_serialize_deserialize_roundtrip, gsb_magic_bytes, gsb_invalid_magic_rejected, stripped_block_merkle_root, stripped_tx_stored_txid, stripped_opreturn_minimal
  - Block Stripper: strip_block_preserves_merkle, strip_block_removes_witness, strip_block_statistics, strip_coinbase_only_block
  - Block Reconstruct: reconstruct_partial_block, reconstruct_preserves_outputs, reconstruct_meta_flags
- [x] `haze_sync_tests.cpp` — 14 test cases covering:
  - Ed25519: ed25519_sign_verify, ed25519_wrong_key_fails, ed25519_tampered_data_fails, ed25519_derive_public_key
  - Bloom Filter: bloom_filter_insert_query, bloom_filter_absent_items, bloom_filter_false_positive_rate, bloom_filter_save_load_roundtrip, bloom_filter_parameters
  - Chunk Downloader: chunk_downloader_init, chunk_downloader_request_receive, chunk_downloader_invalid_hash_rejected, chunk_downloader_peer_disconnect, chunk_downloader_completion
- [x] `haze_integration_tests.cpp` — 10 test cases covering:
  - Mode Selector: mode_lock_write_read_roundtrip, mode_lock_missing_returns_nullopt, mode_consistency_hazed_with_blk_files, mode_consistency_archive_with_gsb_files, mode_consistency_clean_dir
  - Exorcism: exorcism_init_hazed, exorcism_init_archive, exorcism_statistics
  - P2P Messages: ghost_redirect_serialize_deserialize, ghost_redirect_empty_peers
- [x] All 43 test cases pass (no errors)
- [x] `src/test/CMakeLists.txt` updated with 3 new test files
- **Files:** `src/test/haze_tests.cpp`, `src/test/haze_sync_tests.cpp`, `src/test/haze_integration_tests.cpp`

### Task 4.2: Functional Tests — DONE
- [x] `feature_ghost_haze.py` — Haze mode basic functionality (2-node regtest)
  - Mine 110 blocks, create P2WPKH + OP_RETURN transactions
  - Verify gethazestatus RPC on both modes
  - Verify getblock haze_status presence/absence
  - Verify getlegalpacket works in hazed, errors in full_archive
  - Grep datadir for payload — must NOT be found
- [x] `feature_ghost_exorcism.py` — Archive-to-Hazed conversion
  - Mine with OP_RETURN payloads in full_archive mode
  - Convert with --exorcist flag
  - Verify gsb*.dat created, blk*.dat removed
  - Verify getblock still works post-conversion
  - Verify hazeable content not present on disk
  - Mine new blocks in hazed mode
- **Files:** `test/functional/feature_ghost_haze.py`, `test/functional/feature_ghost_exorcism.py`

### Task 4.3: UTXO Equivalence Tests — DONE
- [x] `feature_ghost_utxo_equiv.py` — THE CRITICAL TEST
  - 2 nodes: hazed + full_archive, connected and syncing
  - Diverse tx types: P2WPKH, P2TR, OP_RETURN, multi-input, coinbase spends
  - 200+ block chain
  - Compares hash_serialized_3 — MUST be identical
  - Compares txouts count and total_amount
  - Spot-checks 20 random UTXOs via gettxout
- **Files:** `test/functional/feature_ghost_utxo_equiv.py`

### Task 4.4: Cross-Mode P2P Tests — DONE
- [x] `feature_ghost_haze_p2p.py` — Multi-node P2P interoperability
  - 3 nodes: hazed, hazed, full_archive
  - Hazed ↔ Hazed block propagation
  - Full Archive ↔ Hazed block propagation (both directions)
  - NODE_GHOST_HAZE service flag verification
  - Chain sync consistency + UTXO equivalence across all 3 nodes
- **Files:** `test/functional/feature_ghost_haze_p2p.py`

## Phase 4 COMPLETE

All four Phase 4 tasks are implemented. 43 C++ unit tests pass. 4 Python functional test scripts ready.

## Phase 5: Hazed Node Bootstrap (UTXO Snapshot)

### Task 5.1: Disable Background IBD for Hazed Nodes — DONE
- [x] `ActivateSnapshot()` — disable IBD chainstate immediately after snapshot activation
- [x] `MaybeCompleteSnapshotValidation()` — auto-validate on restart (skip UTXO hash verification)
- [x] Hazed check moved before IBD height check so it fires even when IBD tip is at genesis
- **Modified:** `src/validation.cpp`

### Task 5.2: Prevent NODE_NETWORK Re-enable — DONE
- [x] `snapshot_download_completed` callback — skip NODE_NETWORK for hazed nodes
- [x] Hazed nodes can't serve full blocks, must stay NODE_NETWORK_LIMITED
- **Modified:** `src/init.cpp`

### Task 5.3: CLI Snapshot Loading — DONE
- [x] `-loadtxoutset=<path>` argument registered with other haze args
- [x] Handler loads snapshot, prints summary, exits cleanly
- [x] Enables offline snapshot loading without RPC
- [x] `#include <node/utxo_snapshot.h>` added
- **Modified:** `src/init.cpp`

### Task 5.4: RPC Hazed Logging — DONE
- [x] `loadtxoutset` RPC logs hazed-mode status after snapshot activation
- **Modified:** `src/rpc/blockchain.cpp`

### Task 5.5: Regtest AssumeutxoData Entry — DONE
- [x] Height 160 entry for functional test's deterministic chain (mocktime-based)
- [x] `feature_assumeutxo.py` updated for new available heights list
- **Modified:** `src/kernel/chainparams.cpp`, `test/functional/feature_assumeutxo.py`

### Task 5.6: Functional Test — DONE
- [x] `feature_ghost_haze_snapshot.py` — end-to-end snapshot bootstrap test
  - Mine deterministic chain (mocktime) on full_archive node to height 160
  - Dump UTXO snapshot, sync headers to hazed node
  - Load snapshot via loadtxoutset RPC
  - Verify UTXO set equivalence at snapshot height
  - Verify single chainstate (no background IBD)
  - Mine 10 new blocks, sync, verify final UTXO equivalence
  - Verify GSB files exist for new blocks (stripped storage)
  - Restart node, verify chain persists and UTXO still matches
- **Files:** `test/functional/feature_ghost_haze_snapshot.py`

## Phase 5 COMPLETE

All six Phase 5 tasks are implemented. Enables hazed→hazed networks with no full_archive peer required.

## All Phases Complete (1-5)

## Phase 6: Production Deployment & Bug Fixes

### SQLite Initialization Order Fix — DONE
- [x] GSP's `WalletRegistry::Initialize()` calls `sqlite3_open()` before wallet code calls `sqlite3_config()`
- [x] `wallet/sqlite.cpp` — tolerate `SQLITE_MISUSE` from `sqlite3_config()` when GSP initialized first
- [x] Fix: both `SQLITE_CONFIG_LOG` and `SQLITE_CONFIG_SERIALIZED` calls accept `SQLITE_MISUSE`
- **Modified:** `src/wallet/sqlite.cpp`

### Haze Block Cache (P2P Batch Processing Fix) — DONE
- [x] `ActivateBestChain` batch-connects multiple blocks but only passes `pblock` for the tip
- [x] Intermediate blocks must be read from disk — fails on GSB files (wrong magic bytes)
- [x] Fix: `m_haze_block_cache` in ChainstateManager caches full blocks between AcceptBlock and ConnectTip
- [x] AcceptBlock populates cache when in haze mode
- [x] ConnectTip checks cache before falling back to disk read, evicts after connection
- **Modified:** `src/validation.h`, `src/validation.cpp`

### Exorcist Partial-Hazed Node Support — DONE
- [x] Exorcist previously bailed with "already HAZED" if `haze_mode.lock` indicated hazed mode
- [x] Fix: checks for blk*.dat files with non-zero data before bailing (handles hazemode set before exorcist)
- [x] StripArchive gracefully skips blocks already in GSB format (ReadBlock failure → skip, not abort)
- [x] Logs count of skipped blocks for transparency
- **Modified:** `src/init.cpp`, `src/haze/exorcist.cpp`

### Production Deployment — DONE
- [x] Ghost Core (ghostd) deployed to 4 signet VMs (ghost-vm1 through ghost-vm4)
- [x] VM1-3: full_archive mode, VM4: hazed mode
- [x] Exorcist conversion successful on VM4: 29,321 blocks converted (9.21 MB → 6.77 MB, 26.5% reduction)
- [x] 4 blocks in GSB format correctly skipped during conversion
- [x] blk*.dat securely zeroed and deleted on VM4
- [x] VM4 in sync with full_archive peers, stripping new blocks as they arrive
- [x] Verified stripped blocks contain no witness data, scriptSig, OP_RETURN payloads, or coinbase messages
- [x] All 4 VMs at same chain tip with 6 peer connections each

### Test Results — ALL PASS
- [x] 43 C++ unit tests pass (`test_ghost`)
- [x] 8 Python functional tests pass:
  1. `feature_ghost_haze.py` — basic haze mode functionality
  2. `feature_ghost_exorcism.py` — archive-to-hazed conversion
  3. `feature_ghost_haze_p2p.py` — cross-mode P2P interoperability
  4. `feature_ghost_utxo_equiv.py` — UTXO equivalence (THE critical test)
  5. `feature_ghost_haze_serve.py` — block serving
  6. `feature_ghost_exorcist.py` — exorcist tool
  7. `feature_ghost_haze_snapshot.py` — UTXO snapshot bootstrap
  8. `feature_ghost_checkpoint_sync.py` — checkpoint sync

## Implementation Status: COMPLETE AND DEPLOYED
