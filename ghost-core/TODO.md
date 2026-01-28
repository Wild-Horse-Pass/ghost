# Ghost-Core TODO

Bitcoin Core fork enhancements for Ghost Pay L1 integration.

Last updated: 2026-01-03

---

## 1. Silent Payment (BIP-352) Implementation

**Priority:** HIGH - Blocks wallet recovery and L1 scanning

**Status:** Core infrastructure COMPLETE, wallet integration pending

### What It Enables
- Wallet recovery from seed (scanning blockchain for Ghost Lock UTXOs)
- Post-reconciliation detection (finding new Ghost Locks after L1 settlement)
- Privacy-preserving address derivation (receivers never reuse addresses)

### Completed Tasks

#### 1.1 Silent Payment Address Type ✅
**Files:** `src/addresstype.h`, `src/outputtype.h`, `src/key_io.cpp`

- [x] Add `SilentPaymentDestination` struct with scan/spend pubkeys
- [x] Add `OutputType::SILENT_PAYMENT` variant
- [x] Implement `ghost1...` bech32m encoding (66-byte payload)
- [x] Add address parsing/validation

#### 1.2 ECDH Derivation ✅
**Files:** `src/silentpayments.h`, `src/silentpayments.cpp`

- [x] Implement `ComputeSharedSecret(scan_privkey, sender_pubkey)`
- [x] Implement `ComputeTweak(shared_secret, index, nonce)`
- [x] Implement `DeriveOutputPubKey(spend_pubkey, tweak)`
- [x] Implement `DeriveSpendKey(spend_secret, tweak)`
- [x] Implement `CreatePayment()` for senders
- [x] Implement `ScanOutput()` for receivers
- [x] Enable secp256k1 ECDH module in cmake

#### 1.3 Ghost Lock OP_RETURN Format ✅
**Files:** `src/silentpayments.h`, `src/silentpayments.cpp`

```
OP_RETURN Format for Ghost Lock Transactions:
┌─────────────────────────────────────────────────────────┐
│ GHOST_MARKER (4 bytes) │ Ephemeral Pubkey (33 bytes)   │
│ 0x47484F53 ("GHOS")    │ Compressed secp256k1 point    │
├─────────────────────────────────────────────────────────┤
│ Optional: extra metadata (variable)                     │
└─────────────────────────────────────────────────────────┘
```

- [x] Define `GHOST_MARKER` constant (`0x47484F53` = "GHOS")
- [x] Implement `CreateGhostOpReturn(ephemeral_pubkey, extra_data)`
- [x] Implement `ParseGhostOpReturn(data)` - extract ephemeral pubkey
- [x] Implement `IsGhostOpReturn(data)` - marker detection

#### 1.4 RPC Commands ✅
**Files:** `src/wallet/rpc/silentpayments.cpp`, `src/wallet/rpc/wallet.cpp`

| RPC Method | Status | Description |
|------------|--------|-------------|
| `getsilentpaymentaddress` | ✅ | Get wallet's Ghost ID (SP address) |
| `derivesilentpaymentaddress` | ✅ | Derive one-time P2TR address from Ghost ID |
| `checksilentpayment` | ✅ | Check if output belongs to wallet |
| `parseghostopreturn` | ✅ | Parse Ghost Lock OP_RETURN data |

#### 1.5 SilentPaymentScriptPubKeyMan ✅
**Files:** `src/wallet/silentpayment_spkm.h`, `src/wallet/silentpayment_spkm.cpp`

- [x] Key pair management (scan_secret, spend_secret)
- [x] Ghost ID generation
- [x] Transaction scanning (`ScanTransaction()`)
- [x] Tweak storage for detected outputs
- [x] Spending key derivation (`DeriveSpendingKey()`)
- [x] Encryption support

### Completed Tasks (New)

#### 1.6 Database Persistence ✅
**Files:** `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`

- [x] Add `DBKeys::SILENTPAYMENT_KEYS` constant
- [x] Add `DBKeys::SILENTPAYMENT_OUTPUT` constant
- [x] Add `SilentPaymentKeyData` and `SilentPaymentOutputData` serializable structs
- [x] Implement `WriteSilentPaymentKeys()`
- [x] Implement `WriteSilentPaymentOutput()`
- [x] Implement `EraseSilentPaymentOutput()`
- [x] Add `LoadSilentPaymentRecords()` in `LoadWallet()`

#### 1.7 Wallet Integration ✅
**Files:** `src/wallet/wallet.h`, `src/wallet/wallet.cpp`

- [x] Add `m_sp_spkm` member for SilentPaymentScriptPubKeyMan
- [x] Add `GetSilentPaymentScriptPubKeyMan()` method
- [x] Add `SetupSilentPaymentScriptPubKeyMan()` method
- [x] Add `LoadSilentPaymentKeys()` and `LoadSilentPaymentOutput()` methods
- [x] Auto-create SP SPKM on wallet creation (in `SetupOwnDescriptorScriptPubKeyMans`)
- [x] Load SP SPKM on wallet load (via `LoadSilentPaymentRecords`)
- [x] Hook SP scanning into `AddToWalletIfInvolvingMe()`
- [x] Add SP outputs to `IsMine()` checks

#### 1.8 Block Scanning ✅
**Files:** `src/wallet/wallet.cpp`

- [x] Integrated SP scanning into `AddToWalletIfInvolvingMe()` for real-time detection
- [x] Works with existing wallet rescan (ScanForWalletTransactions calls AddToWalletIfInvolvingMe)

### Completed Enhancements

#### 1.9 Batch Scanning & Rescan ✅
**Files:** `src/wallet/silentpayment_spkm.cpp`, `src/wallet/wallet.cpp`, `src/wallet/rpc/silentpayments.cpp`

- [x] Add `ScanBlockForSilentPayments()` method for dedicated batch scanning
- [x] Add progress reporting for long SP scans (via ShowProgress and m_scanning_progress)
- [x] Add `RescanForSilentPayments()` wallet method
- [x] Add `rescansilentpayments` RPC command (start_height, stop_height)
- [x] Add `getsilentpaymentstats` RPC command (outputs, amounts, block range)

---

## 2. Ghost Lock Script Templates

**Priority:** MEDIUM

**Status:** COMPLETE

### What It Enables
- Standardized Ghost Lock output scripts
- Proper denomination encoding
- Timelocked recovery paths

### Completed Tasks

#### 2.1 Ghost Lock Script Structure ✅
**Files:** `src/ghostlock.h`, `src/ghostlock.cpp`

```
Ghost Lock Output (P2TR):
- Internal key: lock_pubkey (derived via SP)
- Taproot tree:
  - Leaf 0: <lock_pubkey> OP_CHECKSIG (normal spend)
  - Leaf 1: <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP <recovery_pubkey> OP_CHECKSIG (recovery)
```

- [x] Define `IsGhostLockScript()` detection
- [x] Add script template builder (`BuildGhostLockScript()`, `GhostLockScript` struct)
- [x] Implement denomination validation (`IsValidDenomination()`, `Denomination` enum)
- [x] Add recovery timelock validation (`IsValidRecoveryTimelock()`)
- [x] Add P2TR key extraction (`ExtractP2TRKey()`)
- [x] Add control block builder (`BuildControlBlock()`)

---

## 3. Wraith Protocol L1 Support

**Priority:** MEDIUM

**Status:** COMPLETE

### What It Enables
- Two-phase mixing transaction creation
- Proper input/output shuffling
- Coordinator transaction building

### Completed Tasks

#### 3.1 RPC Commands ✅
**Files:** `src/wallet/rpc/wraith.cpp`

| RPC Method | Status | Description |
|------------|--------|-------------|
| `createwraithtx` | ✅ | Create Phase 1 (Split) transaction |
| `createwraithfinaltx` | ✅ | Create Phase 2 (Merge) transaction |
| `parsewraithtx` | ✅ | Parse Wraith transaction metadata |
| `shuffleoutputs` | ✅ | Shuffle transaction outputs |

- [x] Add `createwraithtx` RPC for Phase 1 transaction
- [x] Add `createwraithfinaltx` RPC for Phase 2 transaction
- [x] Implement CoinJoin-style input aggregation
- [x] Add shuffle utilities for output ordering

---

## 4. Reconciliation Batch Support

**Priority:** MEDIUM

**Status:** COMPLETE (including enhancements)

### What It Enables
- Efficient batch settlement transactions
- Multiple Ghost Lock outputs per transaction
- Fee optimization for batch operations

### Completed Tasks

#### 4.1 RPC Commands ✅
**Files:** `src/wallet/rpc/wraith.cpp`

| RPC Method | Status | Description |
|------------|--------|-------------|
| `createreconciliationtx` | ✅ | Create reconciliation batch transaction |

- [x] Add `createreconciliationtx` RPC
- [x] Support multiple output creation with ephemeral pubkeys
- [x] Include epoch ID and state root in OP_RETURN
- [x] Support treasury fee output

#### 4.2 Reconciliation Enhancements ✅
**Files:** `src/wallet/rpc/wraith.cpp`

| RPC Method | Status | Description |
|------------|--------|-------------|
| `coordinatebatchsigning` | ✅ | Create PSBT for batch signing coordination |
| `combinebatchpsbt` | ✅ | Combine multiple PSBTs from participants |
| `estimatebatchfee` | ✅ | Estimate fee for batch reconciliation transactions |
| `derivereconciliationoutputs` | ✅ | Derive P2TR addresses from Ghost IDs via Silent Payments |

- [x] Add batch signing coordination RPC
- [x] Implement fee estimation for batches
- [x] Add SP address derivation within RPC

---

## 5. Testing Infrastructure

**Priority:** LOW (after implementation)

**Status:** COMPLETE

### Completed Tasks

#### 5.1 Silent Payment Unit Tests ✅
**Files:** `src/test/silentpayments_tests.cpp`

- [x] Ghost ID address encoding/decoding (ghost1...)
- [x] ECDH shared secret computation
- [x] Tweak computation
- [x] Output pubkey derivation
- [x] Spend key derivation
- [x] Full payment creation and scanning flow
- [x] Ghost OP_RETURN creation/parsing
- [x] Invalid OP_RETURN detection

#### 5.2 Ghost Lock Unit Tests ✅
**Files:** `src/test/silentpayments_tests.cpp`

- [x] Denomination value lookups
- [x] Denomination from value/name conversion
- [x] Recovery timelock validation
- [x] Ghost Lock script building
- [x] P2TR output key extraction
- [x] Taproot merkle root computation

#### 5.3 Functional Tests ✅
**Files:** `test/functional/wallet_silentpayments.py`, `test/functional/wallet_ghostlock.py`, `test/functional/wallet_sp_scanning.py`

- [x] Ghost ID generation and encoding tests
- [x] SP address derivation tests
- [x] Cross-wallet payment detection tests
- [x] Wraith tx creation tests (Phase 1 & 2)
- [x] Reconciliation tx creation tests
- [x] Output shuffling tests
- [x] Batch fee estimation tests
- [x] Reconciliation output derivation tests
- [x] SP rescan tests with Ghost Lock UTXOs

#### 5.4 Performance Benchmark ✅
**Files:** `test/functional/bench_sp_scanning.py`

- [x] Ghost ID generation benchmark
- [x] Address derivation throughput
- [x] OP_RETURN parsing speed
- [x] Check silent payment performance
- [x] Block rescan benchmark

---

## Integration Points with Ghost-Pay

| Ghost-Pay Component | Ghost-Core Requirement | Status |
|---------------------|------------------------|--------|
| `ghost-wallet` Ghost ID | `getsilentpaymentaddress` RPC | ✅ |
| `ghost-wallet` send | `derivesilentpaymentaddress` RPC | ✅ |
| `ghost-wallet` check | `checksilentpayment` RPC | ✅ |
| `ghost-wallet` wallet recovery | Wallet SP scanning | ✅ |
| `BatchScanner` in ghost-keys | RPC for ephemeral pubkey access | ✅ |
| Wraith executor | `createwraithtx` / `createwraithfinaltx` | ✅ |
| Reconciliation manager | `createreconciliationtx` RPC | ✅ |
| L1 chain monitor | Block notification with SP data | ✅ |

### Ghost-Pay Integration Files

| File | Changes |
|------|---------|
| `ghost-rpc/src/client.rs` | Added SP, Wraith, and Reconciliation RPC methods |
| `ghost-rpc/src/types.rs` | Added types for SP, Wraith, and Reconciliation responses |
| `ghost-pay-node/src/l1/chain_monitor.rs` | Added SP scanning and GhostLockDetected events |
| `ghost-pay-node/src/main.rs` | Handle GhostLockDetected events |

---

## File Summary

| New File | Purpose | Status |
|----------|---------|--------|
| `src/silentpayments.h` | SP core types and functions | ✅ |
| `src/silentpayments.cpp` | SP implementation | ✅ |
| `src/wallet/silentpayment_spkm.h` | SP key manager header | ✅ |
| `src/wallet/silentpayment_spkm.cpp` | SP key manager implementation | ✅ |
| `src/wallet/rpc/silentpayments.cpp` | SP RPC methods | ✅ |
| `src/ghostlock.h` | Ghost Lock script templates | ✅ |
| `src/ghostlock.cpp` | Ghost Lock implementation | ✅ |
| `src/wallet/rpc/wraith.cpp` | Wraith Protocol RPCs | ✅ |
| `src/test/silentpayments_tests.cpp` | SP and Ghost Lock unit tests | ✅ |
| `test/functional/wallet_silentpayments.py` | SP functional tests | ✅ |
| `test/functional/wallet_ghostlock.py` | Ghost Lock/Wraith functional tests | ✅ |
| `test/functional/wallet_sp_scanning.py` | SP scanning functional tests | ✅ |
| `test/functional/bench_sp_scanning.py` | SP scanning performance benchmark | ✅ |

| Modified File | Changes | Status |
|---------------|---------|--------|
| `src/addresstype.h` | Add SP address type | ✅ |
| `src/addresstype.cpp` | Add visitor handlers | ✅ |
| `src/outputtype.h` | Add SP output type | ✅ |
| `src/outputtype.cpp` | Add SP handling | ✅ |
| `src/key_io.cpp` | SP address encoding, Ghost ID decoding | ✅ |
| `src/bech32.h` | Add SILENT_PAYMENT CharLimit for longer addresses | ✅ |
| `src/rpc/util.cpp` | Add visitor handler | ✅ |
| `src/wallet/rpc/addresses.cpp` | Add visitor handler | ✅ |
| `src/wallet/rpc/wallet.cpp` | Register SP and Wraith RPC commands | ✅ |
| `src/wallet/CMakeLists.txt` | Add new source files (SP, wraith) | ✅ |
| `src/CMakeLists.txt` | Add silentpayments.cpp, ghostlock.cpp | ✅ |
| `cmake/secp256k1.cmake` | Enable ECDH module | ✅ |
| `src/test/transaction_tests.cpp` | Update variant count | ✅ |
| `src/test/CMakeLists.txt` | Add silentpayments_tests.cpp | ✅ |
| `src/wallet/wallet.h` | SP SPKM member and methods | ✅ |
| `src/wallet/wallet.cpp` | SP scanning integration, IsMine, wallet hooks | ✅ |
| `src/wallet/walletdb.h` | SP serialization structs and methods | ✅ |
| `src/wallet/walletdb.cpp` | SP database persistence and loading | ✅ |

---

## References

- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- Ghost Pay Spec: `ghost-pay/GHOST_Pay_Spec.md`
