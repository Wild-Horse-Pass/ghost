# Ghost-Core Integration Guide

## Overview

Bitcoin Ghost v1.4 requires `ghost-core` - a comprehensive Bitcoin Core v30.1 fork with Ghost Pay L1 integration. This document describes how the Rust codebase integrates with ghost-core.

## Directory Structure

```
bitcoin-ghost-v1.4/
├── ghost-core/           # Bitcoin Core v30.1 fork (C++)
│   ├── src/
│   │   ├── silentpayments.h/cpp    # BIP-352 Silent Payments
│   │   ├── ghostlock.h/cpp         # Ghost Lock P2TR scripts
│   │   ├── wallet/
│   │   │   ├── silentpayment_spkm.h/cpp  # SP key manager
│   │   │   └── rpc/
│   │   │       ├── silentpayments.cpp    # SP RPC commands
│   │   │       └── wraith.cpp            # Wraith & Reconciliation RPCs
│   │   └── qt/ghost*.cpp/h         # Ghost-branded Qt GUI
│   └── ...
├── crates/               # Rust library crates
│   └── ghost-common/
│       └── src/rpc.rs    # RPC client with ghost-core methods
└── bins/                 # Rust binaries
```

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Rust Applications                        │
│  (ghost-pool, ghost-pay, ghost-coordinator, translator)     │
└─────────────────────────┬───────────────────────────────────┘
                          │ JSON-RPC
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  ghost-common::BitcoinRpc                    │
│                                                              │
│  Standard Bitcoin Core RPCs:                                 │
│    - getblockchaininfo, getblock, sendrawtransaction, etc.  │
│                                                              │
│  Ghost-Core Specific RPCs:                                   │
│    - getsilentpaymentaddress, derivesilentpaymentaddress    │
│    - createwraithtx, createwraithfinaltx                    │
│    - createreconciliationtx, coordinatebatchsigning         │
└─────────────────────────┬───────────────────────────────────┘
                          │ JSON-RPC over HTTP
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      ghost-core                              │
│              (Bitcoin Core v30.1 + Ghost)                    │
│                                                              │
│  - Silent Payment wallet (SPKM)                              │
│  - Ghost Lock script building & spending                     │
│  - Wraith transaction construction                           │
│  - Reconciliation batch coordination                         │
│  - L1 blockchain & mempool                                   │
└─────────────────────────────────────────────────────────────┘
```

## Ghost-Core RPC Commands

### Silent Payments (Ghost Keys)

| RPC Command | Purpose | Used By |
|-------------|---------|---------|
| `getsilentpaymentaddress` | Get wallet's Ghost ID | ghost-pay wallet setup |
| `derivesilentpaymentaddress` | Derive one-time P2TR address | Sending to Ghost IDs |
| `checksilentpayment` | Check if output belongs to wallet | Payment detection |
| `parseghostopreturn` | Extract ephemeral pubkey from OP_RETURN | Scanning transactions |
| `rescansilentpayments` | Scan blockchain for SP outputs | Wallet recovery |
| `getsilentpaymentstats` | Get SP wallet statistics | Status reporting |

### Wraith Protocol

| RPC Command | Purpose | Used By |
|-------------|---------|---------|
| `createwraithtx` | Build Phase 1 (Split) transaction | wraith-protocol coordinator |
| `createwraithfinaltx` | Build Phase 2 (Merge) transaction | wraith-protocol coordinator |
| `parsewraithtx` | Parse Wraith OP_RETURN metadata | Transaction validation |
| `shuffleoutputs` | Deterministic output shuffling | Privacy enhancement |

### Reconciliation

| RPC Command | Purpose | Used By |
|-------------|---------|---------|
| `createreconciliationtx` | Build L1 settlement batch | ghost-reconciliation |
| `coordinatebatchsigning` | Create PSBT for multi-party signing | Batch coordination |
| `combinebatchpsbt` | Combine participant PSBTs | Batch finalization |
| `estimatebatchfee` | Estimate batch transaction fee | Fee planning |
| `derivereconciliationoutputs` | Derive output addresses from Ghost IDs | Batch building |

## Why Ghost-Core is Required

The Rust crates provide business logic, but ghost-core provides:

1. **Wallet Functionality**: Private key management, signing, balance tracking
2. **Silent Payment SPKM**: Key derivation, scanning, tweak storage
3. **Transaction Signing**: Only ghost-core wallet can sign transactions
4. **Block Template Access**: IPC interface for mining pools
5. **Blockchain Data**: Full node with historical block access

### What Rust Crates Handle

| Crate | Responsibility |
|-------|---------------|
| `ghost-keys` | Ghost ID encoding/decoding, address validation, client-side scanning |
| `ghost-locks` | Lock structure validation, denomination logic, P2TR script building |
| `wraith-protocol` | Session management, coordinator logic, phase state |
| `ghost-reconciliation` | Batch management, settlement rules, L1 monitoring |
| `ghost-common` | RPC client with ghost-core methods |

### What Ghost-Core Handles

| Component | Responsibility |
|-----------|---------------|
| Wallet SPKM | Actual key storage, signing, scanning |
| RPC Server | Transaction building with signatures |
| P2P Network | Block/tx propagation, mempool |
| Consensus | Block validation, chain state |

## RPC Modules in Rust Crates

The Rust crates include RPC modules that delegate transaction building to ghost-core:

### wraith-protocol/src/rpc.rs

```rust
use wraith_protocol::rpc::WraithRpcBuilder;

let rpc_builder = WraithRpcBuilder::new(rpc, session_id, denomination);

// Build Phase 1 (Split) via ghost-core
let result = rpc_builder.build_split_transaction(&inputs, &addresses).await?;
// result.hex is signed if wallet has keys

// Build Phase 2 (Merge) via ghost-core
let result = rpc_builder.build_merge_transaction(&intermediates, &finals).await?;

// Broadcast
let txid = rpc_builder.broadcast_transaction(&result.hex).await?;
```

### ghost-reconciliation/src/rpc.rs

```rust
use ghost_reconciliation::rpc::ReconciliationRpcBuilder;

let rpc_builder = ReconciliationRpcBuilder::new(rpc);

// Build reconciliation transaction via ghost-core
let result = rpc_builder.build_reconciliation_tx(
    &inputs,
    &outputs,
    epoch_id,
    &state_root,
    Some(&treasury_address),
    Some(treasury_amount),
).await?;

// Create PSBT for multi-party signing
let psbt = rpc_builder.create_batch_psbt(&inputs, &outputs).await?;

// Combine signed PSBTs
let combined = rpc_builder.combine_psbts(vec![psbt1, psbt2]).await?;
```

### Architecture: Pure Rust vs RPC

Each crate provides two approaches:

1. **Pure Rust** (executor.rs, transaction.rs): Build unsigned transactions locally
   - Good for: Testing, validation, understanding transaction structure
   - Limitation: Cannot sign without wallet access

2. **RPC-backed** (rpc.rs): Delegate to ghost-core
   - Good for: Production use with real transactions
   - Benefit: Signed transactions via wallet integration

```
┌──────────────────────────────────────────────────────────────┐
│                    Rust Application                          │
├──────────────────────────────────────────────────────────────┤
│  Option A: Pure Rust              Option B: RPC-backed       │
│  ┌────────────────────┐          ┌────────────────────┐     │
│  │ WraithTransaction  │          │ WraithRpcBuilder   │     │
│  │ Builder            │          │                    │     │
│  │ - Unsigned tx      │          │ - Signed tx        │     │
│  │ - For testing      │          │ - For production   │     │
│  └────────────────────┘          └─────────┬──────────┘     │
│                                            │ RPC            │
└────────────────────────────────────────────┼────────────────┘
                                             ▼
                                   ┌──────────────────┐
                                   │    ghost-core    │
                                   │  (wallet, sigs)  │
                                   └──────────────────┘
```

## Building Ghost-Core

```bash
cd ghost-core

# Build
cmake -B build
cmake --build build -j$(nproc)

# Run (binary is in build/bin/, not build/src/)
./build/bin/ghostd -daemon -server \
  -rpcuser=ghost -rpcpassword=yourpassword \
  -rpcport=38332
```

## Configuration

The Rust applications connect to ghost-core via RPC:

```toml
# pool.toml or similar
[core_rpc_config]
url = "http://127.0.0.1:38332"
user = "ghost"
password = "your_rpc_password"
```

## Migration from Pure-Rust Implementation

The v1.4 Rust crates previously attempted to build transactions directly using the `bitcoin` crate. This approach had limitations:

1. **Cannot Sign**: No wallet access means no signatures
2. **No SP Scanning**: Silent Payment detection requires wallet SPKM
3. **No Batch Signing**: Multi-party PSBT workflow needs wallet

The solution is to use ghost-core's RPC commands:

```rust
// OLD: Build unsigned transaction in Rust
let tx = WraithTransactionBuilder::new(...)
    .build_split_transaction(&addresses)?;
// Problem: tx.transaction is unsigned

// NEW: Use ghost-core RPC
let result = rpc.create_wraith_tx(
    inputs,
    addresses,
    session_id,
    denomination
).await?;
// result.hex is a signed transaction (if wallet has keys)
```

## Testing

Ensure ghost-core is running before running integration tests:

```bash
# Start ghost-core
./ghost-core/build/src/ghostd -regtest -server

# Run Rust tests
cargo test --workspace
```

## References

- `ghost-core/TODO.md` - Ghost-core feature status
- `ghost-core/src/silentpayments.h` - Silent Payment API
- `ghost-core/src/ghostlock.h` - Ghost Lock API
- `ghost-core/src/wallet/rpc/wraith.cpp` - Wraith RPC implementation
