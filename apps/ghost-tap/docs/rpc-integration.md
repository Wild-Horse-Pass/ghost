# RPC Integration Guide

**Version:** 0.2.0
**Last Updated:** 2026-03-01

---

## 1. Overview

GhostTap connects to Ghost nodes to query blockchain data and broadcast transactions. There are two transport modes:

| Mode | Transport | Use Case |
|------|-----------|----------|
| Direct RPC | JSON-RPC over HTTP | Own node, full control |
| GSP | WebSocket | Built into ghostd, push notifications, BIP-157 privacy |

The `ConnectionManager` in `core/src/network/connection.rs` abstracts over both. The mobile UI doesn't need to know which is active.

## 2. Ghost Node RPC Methods

Validated against the `ghost-core` source code. These are the methods GhostTap uses.

### Balance & UTXOs

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `getbalance` | Wallet balance | `(dummy, minconf, include_watchonly)` | Amount |
| `getbalances` | Detailed balances | `()` | `{ mine: { trusted, untrusted_pending, immature }, watchonly: {...} }` |
| `listunspent` | List UTXOs | `(minconf, maxconf, [addresses])` | `[{ txid, vout, address, amount, confirmations, ... }]` |
| `getreceivedbyaddress` | Total received by address | `(address, minconf)` | Amount |

### Transaction History

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `listtransactions` | Wallet tx history | `(label, count, skip, include_watchonly)` | `[{ txid, address, amount, confirmations, time, category }]` |
| `gettransaction` | Full tx details | `(txid, include_watchonly)` | `{ txid, amount, fee, confirmations, time, details[] }` |
| `getrawtransaction` | Raw tx hex/decoded | `(txid, verbose)` | Hex string or decoded JSON |
| `listsinceblock` | Txs since block | `(blockhash, target_confirmations)` | `{ transactions[], lastblock }` |

### Building & Sending Transactions

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `createrawtransaction` | Build unsigned tx | `([{txid, vout}], [{addr: amount}])` | Raw tx hex |
| `fundrawtransaction` | Add inputs/change | `(hex, options)` | `{ hex, fee, changepos }` |
| `signrawtransactionwithkey` | Sign with provided keys | `(hex, [privkeys])` | `{ hex, complete }` |
| `sendrawtransaction` | Broadcast signed tx | `(hex)` | txid |
| `sendtoaddress` | Simple send | `(address, amount)` | txid |
| `send` | Advanced send | `([{addr: amount}], conf_target, estimate_mode)` | `{ txid, complete }` |
| `testmempoolaccept` | Validate before broadcast | `([hex])` | `[{ txid, allowed, reject-reason }]` |

### Fee Estimation

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `estimatesmartfee` | Fee estimate for confirmation target | `(conf_target, estimate_mode)` | `{ feerate, blocks }` |

### Address Management

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `getnewaddress` | Generate address | `(label, address_type)` | address string |
| `getrawchangeaddress` | Change address | `(address_type)` | address string |
| `validateaddress` | Validate format | `(address)` | `{ isvalid, address, ... }` |
| `getaddressinfo` | Address details | `(address)` | `{ address, ismine, iswatchonly, ... }` |

### Watch-Only (Descriptor Wallets)

Legacy `importaddress` is NOT available. Ghost uses the modern descriptor wallet model:

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `createwallet` | Create wallet (watch-only capable) | `(name, disable_private_keys, blank)` | `{ name, warning }` |
| `importdescriptors` | Import descriptors | `([{desc, timestamp, range, ...}])` | `[{ success, ... }]` |
| `listdescriptors` | List wallet descriptors | `(private)` | `{ descriptors[] }` |

To create a watch-only wallet for GhostTap address monitoring:
```bash
ghost-cli createwallet "ghosttap_watch" true true "" false true true
ghost-cli -rpcwallet="ghosttap_watch" importdescriptors '[{"desc":"wpkh(...)","timestamp":0}]'
```

### Wraith Protocol (Privacy)

The Wraith protocol uses a two-phase CoinJoin approach, NOT simple anon send/receive:

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `createwraithtx` | Phase 1: Split into 10N intermediate UTXOs | `(amount, outputs)` | Raw tx hex |
| `createwraithfinaltx` | Phase 2: Merge intermediates into N final outputs | `(inputs, outputs)` | Raw tx hex |
| `parsewraithtx` | Parse Wraith OP_RETURN metadata | `(txhex)` | `{ phase, marker, ... }` |
| `shuffleoutputs` | Shuffle tx outputs for CoinJoin privacy | `(txhex)` | Shuffled tx hex |
| `createreconciliationtx` | L1 settlement/reconciliation batch | `(inputs, outputs)` | Raw tx hex |
| `coordinatebatchsigning` | Multi-party batch PSBT | `(inputs, outputs, participants)` | PSBT |
| `combinebatchpsbt` | Combine batch PSBTs | `([psbts])` | Combined PSBT |
| `estimatebatchfee` | Estimate batch reconciliation fee | `(inputs, outputs)` | Fee estimate |
| `derivereconciliationoutputs` | Derive outputs from Ghost IDs (Silent Payments) | `([ghost_ids], amounts)` | `[{address, amount}]` |

Wraith OP_RETURN markers:
- Phase 1 (Split): `GPW1` (`0x47 0x50 0x57 0x31`)
- Phase 2 (Merge): `GPW2` (`0x47 0x50 0x57 0x32`)

### Silent Payments (Ghost ID)

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `getsilentpaymentaddress` | Get wallet's Ghost ID (`ghost1...`) | `()` | Ghost ID string |
| `derivesilentpaymentaddress` | Derive one-time P2TR address from Ghost ID | `(ghost_id)` | P2TR address |
| `checksilentpayment` | Check if tx output belongs to wallet | `(txid, vout)` | `{ ismine, ... }` |
| `rescansilentpayments` | Rescan for Silent Payment outputs | `(start_height)` | Status |
| `getsilentpaymentstats` | Scanning statistics | `()` | `{ scanned_blocks, found, ... }` |

### Ghost-Specific Network

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `setghostmode` | Enable/disable ghost privacy routing | `(enabled)` | Status |
| `getghostmode` | Current ghost mode | `()` | `{ enabled, ... }` |
| `getgspnodes` | Find GSP-enabled peers | `(count)` | `[{ addr, ... }]` |
| `gethazestatus` | Ghost Haze mode and stats | `()` | `{ mode, ... }` |

### Node Info

| Method | Purpose | Parameters | Returns |
|--------|---------|------------|---------|
| `getblockchaininfo` | Chain state | `()` | `{ chain, blocks, headers, bestblockhash }` |
| `getnetworkinfo` | Network state | `()` | `{ version, connections, ... }` |
| `getpeerinfo` | Connected peers | `()` | `[{ addr, version, ... }]` |
| `getzmqnotifications` | Active ZMQ endpoints | `()` | `[{ type, address, ... }]` |

## 3. RPC Configuration

### Connection Parameters

```rust
// core/src/network/client.rs
pub struct NodeConfig {
    pub host: String,          // e.g., "192.168.1.100"
    pub port: u16,             // e.g., 8332 (Ghost mainnet RPC)
    pub username: String,      // RPC auth
    pub password: String,      // RPC auth
    pub use_tls: bool,         // HTTPS (required for non-localhost)
    pub timeout_ms: u64,       // Request timeout (default: 30000)
}
```

### Ghost Network Ports

| Network | P2P Port | RPC Port | GSP Port |
|---------|----------|----------|----------|
| Mainnet | — | **8332** | **8900** |
| Testnet3 | — | 18332 | — |
| Testnet4 | — | 48332 | — |
| Signet | — | **38332** | **8900** |
| Regtest | — | 18443 | — |

### Authentication

Two methods supported:

**Cookie-based (default, for local access):**
- Ghost daemon generates `~/.ghost/.cookie` on startup
- `ghost-cli` reads it automatically — no credentials needed
- Cookie username: `__cookie__`

**HTTP Basic Auth (for remote access):**
```
rpcuser=ghosttap
rpcpassword=<strong_password>
rpcallowip=<mobile_device_ip_or_vpn_subnet>
```

Also supports hashed credentials via `rpcauth=` (generated by `share/rpcauth/rpcauth.py`).

**Security requirement:** TLS is required for non-localhost connections. The Ghost RPC client enforces `tls_enabled=true` when not connecting to `127.0.0.1` or `localhost`.

## 4. ZMQ Real-Time Notifications

Ghost supports ZMQ for real-time block and transaction notifications without polling:

| Topic | Config Option | Description |
|-------|---------------|-------------|
| `hashblock` | `zmqpubhashblock` | Block hash on new block |
| `hashtx` | `zmqpubhashtx` | Tx hash on mempool acceptance |
| `rawblock` | `zmqpubrawblock` | Full raw block data |
| `rawtx` | `zmqpubrawtx` | Full raw transaction data |
| `sequence` | `zmqpubsequence` | Block/mempool connect/disconnect events |

Configuration (in `ghost.conf` or `mainnet.toml`):
```toml
zmq_hashblock = "tcp://127.0.0.1:28332"
zmq_hashtx    = "tcp://127.0.0.1:28333"
zmq_sequence  = "tcp://127.0.0.1:28334"
```

GhostTap can subscribe to `hashtx` for instant incoming payment detection and `hashblock` for confirmation tracking — no polling delay.

## 5. Failover Configuration

GhostTap supports multiple node endpoints for redundancy:

```
Primary:    node1.example.com:8332
Fallback 1: node2.example.com:8332
Fallback 2: node3.example.com:8332
Fallback 3: node4.example.com:8332
```

Failover behavior:
1. Try primary endpoint
2. On connection failure or timeout, try next endpoint
3. Cycle through all endpoints with configurable retry count
4. If all endpoints fail, show "Network unavailable" in UI

## 6. GSP WebSocket Protocol

GSP (Ghost Service Provider) is built into ghostd. Every full node can serve light wallets by default.

### Connection

```
ws://<host>:8900/gsp/ws/v1
```

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/gsp/health` | Health check |
| GET | `/gsp/api/v1/info` | Server info (version, network, sync, connections) |
| POST | `/gsp/api/v1/register` | Register wallet (Schnorr signature required) |
| POST | `/gsp/api/v1/session` | Create JWT session (24-hour expiry) |
| GET | `/gsp/api/v1/filters/:height` | BIP-157 compact block filter |
| GET | `/gsp/api/v1/filters/batch?start=&count=` | Batch filter download |
| GET | `/gsp/api/v1/filters/headers` | Filter header checkpoints |
| GET | `/gsp/api/v1/block/:hash` | Block data |
| GET | `/gsp/metrics` | Prometheus metrics |

### WebSocket Message Types

| Client → Server | Server → Client | Description |
|----------------|-----------------|-------------|
| `Authenticate` | `AuthResult` | JWT token auth |
| `GetBalance` | `Balance` | Balance (confirmed/unconfirmed/L2) |
| `GetUtxos` | `Utxos` | UTXO list |
| `GetGhostLocks` | `GhostLocks` | Ghost Lock list |
| `SubscribeBalance` | `BalanceUpdate` (push) | Live balance changes |
| `SubscribePayments` | `PaymentReceived` / `PaymentConfirmed` (push) | Payment notifications |
| `SubscribeLockState` | `LockStateUpdate` (push) | Lock state changes |
| `CheckInstantCapability` | `InstantCapabilityResult` | 8-condition bitmap |
| `AcceptInstantPayment` | `InstantPaymentAccepted` / `InstantPaymentSettled` | Instant payment flow |

### Authentication Flow

1. **Register:** POST Schnorr signature over `"ghost-gsp-register:" + ghost_id + ":" + timestamp` → receive `wallet_id`
2. **Create session:** POST wallet_id + signed challenge → receive JWT (24-hour expiry)
3. **Connect WebSocket:** Send `Authenticate` message with JWT
4. **Subscribe:** Request push notifications for balance/payment events

### Privacy Model

GSP uses BIP-157 compact block filters. The server cannot determine which addresses belong to a wallet. Wallets download filters, scan locally, and only request full blocks on match.

GSP node config requirements:
```ini
gsp=1                    # Enable GSP (default: 1)
gspport=8900             # Port (default: 8900)
gspmaxconnections=100    # Max WebSocket clients
gspratelimit=1           # Rate limiting
blockfilterindex=basic   # Required for BIP-157
peerblockfilters=1       # Required for filter serving
```

## 7. Signet Node Integration

### Current Setup

4 Ghost signet nodes running (VM1-VM4). GhostTap connects to these for development and testing.

### Configuration Steps

1. On each signet node, ensure RPC is enabled:
   ```
   server=1
   rpcuser=ghosttap
   rpcpassword=<password>
   rpcallowip=<vpn_subnet>
   rpcport=38332
   ```

2. Enable GSP (if using WebSocket mode):
   ```
   gsp=1
   gspport=8900
   blockfilterindex=basic
   peerblockfilters=1
   ```

3. Optionally enable ZMQ for real-time notifications:
   ```
   zmqpubhashblock=tcp://0.0.0.0:28332
   zmqpubhashtx=tcp://0.0.0.0:28333
   ```

4. In GhostTap, configure endpoints (stored encrypted in local DB):
   ```
   RPC:  https://<vm1_ip>:38332 (primary)
   GSP:  ws://<vm1_ip>:8900/gsp/ws/v1
   Fallbacks: vm2, vm3, vm4
   ```

5. Test connectivity:
   ```bash
   curl -u ghosttap:<password> \
     --data-binary '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
     -H "content-type: text/plain;" \
     https://<vm1_ip>:38332/
   ```

### Testing Flow

1. Create wallet in GhostTap → get receive address
2. From signet node: `ghost-cli -signet sendtoaddress <ghosttap_address> 10.0`
3. GhostTap syncs → balance shows 10.0 Ghost
4. Send 1.0 Ghost from GhostTap to another address
5. Verify transaction confirms on signet

## 8. Bitcoin RPC (Planned)

For Bitcoin on-chain support, GhostTap will connect to either:

### Bitcoin Core RPC

Same JSON-RPC pattern as Ghost. Key methods:
- `listunspent`, `createrawtransaction`, `sendrawtransaction`
- `estimatesmartfee` for fee estimation
- `getblockchaininfo` for chain state

### Electrum Protocol

Lighter alternative — doesn't require running a full Bitcoin node:
- Uses Electrum server protocol (TCP/SSL)
- Methods: `blockchain.scripthash.get_balance`, `blockchain.scripthash.listunspent`, `blockchain.transaction.broadcast`
- Public servers available (privacy tradeoff) or run own Electrs/Fulcrum

### BDK (Bitcoin Dev Kit)

Rust library that wraps Electrum/Esplora connectivity with wallet functionality:
- UTXO management and coin selection
- Transaction building and signing
- Fee estimation
- Address generation (native segwit)

Most likely integration path for Bitcoin support.
