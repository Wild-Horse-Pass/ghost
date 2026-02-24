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
//| FILE: RPC_COMMANDS.md                                                                                                |
//|======================================================================================================================|
```

# Bitcoin Ghost RPC Commands Reference

This document describes all RPC commands available in Bitcoin Ghost.

## Table of Contents

- [Core Blockchain Commands](#core-blockchain-commands)
- [Mining Commands](#mining-commands)
- [Raw Transaction Commands](#raw-transaction-commands)
- [Network Commands](#network-commands)
- [Wallet Commands](#wallet-commands)
- [Silent Payment Commands (Ghost-Specific)](#silent-payment-commands)
- [Wraith Protocol Commands (Ghost-Specific)](#wraith-protocol-commands)
- [Reconciliation Commands (Ghost-Specific)](#reconciliation-commands)
- [Stratum Mining Protocol](#stratum-mining-protocol)

---

## Core Blockchain Commands

Commands for querying blockchain state and data.

| Command | Description |
|---------|-------------|
| `getbestblockhash` | Returns the hash of the best (tip) block |
| `getblock` | Returns block data by hash with specified verbosity |
| `getblockchaininfo` | Returns blockchain state information |
| `getblockcount` | Returns the current block height |
| `getblockfilter` | Returns block filter for a given block |
| `getblockfrompeer` | Requests a block from a peer |
| `getblockhash` | Returns block hash at a given height |
| `getblockheader` | Returns block header information |
| `getblockstats` | Returns block statistics |
| `getchaintips` | Returns information about all known chain tips |
| `getchaintxstats` | Returns statistics about transactions in blocks |
| `getdifficulty` | Returns the current difficulty |
| `getmempoolancestors` | Returns all ancestors of a transaction in mempool |
| `getmempooldescendants` | Returns all descendants of a transaction in mempool |
| `getmempoolentry` | Returns information about a transaction in mempool |
| `getmempoolinfo` | Returns mempool statistics |
| `getrawmempool` | Returns raw mempool transactions |
| `gettxout` | Returns UTXO information |
| `gettxoutproof` | Returns proof that transactions are in a block |
| `gettxoutsetinfo` | Returns UTXO set statistics |
| `verifytxoutproof` | Verifies a transaction inclusion proof |

---

## Mining Commands

Commands for block generation and mining operations.

| Command | Description |
|---------|-------------|
| `generate` | Generates blocks (requires mining enabled) |
| `generateblock` | Generates a block with specified transactions |
| `generatetoaddress` | Generates blocks to a specified address |
| `generatetodescriptor` | Generates blocks to a descriptor output |
| `getblocktemplate` | Returns data needed to construct a block |
| `getmininginfo` | Returns mining-related information |
| `getnetworkhashps` | Returns the network hash rate |
| `submitblock` | Submits a block to the network |
| `submitheader` | Submits a block header |
| `submitpackage` | Submits a package of transactions |

---

## Raw Transaction Commands

Commands for creating and manipulating transactions.

| Command | Description |
|---------|-------------|
| `analyzepsbt` | Analyzes a PSBT |
| `combinepsbt` | Combines multiple PSBTs |
| `combinerawtransaction` | Combines multiple transactions into one |
| `createpsbt` | Creates a PSBT |
| `createrawtransaction` | Creates an unsigned raw transaction |
| `decoderawtransaction` | Decodes a raw transaction hex |
| `decodepsbt` | Decodes a PSBT |
| `decodescript` | Decodes a script |
| `descriptorprocesspsbt` | Processes a PSBT using a descriptor |
| `finalizepsbt` | Finalizes a PSBT for signing |
| `joinpsbts` | Joins multiple PSBTs |
| `sendrawtransaction` | Broadcasts a signed raw transaction |
| `signrawtransactionwithkey` | Signs a raw transaction with provided keys |
| `testmempoolaccept` | Tests if transactions would be accepted to mempool |
| `utxoupdatepsbt` | Updates UTXO information in a PSBT |

---

## Network Commands

Commands for peer management and network information.

| Command | Description |
|---------|-------------|
| `addconnection` | Adds a connection to a node |
| `addnode` | Adds or removes a node from the peer list |
| `addpeeraddress` | Adds a peer address to the address book |
| `clearbanned` | Clears banned node list |
| `disconnectnode` | Disconnects from a node |
| `getaddednodeinfo` | Returns information about manually added nodes |
| `getaddrmaninfo` | Returns address manager statistics |
| `getconnectioncount` | Returns peer connection count |
| `getnettotals` | Returns aggregate network statistics |
| `getnetworkinfo` | Returns network information |
| `getnodeaddresses` | Returns a list of known node addresses |
| `getpeerinfo` | Returns peer connection information |
| `listbanned` | Lists banned nodes |
| `setban` | Bans or unbans a node |
| `setnetworkactive` | Sets network activity on/off |

---

## Wallet Commands

Commands for wallet management and transactions.

### Address Management

| Command | Description |
|---------|-------------|
| `getnewaddress` | Generates a new address |
| `getrawchangeaddress` | Returns a change address |
| `getaddressesbylabel` | Returns addresses with a label |
| `getaddressinfo` | Returns information about an address |
| `setlabel` | Sets an address label |
| `listlabels` | Lists address labels |
| `listaddressgroupings` | Returns address groupings |
| `validateaddress` | Validates an address format |

### Balance & Transactions

| Command | Description |
|---------|-------------|
| `getbalance` | Returns wallet balance |
| `getbalances` | Returns detailed balance information |
| `gettransaction` | Returns transaction details |
| `getreceivedbyaddress` | Returns amount received by address |
| `getreceivedbylabel` | Returns amount received by label |
| `listreceivedbyaddress` | Lists amounts received by address |
| `listreceivedbylabel` | Lists amounts received by label |
| `listsinceblock` | Lists transactions since a block |
| `listtransactions` | Lists wallet transactions |
| `listunspent` | Lists unspent outputs |

### Sending

| Command | Description |
|---------|-------------|
| `send` | Creates and broadcasts a transaction |
| `sendall` | Sends all funds from wallet |
| `sendmany` | Sends funds to multiple addresses |
| `sendtoaddress` | Sends funds to an address |
| `bumpfee` | Increases transaction fee |
| `psbtbumpfee` | Bumps PSBT transaction fee |
| `abandontransaction` | Marks a transaction as abandoned |

### Wallet Management

| Command | Description |
|---------|-------------|
| `createwallet` | Creates a new wallet |
| `loadwallet` | Loads a wallet file |
| `unloadwallet` | Unloads a wallet |
| `backupwallet` | Backs up the wallet |
| `restorewallet` | Restores a wallet from backup |
| `encryptwallet` | Encrypts the wallet |
| `walletlock` | Locks the wallet |
| `walletpassphrase` | Unlocks the wallet |
| `walletpassphrasechange` | Changes wallet passphrase |
| `getwalletinfo` | Returns wallet information |
| `listwallets` | Lists loaded wallets |
| `listwalletdir` | Lists wallets in directory |

### PSBT Operations

| Command | Description |
|---------|-------------|
| `walletcreatefundedpsbt` | Creates a funded PSBT |
| `walletprocesspsbt` | Processes a PSBT |
| `signrawtransactionwithwallet` | Signs a raw transaction with wallet keys |

### Descriptors

| Command | Description |
|---------|-------------|
| `importdescriptors` | Imports descriptors into wallet |
| `listdescriptors` | Lists wallet descriptors |
| `createwalletdescriptor` | Creates a descriptor in the wallet |
| `deriveaddresses` | Derives addresses from a descriptor |

---

## Silent Payment Commands

Ghost-specific commands for privacy-preserving payments using BIP-352 style Silent Payments.

| Command | Description |
|---------|-------------|
| `getsilentpaymentaddress` | Returns the wallet's Ghost ID (Silent Payment address) |
| `derivesilentpaymentaddress` | Derives a one-time P2TR address from a Ghost ID |
| `checksilentpayment` | Checks if a transaction output belongs to the wallet |
| `parseghostopreturn` | Parses Ghost Lock OP_RETURN data |
| `rescansilentpayments` | Rescans blockchain for Silent Payment outputs |
| `getsilentpaymentstats` | Returns Silent Payment scanning statistics |

### Example Usage

```bash
# Get your Ghost ID for receiving private payments
ghost-cli getsilentpaymentaddress

# Derive a one-time address to send to someone's Ghost ID
ghost-cli derivesilentpaymentaddress "sp1q..."

# Check if a transaction paid you via Silent Payment
ghost-cli checksilentpayment "txid" 0
```

---

## Wraith Protocol Commands

Ghost-specific commands for CoinJoin-style transaction mixing.

| Command | Description |
|---------|-------------|
| `createwraithtx` | Creates Phase 1 (Split) transaction |
| `createwraithfinaltx` | Creates Phase 2 (Merge) transaction |
| `parsewraithtx` | Parses Wraith transaction metadata from OP_RETURN |
| `shuffleoutputs` | Shuffles transaction outputs deterministically |

### Wraith Protocol Flow

1. **Phase 1 (Split)**: Create split transaction to break amount into smaller UTXOs
2. **Wait**: Allow time for mixing with other participants
3. **Phase 2 (Merge)**: Create merge transaction to recombine outputs

```bash
# Phase 1: Split funds for mixing
ghost-cli createwraithtx "amount" "session_id"

# Phase 2: Merge mixed outputs
ghost-cli createwraithfinaltx "session_id" "destination_address"
```

---

## Reconciliation Commands

Ghost-specific commands for L2-to-L1 batch settlement.

| Command | Description |
|---------|-------------|
| `createreconciliationtx` | Creates L1 settlement transaction for batch reconciliation |
| `coordinatebatchsigning` | Creates PSBT for multi-party batch signing |
| `combinebatchpsbt` | Combines multiple PSBTs from batch signing participants |
| `estimatebatchfee` | Estimates fee for batch reconciliation transactions |
| `derivereconciliationoutputs` | Derives output addresses from Ghost IDs via Silent Payments |

### Example Usage

```bash
# Create a batch reconciliation transaction
ghost-cli createreconciliationtx '[{"ghost_id": "sp1q...", "amount": 0.01}]'

# Coordinate multi-party signing
ghost-cli coordinatebatchsigning "batch_id"
```

---

## Stratum Mining Protocol

JSON-RPC methods for Stratum V1/V2 mining protocol.

### Client Methods (Miner to Pool)

| Method | Description |
|--------|-------------|
| `mining.subscribe` | Subscribe to receive job updates and difficulty changes |
| `mining.authorize` | Authenticate miner with username/password |
| `mining.submit` | Submit proof-of-work solutions |
| `mining.extranonce.subscribe` | Subscribe to receive extra nonce updates |
| `mining.get_transactions` | Retrieve mempool transactions (optional) |
| `mining.configure` | Stratum V2 extension for protocol configuration |

### Server Notifications (Pool to Miner)

| Method | Description |
|--------|-------------|
| `mining.notify` | Sends new block template to miners |
| `mining.set_difficulty` | Sets difficulty for miner |

### Example Stratum Session

```json
// 1. Subscribe
{"id": 1, "method": "mining.subscribe", "params": ["ghost-miner/1.0"]}

// 2. Authorize
{"id": 2, "method": "mining.authorize", "params": ["worker.1", "password"]}

// 3. Submit share
{"id": 3, "method": "mining.submit", "params": ["worker.1", "job_id", "extranonce2", "ntime", "nonce"]}
```

---

## Server & Utility Commands

| Command | Description |
|---------|-------------|
| `echo` | Echoes a string |
| `echojson` | Echoes JSON |
| `getrpcinfo` | Returns RPC server information |
| `help` | Returns help text for RPC commands |
| `logging` | Adjusts logging verbosity |
| `ping` | Pings the server |
| `stop` | Shuts down the server |
| `uptime` | Returns server uptime |

---

## Fee Estimation

| Command | Description |
|---------|-------------|
| `estimaterawfee` | Estimates fee rate from historical blocks |
| `estimatesmartfee` | Estimates fee rate for a target confirmation time |

---

## Security Features

The RPC system includes several security hardening measures:

- **Message Size Limits**: 4096 bytes maximum per message
- **JSON Nesting Limits**: 4 levels maximum
- **Parameter Limits**: 10 parameters maximum, 256 bytes per string
- **Method Whitelisting**: Only allowed Stratum methods accepted
- **TLS Enforcement**: Required for remote connections
- **Circuit Breaker**: Prevents cascading failures
- **Block Template Validation**: Prevents DoS via malformed templates

---

## Connection Examples

### Bitcoin Core Compatible

```bash
# Using bitcoin-cli
bitcoin-cli -rpcuser=user -rpcpassword=pass getblockchaininfo

# Using curl
curl --user user:pass --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  -H 'content-type:text/plain;' http://127.0.0.1:8332/
```

### Ghost-Specific

```bash
# Using ghost-cli
ghost-cli getsilentpaymentaddress
ghost-cli createwraithtx 0.1 "session123"
```
