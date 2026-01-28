# Full Node Wallet Guide

The Bitcoin Ghost Full Node Wallet runs alongside `ghostd` (the Ghost-enhanced Bitcoin Core) for maximum privacy, security, and network support. All blockchain data is validated locally.

## Overview

| Aspect | Details |
|--------|---------|
| **Type** | Full node with integrated wallet |
| **Storage** | ~500GB+ (full blockchain) |
| **Memory** | 2GB+ RAM recommended |
| **Sync Time** | Several hours to days (initial) |
| **Interface** | CLI (ghost-cli) and TUI available |
| **Key Storage** | Local wallet database (encrypted) |
| **Network** | Direct P2P connection |

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 2 GB | 8+ GB |
| **Storage** | 500 GB SSD | 1+ TB SSD |
| **Network** | 10 Mbps | 50+ Mbps |

### Software Requirements

- 64-bit Linux, macOS, or Windows
- Build tools (gcc/clang, cmake, make)
- Boost libraries
- Berkeley DB 4.8
- OpenSSL

## Installation

### From Binary Release

```bash
# Download the latest release
curl -LO https://github.com/anthropics/bitcoin-ghost/releases/latest/download/ghostd-linux-x64.tar.gz

# Extract
tar -xzf ghostd-linux-x64.tar.gz

# Move to PATH
sudo mv ghostd ghost-cli /usr/local/bin/

# Verify installation
ghostd --version
ghost-cli --version
```

### From Source

```bash
# Clone repository
git clone https://github.com/anthropics/bitcoin-ghost.git
cd bitcoin-ghost/ghost-core

# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake \
    pkg-config bsdmainutils python3 libevent-dev libboost-dev \
    libboost-system-dev libboost-filesystem-dev libboost-test-dev \
    libsqlite3-dev libzmq3-dev

# Build
./autogen.sh
./configure --with-gui=no
make -j$(nproc)

# Install (optional)
sudo make install
```

## Quick Start

### 1. Start the Node

```bash
# Start ghostd (daemon mode)
ghostd -daemon

# Or start in foreground with logs
ghostd -printtoconsole

# Check sync status
ghost-cli getblockchaininfo
```

### 2. Wait for Initial Sync

The node must download and validate the entire blockchain. This can take several hours to days depending on your hardware and connection.

```bash
# Monitor sync progress
watch ghost-cli getblockchaininfo

# Output shows:
# "blocks": 234567,
# "headers": 850000,
# "verificationprogress": 0.27534,
# "initialblockdownload": true
```

### 3. Create a Wallet

```bash
# Create new wallet
ghost-cli createwallet "main" false false "" false true true

# Parameters:
# - wallet_name: "main"
# - disable_private_keys: false
# - blank: false
# - passphrase: "" (set later)
# - avoid_reuse: false
# - descriptors: true
# - load_on_startup: true
```

### 4. Set Wallet Passphrase

```bash
# Encrypt wallet with passphrase
ghost-cli encryptwallet "your-secure-passphrase"

# Node will restart. Reconnect and unlock for operations:
ghost-cli walletpassphrase "your-secure-passphrase" 300
```

### 5. Get Your Ghost ID

```bash
# Generate Ghost ID (Silent Payment address)
ghost-cli getsilentpaymentaddress

# Output:
# ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
```

### 6. Check Balance

```bash
ghost-cli getbalance

# Detailed balance info
ghost-cli getbalances

# Output:
# {
#   "mine": {
#     "trusted": 0.00000000,
#     "untrusted_pending": 0.00000000,
#     "immature": 0.00000000
#   }
# }
```

### 7. Send a Payment

```bash
# Send to Ghost ID
ghost-cli sendtoaddress ghost1abc... 0.001

# Send to standard address
ghost-cli sendtoaddress bc1q... 0.001

# Send with custom fee rate (sat/vB)
ghost-cli sendtoaddress ghost1abc... 0.001 "" "" false true 3
```

## Configuration

### Config File Location

```
# Linux
~/.ghost/ghost.conf

# macOS
~/Library/Application Support/Ghost/ghost.conf

# Windows
%APPDATA%\Ghost\ghost.conf
```

### Essential Configuration

```ini
# Network (mainnet, testnet, signet, regtest)
chain=main

# Data directory (customize if needed)
# datadir=/path/to/data

# RPC settings
server=1
rpcuser=ghostrpc
rpcpassword=your-secure-rpc-password

# GSP (Light Wallet Server) - enabled by default
gsp=1
gspport=8900

# Block filters for privacy
blockfilterindex=basic
peerblockfilters=1

# Performance tuning
dbcache=4000
maxmempool=300

# Network
listen=1
maxconnections=125

# Logging
debug=0
printtoconsole=0
```

### Privacy-Enhanced Configuration

```ini
# Enable Tor for all connections
proxy=127.0.0.1:9050
listen=0
onlynet=onion

# Disable address relay
addresstype=bech32m
avoidpartialspends=1

# Disable wallet broadcast (manual control)
walletbroadcast=0
```

## Ghost-Specific RPC Commands

### Ghost Keys (Silent Payments)

```bash
# Get your Ghost ID
ghost-cli getsilentpaymentaddress

# Derive address from someone's Ghost ID (for verification)
ghost-cli derivesilentpaymentaddress ghost1abc...

# Check if a transaction pays to your wallet
ghost-cli checksilentpayment <txid>

# Rescan blockchain for missed payments
ghost-cli rescansilentpayments 0  # from block 0

# Get detection statistics
ghost-cli getsilentpaymentstats
```

### Ghost Locks

```bash
# Create a Ghost Lock
ghost-cli createghostlock <amount> <denomination> <timelock>

# Example: 1M sats, small denomination, 6-month recovery
ghost-cli createghostlock 0.01 "small" "6m"

# List your Ghost Locks
ghost-cli listghostlocks

# Spend a Ghost Lock
ghost-cli spendghostlock <lock_id> <destination>

# Get lock details
ghost-cli getghostlock <lock_id>
```

### Ghost Pay (L2)

```bash
# Get L2 balance
ghost-cli getl2balance

# Send L2 payment
ghost-cli l2send ghost1abc... 0.001

# Deposit to L2 (L1 → L2)
ghost-cli l2deposit 0.01

# Withdraw from L2 (L2 → L1)
ghost-cli l2withdraw 0.01

# L2 transaction history
ghost-cli l2listtransactions
```

### Wraith Protocol (Mixing)

```bash
# Initiate a mixing session
ghost-cli createwraithtx <amount>

# Join an existing session
ghost-cli joinwraithtx <session_id>

# Check mixing status
ghost-cli getwraithstatus <session_id>
```

### Reconciliation (L1 Settlement)

```bash
# Create reconciliation transaction
ghost-cli createreconciliationtx

# Parse Ghost OP_RETURN data
ghost-cli parseghostopreturn <txid>
```

## Wallet Management

### List Wallets

```bash
ghost-cli listwallets
```

### Load/Unload Wallets

```bash
# Load wallet
ghost-cli loadwallet "wallet-name"

# Unload wallet
ghost-cli unloadwallet "wallet-name"
```

### Backup Wallet

```bash
# Backup wallet file
ghost-cli backupwallet /path/to/backup.dat

# Or copy directly
cp ~/.ghost/wallets/main/wallet.dat /backup/location/
```

### Restore Wallet

```bash
# From backup file
ghostd -wallet=/path/to/backup.dat

# Or copy to wallets directory before starting
cp /backup/wallet.dat ~/.ghost/wallets/restored/wallet.dat
ghost-cli loadwallet "restored"
```

### Import Private Key

```bash
# Unlock wallet first
ghost-cli walletpassphrase "passphrase" 300

# Import key
ghost-cli importprivkey "your-private-key-here" "label" true
```

### Export Private Keys

```bash
# Dump all private keys
ghost-cli dumpwallet /path/to/dump.txt
```

## Transaction Management

### List Transactions

```bash
# Recent transactions
ghost-cli listtransactions

# All transactions for an address
ghost-cli listtransactions "*" 100 0 true

# Detailed transaction info
ghost-cli gettransaction <txid>
```

### Unspent Outputs (UTXOs)

```bash
# List UTXOs
ghost-cli listunspent

# Filter by minimum confirmations
ghost-cli listunspent 6

# Filter by address
ghost-cli listunspent 1 9999999 '["bc1q..."]'
```

### Raw Transactions

```bash
# Create raw transaction
ghost-cli createrawtransaction '[{"txid":"...","vout":0}]' '{"bc1q...":0.001}'

# Sign transaction
ghost-cli signrawtransactionwithwallet "hex..."

# Broadcast
ghost-cli sendrawtransaction "signed-hex..."
```

### Fee Estimation

```bash
# Estimate fee for confirmation in N blocks
ghost-cli estimatesmartfee 6

# Output:
# {
#   "feerate": 0.00005,  # BTC/kB
#   "blocks": 6
# }
```

### Replace-By-Fee (RBF)

```bash
# Bump fee on unconfirmed transaction
ghost-cli bumpfee <txid>

# Specify target fee rate
ghost-cli bumpfee <txid> '{"fee_rate": 10}'
```

## Node Operations

### Stop Node

```bash
ghost-cli stop
```

### Node Info

```bash
# Blockchain info
ghost-cli getblockchaininfo

# Network info
ghost-cli getnetworkinfo

# Peer info
ghost-cli getpeerinfo

# Memory info
ghost-cli getmemoryinfo
```

### Peer Management

```bash
# Add peer manually
ghost-cli addnode "1.2.3.4:8333" "add"

# Ban peer
ghost-cli setban "1.2.3.4" "add" 86400

# List banned
ghost-cli listbanned

# Clear bans
ghost-cli clearbanned
```

### GSP Status (Light Wallet Server)

```bash
# Check if GSP is running
ghost-cli getgspinfo

# List connected light wallet clients
ghost-cli getgspclients

# Find GSP-enabled peers
ghost-cli getgspnodes
```

## Pruning (Reduce Storage)

If you have limited storage, enable pruning:

```ini
# In ghost.conf - keep last 10GB of blocks
prune=10000

# Or in MB
prune=10000
```

**Note**: Pruned nodes cannot:
- Serve historical blocks to peers
- Rescan old transactions
- Run a full GSP server (use compact filters instead)

```bash
# Manual prune
ghost-cli pruneblockchain 700000  # prune up to block 700000
```

## TUI Wallet

For an interactive terminal interface:

```bash
ghost-wallet-tui
```

### TUI Features

- Real-time blockchain sync status
- Interactive transaction builder
- Address book management
- Ghost Lock dashboard
- L2 balance and payments
- QR code display for addresses

## Systemd Service (Linux)

Create `/etc/systemd/system/ghostd.service`:

```ini
[Unit]
Description=Ghost Daemon
After=network.target

[Service]
Type=forking
User=ghost
Group=ghost
ExecStart=/usr/local/bin/ghostd -daemon -conf=/home/ghost/.ghost/ghost.conf
ExecStop=/usr/local/bin/ghost-cli stop
Restart=on-failure
RestartSec=30
TimeoutStartSec=infinity
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable ghostd
sudo systemctl start ghostd

# Check status
sudo systemctl status ghostd

# View logs
journalctl -u ghostd -f
```

## Security Best Practices

### DO:
- Use a strong wallet passphrase
- Keep your node updated
- Backup wallet.dat regularly
- Use firewall to restrict RPC access
- Run behind Tor for privacy
- Enable wallet encryption

### DON'T:
- Expose RPC to the internet
- Use weak RPC credentials
- Skip wallet encryption
- Store backups unencrypted
- Run as root user
- Ignore security updates

### Firewall Rules (UFW example)

```bash
# Allow P2P
sudo ufw allow 8333/tcp

# Allow GSP (light wallets)
sudo ufw allow 8900/tcp

# Restrict RPC to localhost only
# (default - no rule needed)

# Enable firewall
sudo ufw enable
```

## Troubleshooting

### Node Won't Start

```bash
# Check for running instance
ps aux | grep ghostd

# Check debug log
tail -100 ~/.ghost/debug.log

# Start with debug output
ghostd -printtoconsole -debug=1
```

### Sync Issues

```bash
# Check sync status
ghost-cli getblockchaininfo

# Check peer connections
ghost-cli getpeerinfo | jq '.[].synced_blocks'

# Add more peers
ghost-cli addnode "seed.ghostnetwork.io" "onetry"
```

### Wallet Issues

```bash
# Check wallet is loaded
ghost-cli listwallets

# Load specific wallet
ghost-cli loadwallet "main"

# Verify wallet
ghost-cli verifywallet
```

### Low Disk Space

```bash
# Check data directory size
du -sh ~/.ghost/

# Enable pruning (requires restart)
echo "prune=10000" >> ~/.ghost/ghost.conf
ghost-cli stop
ghostd -daemon
```

### RPC Connection Refused

```bash
# Check if server=1 in config
grep server ~/.ghost/ghost.conf

# Check if node is running
ghost-cli getblockchaininfo

# Check for cookie auth
ls ~/.ghost/.cookie
```

## CLI Reference

### Core Commands

| Command | Description |
|---------|-------------|
| `getblockchaininfo` | Blockchain status |
| `getnetworkinfo` | Network status |
| `getwalletinfo` | Wallet status |
| `getbalance` | Total balance |
| `getnewaddress` | Generate address |
| `sendtoaddress` | Send payment |
| `listtransactions` | Transaction history |
| `listunspent` | List UTXOs |

### Ghost Commands

| Command | Description |
|---------|-------------|
| `getsilentpaymentaddress` | Get Ghost ID |
| `derivesilentpaymentaddress` | Derive from Ghost ID |
| `checksilentpayment` | Check TX for payments |
| `rescansilentpayments` | Rescan for payments |
| `createghostlock` | Create Ghost Lock |
| `listghostlocks` | List locks |
| `spendghostlock` | Spend lock |
| `getl2balance` | L2 balance |
| `l2send` | L2 payment |
| `createwraithtx` | Mixing transaction |

### GSP Commands

| Command | Description |
|---------|-------------|
| `getgspinfo` | GSP server status |
| `getgspnodes` | Find GSP peers |
| `getgspclients` | Connected light wallets |

## Appendix: Data Directory Structure

```
~/.ghost/
├── ghost.conf              # Configuration file
├── debug.log               # Debug log
├── .cookie                 # RPC auth cookie
├── blocks/                 # Block data
│   ├── blk*.dat           # Raw blocks
│   └── rev*.dat           # Undo data
├── chainstate/            # UTXO set
├── indexes/               # Optional indexes
│   ├── txindex/          # Transaction index
│   └── blockfilter/      # BIP-157 filters
├── wallets/               # Wallet data
│   └── main/
│       └── wallet.dat
├── gsp/                   # GSP data
│   └── wallets.db        # Light wallet registry
└── peers.dat              # Known peers
```
