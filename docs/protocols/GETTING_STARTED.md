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
//| FILE: GETTING_STARTED.md                                                                                             |
//|======================================================================================================================|

# Getting Started

Quick start guide for miners, node operators, and L2 users.

## For Miners

### Requirements

- Mining hardware (ASIC, GPU, or CPU)
- Network connection
- Bitcoin payout address

### Connect to the Pool

```
Pool URL: stratum+tcp://node.bitcoinghost.org:3333
Username: <your_btc_address>.<worker_name>
Password: x (or anything)
```

### Example Configurations

**CGMiner:**
```bash
cgminer -o stratum+tcp://node.bitcoinghost.org:3333 \
        -u bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.rig1 \
        -p x
```

**BFGMiner:**
```bash
bfgminer -o stratum+tcp://node.bitcoinghost.org:3333 \
         -u bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.rig1 \
         -p x
```

**ASIC (most brands):**
```
URL: stratum+tcp://node.bitcoinghost.org:3333
Worker: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.worker1
Password: x
```

### What You Earn

- **99% of block subsidy** - distributed proportionally to work
- **Paid in coinbase** - direct on-chain, no withdrawal needed
- **Top 200 miners per block** - smaller miners accumulate until threshold

### Monitor Your Mining

```bash
# Check your stats (when CLI available)
ghost-cli miner stats bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

---

## For Node Operators

### Requirements

| Component | Minimum |
|-----------|---------|
| CPU | 4 cores |
| RAM | 8 GB |
| Storage | 500 GB SSD (archive mode) |
| Network | 100 Mbps, public IP |
| OS | Linux (Ubuntu 22.04+) |

### Quick Setup

```bash
# 1. Clone repository
git clone https://github.com/bitcoin-ghost/ghost.git
cd bitcoin-ghost

# 2. Build
cargo build --release

# 3. Copy example config
cp examples/ghost.toml /etc/ghost/pool.toml
# Edit /etc/ghost/pool.toml with your settings

# 4. Start ghost-core first
./target/release/ghost-core-launcher -datadir=/home/ghost/.ghost/ghost-core

# 5. Start ghost-pool
./target/release/ghost-pool --config /etc/ghost/pool.toml
```

### Configuration

Edit `/etc/ghost/pool.toml`:

```toml
[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = 38332
rpc_user = "ghost"
rpc_password = "yourpassword"
network = "mainnet"

[network]
sv1_port = 3333
http_port = 8080

[pool]
treasury_address = "bc1q..."
node_payout_address = "bc1q..."

[capabilities]
archive_mode = true
ghost_pay = true
public_mining = true
policy_enabled = true
policy_profile = "permissive"
```

### What You Earn

| Source | Amount |
|--------|--------|
| TX Fees | 100% of fees from blocks you build |
| Node Shares | Up to 15 shares (5-4-3-2-1 system) |
| L2 Fees | If running Ghost Pay |

### Monitor Your Node

```bash
# Node status
ghost-cli status

# Connected miners
ghost-cli miner list

# Consensus peers
ghost-cli consensus peers

# Your capabilities
ghost-cli capabilities status
```

---

## For Ghost Pay Users

### Setup Wallet

1. **Download Ghost Pay wallet** (when available)
2. **Generate Ghost Keys**
3. **Back up your keys** (critical!)

### Your Ghost ID

```
ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
```

Share this to receive payments. Each payment goes to a unique address.

### Deposit Funds

**Option 1: Wraith (Private)**
```
1. Open wallet
2. Select "Deposit via Wraith"
3. Choose denomination and anonymity tier
4. Send BTC to provided address
5. Wait for mixing session (hours to days)
6. Receive clean Ghost Lock
```

**Option 2: Direct (Faster)**
```
1. Open wallet
2. Select "Direct Deposit"
3. Send BTC to provided address
4. Wait for 6 confirmations
5. Balance available in L2
```

### Send Payment

```
1. Enter recipient's Ghost ID
2. Enter amount
3. Confirm (ZK proof generated automatically)
4. Done! (~10 seconds)
```

### Withdraw to L1

```
1. Select "Withdraw"
2. Enter L1 destination address
3. Choose settlement class:
   - Express: ~6 hours, higher fee
   - Standard: ~24 hours, medium fee
   - Economy: ~7 days, lowest fee
4. Wait for reconciliation
5. Funds on L1
```

---

## Common Tasks

### Check Pool Status

```bash
ghost-cli status
```

### View Current Round

```bash
ghost-cli round current
```

### Check Pending Payouts

```bash
ghost-cli payout pending
```

### Export Data for Taxes

```bash
ghost-cli export payouts --address bc1q... --format csv --year 2024
```

---

## Network Ports

### Must Be Open (Firewall)

| Port | Purpose |
|------|---------|
| 3333 | Miner connections |
| 8080 | Verification API |
| 8555-8562 | P2P consensus (if node) |

### Internal Only

| Port | Purpose |
|------|---------|
| 38332 | Bitcoin Core RPC |
| 28332 | ZMQ notifications |

---

## Troubleshooting

### Miner Not Connecting

```
Check:
├── Correct pool URL (stratum+tcp://...)
├── Port 3333 accessible
├── Valid Bitcoin address in username
└── Network connectivity
```

### Node Not Earning Shares

```
Check:
├── Uptime ≥95%?
├── Capabilities properly configured?
├── Verification challenges passing?
└── At least 10 challenges completed?

Debug:
ghost-cli capabilities status
ghost-cli capabilities challenges
```

### L2 Transfer Stuck

```
Check:
├── Sufficient balance?
├── L2 network healthy?
├── Validators responding?

If stuck:
└── Wait for next epoch reconciliation
```

---

## Getting Help

- **Documentation**: [docs/protocols/](./README.md)
- **Issues**: https://github.com/bitcoin-ghost/ghost/issues
- **Community**: (links when available)

## Next Steps

- **Miners**: Just connect and start earning
- **Node Operators**: Read [Node Capabilities](NODE_CAPABILITIES.md) for maximizing rewards
- **L2 Users**: Read [Ghost Pay](GHOST_PAY.md) for full feature overview
- **Developers**: Read [Architecture](ARCHITECTURE.md) for system design
