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
//| FILE: DEPLOYMENT_RUNBOOK.md                                                                                          |
//|======================================================================================================================|
```

# Bitcoin Ghost v1.4 Deployment Runbook

This runbook provides step-by-step instructions for deploying Bitcoin Ghost in production.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Deployment Steps](#deployment-steps)
6. [Network Ports](#network-ports)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)
9. [MPC Ceremony](#mpc-ceremony)
10. [Maintenance](#maintenance)

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 500 GB SSD | 1 TB NVMe |
| Network | 100 Mbps | 1 Gbps |

### Software Requirements

- **Operating System**: Ubuntu 22.04 LTS or later (Debian-based recommended)
- **Rust**: 1.75+ (for building from source)
- **Bitcoin Core**: ghost-core (fork with Ghost extensions) or compatible Bitcoin Core 27+
- **SQLite**: 3.35+ (bundled)

### Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# Install Rust (if building from source)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

---

## Architecture Overview

### Standard Mode (Native Stratum)

```
                                    ┌─────────────────┐
                                    │   ghost-core    │
                                    │   (Bitcoin)     │
                                    └────────┬────────┘
                                             │ RPC + ZMQ
                              ┌──────────────┴──────────────┐
                              │                             │
                    ┌─────────▼─────────┐         ┌────────▼────────┐
                    │    ghost-pool     │         │  ghost-pay (L2) │
                    │  (Mining Pool)    │◄────────┤  (Optional)     │
                    └─────────┬─────────┘         └─────────────────┘
                              │ Stratum V1
                              │ (port 3333)
                              ▼
                    ┌─────────────────┐
                    │    SV1 Miners   │
                    └─────────────────┘
```

### TDP Mode (SRI Integration for Stratum V2)

For Stratum V2 support with full BUDS/policy control, use TDP mode with SRI:

```
                                    ┌─────────────────┐
                                    │   ghost-core    │
                                    │   (Bitcoin)     │
                                    └────────┬────────┘
                                             │ RPC + ZMQ
                                             ▼
                    ┌─────────────────────────────────────┐
                    │           ghost-pool                 │
                    │  (TDP Server - Noise encrypted)     │
                    │  --tdp-enabled --no-stratum         │
                    └─────────────────┬───────────────────┘
                                      │ TDP (port 8442)
                                      │ Block templates
                                      ▼
                    ┌─────────────────────────────────────┐
                    │        SRI Pool (pool-sv2)          │
                    │  (SV2 protocol distribution)        │
                    └─────────────────┬───────────────────┘
                                      │ SV2 (port 34256)
                                      ▼
                    ┌─────────────────────────────────────┐
                    │    SRI Translator (translator-sv1)  │
                    │         (SV1 ↔ SV2 proxy)           │
                    └─────────────────┬───────────────────┘
                                      │ SV1 (port 3333)
                                      ▼
                    ┌─────────────────────────────────────┐
                    │     Legacy Miners (BitAxe, etc.)    │
                    └─────────────────────────────────────┘
```

**TDP Mode Benefits:**
- Ghost-pool controls block template building (BUDS, mempool policy, custom block building)
- Full Stratum V2 protocol support via SRI
- Noise protocol encryption for template distribution
- Compatible with legacy SV1 miners through SRI translator

### Components

| Binary | Purpose | Required |
|--------|---------|----------|
| `ghost-pool` | Main mining pool node | Yes |
| `translator` | SV1 to SV2 protocol translator | If SV1 miners |
| `ghost-pay` | L2 instant payments | Optional |

---

## Installation

### Option 1: Build from Source

```bash
# Clone repository
git clone https://github.com/your-org/bitcoin-ghost.git
cd bitcoin-ghost

# Build release binaries
cargo build --release

# Binaries are in target/release/
ls -la target/release/ghost-pool
ls -la target/release/translator
ls -la target/release/ghost-pay
```

### Option 2: Pre-built Binaries

```bash
# Download latest release
wget https://releases.bitcoin-ghost.org/v1.4/ghost-pool-linux-amd64.tar.gz
tar -xzf ghost-pool-linux-amd64.tar.gz
sudo mv ghost-pool /opt/ghost/bin/
```

### Install ghost-core (Bitcoin Core Fork)

```bash
# Build ghost-core
cd ghost-core
./autogen.sh
./configure --with-gui=no
make -j$(nproc)
sudo make install
```

---

## Configuration

### Directory Structure

```
/etc/ghost/
├── config.toml          # Main configuration
├── node.key             # Ed25519 identity key (auto-generated)
└── policy.toml          # Custom policy (optional)

/var/lib/ghost/
├── data/
│   ├── ghost.db         # SQLite database
│   └── shares/          # Share data
└── logs/
```

### Generate Node Identity

```bash
# First run auto-generates identity key
ghost-pool --config /etc/ghost/config.toml --generate-key

# Or manually generate
ghost-pool keygen --output /etc/ghost/node.key
```

### Configuration File (`/etc/ghost/config.toml`)

```toml
# Bitcoin Ghost v1.4 Configuration

[identity]
key_path = "/etc/ghost/node.key"
display_name = "MyGhostNode"

[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = 8332                    # 38332 for signet
rpc_user = "ghostrpc"
rpc_password = "CHANGE_THIS_SECURE_PASSWORD"
network = "mainnet"                # mainnet, signet, testnet, regtest
zmq_hashblock = "tcp://127.0.0.1:28332"
zmq_hashtx = "tcp://127.0.0.1:28333"

[network]
public_address = "pool.example.com"
sv2_port = 34255                   # Stratum V2 miners
sv1_port = 3333                    # Stratum V1 (native)
http_port = 8080                   # API
max_miners = 1000
public_mining = true

[network.p2p]
share_propagation = 8555
block_announcement = 8556
consensus_voting = 8557
health_monitoring = 8558
discovery = 8559
elder_management = 8560
payout_proposal = 8561
payout_transaction = 8562

# Noise Protocol Encryption (P2P)
# Encrypts sensitive messages (shares, blocks, votes, payouts)
noise_enabled = true                           # Enable Noise encryption (default: true)
noise_port = 8563                              # TCP port for encrypted connections
noise_keypair_path = "/etc/ghost/noise.key"   # X25519 keypair (auto-generated if missing)
noise_required = false                         # Reject plaintext peers (set true after all nodes upgraded)

[policy]
profile = "permissive"             # bitcoin_pure, permissive, full_open

[storage]
db_path = "/var/lib/ghost/data"
wal_mode = true
archive_mode = false
prune_height = 0

[pool]
treasury_address = "bc1q..."      # Your treasury P2TR address
treasury_fee_percent = 1.0
min_payout_sats = 10000

# Optional: Ghost Pay L2
[ghost_pay]
enabled = false
virtual_block_secs = 10
epoch_blocks = 100
transfer_fee_bps = 10
wraith_enabled = true
wraith_fee_percent = 0.5

```

### TDP Mode Configuration (SRI Integration)

For Stratum V2 support via SRI, use TDP mode. This allows ghost-pool to control block template building (BUDS, mempool policy) while SRI handles the SV2 protocol.

**ghost-pool CLI flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--tdp-enabled` | false | Enable Template Distribution Protocol server |
| `--tdp-port` | 8442 | TDP server port (Noise encrypted) |
| `--no-stratum` | false | Disable native stratum server |

**Example TDP mode startup:**

```bash
ghost-pool --config /etc/ghost/config.toml \
           --tdp-enabled \
           --tdp-port 8442 \
           --no-stratum
```

**SRI Pool Configuration (`/etc/ghost/sri/pool-config.toml`):**

```toml
# Pool identity (Ed25519)
authority_public_key = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
authority_secret_key = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"

# Listen for SV2 connections (port 34256 to avoid conflict with ghost-pool's 34255)
listen_address = "0.0.0.0:34256"

# Coinbase reward destination
coinbase_reward_script = "addr(tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8)"

# Template Provider - connects to ghost-pool TDP server
[template_provider_type.Sv2Tp]
address = "127.0.0.1:8442"
# ghost-pool's TDP authority public key (from --tdp-enabled startup logs)
public_key = "9bRi8WdawJSqbhc4CjK9UDTCudaBxkNx1a6qaJ4yx5qjnrQgQDF"
```

**SRI Translator Configuration (`/etc/ghost/sri/translator-config.toml`):**

```toml
# Listen for SV1 miners (standard stratum port)
downstream_address = "0.0.0.0"
downstream_port = 3333

# Upstream SRI Pool connection
[[upstreams]]
address = "127.0.0.1"
port = 34256
authority_pubkey = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
```

### ghost-core Configuration (`bitcoin.conf`)

```ini
# Bitcoin Ghost compatible configuration

# Network
server=1
txindex=1

# RPC
rpcuser=ghostrpc
rpcpassword=CHANGE_THIS_SECURE_PASSWORD
rpcallowip=127.0.0.1
rpcbind=127.0.0.1

# ZMQ (required for real-time updates)
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashtx=tcp://127.0.0.1:28333

# Mining
blockmaxweight=4000000

# Performance
dbcache=4096
maxconnections=125
```

---

## Deployment Steps

### Step 1: Prepare System

```bash
# Create ghost user
sudo useradd -r -s /bin/false ghost

# Create directories
sudo mkdir -p /etc/ghost /var/lib/ghost/data /var/log/ghost
sudo chown -R ghost:ghost /etc/ghost /var/lib/ghost /var/log/ghost
sudo chmod 700 /etc/ghost
```

### Step 2: Deploy Configuration

```bash
# Copy configuration
sudo cp config.toml /etc/ghost/config.toml
sudo chmod 600 /etc/ghost/config.toml
sudo chown ghost:ghost /etc/ghost/config.toml

# Validate configuration
ghost-pool --config /etc/ghost/config.toml --validate
```

### Step 3: Create Systemd Service

Create `/etc/systemd/system/ghost-pool.service`:

```ini
[Unit]
Description=Bitcoin Ghost Mining Pool
After=network.target bitcoind.service
Wants=bitcoind.service

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/ghost-pool --config /etc/ghost/config.toml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ghost /var/log/ghost

# Resource limits
LimitNOFILE=65535
MemoryLimit=8G

[Install]
WantedBy=multi-user.target
```

### Step 4: Start Services

```bash
# Reload systemd
sudo systemctl daemon-reload

# Start Bitcoin Core first
sudo systemctl start bitcoind
sudo systemctl status bitcoind

# Wait for Bitcoin Core to sync (check progress)
bitcoin-cli getblockchaininfo | jq '.verificationprogress'

# Start Ghost Pool
sudo systemctl start ghost-pool
sudo systemctl enable ghost-pool

# Check status
sudo systemctl status ghost-pool
```

### Step 5: Verify Deployment

```bash
# Check logs
journalctl -u ghost-pool -f

# Test API
curl http://localhost:8080/api/v1/status

# Check miner connectivity
curl http://localhost:8080/api/v1/miners
```

---

## Network Ports

### Inbound Ports (Must be open)

| Port | Protocol | Purpose |
|------|----------|---------|
| 34255 | TCP | Native Stratum (ghost-pool) |
| 34256 | TCP | SV2 miners/translators (SRI pool, TDP mode) |
| 3333 | TCP | SV1 miners (SRI translator, TDP mode) |
| 8080 | TCP | HTTP API |
| 8442 | TCP | TDP server (Noise encrypted, TDP mode) |
| 8555-8562 | TCP | P2P consensus mesh (ZMQ) |
| 8563 | TCP | P2P encrypted channel (Noise Protocol) |

### Internal Only (Localhost)

| Port | Purpose |
|------|---------|
| 8332 | Bitcoin RPC (mainnet) |
| 38332 | Bitcoin RPC (signet) |
| 28332 | ZMQ hashblock |
| 28333 | ZMQ hashtx |

---

## DNS Configuration for Regional Endpoints

Ghost Pool uses regional subdomains for miner routing. Miners connect to the nearest region for lowest latency.

### Required DNS Records

Create A records for each regional subdomain pointing to your pool nodes:

```dns
# Regional stratum endpoints
eu.pool.bitcoinghost.org      A    <EU_NODE_IP>
us.pool.bitcoinghost.org      A    <US_NODE_IP>
asia.pool.bitcoinghost.org    A    <ASIA_NODE_IP>

# For multiple nodes per region (DNS round-robin)
eu.pool.bitcoinghost.org      A    <EU_NODE_1_IP>
eu.pool.bitcoinghost.org      A    <EU_NODE_2_IP>
```

### Regional Endpoint Reference

| Region | Subdomain | SV1 Port | SV2 Port |
|--------|-----------|----------|----------|
| Europe | `eu.pool.bitcoinghost.org` | 3333 | 34255 |
| North America | `us.pool.bitcoinghost.org` | 3333 | 34255 |
| Asia-Pacific | `asia.pool.bitcoinghost.org` | 3333 | 34255 |

### Miner Configuration Example

```
URL:      stratum+tcp://eu.pool.bitcoinghost.org:3333
Username: bc1qYourAddress.worker1
Password: x
```

### HTTPS for Node Finder

The website includes a Node Finder tool (`/node-finder.html`) that discovers pool nodes and tests latency.
For this to work:

1. Enable CORS on the HTTP API (already enabled by default)
2. Configure HTTPS with valid SSL certificates
3. Ensure port 8080 is accessible from the internet

The Node Finder uses `https://<node>/health` and `/api/v1/node/public-info` endpoints.

### Firewall Configuration (UFW)

```bash
# Allow Stratum ports
sudo ufw allow 34255/tcp comment "Ghost SV2"
sudo ufw allow 3333/tcp comment "Ghost SV1"

# Allow HTTP API (consider restricting to management IPs)
sudo ufw allow 8080/tcp comment "Ghost API"

# Allow P2P mesh (ZMQ)
sudo ufw allow 8555:8562/tcp comment "Ghost P2P ZMQ"

# Allow P2P encrypted channel (Noise Protocol)
sudo ufw allow 8563/tcp comment "Ghost P2P Noise"

# Reload
sudo ufw reload
```

---

## Monitoring

### Health Checks

```bash
# Basic health check (returns wrapped response)
curl -s http://localhost:8080/health | jq

# Expected response:
# {
#   "signed": true,
#   "response": {
#     "node_id": "abc123...",
#     "version": "1.4.0",
#     "capabilities": [...],
#     "uptime_secs": 86400,
#     "block_height": 820000,
#     "round_id": 12345,
#     "miner_count": 42,
#     "peer_count": 7
#   }
# }

# Extract just the response data:
curl -s http://localhost:8080/health | jq '.response'
```

### Key Metrics to Monitor

| Metric | Warning Threshold | Critical Threshold |
|--------|-------------------|-------------------|
| Block height lag | >3 blocks behind | >6 blocks behind |
| Miner connections | <10% of capacity | <5% of capacity |
| Share rate | <50% of expected | <25% of expected |
| Memory usage | >80% limit | >95% limit |
| Disk usage | >80% capacity | >95% capacity |

### Log Analysis

```bash
# Check for errors
journalctl -u ghost-pool --since "1 hour ago" | grep -i error

# Check consensus participation
journalctl -u ghost-pool | grep -i "consensus\|vote"

# Check share submissions
journalctl -u ghost-pool | grep -i "share accepted"
```

---

## Troubleshooting

### Common Issues

#### Bitcoin RPC Connection Failed

```bash
# Verify Bitcoin Core is running
bitcoin-cli getblockchaininfo

# Check RPC credentials
curl --user ghostrpc:password -d '{"method":"getblockcount"}' http://127.0.0.1:8332/

# Verify config matches
grep rpc /etc/ghost/config.toml
grep rpc ~/.bitcoin/bitcoin.conf
```

#### ZMQ Not Working

```bash
# Verify ZMQ is enabled in Bitcoin Core
bitcoin-cli getzmqnotifications

# Test ZMQ manually
python3 -c "
import zmq
ctx = zmq.Context()
sock = ctx.socket(zmq.SUB)
sock.connect('tcp://127.0.0.1:28332')
sock.setsockopt_string(zmq.SUBSCRIBE, 'hashblock')
print('Waiting for block...')
print(sock.recv())
"
```

#### Miners Can't Connect

```bash
# Check port is listening
ss -tlnp | grep 34255

# Check firewall
sudo ufw status | grep 34255

# Test connectivity externally
nc -zv pool.example.com 34255
```

#### Database Locked

```bash
# Check for stale lock
lsof /var/lib/ghost/data/ghost.db

# If stuck, restart service
sudo systemctl restart ghost-pool
```

### Emergency Procedures

#### Graceful Shutdown

```bash
# Stop accepting new miners
curl -X POST http://localhost:8080/api/v1/admin/drain

# Wait for current round to complete
sleep 60

# Stop service
sudo systemctl stop ghost-pool
```

#### Database Recovery

```bash
# Stop service
sudo systemctl stop ghost-pool

# Backup current database
cp /var/lib/ghost/data/ghost.db /var/lib/ghost/data/ghost.db.bak

# Check database integrity
sqlite3 /var/lib/ghost/data/ghost.db "PRAGMA integrity_check"

# If corrupted, restore from backup
cp /var/lib/ghost/data/ghost.db.backup /var/lib/ghost/data/ghost.db

# Start service
sudo systemctl start ghost-pool
```

---

## MPC Ceremony

### Overview

The MPC (Multi-Party Computation) ceremony generates ZK proof parameters. The first 101 nodes to contribute become elders. Only one honest participant is needed for security (1-of-N).

### Genesis Node Startup

**Only VM1 (genesis node) runs with the `--genesis` flag.** This generates the initial parameters and claims position 1.

```bash
# VM1 only
ghost-pool --config /etc/ghost/config.toml --genesis
```

### Startup Order (Critical)

1. Start VM1 (genesis node) first
2. Wait 60 seconds for genesis parameters to initialize
3. Start VM2, VM3, VM4 **without** `--genesis`

```bash
# VM2-4 (non-genesis nodes)
ghost-pool --config /etc/ghost/config.toml
```

**Warning**: If all nodes run with `--genesis`, they each independently generate genesis params and all try to claim position 1, causing UNIQUE constraint failures.

VM2-4 have systemd drop-in overrides at `/etc/systemd/system/ghost-pool.service.d/` that ensure the `--genesis` flag is not present.

### MPC State Wipe

To reset MPC state on a node (e.g., after a failed ceremony or for testing):

```bash
# 1. Stop the service
sudo systemctl stop ghost-pool

# 2. Wait for process to fully exit
sleep 5
sudo kill -9 $(pgrep ghost-pool) 2>/dev/null

# 3. Wipe the database (runs as ghost user)
sudo rm -f /home/ghost/.ghost/ghost.db

# 4. Wipe MPC parameters
sudo rm -rf /home/ghost/.ghost/mpc_params/

# 5. Restart the service
sudo systemctl start ghost-pool
```

**Note**: The database path is `/home/ghost/.ghost/ghost.db` (NOT `/root/.ghost/ghost.db`) because the service runs as the `ghost` user.

### MPC Parameter Lifecycle

```
Genesis node starts with --genesis
├── Generates initial parameters (position 1)
├── Parameters stored in /home/ghost/.ghost/mpc_params/
└── Broadcasts availability to peers

Other nodes start without --genesis
├── Discover existing ceremony via P2P
├── Fetch parameters from /api/v1/mpc/contributors
├── Contribute (requires 67% BFT approval from existing contributors)
└── Updated parameters stored locally

After 101 contributions → parameters ossify permanently
```

---

## Maintenance

### Regular Tasks

| Task | Frequency | Command |
|------|-----------|---------|
| Check logs for errors | Daily | `journalctl -u ghost-pool --since "24 hours ago" \| grep error` |
| Verify backups | Weekly | Check backup integrity |
| Update software | Monthly | `cargo build --release` |
| Review security logs | Weekly | Check for suspicious activity |

### Backup Procedures

```bash
# Backup script (/etc/cron.daily/ghost-backup)
#!/bin/bash
DATE=$(date +%Y%m%d)
BACKUP_DIR=/var/backup/ghost

# Stop service for consistent backup
systemctl stop ghost-pool

# Backup database
sqlite3 /var/lib/ghost/data/ghost.db ".backup '$BACKUP_DIR/ghost-$DATE.db'"

# Backup configuration
cp -r /etc/ghost $BACKUP_DIR/config-$DATE/

# Backup identity key
cp /etc/ghost/node.key $BACKUP_DIR/node-$DATE.key

# Restart service
systemctl start ghost-pool

# Clean old backups (keep 7 days)
find $BACKUP_DIR -mtime +7 -delete
```

### Upgrade Procedure

```bash
# 1. Announce maintenance window

# 2. Stop accepting new work
curl -X POST http://localhost:8080/api/v1/admin/drain

# 3. Wait for round completion
sleep 120

# 4. Stop service
sudo systemctl stop ghost-pool

# 5. Backup
/etc/cron.daily/ghost-backup

# 6. Deploy new binary
sudo cp target/release/ghost-pool /opt/ghost/bin/ghost-pool

# 7. Validate config (new version may have changes)
ghost-pool --config /etc/ghost/config.toml --validate

# 8. Start service
sudo systemctl start ghost-pool

# 9. Verify health
curl http://localhost:8080/api/v1/health
```

---

## Support

- **Documentation**: https://docs.bitcoin-ghost.org
- **Issues**: https://github.com/your-org/bitcoin-ghost/issues
- **Security**: security@bitcoin-ghost.org

---

*Last Updated: 2026-01-23*
