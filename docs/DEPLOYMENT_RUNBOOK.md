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
9. [Maintenance](#maintenance)

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

```
                                    ┌─────────────────┐
                                    │  Bitcoin Core   │
                                    │  (ghost-core)   │
                                    └────────┬────────┘
                                             │ RPC + ZMQ
                              ┌──────────────┴──────────────┐
                              │                             │
                    ┌─────────▼─────────┐         ┌────────▼────────┐
                    │    ghost-pool     │         │  ghost-pay (L2) │
                    │  (Mining Pool)    │◄────────┤  (Optional)     │
                    └─────────┬─────────┘         └─────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
   ┌────────▼────────┐ ┌──────▼──────┐ ┌───────▼───────┐
   │   translator    │ │  Stratum V2 │ │  P2P Mesh     │
   │   (SV1↔SV2)    │ │   Miners    │ │  (Consensus)  │
   └─────────────────┘ └─────────────┘ └───────────────┘
```

### Components

| Binary | Purpose | Required |
|--------|---------|----------|
| `ghost-pool` | Main mining pool node | Yes |
| `translator` | SV1 to SV2 protocol translator | If SV1 miners |
| `ghost-pay` | L2 instant payments | Optional |
| `ghost-coordinator` | Wraith Protocol coordinator | Optional |

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
ls -la target/release/ghost-coordinator
```

### Option 2: Pre-built Binaries

```bash
# Download latest release
wget https://releases.bitcoin-ghost.org/v1.4/ghost-pool-linux-amd64.tar.gz
tar -xzf ghost-pool-linux-amd64.tar.gz
sudo mv ghost-pool /usr/local/bin/
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
sv1_port = 3333                    # Stratum V1 (via translator)
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

# Optional: Wraith Coordinator
[coordinator]
port = 8333
heartbeat_secs = 30
fire_ping_timeout_ms = 5000
convergence_threshold = 0.67
```

### Bitcoin Core Configuration (`bitcoin.conf`)

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
ExecStart=/usr/local/bin/ghost-pool --config /etc/ghost/config.toml
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
| 34255 | TCP | Stratum V2 miners |
| 3333 | TCP | Stratum V1 miners (translator) |
| 8080 | TCP | HTTP API |
| 8555-8562 | TCP | P2P consensus mesh |

### Internal Only (Localhost)

| Port | Purpose |
|------|---------|
| 8332 | Bitcoin RPC (mainnet) |
| 38332 | Bitcoin RPC (signet) |
| 28332 | ZMQ hashblock |
| 28333 | ZMQ hashtx |

### Firewall Configuration (UFW)

```bash
# Allow Stratum ports
sudo ufw allow 34255/tcp comment "Ghost SV2"
sudo ufw allow 3333/tcp comment "Ghost SV1"

# Allow HTTP API (consider restricting to management IPs)
sudo ufw allow 8080/tcp comment "Ghost API"

# Allow P2P mesh
sudo ufw allow 8555:8562/tcp comment "Ghost P2P"

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
sudo cp target/release/ghost-pool /usr/local/bin/ghost-pool

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
