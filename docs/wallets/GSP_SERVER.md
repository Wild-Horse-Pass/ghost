# GSP Server Guide

The Ghost Service Provider (GSP) enables light wallets to interact with the Bitcoin Ghost network without running a full node. This guide covers setting up and operating a GSP server.

## Overview

| Aspect | Details |
|--------|---------|
| **Purpose** | Serve light wallet clients |
| **Requirements** | Full node (ghostd) running |
| **Default Port** | 8900 (HTTP/WebSocket) |
| **Integration** | Built into ghostd (default enabled) |
| **Authentication** | WalletProof + JWT sessions |
| **Privacy** | BIP-157 filters (server can't track wallets) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           GSP SERVER                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│  │ Light       │     │ Light       │     │ Light       │               │
│  │ Wallet 1    │     │ Wallet 2    │     │ Wallet N    │               │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘               │
│         │ WSS              │ WSS              │ WSS                    │
│         └─────────────┬────┴────────────┬─────┘                        │
│                       ▼                 ▼                               │
│              ┌────────────────────────────────────┐                    │
│              │         GSP Module (:8900)         │                    │
│              │  ┌─────────┐  ┌─────────────────┐ │                    │
│              │  │  REST   │  │   WebSocket     │ │                    │
│              │  │  API    │  │   Server        │ │                    │
│              │  └────┬────┘  └────────┬────────┘ │                    │
│              │       │                │          │                    │
│              │  ┌────┴────────────────┴────┐    │                    │
│              │  │     Authentication       │    │                    │
│              │  │  (WalletProof + JWT)     │    │                    │
│              │  └──────────────────────────┘    │                    │
│              └───────────────┬──────────────────┘                    │
│                              │                                        │
│              ┌───────────────┴──────────────────┐                    │
│              │          ghostd Core              │                    │
│              │  ┌──────────┐  ┌──────────────┐  │                    │
│              │  │ Chain    │  │ BIP-157      │  │                    │
│              │  │ Manager  │  │ Filters      │  │                    │
│              │  └──────────┘  └──────────────┘  │                    │
│              │  ┌──────────┐  ┌──────────────┐  │                    │
│              │  │ Mempool  │  │ P2P Network  │  │                    │
│              │  └──────────┘  └──────────────┘  │                    │
│              └──────────────────────────────────┘                    │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

## GSP is Built Into ghostd

Starting with v1.4, GSP is integrated directly into `ghostd`. Every full node can serve light wallets by default - no separate binary needed.

### Why Built-In?

1. **Bootstrap Problem Solved**: If GSP were optional/separate, nobody would run it
2. **Network Effect**: More GSP servers = better light wallet experience
3. **Decentralization**: Light wallets can connect to any full node
4. **Simplicity**: One binary to run, one service to manage

## Quick Start

### 1. Start ghostd with GSP (Default)

GSP is enabled by default. Just start ghostd:

```bash
ghostd -daemon

# GSP server automatically starts on port 8900
```

### 2. Verify GSP is Running

```bash
# Check GSP health
curl http://localhost:8900/gsp/health

# Output:
# {"status":"ok","version":"1.0.0"}

# Get GSP info
curl http://localhost:8900/gsp/api/v1/info

# Output:
# {
#   "protocol_version": "1.0.0",
#   "network": "main",
#   "connections": 5,
#   "registered_wallets": 42,
#   "sync_status": "synced",
#   "uptime_secs": 3600
# }
```

### 3. Connect a Light Wallet

```bash
# Light wallet connects via WebSocket
ghost-light-wallet-cli connect --gsp ws://your-server:8900/gsp/ws/v1
```

## Configuration

### Basic Configuration

In `ghost.conf`:

```ini
# Enable GSP (default: 1)
gsp=1

# GSP port (default: 8900)
gspport=8900

# Maximum WebSocket connections (default: 100)
gspmaxconnections=100

# Enable rate limiting (default: 1)
gspratelimit=1
```

### Disable GSP

If you don't want to serve light wallets:

```ini
gsp=0
```

### Advanced Configuration

```ini
# GSP Settings
gsp=1
gspport=8900
gspmaxconnections=500
gspratelimit=1

# Required for GSP privacy features
blockfilterindex=basic
peerblockfilters=1

# Recommended for GSP performance
txindex=1
server=1

# RPC for administration
rpcuser=ghostrpc
rpcpassword=your-secure-password

# Network settings
listen=1
maxconnections=125
```

## API Reference

### REST Endpoints

#### Health Check

```
GET /gsp/health
```

Response:
```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

#### Server Info

```
GET /gsp/api/v1/info
```

Response:
```json
{
  "protocol_version": "1.0.0",
  "network": "main",
  "connections": 42,
  "registered_wallets": 156,
  "sync_status": "synced",
  "uptime_secs": 86400
}
```

#### Register Wallet

```
POST /gsp/api/v1/register
Content-Type: application/json

{
  "pubkey": "02abc123...",
  "signature": "3045...",
  "challenge": "random-challenge-string",
  "timestamp": 1706460000,
  "label": "My Wallet"
}
```

Response:
```json
{
  "wallet_id": "w_abc123...",
  "token": "eyJhbGciOiJIUzI1...",
  "expires_in": 86400
}
```

#### Create Session

```
POST /gsp/api/v1/session
Content-Type: application/json

{
  "wallet_id": "w_abc123...",
  "signature": "3045...",
  "challenge": "random-challenge-string",
  "timestamp": 1706460000
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1...",
  "expires_in": 86400
}
```

### BIP-157 Filter Endpoints (Privacy-Preserving)

These endpoints enable light wallets to scan for their transactions without revealing their addresses to the GSP.

#### Get Single Filter

```
GET /gsp/api/v1/filters/:height
```

Response:
```json
{
  "height": 850000,
  "block_hash": "00000000000000000002a7c...",
  "filter": "0a1b2c3d4e5f...",
  "filter_header": "abc123...",
  "filter_type": "basic"
}
```

#### Get Filter Batch

```
GET /gsp/api/v1/filters/batch?start=850000&count=100
```

Response:
```json
{
  "filter_type": "basic",
  "start": 850000,
  "count": 100,
  "tip_height": 850500,
  "filters": [
    {
      "height": 850000,
      "block_hash": "...",
      "filter": "...",
      "filter_header": "..."
    },
    ...
  ]
}
```

#### Get Filter Headers (Checkpoints)

```
GET /gsp/api/v1/filters/headers
```

Response:
```json
{
  "filter_type": "basic",
  "tip_height": 850500,
  "checkpoint_interval": 1000,
  "headers": [
    {"height": 0, "block_hash": "...", "filter_header": "..."},
    {"height": 1000, "block_hash": "...", "filter_header": "..."},
    ...
  ]
}
```

#### Get Block

```
GET /gsp/api/v1/block/:hash
```

Response:
```json
{
  "hash": "00000000000000000002a7c...",
  "height": 850000,
  "block": "0100000000000000...",
  "size": 1234567
}
```

### WebSocket API

Connect: `ws://localhost:8900/gsp/ws/v1`

#### Authentication

```json
{
  "type": "Authenticate",
  "token": "eyJhbGciOiJIUzI1..."
}
```

Response:
```json
{
  "type": "AuthResult",
  "success": true,
  "wallet_id": "w_abc123..."
}
```

#### Get Balance

```json
{
  "type": "GetBalance"
}
```

Response:
```json
{
  "type": "Balance",
  "confirmed": 100000000,
  "unconfirmed": 5000000,
  "l2_available": 50000000
}
```

#### Get UTXOs

```json
{
  "type": "GetUtxos",
  "min_confirmations": 1
}
```

Response:
```json
{
  "type": "Utxos",
  "utxos": [
    {
      "txid": "abc123...",
      "vout": 0,
      "amount": 100000000,
      "confirmations": 6,
      "script_pubkey": "5120..."
    }
  ]
}
```

#### Get Ghost Locks

```json
{
  "type": "GetGhostLocks"
}
```

Response:
```json
{
  "type": "GhostLocks",
  "locks": [
    {
      "lock_id": "lock_abc...",
      "amount": 1000000,
      "denomination": "small",
      "timelock": "6m",
      "expires_at": 1720000000,
      "confirmations": 100
    }
  ]
}
```

#### Subscribe to Updates

```json
{
  "type": "SubscribeBalance"
}
```

```json
{
  "type": "SubscribePayments"
}
```

#### Push Notifications

```json
{
  "type": "BalanceUpdate",
  "confirmed": 105000000,
  "unconfirmed": 0
}
```

```json
{
  "type": "PaymentReceived",
  "txid": "abc123...",
  "amount": 5000000,
  "confirmations": 0
}
```

### Instant Payment API

The GSP provides endpoints for instant (optimistic) payment support.

#### Check Instant Capability

```json
{
  "type": "CheckInstantCapability",
  "lock_id": "lock_abc123",
  "amount_sats": 50000
}
```

Response:
```json
{
  "type": "InstantCapabilityResult",
  "lock_id": "lock_abc123",
  "capable": true,
  "max_instant_sats": 100000,
  "confidence": 0.95,
  "valid_until_height": 847200,
  "conditions_met": 255,
  "conditions_failed": 0,
  "error": null
}
```

#### Subscribe to Lock State

Real-time updates when a lock's state changes (for instant payment monitoring):

```json
{
  "type": "SubscribeLockState",
  "lock_id": "lock_abc123"
}
```

Response (initial snapshot):
```json
{
  "type": "LockStateSubscribed",
  "lock_id": "lock_abc123",
  "snapshot": {
    "state": "Active",
    "balance_sats": 500000,
    "confirmations": 50,
    "jump_urgency": 0.05,
    "in_mempool": false,
    "pending_l2_sats": 0,
    "max_instant_sats": 100000,
    "current_height": 847100
  }
}
```

Push notification (on state change):
```json
{
  "type": "LockStateUpdate",
  "lock_id": "lock_abc123",
  "snapshot": {
    "state": "Active",
    "balance_sats": 495000,
    "confirmations": 51,
    "jump_urgency": 0.05,
    "in_mempool": false,
    "pending_l2_sats": 0,
    "max_instant_sats": 100000,
    "current_height": 847101
  },
  "change_type": "balance_change",
  "timestamp": 1706460000
}
```

Change types: `balance_change`, `state_transition`, `confirmation`, `jump_urgency`, `mempool_change`, `pending_l2_change`

#### Unsubscribe from Lock State

```json
{
  "type": "UnsubscribeLockState",
  "lock_id": "lock_abc123"
}
```

Response:
```json
{
  "type": "LockStateUnsubscribed",
  "lock_id": "lock_abc123"
}
```

#### Accept Instant Payment (Merchant)

```json
{
  "type": "AcceptInstantPayment",
  "sender_lock_id": "lock_abc123",
  "amount_sats": 5000,
  "proof": {
    "public_key": "02abc...",
    "signature": "3045...",
    "challenge": "merchant-challenge",
    "timestamp": 1706460000
  }
}
```

Response:
```json
{
  "type": "InstantPaymentAccepted",
  "payment_id": "0x1234abcd...",
  "sender_lock_id": "lock_abc123",
  "amount_sats": 5000,
  "settlement_block": 847201,
  "confidence": 0.97,
  "timestamp": 1706460000
}
```

Settlement notification (sent when payment settles):
```json
{
  "type": "InstantPaymentSettled",
  "payment_id": "0x1234abcd...",
  "settled_at_height": 847201,
  "success": true
}
```

### Instant Payment Conditions

The GSP evaluates 8 conditions for instant capability:

| Bit | Condition | Description |
|-----|-----------|-------------|
| 0 | ActiveState | Lock is in Active state |
| 1 | SufficientConfirmations | 6+ L1 confirmations |
| 2 | DenominationEligible | Micro/Tiny denomination |
| 3 | LowJumpUrgency | < 50% through rotation |
| 4 | RecoveryWindowSafe | > 50% recovery remaining |
| 5 | NoPendingL1 | No mempool transactions |
| 6 | NoPendingL2 | No pending L2 payments |
| 7 | SufficientBalance | Balance >= amount |

The `conditions_met` and `conditions_failed` fields are bitmaps of these conditions.

## Rate Limiting

GSP implements rate limiting to prevent abuse:

### Unauthenticated (per IP)

| Endpoint | Limit |
|----------|-------|
| `/register` | 10/hour |
| `/session` | 30/hour |
| `/health`, `/info` | 60/minute |
| Filter endpoints | 120/minute |

### Authenticated (per wallet)

| Operation | Limit |
|-----------|-------|
| `GetBalance` | 60/minute |
| `GetUtxos` | 30/minute |
| Filter downloads | 120/minute |
| `Subscribe*` | 10/minute |

## Privacy Model

GSP is designed to preserve user privacy:

### What GSP Knows

- Wallet public keys (for registration)
- When wallets connect/disconnect
- Aggregate query patterns

### What GSP Cannot Know

- Which addresses belong to which wallet
- Wallet balances (only aggregate queries)
- Transaction history
- Ghost Lock ownership

### How Privacy is Preserved

1. **BIP-157 Compact Block Filters**
   - Wallet downloads small filters (~4MB/year)
   - Scans filters locally for potential matches
   - Only requests blocks where filter matches
   - GSP sees block requests, not address queries

2. **No Address Indexing**
   - GSP doesn't index addresses to wallets
   - Balance queries use filters, not direct lookup
   - Ghost Locks are never linked to wallet IDs

3. **Ephemeral Sessions**
   - JWT tokens expire after 24 hours
   - Wallets can use different GSPs
   - No persistent tracking

## Monitoring

### RPC Commands

```bash
# GSP server info
ghost-cli getgspinfo

# Output:
# {
#   "enabled": true,
#   "port": 8900,
#   "connections": 42,
#   "registered_wallets": 156,
#   "uptime_secs": 86400,
#   "sync_status": "synced"
# }

# List connected clients
ghost-cli getgspclients

# Find other GSP nodes
ghost-cli getgspnodes 20
```

### Health Endpoint

```bash
# Continuous health monitoring
while true; do
  curl -s http://localhost:8900/gsp/health | jq .
  sleep 60
done
```

### Metrics

GSP exposes metrics at `/gsp/metrics`:

```
gsp_connections_total 1234
gsp_connections_current 42
gsp_registered_wallets 156
gsp_requests_total{endpoint="/register"} 500
gsp_requests_total{endpoint="/session"} 2000
gsp_websocket_messages_total 50000
gsp_filter_requests_total 10000
gsp_block_requests_total 500
```

## Performance Tuning

### For High Traffic

```ini
# ghost.conf
gspmaxconnections=1000
gspratelimit=1

# Increase system limits
# /etc/security/limits.conf
# ghost soft nofile 65535
# ghost hard nofile 65535

# Increase memory for filter cache
dbcache=8000
```

### Hardware Recommendations

| Load Level | RAM | CPU | Storage |
|------------|-----|-----|---------|
| Light (<100 clients) | 4GB | 2 cores | SSD |
| Medium (100-500) | 8GB | 4 cores | NVMe |
| Heavy (500+) | 16GB+ | 8 cores | NVMe RAID |

## Security

### TLS Configuration

For production, always use TLS:

```nginx
# Nginx reverse proxy with TLS
server {
    listen 443 ssl;
    server_name gsp.example.com;

    ssl_certificate /etc/letsencrypt/live/gsp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gsp.example.com/privkey.pem;

    location /gsp/ {
        proxy_pass http://127.0.0.1:8900;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Firewall

```bash
# Allow GSP port
sudo ufw allow 8900/tcp

# Or restrict to specific IPs
sudo ufw allow from 10.0.0.0/8 to any port 8900
```

### DoS Protection

```ini
# ghost.conf - enable rate limiting
gspratelimit=1
gspmaxconnections=100

# Fail2ban rule (optional)
# /etc/fail2ban/jail.d/ghostgsp.conf
```

## Troubleshooting

### GSP Not Starting

```bash
# Check if port is in use
ss -tlnp | grep 8900

# Check ghostd logs
tail -100 ~/.ghost/debug.log | grep -i gsp

# Verify config
grep gsp ~/.ghost/ghost.conf
```

### Clients Can't Connect

```bash
# Test connectivity
curl http://localhost:8900/gsp/health

# Check firewall
sudo ufw status

# Check GSP is bound to correct interface
# For external access, don't bind to 127.0.0.1
```

### Filter Index Missing

```bash
# Enable filter index in config
echo "blockfilterindex=basic" >> ~/.ghost/ghost.conf

# Restart and wait for index build
ghost-cli stop
ghostd -daemon

# Check indexing progress
ghost-cli getindexinfo
```

### High Memory Usage

```bash
# Reduce max connections
echo "gspmaxconnections=50" >> ~/.ghost/ghost.conf

# Reduce filter cache
echo "dbcache=2000" >> ~/.ghost/ghost.conf

# Restart
ghost-cli stop
ghostd -daemon
```

## P2P Discovery

Light wallets can discover GSP servers via P2P:

### How It Works

1. Node advertises `NODE_GSP` service flag
2. Light wallets query DNS seeds or known nodes
3. Filter responses by `NODE_GSP` capability
4. Connect to discovered GSP endpoints

### Finding GSP Nodes

```bash
# From ghostd
ghost-cli getgspnodes 20

# Output:
# [
#   {
#     "address": "1.2.3.4:8333",
#     "port": 8333,
#     "services": "000000000000100d",
#     "servicesnames": ["NETWORK", "WITNESS", "COMPACT_FILTERS", "GSP"],
#     "network": "ipv4",
#     "connected": true
#   },
#   ...
# ]
```

### Advertising Your GSP

Your node automatically advertises GSP capability when enabled. Ensure:

1. GSP is enabled (`gsp=1`)
2. Node is listening (`listen=1`)
3. Port 8900 is accessible externally
4. Block filter index is enabled (`blockfilterindex=basic`)

## Running a Public GSP

To run a GSP for the community:

### Requirements

1. Reliable server (99.9% uptime)
2. Fast internet (100Mbps+)
3. Static IP or domain
4. TLS certificate
5. Monitoring/alerting

### Best Practices

```ini
# Production ghost.conf
gsp=1
gspport=8900
gspmaxconnections=500
gspratelimit=1

blockfilterindex=basic
peerblockfilters=1
txindex=1

listen=1
maxconnections=125

# Logging
debug=gsp
debuglogfile=/var/log/ghostd/debug.log
```

### Announce Your GSP

Add to community lists:
- Ghost network documentation
- Community forums
- Social media

Light wallet developers can hardcode reliable GSP endpoints as fallbacks.

## Appendix: GSP Data Directory

```
~/.ghost/gsp/
├── wallets.db      # Registered wallets (SQLite)
└── sessions/       # Active session data
```

### Database Schema

```sql
-- wallets.db
CREATE TABLE wallets (
    id TEXT PRIMARY KEY,
    pubkey BLOB NOT NULL,
    label TEXT,
    created_at INTEGER,
    last_seen INTEGER,
    active INTEGER DEFAULT 1
);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    wallet_id TEXT,
    created_at INTEGER,
    expires_at INTEGER,
    FOREIGN KEY (wallet_id) REFERENCES wallets(id)
);
```
