# Bitcoin Ghost HTTP API Reference

This document describes all HTTP API endpoints available in Bitcoin Ghost services.

## Table of Contents

- [Ghost Pool (Verification Node)](#ghost-pool-verification-node)
- [Ghost Coordinator](#ghost-coordinator)
- [Ghost Pay (L2 Payments)](#ghost-pay-l2-payments)
- [Ghost GSP (Silent Payment Server)](#ghost-gsp-silent-payment-server)

---

## Ghost Pool (Verification Node)

The main pool node API for mining operations, status monitoring, and dashboard integration.

**Default Port:** `8080`

### Health & Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/node-info` | Node information |
| GET | `/ws` | WebSocket for real-time updates |

### Node Status (`/api/v1/node/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/node/status` | Node status (sync, uptime, connections) |
| GET | `/api/v1/node/info` | Detailed node information |
| GET | `/api/v1/node/shares` | Node share statistics |
| GET | `/api/v1/node/nickname` | Node nickname |

### Mining (`/api/v1/mining/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mining/status` | Mining status |
| GET | `/api/v1/mining/miners` | Connected miners list |
| GET | `/api/v1/mining/private` | Private mining info |
| GET | `/api/v1/mining/public` | Public mining info |

### Network (`/api/v1/network/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/network/peers` | Network peers |
| GET | `/api/v1/network/pool` | Pool status |
| GET | `/api/v1/network/treasury` | Treasury status |
| GET | `/api/v1/network/elder` | Elder node status |

### Mesh/Consensus (`/api/v1/mesh/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mesh/status` | Mesh/consensus status |

### Configuration (`/api/v1/config/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/config` | Configuration |
| GET | `/api/v1/config/full` | Full configuration |

### Resources (`/api/v1/resources/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/resources/status` | Resource usage (CPU, memory, disk) |

### BUDS Classification (`/api/v1/buds/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/buds/capabilities` | BUDS capabilities |
| GET | `/api/v1/buds/mempool` | BUDS mempool analysis |

### Ghost Pay Integration (`/api/v1/ghostpay/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ghostpay/status` | Ghost Pay status |
| GET | `/api/v1/locks` | Ghost Locks information |
| GET | `/api/v1/payments` | Payment information |
| GET | `/api/v1/settlement/status` | Settlement status |

### Swarm Management (`/api/v1/swarm/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/swarm` | Swarm status |
| GET | `/api/v1/swarm/nodes` | Swarm nodes |
| GET | `/api/v1/swarm/sync` | Swarm sync status |

### Rewards (`/api/v1/rewards/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/rewards/current` | Current round rewards |
| GET | `/api/v1/rewards/history` | Reward history |
| GET | `/api/v1/rewards/full` | Full rewards data |

### Wraith Protocol (`/api/v1/wraith/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/wraith/sessions` | Active Wraith mixing sessions |

### Watchdog (`/api/v1/watchdog/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/watchdog/status` | Watchdog status |
| GET | `/api/v1/watchdog/events` | Watchdog events |

### System Management (`/api/v1/system/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/system/version` | System version |
| GET | `/api/v1/system/updates` | Available updates |
| GET | `/api/v1/system/update` | Trigger update |
| GET | `/api/v1/system/rollback` | Rollback to previous version |

### Backup (`/api/v1/backup/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/backup/history` | Backup history |
| GET | `/api/v1/backup/export` | Export backup |
| GET | `/api/v1/backup/import` | Import backup |
| GET | `/api/v1/backup/verify` | Verify backup integrity |

### Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/logs` | Recent logs |

### Verification Challenges

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/verify/archive` | Verify archive challenge |
| GET | `/verify/policy` | Verify policy challenge |
| GET | `/verify/stratum` | Verify stratum challenge |
| GET | `/verify/ghostpay` | Verify Ghost Pay challenge |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/token` | Get authentication token |

### Admin (Protected)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/admin/test-consensus` | Test consensus (admin only) |

---

## Ghost Coordinator

Load balancer and miner assignment service.

**Default Port:** `8333`

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check (status, service, version) |

### Node Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/nodes` | List all registered nodes |
| GET | `/register` | Register or update a node |

**Register Parameters:**
- `node_id` - Unique node identifier
- `address` - Node address (host:port)
- `max_miners` - Maximum concurrent miners

### Miner Assignment

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/assign` | Find best node for miner |

**Assign Parameters:**
- `miner_ip` - Miner's IP address for latency optimization

**Response:**
```json
{
  "node_id": "node1",
  "address": "192.168.1.100:3333",
  "load": 0.45
}
```

### Latency Measurement

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/fire-ping` | Measure latency to node |

**Fire Ping Parameters:**
- `address` - Target node address
- `detailed` - Return detailed stats (default: false)

### Public API (`/api/v1/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/stats` | Aggregated pool statistics |
| GET | `/api/v1/nodes` | Node list for website display |

**Stats Response:**
```json
{
  "total_hashrate": 1250000000000,
  "active_miners": 342,
  "online_nodes": 4,
  "blocks_found_24h": 2,
  "current_difficulty": 52328312332
}
```

---

## Ghost Pay (L2 Payments)

Privacy-preserving Layer 2 payment service.

**Default Port:** `8800`

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/status` | Node status (keys, locks, sessions) |

### Key Management (`/api/v1/keys/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/keys/generate` | Generate new ghost keys |
| GET | `/api/v1/keys/export` | Export public keys |
| GET | `/api/v1/keys/ghost-id` | Get Ghost ID |

**Ghost ID Response:**
```json
{
  "ghost_id": "sp1q...",
  "scan_pubkey": "02...",
  "spend_pubkey": "03..."
}
```

### Lock Management (`/api/v1/locks/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/locks` | List all ghost locks |
| POST | `/api/v1/locks/create` | Create new ghost lock |
| GET | `/api/v1/locks/:id` | Get lock details |
| POST | `/api/v1/locks/:id/jump` | Initiate key rotation |

**Create Lock Request:**
```json
{
  "amount_sats": 100000,
  "timelock_blocks": 144,
  "recovery_pubkey": "02..."
}
```

### Wraith Sessions (`/api/v1/wraith/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/wraith/sessions` | List active mixing sessions |
| POST | `/api/v1/wraith/join` | Join or create session |
| GET | `/api/v1/wraith/sessions/:id` | Get session details |

**Join Session Request:**
```json
{
  "amount_sats": 100000,
  "session_id": "optional_existing_session"
}
```

### Payments (`/api/v1/payments/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/payments/address` | Derive silent payment address |
| POST | `/api/v1/payments/scan` | Queue transaction for scanning |

**Derive Address Request:**
```json
{
  "ghost_id": "sp1q...",
  "label": "optional_label"
}
```

### Withdrawals (`/api/v1/withdrawals/*`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/withdrawals` | List pending withdrawals |
| POST | `/api/v1/withdrawals/request` | Request withdrawal |
| GET | `/api/v1/withdrawals/:id` | Get withdrawal details |
| POST | `/api/v1/withdrawals/:id/cancel` | Cancel withdrawal |

**Withdrawal Request:**
```json
{
  "lock_id": "lock123",
  "destination": "bc1q...",
  "amount_sats": 50000
}
```

---

## Ghost GSP (Silent Payment Server)

Light wallet backend for Silent Payment scanning.

**Default Port:** `8900`

### Health & Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/info` | Server info (version, network, sync) |

**Info Response:**
```json
{
  "version": "1.4.0",
  "protocol": "gsp/1.0",
  "network": "mainnet",
  "sync_height": 850000,
  "is_synced": true,
  "connections": 8
}
```

### Wallet Registration

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/register` | Register wallet with proof of ownership |

**Register Request:**
```json
{
  "ghost_id": "sp1q...",
  "scan_pubkey": "02...",
  "signature": "schnorr_signature_hex",
  "message": "registration_challenge"
}
```

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/session` | Create authenticated session |

**Session Response:**
```json
{
  "token": "jwt_token",
  "expires_at": 1706500000
}
```

### WebSocket

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/WS | `/ws/v1` | WebSocket for real-time notifications |

**WebSocket Messages:**
```json
// Payment received
{
  "type": "payment_received",
  "txid": "abc123...",
  "amount_sats": 100000,
  "block_height": 850001
}

// Sync progress
{
  "type": "sync_progress",
  "height": 850000,
  "target": 850100
}
```

---

## Common Response Formats

### Success Response

```json
{
  "success": true,
  "data": { ... }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Description of the error"
  }
}
```

### Pagination

For endpoints returning lists:

```json
{
  "data": [...],
  "pagination": {
    "offset": 0,
    "limit": 100,
    "total": 1234
  }
}
```

---

## Authentication

### JWT Authentication (GSP)

```bash
# Get session token
curl -X POST http://localhost:8900/api/v1/session \
  -H "Content-Type: application/json" \
  -d '{"ghost_id": "sp1q...", "signature": "..."}'

# Use token
curl http://localhost:8900/api/v1/protected \
  -H "Authorization: Bearer <token>"
```

### Schnorr Signature Verification

Registration requires proof of key ownership via Schnorr signature:

```
message = "ghost-gsp-register:" + ghost_id + ":" + timestamp
signature = schnorr_sign(message, scan_secret_key)
```

---

## WebSocket Connections

### Pool Node WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  switch(msg.type) {
    case 'new_block':
      console.log('New block:', msg.height);
      break;
    case 'share_accepted':
      console.log('Share accepted');
      break;
  }
};
```

### GSP WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8900/ws/v1');

// Authenticate after connection
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'jwt_token'
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === 'payment_received') {
    console.log('Payment received:', msg.amount_sats, 'sats');
  }
};
```

---

## Rate Limiting

| Service | Limit |
|---------|-------|
| Ghost Pool | 100 requests/minute |
| Ghost Coordinator | 60 requests/minute |
| Ghost Pay | 30 requests/minute |
| Ghost GSP | 100 requests/minute |

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1706500060
```

---

## CORS

All services enable CORS with:
- Allowed origins: `*` (configurable)
- Allowed methods: `GET, POST, OPTIONS`
- Allowed headers: `Content-Type, Authorization`

---

## Example Requests

### Get Pool Stats

```bash
curl http://localhost:8333/api/v1/stats
```

### Get Node Status

```bash
curl http://localhost:8080/api/v1/node/status
```

### Create Ghost Lock

```bash
curl -X POST http://localhost:8800/api/v1/locks/create \
  -H "Content-Type: application/json" \
  -d '{
    "amount_sats": 100000,
    "timelock_blocks": 144
  }'
```

### Register with GSP

```bash
curl -X POST http://localhost:8900/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "ghost_id": "sp1q...",
    "scan_pubkey": "02...",
    "signature": "...",
    "message": "ghost-gsp-register:sp1q...:1706500000"
  }'
```
