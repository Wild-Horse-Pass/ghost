# Ghost Service Protocol (GSP)

GSP is a light wallet protocol for Ghost that enables mobile and web wallets to interact with the Ghost network without running a full node.

## Overview

GSP provides:
- **HTTP REST API** for wallet registration, authentication, and queries
- **WebSocket API** for real-time notifications and subscriptions
- **BIP-157/158 Block Filters** for privacy-preserving transaction queries
- **JWT Authentication** for secure session management

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Light Wallet                          │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTPS / WSS
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                      GSP Server                             │
├─────────────────────────────────────────────────────────────┤
│  HTTP Endpoints:                                            │
│  - /gsp/health          - Health check                      │
│  - /gsp/api/v1/info     - Server info                       │
│  - /gsp/api/v1/register - Wallet registration               │
│  - /gsp/api/v1/session  - Session creation                  │
│  - /gsp/api/v1/filters/* - BIP-157 block filters           │
│  - /gsp/api/v1/block/*  - Block retrieval                   │
├─────────────────────────────────────────────────────────────┤
│  WebSocket: /gsp/ws/v1                                      │
│  - Real-time block notifications                            │
│  - Balance update subscriptions                             │
│  - Ghost Lock state changes                                 │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

GSP is enabled by default. Configuration options in `ghost.conf`:

```ini
# GSP port (default: 8900)
gspport=8900

# Maximum WebSocket connections (default: 100)
gspmaxconnections=100

# Enable rate limiting (default: 1)
gspratelimit=1
```

**Important**: GSP requires the block filter index to be enabled:

```ini
blockfilterindex=basic
```

## API Reference

### HTTP Endpoints

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
  "network": "mainnet",
  "connections": 5,
  "registered_wallets": 42,
  "sync_status": "synced",
  "uptime_secs": 3600
}
```

#### Wallet Registration
```
POST /gsp/api/v1/register
Content-Type: application/json

{
  "pubkey": "<hex-encoded-compressed-pubkey>",
  "signature": "<hex-encoded-schnorr-signature>",
  "challenge": "GSP-AUTH:<wallet_id>:<timestamp>",
  "timestamp": 1706700000,
  "label": "My Wallet"
}
```

Response:
```json
{
  "wallet_id": "abc123...",
  "token": "<jwt-token>"
}
```

#### Session Creation
```
POST /gsp/api/v1/session
Content-Type: application/json

{
  "wallet_id": "abc123...",
  "signature": "<hex-encoded-schnorr-signature>",
  "challenge": "GSP-AUTH:<wallet_id>:<timestamp>",
  "timestamp": 1706700000
}
```

Response:
```json
{
  "token": "<jwt-token>",
  "expires_at": 1706786400
}
```

#### Block Filter (BIP-157)
```
GET /gsp/api/v1/filters/:height
```
Response:
```json
{
  "height": 100000,
  "block_hash": "0000000000003a5c...",
  "filter": "<hex-encoded-filter>",
  "filter_header": "<hex-encoded-header>",
  "filter_type": "basic"
}
```

#### Block Filter Headers (Checkpoints)
```
GET /gsp/api/v1/filters/headers
```
Response:
```json
{
  "filter_type": "basic",
  "tip_height": 100000,
  "checkpoint_interval": 1000,
  "headers": [
    {"height": 0, "block_hash": "...", "filter_header": "..."},
    {"height": 1000, "block_hash": "...", "filter_header": "..."}
  ]
}
```

#### Batch Filter Download
```
GET /gsp/api/v1/filters/batch?start=1000&count=100
```
Response:
```json
{
  "start_height": 1000,
  "count": 100,
  "filters": [
    {"height": 1000, "filter": "...", "filter_header": "..."},
    {"height": 1001, "filter": "...", "filter_header": "..."}
  ]
}
```

#### Block Retrieval
```
GET /gsp/api/v1/block/:hash
```
Response:
```json
{
  "hash": "0000000000003a5c...",
  "height": 100000,
  "block": "<hex-encoded-block>",
  "size": 1234567
}
```

### WebSocket Protocol

Connect to: `ws://hostname:8900/gsp/ws/v1`

#### Message Format
```json
{
  "type": <message_type_number>,
  "id": "<optional_request_id>",
  "payload": { ... }
}
```

#### Message Types

| Type | Name | Direction | Description |
|------|------|-----------|-------------|
| 1 | Authenticate | C→S | Authenticate with JWT token |
| 2 | GetBalance | C→S | Query wallet balance |
| 3 | GetUtxos | C→S | Query wallet UTXOs |
| 6 | GetBlockFilter | C→S | Query block filter |
| 7 | GetBlock | C→S | Query block data |
| 10 | SubscribeBalance | C→S | Subscribe to balance updates |
| 11 | SubscribePayments | C→S | Subscribe to payment notifications |
| 20 | Unsubscribe | C→S | Unsubscribe from notifications |
| 30 | Ping | C→S | Keep-alive ping |
| 101 | AuthResult | S→C | Authentication result |
| 102 | BalanceResult | S→C | Balance query result |
| 130 | Pong | S→C | Keep-alive pong |
| 201 | BalanceUpdate | S→C | Push: Balance changed |
| 202 | PaymentReceived | S→C | Push: Payment received |
| 204 | NewBlock | S→C | Push: New block connected |
| 255 | Error | S→C | Error response |

#### Example: Authentication
```json
// Request
{
  "type": 1,
  "id": "auth-1",
  "payload": {
    "token": "<jwt-token>"
  }
}

// Response
{
  "type": 101,
  "id": "auth-1",
  "success": true,
  "wallet_id": "abc123..."
}
```

#### Example: Subscribe to Balance Updates
```json
// Request
{
  "type": 10,
  "id": "sub-1"
}

// Response
{
  "type": 110,
  "id": "sub-1",
  "success": true,
  "subscription": "SubscribeBalance"
}

// Push notification (later)
{
  "type": 201,
  "payload": {
    "wallet_id": "abc123...",
    "confirmed": 1000000,
    "unconfirmed": 50000
  }
}
```

## Authentication Flow

1. **Wallet Registration** (one-time):
   - Client generates a key pair
   - Client signs a challenge message: `GSP-AUTH:<wallet_id>:<timestamp>`
   - Server verifies signature and stores wallet registration
   - Server returns a JWT token

2. **Session Creation** (on reconnect):
   - Client signs a new challenge with existing key
   - Server verifies signature against registered wallet
   - Server returns a new JWT token

3. **API Requests**:
   - Include JWT in `Authorization: Bearer <token>` header
   - Or for WebSocket, send `Authenticate` message after connect

## Privacy Considerations

GSP is designed with privacy in mind:

1. **BIP-157/158 Block Filters**: Wallets download compact block filters and scan locally instead of sending addresses to the server

2. **No Address Exposure**: The server never learns which addresses belong to a wallet

3. **Minimal Metadata**: Only wallet registration (public key) is stored server-side

4. **JWT Sessions**: Short-lived tokens minimize the window for token theft

## Testing

### Unit Tests
```bash
./bin/test_ghost --run_test=gsp_tests
```

### Manual Testing with curl

```bash
# Health check
curl http://localhost:8900/gsp/health

# Server info
curl http://localhost:8900/gsp/api/v1/info

# Get block filter at height 1000
curl http://localhost:8900/gsp/api/v1/filters/1000

# Get block by hash
curl http://localhost:8900/gsp/api/v1/block/0000000000000000000...
```

## Files

| File | Description |
|------|-------------|
| `src/gsp/gsp.h` | Main GSP server interface |
| `src/gsp/gsp.cpp` | HTTP handlers and server implementation |
| `src/gsp/gsp_auth.h` | JWT and wallet proof authentication |
| `src/gsp/gsp_auth.cpp` | Authentication implementation |
| `src/gsp/gsp_wallet.h` | Wallet registry interface |
| `src/gsp/gsp_wallet.cpp` | SQLite-backed wallet storage |
| `src/gsp/gsp_ws.h` | WebSocket protocol definitions |
| `src/gsp/gsp_ws.cpp` | WebSocket message handlers |
| `src/test/gsp_tests.cpp` | Unit tests |

## Building

GSP is built as part of ghost-core:

```bash
mkdir build && cd build
cmake ..
make
```

The GSP library is automatically linked when building `ghostd` and `ghost-node`.
