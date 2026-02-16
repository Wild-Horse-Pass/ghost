# Ghost Node Dashboard

Web-based dashboard for monitoring and managing Ghost Network nodes. Built with Next.js 14 and React.

## Overview

The dashboard provides:
- **Node Status** - Sync height, peer count, uptime, and service health
- **Mining** - Stratum connections, hashrate, shares, blocks found
- **Rewards** - Share breakdown (5-4-3-2-1 model), payout history, earnings projections
- **Ghost Pay (L2)** - Block height, epoch, wraith sessions, settlement status
- **Mesh Network** - Consensus status, peer connections, verification challenges
- **Swarm Management** - Multi-node fleet monitoring and alerts

## Architecture

```
+------------------+     +------------------+     +------------------+
|    Dashboard     |     |   ghost-node     |     |   ghost-pool     |
|    (Next.js)     | --> |   (Rust API)     | --> |   (Pool DB)      |
|    Port 3000     |     |   Port 8080      |     |   SQLite         |
+------------------+     +------------------+     +------------------+
```

The dashboard queries the ghost-node REST API, which in turn:
- Reads node configuration and status directly
- Queries the ghost-pool SQLite database for challenge stats and payouts
- Connects to ghost-pay-node for L2 status
- Aggregates data from configured swarm nodes

## Development

### Prerequisites
- Node.js 18+
- npm or bun

### Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the dashboard.

### Environment Variables

Create `.env.local` for local development:

```env
# API endpoint (defaults to localhost:8080)
NEXT_PUBLIC_API_URL=http://localhost:8080
```

### Build

```bash
# Production build
npm run build

# Start production server
npm start
```

## Pages

| Route | Description |
|-------|-------------|
| `/` | Overview with key metrics |
| `/mining` | Stratum mining status and connected miners |
| `/rewards` | Share breakdown, earnings, payout history |
| `/ghost-pay` | L2 network status, wraith sessions |
| `/operator/mesh` | BFT consensus and verification challenges |
| `/operator/rewards` | Detailed share contributions and network stats |
| `/operator/swarm` | Multi-node fleet management |
| `/network` | Pool-wide statistics and payout transparency |
| `/settings` | Node configuration |

## Share Model (5-4-3-2-1)

Nodes earn shares based on verified capabilities:

| Feature | Shares | Verification |
|---------|--------|--------------|
| Archive Mode | +5 | Random historical block challenges (95% pass rate) |
| Ghost Pay | +4 | L2 block challenges (90% pass rate) |
| Public Mining | +3 | Stratum port accessibility checks (95% pass rate) |
| Bitcoin Pure | +2 | Policy compliance challenges (95% pass rate) |
| Elder Status | +1 | First 101 registered nodes |

**Maximum: 15 shares per node**

## API Integration

The dashboard uses React Query for data fetching with automatic refresh:

```typescript
// Example: Fetch mesh status
const { data, isLoading } = useMeshStatus();
// Refreshes every 30 seconds

// Example: Fetch rewards with custom interval
const { data } = useRewards({ refetchInterval: 60_000 });
```

### Key API Endpoints

- `GET /api/v1/status` - Node status
- `GET /api/v1/mesh/status` - Consensus and challenge stats
- `GET /api/v1/rewards/full` - Complete rewards breakdown
- `GET /api/v1/rewards/node-history` - Payout history for this node
- `GET /api/v1/ghostpay/status` - L2 network status
- `GET /api/v1/swarm` - Fleet node status

## Deployment

### Systemd Service

The dashboard runs as a systemd service on Ghost nodes:

```ini
[Service]
ExecStart=/usr/bin/npm start
WorkingDirectory=/home/ghost/ghost/ghost-node/dashboard
User=ghost
```

### With ghost-node

When deployed alongside ghost-node, the dashboard is accessible at the node's IP on port 3000. Ensure the ghost-node API is running on port 8080.

## Technology Stack

- **Framework**: Next.js 14 (App Router)
- **UI**: Tailwind CSS, custom components
- **State**: React Query (TanStack Query)
- **Charts**: Recharts
- **Build**: Turbopack (dev), Webpack (prod)
