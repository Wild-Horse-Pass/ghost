# Mining Pool Load Balancing

This document describes the DNS-based load balancing system for Ghost mining pools, enabling miners to automatically connect to the nearest, healthiest pool node.

## Overview

The load balancing system routes miners to optimal pool nodes based on:
- **Geographic proximity** - miners connect to the nearest regional pool
- **Node health** - unhealthy nodes are automatically removed from rotation
- **Load distribution** - overloaded nodes are excluded until they recover

Key design principle: **No proxy in data path**. Miners connect directly to pool nodes after DNS resolution, ensuring minimal latency for share submission.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CONTROL PLANE                                    │
│                                                                          │
│   ghost-pool nodes              ghost-registry            Cloudflare    │
│   ┌──────────────┐              ┌─────────────┐          ┌───────────┐  │
│   │  EU Node     │──heartbeat──►│             │          │           │  │
│   │  US Node     │──every 30s──►│  Tracks     │─updates─►│   DNS     │  │
│   │  Asia Node   │─────────────►│  health &   │ every    │  Records  │  │
│   │  AU Node     │─────────────►│  load       │ 60s      │           │  │
│   └──────────────┘              └─────────────┘          └───────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                          DATA PLANE                                      │
│                                                                          │
│   Miner (Germany)                                                        │
│        │                                                                 │
│        │  1. DNS: pool.bitcoinghost.org                                  │
│        ▼                                                                 │
│   Cloudflare Load Balancer (geo-steering)                                │
│        │                                                                 │
│        │  2. Returns: 83.136.251.162 (EU node)                           │
│        ▼                                                                 │
│   Miner connects directly to EU node on port 34255                       │
│        │                                                                 │
│        ╠════════════ Stratum V2 (direct, ~5ms latency) ═════════════════╣│
│        │                                                                 │
│   ghost-pool (EU)                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### ghost-registry Service

The registry service (`bins/ghost-registry/`) is the control plane that:
- Receives node registrations and heartbeats
- Tracks node health and load metrics
- Manages Cloudflare DNS records automatically
- Provides API endpoints for monitoring

**API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/nodes/register` | POST | Node registration with signature |
| `/api/v1/nodes/heartbeat` | POST | Health/load updates |
| `/api/v1/nodes/{id}` | DELETE | Node deregistration |
| `/api/v1/nodes` | GET | List all nodes |
| `/api/v1/regions` | GET | Region statistics |
| `/health` | GET | Service health check |

### ghost-pool Nodes

Pool nodes automatically register with the registry on startup and send heartbeats every 30 seconds containing:
- Node ID (secp256k1 public key)
- Current miner count
- Load percentage
- CPU/memory usage
- Signature for authentication

### Cloudflare Integration

The system uses Cloudflare for DNS management:
- **Load Balancer** with geo-steering routes `pool.bitcoinghost.org` to regional pools
- **DNS A records** for regional subdomains (`eu.pool`, `us.pool`, etc.)
- **TCP health monitors** on Stratum ports (3333 for V1, 34255 for V2)
- **60-second TTL** enables fast failover

## Mining Ports

| Protocol | Port | Description |
|----------|------|-------------|
| Stratum V1 | 3333 | Legacy protocol, SV1→SV2 translator |
| Stratum V2 | 34255 | Native SV2 (recommended) |
| Stratum V2 (alt) | 4444 | Alternative SV2 port |

Miners can connect via:
```bash
# Stratum V1 (legacy miners)
stratum+tcp://pool.bitcoinghost.org:3333

# Stratum V2 (modern miners)
stratum+tcp://pool.bitcoinghost.org:34255
```

## DNS Structure

```
pool.bitcoinghost.org        → Cloudflare Load Balancer (geo-steering)
                               Routes to nearest regional pool

eu.pool.bitcoinghost.org     → A records: [healthy EU node IPs]
us.pool.bitcoinghost.org     → A records: [healthy US node IPs]
asia.pool.bitcoinghost.org   → A records: [healthy Asia node IPs]
au.pool.bitcoinghost.org     → A records: [healthy AU/Oceania node IPs]
```

## Load Distribution

### Multi-Node Regions

When a region has multiple nodes, the registry selects the best nodes for DNS:

1. Sort nodes by load (ascending)
2. Take top N nodes (configurable, default 50)
3. Update DNS A records for the region
4. DNS round-robin distributes miners across these nodes

```toml
[dns]
max_nodes_per_region = 50   # Maximum nodes in DNS per region
```

### Natural Load Balancing

```
Time 0:   node-1 (10% load) ← IN DNS
          node-2 (12% load) ← IN DNS
          node-3 (15% load) ← IN DNS
          node-4 (20% load) ← standby

          New miners connect, nodes fill up...

Time 5:   node-1 (35% load) ← removed from DNS
          node-2 (32% load) ← removed from DNS
          node-3 (30% load) ← IN DNS
          node-4 (20% load) ← IN DNS (now in top N)
```

## Load-Based Exclusion (Hysteresis)

To prevent flapping when nodes hover around load thresholds, the system uses hysteresis:

```toml
[health]
max_load_percent = 80       # Remove from DNS at this load
resume_load_percent = 70    # Re-add to DNS at this load
```

### State Transitions

```
                    ┌─────────────────┐
                    │   IN DNS        │
                    │ (normal state)  │
                    └────────┬────────┘
                             │
                    load >= 80%
                             │
                             ▼
                    ┌─────────────────┐
                    │   EXCLUDED      │
                    │ (out of DNS)    │
                    └────────┬────────┘
                             │
                    load < 70%
                             │
                             ▼
                    ┌─────────────────┐
                    │   IN DNS        │
                    │ (recovered)     │
                    └─────────────────┘
```

### Behavior by Load Range

| Load | If IN DNS | If EXCLUDED |
|------|-----------|-------------|
| < 70% | Stay in DNS | Re-add to DNS |
| 70-79% | Stay in DNS | Stay excluded |
| >= 80% | Remove from DNS | Stay excluded |

The 10% buffer zone prevents rapid on/off cycling.

## Failover

### Node Failure Detection

```
Time 0:00  - Node sends heartbeat, healthy=true
Time 0:30  - Node sends heartbeat, healthy=true
Time 1:00  - Node crashes, no heartbeat
Time 1:30  - Missed heartbeat (1 of 3)
Time 2:00  - Missed heartbeat (2 of 3)
Time 2:30  - Missed heartbeat (3 of 3) → marked unhealthy
Time 3:00  - Registry removes node from DNS
```

Configuration:
```toml
[health]
heartbeat_timeout_secs = 90      # Time before marking unhealthy
missed_heartbeats_threshold = 3  # Consecutive misses allowed
check_interval_secs = 30         # Health check frequency
```

### Failover Timeline

| Event | Time | Action |
|-------|------|--------|
| Node goes offline | T+0 | Last heartbeat received |
| Health check | T+30s | Missed heartbeat detected |
| Health check | T+60s | Second miss |
| Health check | T+90s | Third miss, node marked unhealthy |
| DNS update | T+90s | Node removed from DNS |
| DNS propagation | T+150s | Miners get new DNS (60s TTL) |

**Total failover time: ~2-3 minutes**

## Configuration

### Registry Service (`/etc/ghost/registry.toml`)

```toml
[server]
listen = "0.0.0.0:8335"
request_timeout_secs = 30
max_body_size = 1048576

[cloudflare]
enabled = true
zone_id = "your_zone_id"
api_token = "${CLOUDFLARE_API_TOKEN}"
base_domain = "bitcoinghost.org"

[dns]
ttl_seconds = 60
max_nodes_per_region = 50
update_interval_secs = 60
subdomain_prefix = "pool"

[health]
heartbeat_timeout_secs = 90
missed_heartbeats_threshold = 3
check_interval_secs = 30
max_load_percent = 80
resume_load_percent = 70

[database]
path = "/var/lib/ghost-registry/registry.db"
wal_mode = true
```

### Pool Node (`/etc/ghost/pool.toml`)

```toml
[registry]
url = "http://registry.bitcoinghost.org:8335"
region = "eu_west"              # or: us_east, asia_southeast, oceania
heartbeat_interval_secs = 30

[network]
public_address = "83.136.251.162"  # Node's public IP
```

### Supported Regions

| Region Code | Description | DNS Subdomain |
|-------------|-------------|---------------|
| `us_east` | US East Coast | us.pool |
| `us_west` | US West Coast | us.pool |
| `eu_west` | Western Europe | eu.pool |
| `eu_central` | Central Europe | eu.pool |
| `asia_southeast` | Southeast Asia | asia.pool |
| `asia_northeast` | Northeast Asia | asia.pool |
| `oceania` | Australia/NZ | au.pool |
| `south_america` | South America | sa.pool |
| `africa` | Africa | af.pool |

## Cloudflare Setup

### 1. Create Origin Pools

1. Go to Traffic > Load Balancing > Pools
2. Create a pool for each region (e.g., `eu-pool`, `us-pool`, `asia-pool`, `au-pool`)
3. Add origin servers (pool node IPs) to each pool

### 2. Create TCP Health Monitors

**Important:** Stratum uses raw TCP, not HTTP. You must use TCP monitors.

1. Go to Traffic > Load Balancing > Monitors
2. Create a TCP monitor for each port you want to health check:

**Stratum V1 Monitor:**
```
Type: TCP
Port: 3333
Interval: 60 seconds
Timeout: 5 seconds
Retries: 2
```

**Stratum V2 Monitor:**
```
Type: TCP
Port: 34255
Interval: 60 seconds
Timeout: 5 seconds
Retries: 2
```

3. Attach monitors to your origin pools

### 3. Create Load Balancer

1. Go to Traffic > Load Balancing > Load Balancers
2. Create a new Load Balancer:
   - Hostname: `pool.bitcoinghost.org`
   - Add all regional pools as origins
3. **IMPORTANT:** Enable the Load Balancer toggle on the right side (it's disabled by default!)

### 4. Configure Geo Steering

1. Select "Geo Steering" as the steering policy
2. Map regions to origin pools:
   - Western Europe → EU pool
   - Eastern North America → US pool
   - Southeast Asia → Asia pool
   - Oceania → AU pool
3. Set a fallback pool for regions without a specific mapping

### 5. Configure Session Affinity (Optional)

For consistent miner connections:
- Enable "Session Affinity" with IP-based stickiness
- This keeps miners on the same node during a session

### 6. Configure ECS (EDNS Client Subnet)

For accurate geo-location:
- Set Location Strategy to "Resolver GeoIP"
- Enable ECS preference as "Geo"

### Common Setup Issues

| Issue | Solution |
|-------|----------|
| Pools showing "0 of N healthy" | Ensure Load Balancer toggle is enabled |
| Health checks failing | Use TCP monitors (not HTTP) for Stratum ports |
| Miners not geo-routed | Verify geo-steering is configured, check fallback pool |

## Deployment

### Deploy Registry

```bash
# Build
cargo build --release -p ghost-registry

# Deploy to server
./scripts/deploy-registry-to-web.sh
```

### Deploy Pool Config to All Nodes

```bash
# Updates all pool nodes with registry configuration
./scripts/deploy-pool-registry-config.sh
```

### Full Deployment

```bash
# Deploys registry and updates all pool nodes
./scripts/deploy-all.sh
```

## Monitoring

### Node Status CLI

Node operators can check their pool's position in the load balancer:

```bash
# One-time status check
ghost-pool --config /etc/ghost/pool.toml --status

# Continuous monitoring (refresh every 5 seconds)
ghost-pool --config /etc/ghost/pool.toml --watch 5
```

**Example output:**
```
╔══════════════════════════════════════════════════════════════╗
║                    Ghost Pool Status                          ║
╚══════════════════════════════════════════════════════════════╝

Registry:    http://registry.bitcoinghost.org:8335
Node ID:     02a716..d0af5 (02a716669bb7f7eeae36002bcd3a7a648fbd2bf3980d80b155fcc22670369d0af5)

Status:      ● IN DNS (receiving miners)

┌─ Load Balancer Status ─────────────────────────────────────┐
│ Registered:        Yes                                     │
│ In DNS:            Yes                                     │
│ Healthy:           Yes                                     │
│ Accepting Miners:  Yes                                     │
└─────────────────────────────────────────────────────────────┘

┌─ Load & Ranking ────────────────────────────────────────────┐
│ Current Load:      45%                                      │
│ Region:            EuWest                                   │
│ Rank in Region:    2 of 4 (by load)                         │
│ Total in Region:   4 nodes (4 healthy)                      │
│ Last Heartbeat:    12s ago                                  │
└─────────────────────────────────────────────────────────────┘
```

### Check Registered Nodes

```bash
curl http://registry:8335/api/v1/nodes | jq
```

### Check Region Stats

```bash
curl http://registry:8335/api/v1/regions | jq
```

### Check DNS Resolution

```bash
# Main pool (should return nearest region)
dig pool.bitcoinghost.org

# Regional pools
dig eu.pool.bitcoinghost.org
dig us.pool.bitcoinghost.org
```

### Registry Logs

```bash
journalctl -u ghost-registry -f
```

## Security

### Node Authentication

All registration and heartbeat messages are signed with secp256k1:
- Node ID = public key (self-authenticating)
- Messages include timestamp (prevents replay attacks)
- Registry verifies signatures before accepting updates

### Rate Limiting

```toml
[health]
registration_rate_limit_secs = 300   # 1 registration per 5 min
max_timestamp_drift_secs = 60        # Reject stale messages
```

### Cloudflare API Token

- Scope token to DNS editing only
- Store in environment variable, not config files
- Rotate periodically

## Troubleshooting

### Node Not Appearing in DNS

1. Check node is registered: `curl registry:8335/api/v1/nodes`
2. Verify node is healthy: check `healthy: true`
3. Check load is below threshold: `load_percent < 80`
4. Check Cloudflare API logs on registry

### Cloudflare Load Balancer Not Working

1. **Check the Enable toggle** - Load Balancers are disabled by default. Look for the toggle on the right side of the Load Balancer dashboard.
2. **Verify pools show healthy origins** - Should show "N of N healthy", not "0 of N"
3. **Check health monitors are TCP** - Stratum doesn't speak HTTP; use TCP monitors on port 3333 or 34255
4. **Wait for health checks** - Initial health checks take 60-90 seconds

### Miners Going to Fallback Pool

1. Check if primary pool nodes are marked healthy in Cloudflare
2. Verify TCP health monitors can reach the Stratum port (firewall open?)
3. Check geo-steering configuration maps the miner's region to a pool

### Miners Not Routing to Nearest Node

1. Verify Cloudflare Load Balancer geo-steering is enabled
2. Check ECS is configured correctly
3. Test from different locations using VPN
4. Verify fallback pool isn't overriding geo-steering

### High Latency

1. Verify miners are connecting to regional pool (check IP)
2. Check DNS TTL is 60 seconds
3. Verify no proxy/VPN between miner and pool

### Health Checks Failing

1. Ensure firewall allows inbound TCP on ports 3333/34255 from Cloudflare IPs
2. Verify the Stratum service is actually running
3. Test locally: `nc -zv <node-ip> 3333`
