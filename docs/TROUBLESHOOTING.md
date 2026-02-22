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
//| FILE: TROUBLESHOOTING.md                                                                                             |
//|======================================================================================================================|

# Ghost Pool Operator Troubleshooting Guide

This guide helps operators diagnose and resolve common issues with Ghost Pool nodes.

## Quick Diagnostics

### Health Check

```bash
# Check node health via HTTP API
curl http://localhost:8080/health

# Expected response:
{
  "status": "healthy",
  "node_id": "abc123...",
  "version": "1.4.0",
  "uptime_secs": 86400,
  "block_height": 850000,
  "peer_count": 12,
  "miner_count": 50
}
```

### Key Metrics to Monitor

| Metric | Healthy Range | Warning |
|--------|---------------|---------|
| peer_count | > 3 | < 3 peers = network isolation risk |
| miner_count | > 0 | 0 miners = no hashpower connected |
| uptime_secs | continuous | restarts indicate instability |
| block_height | current chain tip | stale = sync issues |

## Common Issues

### 1. No Peers Connected (peer_count = 0)

**Symptoms:**
- `peer_count: 0` in health check
- Node not participating in consensus
- Shares not propagating to network

**Causes & Solutions:**

1. **Missing seed nodes configuration**
   ```bash
   # Check your config has seed_nodes defined
   grep -A5 "seed_nodes" /etc/ghost/config.toml
   ```

   Add seed nodes if missing:
   ```toml
   [network.p2p]
   seed_nodes = [
       "seed1.bitcoinghost.org:8559",
       "seed2.bitcoinghost.org:8559",
   ]
   ```

2. **Firewall blocking P2P ports**
   ```bash
   # Required P2P ports (default configuration)
   # 8555 - Share propagation
   # 8556 - Block announcements
   # 8557 - Consensus voting
   # 8558 - Health monitoring
   # 8559 - Peer discovery
   # 8560 - Elder management
   # 8561 - Payout proposals
   # 8562 - Payout transactions

   # Check if ports are open
   ss -tlnp | grep -E '855[5-9]|856[0-2]'

   # UFW example
   sudo ufw allow 8555:8562/tcp
   ```

3. **NAT/Router configuration**
   - Ensure ports 8555-8562 are forwarded to your node
   - Set `public_address` in config to your external IP/hostname

### 2. Miners Not Connecting

**Symptoms:**
- `miner_count: 0` in health check
- No share submissions in logs

**Causes & Solutions:**

1. **Stratum port not accessible**
   ```bash
   # Check Stratum is listening (default ports)
   # SV2: 34255, SV1: 3333
   ss -tlnp | grep -E '34255|3333'

   # Test connectivity
   nc -zv your-node-ip 3333
   ```

2. **Public mining disabled**
   ```toml
   # Ensure public_mining is true in config
   [network]
   public_mining = true
   ```

3. **Rate limiting too aggressive**
   ```bash
   # Check banned miners
   curl http://localhost:8080/stats | jq '.banned_miners'

   # If legitimate miners are banned, increase threshold
   [stratum]
   invalid_share_threshold = 20  # (default is 10)
   ```

### 3. Bitcoin Core Connection Issues

**Symptoms:**
- "RPC connection failed" errors
- Block height not updating
- Template generation failures

**Causes & Solutions:**

1. **Incorrect RPC credentials**
   ```bash
   # Test RPC connectivity
   curl --user ghostrpc:yourpassword \
        --data-binary '{"method":"getblockcount"}' \
        http://localhost:8332
   ```

2. **Bitcoin Core not fully synced**
   ```bash
   # Check sync status
   bitcoin-cli getblockchaininfo | grep -E 'blocks|headers|verificationprogress'

   # Wait for sync to complete (verificationprogress should be ~1.0)
   ```

3. **ZMQ not configured in Bitcoin Core**
   ```ini
   # Add to bitcoin.conf
   zmqpubhashblock=tcp://127.0.0.1:28332
   zmqpubhashtx=tcp://127.0.0.1:28333
   ```

### 4. Payout Issues

**Symptoms:**
- Miners not receiving payouts
- Payout proposals failing consensus

**Causes & Solutions:**

1. **Miner payout address not set**
   - Miners must provide address during Stratum authorize
   - Check database: `SELECT payout_address FROM miners WHERE miner_id = ?`

2. **Node payout address not configured**
   ```bash
   # Check node has payout address
   curl http://localhost:8080/node/info | jq '.payout_address'
   ```

   Configure in startup or via registration.

3. **Insufficient peers for consensus**
   - BFT requires 67% agreement
   - Need at least 3 elders online for consensus

4. **Treasury address invalid**
   ```toml
   # Must be a valid Taproot address (bc1p...)
   [pool]
   treasury_address = "bc1p..."
   ```

### 5. Database Issues

**Symptoms:**
- "Database locked" errors
- Slow query performance
- Disk space exhaustion

**Causes & Solutions:**

1. **Database locked**
   ```bash
   # Check for stale lock
   lsof /var/lib/ghost/data/ghost.db

   # If no process is using it, remove lock
   rm /var/lib/ghost/data/ghost.db-wal
   rm /var/lib/ghost/data/ghost.db-shm
   ```

2. **Need to vacuum**
   ```bash
   ghost-cli db vacuum
   ```

3. **Enable WAL mode (recommended)**
   ```toml
   [storage]
   wal_mode = true
   ```

4. **Disk space full**
   ```bash
   # Check usage
   df -h /var/lib/ghost

   # Trigger pruning
   ghost-cli db prune
   ```

### 6. Memory/CPU Issues

**Symptoms:**
- High memory usage
- Slow block processing
- OOM kills

**Causes & Solutions:**

1. **Too many concurrent connections**
   ```toml
   # Reduce max connections
   [network]
   max_miners = 500  # Default is 10000
   ```

2. **Archive mode on limited hardware**
   ```toml
   # Disable archive mode if not needed
   [storage]
   archive_mode = false
   ```

3. **Enable memory limits**
   ```bash
   # In systemd service file
   MemoryMax=4G
   MemoryHigh=3G
   ```

### 7. Consensus/Elder Issues

**Symptoms:**
- Not participating in voting
- "Not an elder" errors
- Elder bond not recognized

**Causes & Solutions:**

1. **Node not registered as elder**
   ```bash
   # Check elder status
   curl http://localhost:8080/node/info | jq '.is_elder, .elder_slot'
   ```

2. **Bond not confirmed**
   - Elder bond requires on-chain confirmation
   - Check transaction has sufficient confirmations (6+)

3. **Poor verification pass rate**
   - Elders must maintain >90% challenge pass rate
   - Check logs for failed verifications

### 8. TDP Mode / SRI Integration Issues

**Symptoms:**
- SRI Pool not receiving templates
- "Waiting for initial template" in SRI logs
- Noise handshake failures

**Causes & Solutions:**

1. **TDP server not started**
   ```bash
   # Verify TDP is enabled
   ghost-pool --help | grep tdp

   # Start with TDP enabled
   ghost-pool --tdp-enabled --tdp-port 8442 --no-stratum
   ```

2. **Public key mismatch**
   ```bash
   # Check ghost-pool's TDP authority public key in startup logs
   journalctl -u ghost-pool | grep "TDP authority public key"

   # Ensure SRI pool config has matching key
   grep public_key /etc/ghost/sri/pool-config.toml
   ```

3. **Port conflicts**
   ```bash
   # Check ports are available
   ss -tlnp | grep -E '8442|34255|34256|3333'

   # TDP mode should use:
   # - 8442: ghost-pool TDP server
   # - 34256: SRI pool (not 34255 - avoid conflict)
   # - 3333: SRI translator for SV1 miners
   ```

4. **SRI Pool stuck on "Waiting for initial template"**
   - Templates must be sent with `future_template: true` for initial registration
   - Check ghost-pool logs for template generation
   - Verify ghost-core RPC connection is working

5. **Noise handshake timeout**
   ```bash
   # Verify SRI can reach TDP port
   nc -zv localhost 8442

   # Check firewall
   sudo ufw status | grep 8442
   ```

6. **SV1 miners not connecting**
   ```bash
   # Check ghost-pool native stratum is listening
   ss -tlnp | grep 3333

   # Check stratum logs
   journalctl -u ghost-pool | grep stratum
   ```

## Log Analysis

### Key Log Patterns

```bash
# Watch for errors
journalctl -u ghost-pool -f | grep -E 'ERROR|WARN'

# Check consensus activity
journalctl -u ghost-pool -f | grep -E 'vote|proposal|consensus'

# Monitor share submissions
journalctl -u ghost-pool -f | grep -E 'share|submit'
```

### Common Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| "RPC connection refused" | Bitcoin Core not running | Start bitcoind |
| "Rate limited" | Too many requests | Wait or adjust limits |
| "Invalid share difficulty" | Miner misconfigured | Check miner stratum settings |
| "Consensus timeout" | Network partition | Check peer connectivity |
| "Template generation failed" | RPC issue | Check Bitcoin Core |
| "Noise handshake failed" | TDP key mismatch | Check public_key in SRI config |
| "Waiting for initial template" | SRI not receiving templates | Verify TDP port and key match |
| "Address already in use" | Port conflict | Use --tdp-port or adjust SRI ports |

## Monitoring Integration

### Prometheus Metrics

Ghost Pool exposes metrics at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

Key metrics:
- `ghost_pool_miners_connected` - Current miner count
- `ghost_pool_peers_connected` - Current peer count
- `ghost_pool_shares_submitted_total` - Total shares
- `ghost_pool_blocks_found_total` - Blocks found
- `ghost_pool_uptime_seconds` - Node uptime

### Health Check Script

```bash
#!/bin/bash
# health_check.sh

HEALTH=$(curl -s http://localhost:8080/health)
STATUS=$(echo $HEALTH | jq -r '.status')
PEERS=$(echo $HEALTH | jq -r '.peer_count')

if [ "$STATUS" != "healthy" ]; then
    echo "CRITICAL: Node unhealthy"
    exit 2
fi

if [ "$PEERS" -lt 3 ]; then
    echo "WARNING: Low peer count ($PEERS)"
    exit 1
fi

echo "OK: Node healthy, $PEERS peers"
exit 0
```

## Backup & Recovery

### Database Backup

```bash
# Create backup
ghost-cli db backup --path /backup/ghost-$(date +%Y%m%d).db

# Or manually with sqlite
sqlite3 /var/lib/ghost/data/ghost.db ".backup '/backup/ghost.db'"
```

### Recovery from Backup

```bash
# Stop the node
systemctl stop ghost-pool

# Restore database
cp /backup/ghost.db /var/lib/ghost/data/ghost.db

# Start the node
systemctl start ghost-pool
```

### Key Recovery

```bash
# Backup node keys
cp /etc/ghost/node.key /backup/

# Keys are critical for elder identity - store securely!
```

## Getting Help

If you're still having issues:

1. Check logs: `journalctl -u ghost-pool --since "1 hour ago"`
2. Review configuration: `ghost-cli config validate`
3. File an issue: https://github.com/bitcoin-ghost/ghost-pool/issues

Include in your report:
- Ghost Pool version
- Operating system
- Configuration (sanitized)
- Relevant log excerpts
- Steps to reproduce
