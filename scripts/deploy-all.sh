#!/bin/bash
#
# Master deployment script for ghost load balancing system
#
# This script:
# 1. Deploys ghost-registry to web server
# 2. Updates all pool nodes with registry config
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          Ghost Load Balancing System Deployment              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Deploy registry to web server
echo "STEP 1: Deploying ghost-registry to web server..."
echo ""
bash "$SCRIPT_DIR/deploy-registry-to-web.sh"

echo ""
echo "Waiting for registry to be ready..."
sleep 5

# Test registry is up
echo "Testing registry..."
if curl -s http://83.136.255.218:8335/health | grep -q "ok"; then
    echo "✓ Registry is running!"
else
    echo "✗ Registry not responding. Check manually."
    exit 1
fi

echo ""

# Step 2: Update pool nodes
echo "STEP 2: Updating pool nodes with registry config..."
echo ""
bash "$SCRIPT_DIR/deploy-pool-registry-config.sh"

echo ""
echo "Waiting for nodes to register..."
sleep 10

# Check registered nodes
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Deployment Complete                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Registered nodes:"
curl -s http://83.136.255.218:8335/api/v1/nodes | jq '.data[] | {node_id: .node_id[0:16], host: .host, region: .region, healthy: .healthy}' 2>/dev/null || curl -s http://83.136.255.218:8335/api/v1/nodes
echo ""
echo "Region stats:"
curl -s http://83.136.255.218:8335/api/v1/regions | jq '.data' 2>/dev/null || curl -s http://83.136.255.218:8335/api/v1/regions
echo ""
echo "DNS will update within 60 seconds."
echo ""
echo "Test miner connection:"
echo "  dig pool.bitcoinghost.org"
echo "  dig eu.pool.bitcoinghost.org"
