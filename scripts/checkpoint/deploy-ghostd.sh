#!/bin/bash
# Deploy ghostd to ghost-web VM for checkpoint serving.
# Run from the project root on the build machine.
set -euo pipefail

GHOST_WEB="83.136.255.218"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building ghostd ==="
cd "$PROJECT_ROOT/ghost-core"
cmake --build build/ --target ghostd -j"$(nproc)"

BINARY="$PROJECT_ROOT/ghost-core/build/bin/ghostd"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed, $BINARY not found"
    exit 1
fi
echo "Binary size: $(du -h "$BINARY" | cut -f1)"

echo "=== Deploying to ghost-web ($GHOST_WEB) ==="
scp "$BINARY" "$GHOST_WEB:/tmp/ghostd"
scp "$SCRIPT_DIR/ghostd.service" "$GHOST_WEB:/tmp/ghostd.service"
scp "$SCRIPT_DIR/install-ghostd.sh" "$GHOST_WEB:/tmp/install-ghostd.sh"
scp "$SCRIPT_DIR/generate-checkpoint.sh" "$GHOST_WEB:/tmp/generate-checkpoint.sh"
scp "$SCRIPT_DIR/ghost-checkpoint.timer" "$GHOST_WEB:/tmp/ghost-checkpoint.timer"
scp "$SCRIPT_DIR/ghost-checkpoint.service" "$GHOST_WEB:/tmp/ghost-checkpoint.service"

echo "=== Running install script ==="
ssh "$GHOST_WEB" "sudo bash /tmp/install-ghostd.sh"

echo "=== Waiting for RPC to come up ==="
for i in $(seq 1 30); do
    if ssh "$GHOST_WEB" "curl -s --user ghost:\$(grep rpcpassword /etc/ghost/ghostd-rpc.conf | cut -d= -f2) --data-binary '{\"jsonrpc\":\"1.0\",\"method\":\"getblockchaininfo\",\"params\":[]}' -H 'content-type:text/plain;' http://127.0.0.1:38332/ 2>/dev/null | grep -q signet"; then
        echo "ghostd RPC is up and syncing signet!"
        break
    fi
    echo "  Waiting for RPC... ($i/30)"
    sleep 10
done

echo "=== Deployment complete ==="
echo "Monitor sync: ssh $GHOST_WEB 'sudo journalctl -u ghostd -f'"
