#!/bin/bash
#
# Deploy ghost-registry to web server
#

set -e

WEB_SERVER="83.136.255.218"
SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"  # Adjust if different

echo "=========================================="
echo "Deploying ghost-registry to $WEB_SERVER"
echo "=========================================="

# Copy binary
echo "Copying binary..."
scp -i "$SSH_KEY" /home/defenwycke/dev/projects/ghost/target/release/ghost-registry root@$WEB_SERVER:/usr/local/bin/

# Copy install script and run it
echo "Copying install script..."
scp -i "$SSH_KEY" /home/defenwycke/dev/projects/ghost/scripts/install-registry.sh root@$WEB_SERVER:/tmp/

echo "Running install script on server..."
ssh -i "$SSH_KEY" root@$WEB_SERVER "bash /tmp/install-registry.sh"

echo ""
echo "=========================================="
echo "ghost-registry deployed to $WEB_SERVER"
echo "=========================================="
echo ""
echo "Test it:"
echo "  curl http://$WEB_SERVER:8333/health"
