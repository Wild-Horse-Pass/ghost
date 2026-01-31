#!/bin/bash
#
# Deploy registry configuration to all ghost-pool nodes
#

set -e

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"  # Adjust if different
REGISTRY_URL="http://83.136.255.218:8335"

# VM definitions: name, IP, region
declare -A VMS=(
    ["signet-1"]="83.136.251.162:eu_west"
    ["signet-2"]="85.9.198.212:us_east"
    ["signet-3"]="213.163.207.46:asia_southeast"
    ["signet-4"]="95.111.221.169:oceania"
)

echo "=========================================="
echo "Updating ghost-pool nodes with registry config"
echo "Registry URL: $REGISTRY_URL"
echo "=========================================="
echo ""

for VM_NAME in "${!VMS[@]}"; do
    IFS=':' read -r IP REGION <<< "${VMS[$VM_NAME]}"

    echo "----------------------------------------"
    echo "Configuring $VM_NAME ($IP) - Region: $REGION"
    echo "----------------------------------------"

    # Create registry config snippet to append
    REGISTRY_CONFIG="
# Registry configuration for load balancer
[registry]
url = \"$REGISTRY_URL\"
region = \"$REGION\"
heartbeat_interval_secs = 30
"

    # Check if registry config already exists, if not append it
    ssh -i "$SSH_KEY" root@$IP << REMOTE_SCRIPT
        # Check if [registry] section exists
        if grep -q "^\[registry\]" /etc/ghost/pool.toml 2>/dev/null; then
            echo "Registry config already exists, updating..."
            # Update existing values
            sed -i "s|^url = .*|url = \"$REGISTRY_URL\"|" /etc/ghost/pool.toml
            sed -i "s|^region = .*|region = \"$REGION\"|" /etc/ghost/pool.toml
        else
            echo "Adding registry config..."
            cat >> /etc/ghost/pool.toml << 'REGISTRY_EOF'

# Registry configuration for load balancer
[registry]
url = "$REGISTRY_URL"
region = "$REGION"
heartbeat_interval_secs = 30
REGISTRY_EOF
        fi

        # Ensure public_address is set in [network]
        if ! grep -q "^public_address" /etc/ghost/pool.toml; then
            echo "Adding public_address..."
            sed -i "/^\[network\]/a public_address = \"$IP\"" /etc/ghost/pool.toml
        fi

        echo "Restarting ghost-pool..."
        systemctl restart ghost-pool || echo "Warning: Could not restart ghost-pool"

        sleep 2
        systemctl status ghost-pool --no-pager | head -5 || true
REMOTE_SCRIPT

    echo ""
done

echo "=========================================="
echo "All nodes updated!"
echo ""
echo "Check registered nodes:"
echo "  curl http://83.136.255.218:8335/api/v1/nodes"
echo "=========================================="
