#!/bin/bash
#|======================================================================================================================|
#| Deploy registry config update to all pool VMs                                                                        |
#|======================================================================================================================|

set -e

# VM IPs
VMS=(
    "168.119.109.81"   # ghost-1 (DE)
    "168.119.110.132"  # ghost-2 (DE)
    "5.78.107.183"     # ghost-3 (US)
    "5.78.109.210"     # ghost-4 (US)
)

# Registry URL (ghost-web-backend load balancer)
REGISTRY_URL="http://83.136.255.218:8333"
HEARTBEAT_SECS=30

echo "====================================="
echo " Deploying registry config to VMs"
echo "====================================="

for VM in "${VMS[@]}"; do
    echo ""
    echo "Configuring $VM..."

    # Determine region based on IP prefix
    if [[ "$VM" == 168.* ]]; then
        REGION="eu_central"
    else
        REGION="us_east"
    fi

    # Add registry section to pool.toml if not present
    ssh root@$VM "
        # Check if registry section already exists
        if grep -q '\[registry\]' /etc/ghost/pool.toml 2>/dev/null; then
            echo '  Registry config already exists, updating...'
            # Update existing values
            sed -i 's|url = .*|url = \"$REGISTRY_URL\"|' /etc/ghost/pool.toml
            sed -i 's|heartbeat_interval_secs = .*|heartbeat_interval_secs = $HEARTBEAT_SECS|' /etc/ghost/pool.toml
            sed -i 's|region = .*|region = \"$REGION\"|' /etc/ghost/pool.toml
        else
            echo '  Adding registry config section...'
            # Add new section at end of file
            echo '' >> /etc/ghost/pool.toml
            echo '[registry]' >> /etc/ghost/pool.toml
            echo 'url = \"$REGISTRY_URL\"' >> /etc/ghost/pool.toml
            echo 'heartbeat_interval_secs = $HEARTBEAT_SECS' >> /etc/ghost/pool.toml
            echo 'region = \"$REGION\"' >> /etc/ghost/pool.toml
        fi

        # Show the config
        echo '  Current registry config:'
        grep -A5 '\[registry\]' /etc/ghost/pool.toml || echo '  (none found)'
    "
done

echo ""
echo "====================================="
echo " Registry config deployed!"
echo "====================================="
echo ""
echo "Next steps:"
echo "1. Build the updated ghost-pool binary:"
echo "   cargo build --release -p ghost-pool"
echo ""
echo "2. Deploy the binary to VMs:"
echo "   for VM in ${VMS[*]}; do"
echo "     scp target/release/ghost-pool root@\$VM:/usr/local/bin/"
echo "     ssh root@\$VM 'systemctl restart ghost-pool'"
echo "   done"
echo ""
echo "3. Check logs on VMs for registration:"
echo "   ssh root@168.119.109.81 'journalctl -u ghost-pool -f'"
