#!/bin/bash
#
# Ghost Registry Installation Script
# Run on the target server
#

set -e

echo "Installing Ghost Registry..."

# Stop if already running
pkill ghost-registry 2>/dev/null || true
systemctl stop ghost-registry 2>/dev/null || true

# Create ghost user if doesn't exist
if ! id -u ghost &>/dev/null; then
    echo "Creating ghost user..."
    useradd -r -s /bin/false ghost
fi

# Create directories
echo "Creating directories..."
mkdir -p /etc/ghost /var/lib/ghost-registry
chown ghost:ghost /var/lib/ghost-registry

# Binary should already be copied to /usr/local/bin/
chmod +x /usr/local/bin/ghost-registry

# Create config
echo "Installing config..."
cat > /etc/ghost/registry.toml << 'EOF'
# Ghost Registry Configuration for bitcoinghost.org

[server]
listen = "0.0.0.0:8333"
request_timeout_secs = 30
max_body_size = 1048576

[cloudflare]
enabled = true
zone_id = "0d7a815b553e01be9a3dbee27fb0283b"
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
registration_rate_limit_secs = 300
max_timestamp_drift_secs = 60

[database]
path = "/var/lib/ghost-registry/registry.db"
wal_mode = true
EOF

# Install systemd service
echo "Installing systemd service..."
cat > /etc/systemd/system/ghost-registry.service << 'EOF'
[Unit]
Description=Ghost Registry - Pool Node Registry & DNS Load Balancer
Documentation=https://github.com/bitcoin-ghost
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ghost
Group=ghost
Environment="CLOUDFLARE_API_TOKEN=your_cloudflare_api_token_here"
ExecStart=/usr/local/bin/ghost-registry --config /etc/ghost/registry.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ghost-registry
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
echo "Starting service..."
systemctl daemon-reload
systemctl enable ghost-registry
systemctl start ghost-registry

# Wait and check
sleep 2
echo ""
echo "=========================================="
systemctl status ghost-registry --no-pager || true
echo "=========================================="
echo ""
curl -s http://localhost:8333/health || echo "Health check pending..."
echo ""
echo "Ghost Registry installed!"
