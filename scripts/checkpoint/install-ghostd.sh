#!/bin/bash
# Install ghostd on ghost-web VM for checkpoint serving.
# Run as root on the target VM.
set -euo pipefail

GHOST_USER="ghost"
GHOST_HOME="/var/lib/ghostd"
BIN_DIR="/opt/ghost/bin"
CONF_DIR="/etc/ghost"
SERVICE_FILE="/etc/systemd/system/ghostd.service"

echo "=== Installing ghostd checkpoint server ==="

# Create ghost user if not exists
if ! id "$GHOST_USER" &>/dev/null; then
    useradd --system --home-dir "$GHOST_HOME" --create-home --shell /usr/sbin/nologin "$GHOST_USER"
    echo "Created user: $GHOST_USER"
fi

# Create directories
mkdir -p "$GHOST_HOME" "$BIN_DIR" "$CONF_DIR"
chown "$GHOST_USER:$GHOST_USER" "$GHOST_HOME"

# Copy binary
if [ -f /tmp/ghostd ]; then
    cp /tmp/ghostd "$BIN_DIR/ghostd"
    chmod 755 "$BIN_DIR/ghostd"
    echo "Installed ghostd to $BIN_DIR/ghostd"
else
    echo "ERROR: /tmp/ghostd not found. SCP the binary first."
    exit 1
fi

# Generate RPC password
RPC_PASS=$(head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 32)
RPC_CONF="$CONF_DIR/ghostd-rpc.conf"
cat > "$RPC_CONF" << EOF
rpcuser=ghost
rpcpassword=$RPC_PASS
EOF
chmod 600 "$RPC_CONF"
chown "$GHOST_USER:$GHOST_USER" "$RPC_CONF"
echo "Generated RPC credentials at $RPC_CONF"

# Install service file (substitute RPC password)
if [ -f /tmp/ghostd.service ]; then
    sed "s/__GHOST_RPC_PASS__/$RPC_PASS/g" /tmp/ghostd.service > "$SERVICE_FILE"
else
    echo "ERROR: /tmp/ghostd.service not found."
    exit 1
fi

# Install checkpoint generation script
if [ -f /tmp/generate-checkpoint.sh ]; then
    cp /tmp/generate-checkpoint.sh "$BIN_DIR/generate-checkpoint.sh"
    chmod 755 "$BIN_DIR/generate-checkpoint.sh"
    echo "Installed generate-checkpoint.sh"
fi

# Install timer units
if [ -f /tmp/ghost-checkpoint.timer ]; then
    cp /tmp/ghost-checkpoint.timer /etc/systemd/system/ghost-checkpoint.timer
    cp /tmp/ghost-checkpoint.service /etc/systemd/system/ghost-checkpoint.service
    echo "Installed checkpoint timer units"
fi

# Create checkpoint serving directory
SERVE_DIR="/var/www/get.bitcoinghost.org/checkpoint"
mkdir -p "$SERVE_DIR"
chown "$GHOST_USER:$GHOST_USER" "$SERVE_DIR"
echo "Created checkpoint serving directory: $SERVE_DIR"

# Enable and start
systemctl daemon-reload
systemctl enable ghostd
systemctl start ghostd

echo "=== ghostd service started ==="
echo "Check status: systemctl status ghostd"
echo "Check logs: journalctl -u ghostd -f"
echo "RPC password stored at: $RPC_CONF"

# Enable checkpoint timer
if [ -f /etc/systemd/system/ghost-checkpoint.timer ]; then
    systemctl enable ghost-checkpoint.timer
    systemctl start ghost-checkpoint.timer
    echo "Checkpoint timer enabled (daily at 04:00 UTC)"
fi
