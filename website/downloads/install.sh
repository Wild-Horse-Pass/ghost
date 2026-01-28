#!/bin/bash
#
# Bitcoin Ghost Pool - Quick Install Script
# Usage: curl -sSL https://bitcoinghost.org/install.sh | bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ____  _ _            _          ____  _               _   "
echo " | __ )(_) |_ ___ ___ (_)_ __    / ___|| |__   ___  ___| |_ "
echo " |  _ \| | __/ __/ _ \| | '_ \  | |  _ | '_ \ / _ \/ __| __|"
echo " | |_) | | || (_| (_) | | | | | | |_| || | | | (_) \__ \ |_ "
echo " |____/|_|\__\___\___/|_|_| |_|  \____||_| |_|\___/|___/\__|"
echo -e "${NC}"
echo ""

INSTALL_DIR="/opt/ghost"
CONFIG_DIR="/etc/ghost"
DATA_DIR="/var/lib/ghost"
BIN_NAME="ghost-pool"
VERSION="1.4.0"
DOWNLOAD_BASE="https://bitcoinghost.org/downloads"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH_NAME="x86_64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    echo -e "${RED}This installer only supports Linux. For other platforms, use Docker.${NC}"
    exit 1
fi

echo -e "${GREEN}Detected:${NC} $OS $ARCH_NAME"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}This script requires root privileges.${NC}"
    echo "Please run with: sudo bash or as root"
    exit 1
fi

# Create ghost user if doesn't exist
if ! id "ghost" &>/dev/null; then
    echo -e "${CYAN}Creating ghost user...${NC}"
    useradd -r -s /bin/false ghost
fi

# Create directories
echo -e "${CYAN}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
chown ghost:ghost "$DATA_DIR"

# Download binary
TARBALL="${BIN_NAME}-linux-${ARCH_NAME}.tar.gz"
DOWNLOAD_URL="${DOWNLOAD_BASE}/${TARBALL}"

echo -e "${CYAN}Downloading ${BIN_NAME} v${VERSION}...${NC}"
if command -v curl &> /dev/null; then
    curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${TARBALL}"
elif command -v wget &> /dev/null; then
    wget -q "$DOWNLOAD_URL" -O "/tmp/${TARBALL}"
else
    echo -e "${RED}Neither curl nor wget found. Please install one.${NC}"
    exit 1
fi

# Verify checksum
echo -e "${CYAN}Verifying checksum...${NC}"
if command -v curl &> /dev/null; then
    curl -fsSL "${DOWNLOAD_URL}.sha256" -o "/tmp/${TARBALL}.sha256"
else
    wget -q "${DOWNLOAD_URL}.sha256" -O "/tmp/${TARBALL}.sha256"
fi

cd /tmp
if ! sha256sum -c "${TARBALL}.sha256"; then
    echo -e "${RED}Checksum verification failed!${NC}"
    rm -f "/tmp/${TARBALL}" "/tmp/${TARBALL}.sha256"
    exit 1
fi

# Extract and install
echo -e "${CYAN}Installing binary...${NC}"
tar xzf "/tmp/${TARBALL}" -C "$INSTALL_DIR/bin"
chmod +x "$INSTALL_DIR/bin/$BIN_NAME"
rm -f "/tmp/${TARBALL}" "/tmp/${TARBALL}.sha256"

# Create default config if doesn't exist
if [ ! -f "$CONFIG_DIR/pool.toml" ]; then
    echo -e "${CYAN}Creating default configuration...${NC}"
    cat > "$CONFIG_DIR/pool.toml" << 'EOF'
# Bitcoin Ghost Pool Configuration
# Edit this file to customize your pool settings

[bitcoin]
rpc_host = "127.0.0.1"
rpc_port = 38332          # signet RPC port
rpc_user = "ghost"
rpc_password = "ghostpass"
network = "signet"
zmq_hashblock = "tcp://127.0.0.1:28332"

[network]
public_address = "0.0.0.0"
sv2_port = 34255          # Stratum V2
sv1_port = 3333           # Stratum V1
http_port = 8080          # API/Dashboard

[policy]
profile = "permissive"    # or "bitcoin_pure", "full_open"

[storage]
data_dir = "/var/lib/ghost"
archive_mode = false

[pool]
treasury_address = "tb1qyouraddress"  # CHANGE THIS
fee_percent = 1.0
min_payout_sats = 100000
EOF
    echo -e "${YELLOW}Please edit $CONFIG_DIR/pool.toml and set your treasury address${NC}"
fi

# Create systemd service
echo -e "${CYAN}Installing systemd service...${NC}"
cat > /etc/systemd/system/ghost-pool.service << EOF
[Unit]
Description=Bitcoin Ghost Mining Pool
After=network.target bitcoind.service

[Service]
Type=simple
User=ghost
ExecStart=$INSTALL_DIR/bin/$BIN_NAME --config $CONFIG_DIR/pool.toml
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Bitcoin Ghost installed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Binary:  $INSTALL_DIR/bin/$BIN_NAME"
echo "Config:  $CONFIG_DIR/pool.toml"
echo "Data:    $DATA_DIR"
echo ""
echo "Next steps:"
echo "  1. Edit your configuration: sudo nano $CONFIG_DIR/pool.toml"
echo "  2. Make sure Bitcoin Core (signet) is running"
echo "  3. Start the pool: sudo systemctl start ghost-pool"
echo "  4. Enable on boot: sudo systemctl enable ghost-pool"
echo "  5. View logs: sudo journalctl -u ghost-pool -f"
echo ""
echo "For Docker installation, visit: https://bitcoinghost.org/install.html"
echo ""
