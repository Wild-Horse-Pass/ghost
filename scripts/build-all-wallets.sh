#!/bin/bash
#|======================================================================================================================|
#|  BUILD ALL WALLETS - Creates standalone wallet binaries for distribution                                             |
#|  Builds both Light Wallets (from v1.4) and Full Node Wallets (from bitcoin-ghost)                                   |
#|======================================================================================================================|

set -e

VERSION=${1:-"1.4.0"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RELEASE_DIR="$PROJECT_DIR/releases"
BITCOIN_GHOST_DIR="/home/defenwycke/dev/bitcoin-ghost"

echo "================================================================================"
echo "                    GHOST WALLET BUILD SCRIPT"
echo "================================================================================"
echo ""
echo "Version: $VERSION"
echo "Output:  $RELEASE_DIR"
echo ""

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="x64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

PLATFORM="${OS}-${ARCH}"
echo "Platform: $PLATFORM"
echo ""

# Create release directory
mkdir -p "$RELEASE_DIR"

# Helper function to build and package
build_and_package() {
    local name=$1
    local pkg=$2
    local dir=$3
    local bin_name=$4

    echo ""
    echo "================================================================================"
    echo "Building $name..."
    echo "================================================================================"

    cd "$dir"
    cargo build --release -p "$pkg"

    local bin="$dir/target/release/$bin_name"
    if [ -f "$bin" ]; then
        local out="$RELEASE_DIR/${bin_name}-${VERSION}-${PLATFORM}"
        cp "$bin" "$out"
        chmod +x "$out"

        # Create tarball
        cd "$RELEASE_DIR"
        tar -czf "${bin_name}-${VERSION}-${PLATFORM}.tar.gz" "${bin_name}-${VERSION}-${PLATFORM}"
        rm "${bin_name}-${VERSION}-${PLATFORM}"

        echo "  -> ${bin_name}-${VERSION}-${PLATFORM}.tar.gz"
    else
        echo "  [FAILED] Binary not found: $bin"
        return 1
    fi
}

echo ""
echo "================================================================================"
echo "                         LIGHT WALLETS (GSP-Connected)"
echo "================================================================================"
echo "These wallets connect to a Ghost Service Provider."
echo "Keys stay local on your device."
echo ""

# Build Light Wallet CLI
build_and_package "Light Wallet CLI" "ghost-light-wallet-cli" "$PROJECT_DIR" "ghost-light-wallet"

# Build Light Wallet TUI
build_and_package "Light Wallet TUI" "ghost-light-wallet-tui" "$PROJECT_DIR" "ghost-light-wallet-tui"

echo ""
echo "================================================================================"
echo "                       FULL NODE WALLETS (ghostd-Connected)"
echo "================================================================================"
echo "These wallets connect to a local ghostd node."
echo "Requires running your own full node."
echo ""

if [ -d "$BITCOIN_GHOST_DIR" ]; then
    # Build Full Node CLI
    build_and_package "Full Node Wallet CLI" "ghost-wallet-cli" "$BITCOIN_GHOST_DIR" "ghost-wallet-cli"

    # Build Full Node TUI
    build_and_package "Full Node Wallet TUI" "ghost-wallet-tui" "$BITCOIN_GHOST_DIR" "ghost-wallet-tui"
else
    echo "[SKIPPED] Full Node Wallets - bitcoin-ghost directory not found"
    echo "          Expected: $BITCOIN_GHOST_DIR"
fi

echo ""
echo "================================================================================"
echo "                         DESKTOP GUI WALLET (Qt)"
echo "================================================================================"
echo "Full-featured desktop wallet with graphical interface."
echo "Built from ghost-core (like Bitcoin Core Qt)."
echo ""

GHOST_CORE_DIR="$PROJECT_DIR/ghost-core"
GHOST_QT_BIN="$GHOST_CORE_DIR/build/bin/ghost-qt"

if [ -f "$GHOST_QT_BIN" ]; then
    echo "Packaging Ghost Qt GUI Wallet..."

    QT_OUT="$RELEASE_DIR/ghost-qt-${VERSION}-${PLATFORM}"
    cp "$GHOST_QT_BIN" "$QT_OUT"
    chmod +x "$QT_OUT"

    # Create tarball
    cd "$RELEASE_DIR"
    tar -czf "ghost-qt-${VERSION}-${PLATFORM}.tar.gz" "ghost-qt-${VERSION}-${PLATFORM}"
    rm "ghost-qt-${VERSION}-${PLATFORM}"
    cd "$PROJECT_DIR"

    echo "  -> ghost-qt-${VERSION}-${PLATFORM}.tar.gz"
else
    echo "[SKIPPED] Ghost Qt - binary not found at $GHOST_QT_BIN"
    echo "          Build ghost-core first: cd ghost-core && cmake -B build && cmake --build build"
fi

echo ""
echo "================================================================================"
echo "                              BUILD COMPLETE"
echo "================================================================================"
echo ""
echo "Files in $RELEASE_DIR:"
echo ""
ls -lh "$RELEASE_DIR"/*.tar.gz 2>/dev/null || echo "No release files found"

echo ""
echo "================================================================================"
echo "                              WALLET SUMMARY"
echo "================================================================================"
echo ""
echo "LIGHT WALLETS (for users without a full node):"
echo "  - ghost-light-wallet     : CLI wallet connecting to GSP"
echo "  - ghost-light-wallet-tui : Terminal UI wallet connecting to GSP"
echo ""
echo "FULL NODE WALLETS (for users running ghostd):"
echo "  - ghost-wallet-cli       : CLI wallet connecting to ghostd"
echo "  - ghost-wallet-tui       : Terminal UI wallet connecting to ghostd"
echo "  - ghost-qt               : Desktop GUI wallet (Qt)"
echo ""
echo "SECURITY NOTES:"
echo "  - ALL wallets store keys LOCALLY on your device"
echo "  - Light wallets connect to GSP but NEVER send private keys"
echo "  - Full node wallets require ghostd running locally"
echo "  - Always backup your mnemonic phrase!"
echo ""
echo "To install any wallet:"
echo "  tar -xzf <wallet>.tar.gz"
echo "  sudo mv <wallet> /usr/local/bin/"
echo ""
