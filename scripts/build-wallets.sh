#!/bin/bash
#|======================================================================================================================|
#|  BUILD WALLETS - Creates standalone wallet binaries for distribution                                                 |
#|  Usage: ./scripts/build-wallets.sh [version]                                                                         |
#|======================================================================================================================|

set -e

VERSION=${1:-"0.1.0"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RELEASE_DIR="$PROJECT_DIR/releases"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           GHOST WALLET BUILD SCRIPT                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
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

# Build CLI Wallet
echo "═══════════════════════════════════════════════════════════════"
echo "Building CLI Wallet..."
echo "═══════════════════════════════════════════════════════════════"
cargo build --release -p ghost-light-wallet-cli

CLI_BIN="$PROJECT_DIR/target/release/ghost-wallet"
if [ -f "$CLI_BIN" ]; then
    CLI_OUT="$RELEASE_DIR/ghost-wallet-${VERSION}-${PLATFORM}"
    cp "$CLI_BIN" "$CLI_OUT"
    chmod +x "$CLI_OUT"

    # Create tarball
    cd "$RELEASE_DIR"
    tar -czf "ghost-wallet-${VERSION}-${PLATFORM}.tar.gz" "ghost-wallet-${VERSION}-${PLATFORM}"
    rm "ghost-wallet-${VERSION}-${PLATFORM}"
    cd "$PROJECT_DIR"

    echo "✓ CLI Wallet: ghost-wallet-${VERSION}-${PLATFORM}.tar.gz"
else
    echo "✗ CLI Wallet build failed"
fi

# Build TUI Wallet
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Building TUI Wallet..."
echo "═══════════════════════════════════════════════════════════════"
cargo build --release -p ghost-wallet-tui

TUI_BIN="$PROJECT_DIR/target/release/ghost-wallet-tui"
if [ -f "$TUI_BIN" ]; then
    TUI_OUT="$RELEASE_DIR/ghost-wallet-tui-${VERSION}-${PLATFORM}"
    cp "$TUI_BIN" "$TUI_OUT"
    chmod +x "$TUI_OUT"

    # Create tarball
    cd "$RELEASE_DIR"
    tar -czf "ghost-wallet-tui-${VERSION}-${PLATFORM}.tar.gz" "ghost-wallet-tui-${VERSION}-${PLATFORM}"
    rm "ghost-wallet-tui-${VERSION}-${PLATFORM}"
    cd "$PROJECT_DIR"

    echo "✓ TUI Wallet: ghost-wallet-tui-${VERSION}-${PLATFORM}.tar.gz"
else
    echo "✗ TUI Wallet build failed"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Release builds complete!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Files in $RELEASE_DIR:"
ls -lh "$RELEASE_DIR"/*.tar.gz 2>/dev/null || echo "No release files found"

echo ""
echo "To install:"
echo "  tar -xzf ghost-wallet-${VERSION}-${PLATFORM}.tar.gz"
echo "  sudo mv ghost-wallet-${VERSION}-${PLATFORM} /usr/local/bin/ghost-wallet"
echo ""
echo "SECURITY NOTE:"
echo "  These wallets store keys LOCALLY on your device."
echo "  They connect to a GSP server but NEVER send private keys."
echo "  Backup your mnemonic phrase!"
