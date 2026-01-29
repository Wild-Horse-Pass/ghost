#!/bin/bash
#
# Bitcoin Ghost - Light Wallet Installer
# https://bitcoinghost.org
#
# Usage: curl -sSL https://get.bitcoinghost.org/wallet.sh | bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Version
GHOST_VERSION="1.4.0"
GHOST_REPO="https://github.com/bitcoin-ghost/ghost"

echo -e "${CYAN}"
echo "   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓"
echo "  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒"
echo " ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░"
echo " ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ "
echo " ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ "
echo -e "${NC}"
echo -e "${GREEN}Ghost Light Wallet Installer v${GHOST_VERSION}${NC}"
echo "============================================"
echo ""

# Detect OS and architecture
detect_system() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac

    case "$OS" in
        linux) OS="linux" ;;
        darwin) OS="macos" ;;
        *)
            echo -e "${RED}Error: Unsupported OS: $OS${NC}"
            echo "For Windows, download from: ${GHOST_REPO}/releases"
            exit 1
            ;;
    esac

    echo -e "Detected: ${CYAN}${OS} ${ARCH}${NC}"
}

# Check for Rust (needed for building)
check_rust() {
    if command -v cargo &> /dev/null; then
        RUST_VERSION=$(rustc --version | awk '{print $2}')
        echo -e "Rust: ${GREEN}${RUST_VERSION}${NC}"
        return 0
    else
        return 1
    fi
}

# Install Rust
install_rust() {
    echo -e "\n${CYAN}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo -e "${GREEN}Rust installed!${NC}"
}

# Install dependencies (Linux)
install_linux_deps() {
    echo -e "\n${CYAN}Installing dependencies...${NC}"

    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq build-essential pkg-config libssl-dev libsqlite3-dev
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y gcc openssl-devel sqlite-devel
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm base-devel openssl sqlite
    else
        echo -e "${YELLOW}Warning: Could not detect package manager. Please install build tools manually.${NC}"
    fi
}

# Install dependencies (macOS)
install_macos_deps() {
    echo -e "\n${CYAN}Checking dependencies...${NC}"

    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}Homebrew not found. Installing...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    brew install openssl sqlite 2>/dev/null || true
}

# Build and install wallet
install_wallet() {
    echo -e "\n${CYAN}Building Ghost Light Wallet...${NC}"

    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    # Clone repo
    echo "Cloning repository..."
    git clone --depth 1 --branch "v${GHOST_VERSION}" "${GHOST_REPO}" ghost 2>/dev/null || \
    git clone --depth 1 "${GHOST_REPO}" ghost

    cd ghost

    # Build
    echo "Compiling (this may take a few minutes)..."
    cargo build --release -p ghost-light-wallet-cli

    # Determine install location
    if [ "$OS" = "macos" ]; then
        INSTALL_DIR="$HOME/.local/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
    fi

    mkdir -p "$INSTALL_DIR"

    # Install binary
    cp target/release/ghost-light-wallet-cli "$INSTALL_DIR/ghost-wallet"
    chmod +x "$INSTALL_DIR/ghost-wallet"

    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"

    echo -e "${GREEN}Wallet installed to: $INSTALL_DIR/ghost-wallet${NC}"
}

# Add to PATH
setup_path() {
    INSTALL_DIR="$HOME/.local/bin"

    # Check if already in PATH
    if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
        return 0
    fi

    echo -e "\n${CYAN}Adding to PATH...${NC}"

    # Detect shell
    SHELL_NAME=$(basename "$SHELL")

    case "$SHELL_NAME" in
        bash)
            RC_FILE="$HOME/.bashrc"
            ;;
        zsh)
            RC_FILE="$HOME/.zshrc"
            ;;
        *)
            RC_FILE="$HOME/.profile"
            ;;
    esac

    # Add to RC file
    echo "" >> "$RC_FILE"
    echo "# Ghost Wallet" >> "$RC_FILE"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$RC_FILE"

    # Export for current session
    export PATH="$HOME/.local/bin:$PATH"

    echo -e "${GREEN}Added to $RC_FILE${NC}"
}

# Create wallet directory
setup_wallet_dir() {
    WALLET_DIR="$HOME/.ghost-wallet"

    if [ ! -d "$WALLET_DIR" ]; then
        mkdir -p "$WALLET_DIR"
        chmod 700 "$WALLET_DIR"
    fi

    # Create default config
    if [ ! -f "$WALLET_DIR/config.toml" ]; then
        cat << EOF > "$WALLET_DIR/config.toml"
# Ghost Light Wallet Configuration

[network]
# Options: mainnet, signet, testnet
network = "signet"

[gsp]
# Default GSP server (Fire Ping load balanced)
default_server = "wss://pool.bitcoinghost.org:8900/gsp"
timeout_ms = 30000

[wallet]
auto_backup = true
backup_path = "$WALLET_DIR/backups"
EOF
        chmod 600 "$WALLET_DIR/config.toml"
    fi
}

# Print summary
print_summary() {
    echo -e "\n${GREEN}============================================"
    echo -e "  Ghost Light Wallet Installation Complete!"
    echo -e "============================================${NC}"
    echo ""
    echo -e "${CYAN}Installation:${NC}"
    echo "  Binary:  $HOME/.local/bin/ghost-wallet"
    echo "  Config:  $HOME/.ghost-wallet/config.toml"
    echo ""
    echo -e "${CYAN}Quick start:${NC}"
    echo ""
    echo -e "  ${YELLOW}# Create a new wallet${NC}"
    echo "  ghost-wallet wallet create"
    echo ""
    echo -e "  ${YELLOW}# Check balance${NC}"
    echo "  ghost-wallet balance"
    echo ""
    echo -e "  ${YELLOW}# Generate receive address (Ghost Key)${NC}"
    echo "  ghost-wallet key generate"
    echo ""
    echo -e "  ${YELLOW}# Send Bitcoin${NC}"
    echo "  ghost-wallet send <address> <amount_sats>"
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo "  https://bitcoinghost.org/light-wallets.html"
    echo "  https://bitcoinghost.org/docs/wallet-light-cli.html"
    echo ""

    # Check if shell needs reload
    if ! command -v ghost-wallet &> /dev/null; then
        echo -e "${YELLOW}Note: Run 'source ~/${RC_FILE##*/}' or restart your terminal to use ghost-wallet${NC}"
        echo ""
    fi

    echo -e "${GREEN}Enjoy private Bitcoin payments! 👻${NC}"
}

# Main
main() {
    detect_system

    # Install Rust if needed
    if ! check_rust; then
        install_rust
    fi

    # Install OS-specific dependencies
    if [ "$OS" = "linux" ]; then
        install_linux_deps
    elif [ "$OS" = "macos" ]; then
        install_macos_deps
    fi

    install_wallet
    setup_path
    setup_wallet_dir
    print_summary
}

main "$@"
