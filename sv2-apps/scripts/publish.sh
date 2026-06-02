#!/usr/bin/env bash

# Script to publish the pool applications in this repository
# Usage: ./scripts/publish-pool-apps.sh [cargo publish options]
# Example: ./scripts/publish-pool-apps.sh --dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Check if user is logged in to crates.io
if ! cargo login --help > /dev/null 2>&1; then
    echo "❌ Error: cargo is not available"
    exit 1
fi

# Warn about publishing
if [[ ! "$*" =~ --dry-run ]]; then
    echo "⚠️  WARNING: This will publish crates to crates.io"
    echo "   Make sure you have the proper permissions and have logged in with 'cargo login <token>'"
    echo ""
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Publishing cancelled"
        exit 1
    fi
fi

echo ""
echo "Starting publication process..."

# Function to publish a crate
publish_crate() {
    local crate_dir="$1"
    local crate_name="$2"
    shift 2  # Remove first two arguments, leaving publish options
    
    echo ""
    echo "📦 Publishing $crate_name from $crate_dir..."
    
    # Change to crate directory
    if ! cd "$crate_dir"; then
        echo "❌ Error: Could not change to directory $crate_dir"
        return 1
    fi
    
    # Run cargo publish with provided arguments
    if cargo publish "$@"; then
        echo "✅ $crate_name published successfully"
        cd "$PROJECT_ROOT"  # Return to project root
        return 0
    else
        local exit_code=$?
        echo "❌ Failed to publish $crate_name (exit code: $exit_code)"
        cd "$PROJECT_ROOT"  # Return to project root
        return $exit_code
    fi
}

# Publish Pool Apps
echo "📦 Publishing Pool Applications..."
publish_crate "pool-apps/pool" "pool_sv2" "$@"
publish_crate "pool-apps/jd-server" "jd_server" "$@"

# Publish Miner Apps  
echo "📦 Publishing Miner Applications..."
publish_crate "miner-apps/jd-client" "jd_client" "$@"
publish_crate "miner-apps/translator" "translator_sv2" "$@"

# Publish Test Utils
echo "📦 Publishing Test Utilities..."
publish_crate "integration-tests" "integration_tests_sv2" "$@"
