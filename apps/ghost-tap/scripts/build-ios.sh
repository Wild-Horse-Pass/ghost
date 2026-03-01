#!/bin/bash
set -e

# Build GhostTap Core for iOS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CORE_DIR="$PROJECT_ROOT/core"
IOS_DIR="$PROJECT_ROOT/ios"

echo "Building GhostTap Core for iOS..."

# Ensure Rust iOS targets are installed
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim

# Build for each target
echo "Building for aarch64-apple-ios (device)..."
cargo build --manifest-path "$CORE_DIR/Cargo.toml" --release --target aarch64-apple-ios

echo "Building for aarch64-apple-ios-sim (M1 simulator)..."
cargo build --manifest-path "$CORE_DIR/Cargo.toml" --release --target aarch64-apple-ios-sim

echo "Building for x86_64-apple-ios (Intel simulator)..."
cargo build --manifest-path "$CORE_DIR/Cargo.toml" --release --target x86_64-apple-ios

# Create output directories
FRAMEWORK_DIR="$IOS_DIR/Frameworks"
mkdir -p "$FRAMEWORK_DIR"

# Create fat library for simulators
echo "Creating universal simulator library..."
SIMULATOR_LIB="$PROJECT_ROOT/target/universal-ios-sim/release/libghost_tap_core.a"
mkdir -p "$(dirname "$SIMULATOR_LIB")"
lipo -create \
    "$PROJECT_ROOT/target/aarch64-apple-ios-sim/release/libghost_tap_core.a" \
    "$PROJECT_ROOT/target/x86_64-apple-ios/release/libghost_tap_core.a" \
    -output "$SIMULATOR_LIB"

# Create XCFramework
echo "Creating XCFramework..."
XCFRAMEWORK_PATH="$FRAMEWORK_DIR/GhostTapCore.xcframework"
rm -rf "$XCFRAMEWORK_PATH"

xcodebuild -create-xcframework \
    -library "$PROJECT_ROOT/target/aarch64-apple-ios/release/libghost_tap_core.a" \
    -library "$SIMULATOR_LIB" \
    -output "$XCFRAMEWORK_PATH"

# Generate Swift bindings using UniFFI
echo "Generating Swift bindings..."
cargo run --manifest-path "$CORE_DIR/Cargo.toml" \
    --features uniffi-cli \
    -- generate \
    --library "$PROJECT_ROOT/target/aarch64-apple-ios/release/libghost_tap_core.a" \
    --language swift \
    --out-dir "$IOS_DIR/GhostTap/Bridge"

echo "iOS build complete!"
echo "XCFramework: $XCFRAMEWORK_PATH"
echo "Swift bindings: $IOS_DIR/GhostTap/Bridge/"
