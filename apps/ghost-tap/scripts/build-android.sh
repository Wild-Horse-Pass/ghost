#!/bin/bash
set -e

# Build GhostTap Core for Android

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CORE_DIR="$PROJECT_ROOT/core"
ANDROID_DIR="$PROJECT_ROOT/android"

echo "Building GhostTap Core for Android..."

# Check for NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "Error: ANDROID_NDK_HOME not set"
    echo "Please set it to your NDK installation path"
    exit 1
fi

# Ensure Rust Android targets are installed
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android

# Set up cargo-ndk if not installed
if ! command -v cargo-ndk &> /dev/null; then
    echo "Installing cargo-ndk..."
    cargo install cargo-ndk
fi

# Build for all Android architectures
echo "Building for all Android architectures..."
cargo ndk \
    --manifest-path "$CORE_DIR/Cargo.toml" \
    --target aarch64-linux-android \
    --target armv7-linux-androideabi \
    --target x86_64-linux-android \
    --target i686-linux-android \
    --platform 26 \
    --release \
    build

# Copy libraries to Android project
echo "Copying libraries to Android project..."
JNI_LIBS_DIR="$ANDROID_DIR/app/src/main/jniLibs"

mkdir -p "$JNI_LIBS_DIR/arm64-v8a"
mkdir -p "$JNI_LIBS_DIR/armeabi-v7a"
mkdir -p "$JNI_LIBS_DIR/x86_64"
mkdir -p "$JNI_LIBS_DIR/x86"

cp "$PROJECT_ROOT/target/aarch64-linux-android/release/libghost_tap_core.so" \
    "$JNI_LIBS_DIR/arm64-v8a/"
cp "$PROJECT_ROOT/target/armv7-linux-androideabi/release/libghost_tap_core.so" \
    "$JNI_LIBS_DIR/armeabi-v7a/"
cp "$PROJECT_ROOT/target/x86_64-linux-android/release/libghost_tap_core.so" \
    "$JNI_LIBS_DIR/x86_64/"
cp "$PROJECT_ROOT/target/i686-linux-android/release/libghost_tap_core.so" \
    "$JNI_LIBS_DIR/x86/"

# Generate Kotlin bindings using UniFFI
echo "Generating Kotlin bindings..."
KOTLIN_OUT_DIR="$ANDROID_DIR/app/src/main/kotlin/com/ghost/tap/bridge"
mkdir -p "$KOTLIN_OUT_DIR"

cargo run --manifest-path "$CORE_DIR/Cargo.toml" \
    --features uniffi-cli \
    -- generate \
    --library "$PROJECT_ROOT/target/aarch64-linux-android/release/libghost_tap_core.so" \
    --language kotlin \
    --out-dir "$KOTLIN_OUT_DIR"

echo "Android build complete!"
echo "JNI libraries: $JNI_LIBS_DIR/"
echo "Kotlin bindings: $KOTLIN_OUT_DIR/"
