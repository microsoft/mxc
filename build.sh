#!/bin/bash
# MXC Linux Build Script
# Builds the lxc-exec binary and TypeScript SDK

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
SDK_DIR="$SCRIPT_DIR/sdk"

# Parse arguments
BUILD_TYPE="release"
BUILD_SDK=true

WITH_HYPERLIGHT=false
WITH_MICROVM=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --rust-only)
            BUILD_SDK=false
            shift
            ;;
        --with-hyperlight)
            WITH_HYPERLIGHT=true
            shift
            ;;
        --with-microvm)
            WITH_MICROVM=true
            shift
            ;;
        --help|-h)
            echo "Usage: build.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug             Build in debug mode (default: release)"
            echo "  --rust-only         Only build Rust binaries, skip SDK"
            echo "  --with-hyperlight   Build with Hyperlight (micro-VM) backend (x86_64 only)"
            echo "  --with-microvm      Build with NanVix MicroVM backend (KVM required at runtime)"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check prerequisites
echo "=== Checking prerequisites ==="

if ! command -v cargo &> /dev/null; then
    echo "Error: cargo is not installed. Install Rust via https://rustup.rs/"
    exit 1
fi

if ! dpkg -s liblxc-dev &> /dev/null 2>&1 && ! rpm -q lxc-devel &> /dev/null 2>&1; then
    echo "Warning: liblxc-dev (or lxc-devel) not found. LXC bindings may fail to compile."
    echo "Install with: sudo apt install liblxc-dev (Debian/Ubuntu) or sudo dnf install lxc-devel (Fedora)"
fi

# Build Rust binaries
echo ""
echo "=== Building Rust binaries ($BUILD_TYPE) ==="
cd "$SRC_DIR"

# Packages to build and lint — kept in one place so build and clippy stay in sync.
LXC_PACKAGES=(-p lxc -p lxc_common -p wxc_common -p bwrap_common -p linux_test_proxy)

CARGO_FEATURES=()
FEATURES_LIST=()
if [ "$WITH_HYPERLIGHT" = true ]; then
    FEATURES_LIST+=(hyperlight)
fi
if [ "$WITH_MICROVM" = true ]; then
    FEATURES_LIST+=(microvm)
fi
if [ ${#FEATURES_LIST[@]} -gt 0 ]; then
    CARGO_FEATURES=(--features "$(IFS=,; echo "${FEATURES_LIST[*]}")")
fi

if [ "$BUILD_TYPE" = "release" ]; then
    cargo build --release "${LXC_PACKAGES[@]}" "${CARGO_FEATURES[@]}"
else
    cargo build "${LXC_PACKAGES[@]}" "${CARGO_FEATURES[@]}"
fi

echo "  Check formatting"
cargo fmt --all -- --check

echo "  Check linting"
# Scope clippy to Linux-compatible crates only. --workspace includes Windows-only
# crates (wxc, wslc_common, etc.) whose dependencies fail to compile on Linux.
cargo clippy "${LXC_PACKAGES[@]}" --all-targets "${CARGO_FEATURES[@]}" -- -D warnings

echo "Rust build complete."

# Copy binaries to SDK bin directory
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        TARGET_TRIPLE="x86_64-unknown-linux-gnu"
        SDK_ARCH="x64"
        ;;
    aarch64)
        TARGET_TRIPLE="aarch64-unknown-linux-gnu"
        SDK_ARCH="arm64"
        ;;
    *)
        echo "Warning: Unknown architecture $ARCH, skipping binary copy to SDK"
        TARGET_TRIPLE=""
        SDK_ARCH=""
        ;;
esac

if [ -n "$TARGET_TRIPLE" ]; then
    BIN_DIR="$SDK_DIR/bin/$SDK_ARCH"
    mkdir -p "$BIN_DIR"

    if [ "$BUILD_TYPE" = "release" ]; then
        cp "$SRC_DIR/target/release/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        cp "$SRC_DIR/target/$TARGET_TRIPLE/release/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        echo "Warning: Could not find lxc-exec binary to copy"
        cp "$SRC_DIR/target/release/linux-test-proxy" "$BIN_DIR/" 2>/dev/null || \
        cp "$SRC_DIR/target/$TARGET_TRIPLE/release/linux-test-proxy" "$BIN_DIR/" 2>/dev/null || \
        echo "Warning: Could not find linux-test-proxy binary to copy"
    else
        cp "$SRC_DIR/target/debug/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        cp "$SRC_DIR/target/$TARGET_TRIPLE/debug/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        echo "Warning: Could not find lxc-exec binary to copy"
        cp "$SRC_DIR/target/debug/linux-test-proxy" "$BIN_DIR/" 2>/dev/null || \
        cp "$SRC_DIR/target/$TARGET_TRIPLE/debug/linux-test-proxy" "$BIN_DIR/" 2>/dev/null || \
        echo "Warning: Could not find linux-test-proxy binary to copy"
    fi
fi

# Build SDK
if [ "$BUILD_SDK" = true ]; then
    echo ""
    echo "=== Building TypeScript SDK ==="
    cd "$SDK_DIR"
    npm install --ignore-scripts 2>/dev/null || true
    npm run build
fi

echo ""
echo "=== Build complete ==="
echo "Binary location: $SRC_DIR/target/$BUILD_TYPE/lxc-exec"
