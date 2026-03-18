#!/bin/bash
# MXC Linux Build Script
# Builds the lxc-exec binary and TypeScript SDK/CLI

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
SDK_DIR="$SCRIPT_DIR/sdk"
CLI_DIR="$SCRIPT_DIR/cli"

# Parse arguments
BUILD_TYPE="release"
BUILD_SDK=true

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
        --help|-h)
            echo "Usage: build.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug       Build in debug mode (default: release)"
            echo "  --rust-only   Only build Rust binaries, skip SDK/CLI"
            echo "  -h, --help    Show this help message"
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

if [ "$BUILD_TYPE" = "release" ]; then
    cargo build --release -p lxc
else
    cargo build -p lxc
fi

echo "Rust build complete."

# Copy binaries to SDK bin directory
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        TARGET_TRIPLE="x86_64-unknown-linux-gnu"
        ;;
    aarch64)
        TARGET_TRIPLE="aarch64-unknown-linux-gnu"
        ;;
    *)
        echo "Warning: Unknown architecture $ARCH, skipping binary copy to SDK"
        TARGET_TRIPLE=""
        ;;
esac

if [ -n "$TARGET_TRIPLE" ]; then
    BIN_DIR="$SDK_DIR/bin/$TARGET_TRIPLE"
    mkdir -p "$BIN_DIR"

    if [ "$BUILD_TYPE" = "release" ]; then
        cp "$SRC_DIR/target/release/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        cp "$SRC_DIR/target/$TARGET_TRIPLE/release/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        echo "Warning: Could not find lxc-exec binary to copy"
    else
        cp "$SRC_DIR/target/debug/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        cp "$SRC_DIR/target/$TARGET_TRIPLE/debug/lxc-exec" "$BIN_DIR/" 2>/dev/null || \
        echo "Warning: Could not find lxc-exec binary to copy"
    fi
fi

# Build SDK and CLI
if [ "$BUILD_SDK" = true ]; then
    echo ""
    echo "=== Building TypeScript SDK ==="
    cd "$SDK_DIR"
    npm install --ignore-scripts 2>/dev/null || true
    npm run build

    echo ""
    echo "=== Building TypeScript CLI ==="
    cd "$CLI_DIR"
    npm install 2>/dev/null || true
    npm run build
fi

echo ""
echo "=== Build complete ==="
echo "Binary location: $SRC_DIR/target/$BUILD_TYPE/lxc-exec"
