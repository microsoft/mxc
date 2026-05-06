#!/bin/bash
# MXC macOS Build Script
# Builds the mxc-exec-darwin binary (macos_sandbox backend) and the
# TypeScript SDK/CLI. This is the macOS counterpart of build.sh.
#
# Codesigning + notarization are NOT performed here — those run later as a
# release-time step (see docs/macos-sandbox-backend.md). This script just
# produces an unsigned binary suitable for local development.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
SDK_DIR="$SCRIPT_DIR/sdk"
CLI_DIR="$SCRIPT_DIR/cli"

# Parse arguments
BUILD_TYPE="release"
BUILD_SDK=true
BUILD_BOTH_ARCHES=false

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
        --all)
            # Build both Apple silicon and Intel slices for distribution.
            BUILD_BOTH_ARCHES=true
            shift
            ;;
        --help|-h)
            echo "Usage: build-mac.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug       Build in debug mode (default: release)"
            echo "  --rust-only   Only build Rust binaries, skip SDK/CLI"
            echo "  --all         Build for both x86_64-apple-darwin and aarch64-apple-darwin"
            echo "  -h, --help    Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Sanity check: refuse to run anywhere except macOS.
if [ "$(uname -s)" != "Darwin" ]; then
    echo "Error: build-mac.sh must run on macOS. Detected $(uname -s)."
    echo "Use build.sh on Linux or build.bat on Windows."
    exit 1
fi

# Check prerequisites
echo "=== Checking prerequisites ==="

if ! command -v cargo &> /dev/null; then
    echo "Error: cargo is not installed. Install Rust via https://rustup.rs/"
    exit 1
fi

if ! xcode-select -p &> /dev/null; then
    echo "Error: Xcode Command Line Tools not installed."
    echo "Install with: xcode-select --install"
    exit 1
fi

# Determine which target triples to build.
NATIVE_ARCH=$(uname -m)
TARGETS=()
if [ "$BUILD_BOTH_ARCHES" = true ]; then
    TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin")
else
    case $NATIVE_ARCH in
        arm64) TARGETS=("aarch64-apple-darwin") ;;
        x86_64) TARGETS=("x86_64-apple-darwin") ;;
        *) echo "Error: unknown architecture $NATIVE_ARCH"; exit 1 ;;
    esac
fi

# Ensure the rustup targets are installed (no-op if already present).
for triple in "${TARGETS[@]}"; do
    if command -v rustup &> /dev/null; then
        rustup target add "$triple" >/dev/null 2>&1 || true
    fi
done

# Build Rust binaries
echo ""
echo "=== Building mxc-exec-darwin ($BUILD_TYPE) ==="
cd "$SRC_DIR"

CARGO_FLAGS=("-p" "mxc_darwin")
if [ "$BUILD_TYPE" = "release" ]; then
    CARGO_FLAGS+=("--release")
fi

for triple in "${TARGETS[@]}"; do
    echo "--- Target: $triple ---"
    cargo build "${CARGO_FLAGS[@]}" --target "$triple"
done

echo "Rust build complete."

# Copy binaries to SDK bin directory.
copy_binary_for_target() {
    local triple="$1"
    local sdk_arch
    case $triple in
        aarch64-apple-darwin) sdk_arch="arm64" ;;
        x86_64-apple-darwin)  sdk_arch="x64" ;;
        *) echo "Skipping unknown triple $triple"; return ;;
    esac

    local bin_dir="$SDK_DIR/bin/$sdk_arch"
    mkdir -p "$bin_dir"

    local src="$SRC_DIR/target/$triple/$BUILD_TYPE/mxc-exec-darwin"
    if [ -f "$src" ]; then
        cp "$src" "$bin_dir/mxc-exec-darwin"
        chmod +x "$bin_dir/mxc-exec-darwin"
        echo "Copied $src -> $bin_dir/mxc-exec-darwin"
    else
        echo "Warning: $src not found, skipping copy"
    fi
}

for triple in "${TARGETS[@]}"; do
    copy_binary_for_target "$triple"
done

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
for triple in "${TARGETS[@]}"; do
    echo "Binary: $SRC_DIR/target/$triple/$BUILD_TYPE/mxc-exec-darwin"
done
echo ""
echo "Note: this binary is unsigned. Codesigning + notarization happen at"
echo "release time (see docs/macos-sandbox-backend.md, codesign-notarize todo)."
