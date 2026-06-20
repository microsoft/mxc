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

# Stage the Linux binary into its per-platform package dir (sdk/platform-packages/linux-<arch>)
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
    BIN_DIR="$SDK_DIR/platform-packages/linux-$SDK_ARCH"
    mkdir -p "$BIN_DIR"

    # Clean previously-staged binaries so stale/flag-toggled artifacts never
    # persist into the package; keep only the tracked metadata files.
    find "$BIN_DIR" -mindepth 1 ! -name package.json ! -name README.md -delete

    # Resolve the lxc-exec build output (explicit --target dir or default dir).
    LXC_SRC=""
    for candidate in \
        "$SRC_DIR/target/$TARGET_TRIPLE/$BUILD_TYPE/lxc-exec" \
        "$SRC_DIR/target/$BUILD_TYPE/lxc-exec"; do
        if [ -f "$candidate" ]; then
            LXC_SRC="$candidate"
            break
        fi
    done

    if [ -z "$LXC_SRC" ]; then
        echo "Error: lxc-exec ($BUILD_TYPE) was not found in src/target — cannot stage an incomplete linux-$SDK_ARCH package." >&2
        exit 1
    fi

    cp "$LXC_SRC" "$BIN_DIR/"
    echo "Copied $LXC_SRC -> $BIN_DIR/lxc-exec"
fi

# Build SDK
if [ "$BUILD_SDK" = true ]; then
    echo ""
    echo "=== Building TypeScript SDK ==="
    if [ -n "${CI:-}" ]; then
        echo "Checking platform package versions (CI)..."
        node "$SCRIPT_DIR/scripts/sync-platform-package-versions.js" --check
    else
        echo "Stamping platform package versions..."
        node "$SCRIPT_DIR/scripts/sync-platform-package-versions.js"
    fi
    cd "$SDK_DIR"
    npm install --ignore-scripts 2>/dev/null || true
    npm run build
fi

echo ""
echo "=== Build complete ==="
echo "Binary location: $SRC_DIR/target/$BUILD_TYPE/lxc-exec"
