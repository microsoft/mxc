#!/bin/bash
# Shared binary-resolution helper for the Seatbelt (macOS) test scripts.
#
# Resolves the target triple from the host architecture (mirroring
# build-mac.sh's arch->triple mapping) and locates the two binaries every
# Seatbelt test needs: the mxc-exec-mac executor and the unix-test-proxy
# testing-only HTTP proxy used by the network-proxy tests. Falls back from
# release to debug so this works right after either `./build-mac.sh` or a
# plain `cargo build -p mxc_darwin -p unix_test_proxy`.
#
# The sourcing script must set REPO_DIR before sourcing this file.

if [ -z "${REPO_DIR:-}" ]; then
    echo "Error: REPO_DIR must be set before sourcing seatbelt_env.sh" >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) ;;
    *)
        echo "Error: the Seatbelt backend only runs on macOS." >&2
        exit 1
        ;;
esac

case "$(uname -m)" in
    arm64) MXC_TARGET_TRIPLE="aarch64-apple-darwin" ;;
    x86_64) MXC_TARGET_TRIPLE="x86_64-apple-darwin" ;;
    *)
        echo "Error: unknown architecture $(uname -m)" >&2
        exit 1
        ;;
esac

MXC_EXEC_MAC="$REPO_DIR/src/target/$MXC_TARGET_TRIPLE/release/mxc-exec-mac"
UNIX_TEST_PROXY="$REPO_DIR/src/target/$MXC_TARGET_TRIPLE/release/unix-test-proxy"

if [ ! -f "$MXC_EXEC_MAC" ]; then
    MXC_EXEC_MAC="$REPO_DIR/src/target/$MXC_TARGET_TRIPLE/debug/mxc-exec-mac"
fi
if [ ! -f "$UNIX_TEST_PROXY" ]; then
    UNIX_TEST_PROXY="$REPO_DIR/src/target/$MXC_TARGET_TRIPLE/debug/unix-test-proxy"
fi

# Some local dev setups (this repo's own build output) also stage binaries
# under target/<profile> without the triple segment when built without an
# explicit --target. Fall back there too before giving up.
if [ ! -f "$MXC_EXEC_MAC" ]; then
    MXC_EXEC_MAC="$REPO_DIR/src/target/release/mxc-exec-mac"
fi
if [ ! -f "$MXC_EXEC_MAC" ]; then
    MXC_EXEC_MAC="$REPO_DIR/src/target/debug/mxc-exec-mac"
fi
if [ ! -f "$UNIX_TEST_PROXY" ]; then
    UNIX_TEST_PROXY="$REPO_DIR/src/target/release/unix-test-proxy"
fi
if [ ! -f "$UNIX_TEST_PROXY" ]; then
    UNIX_TEST_PROXY="$REPO_DIR/src/target/debug/unix-test-proxy"
fi

if [ ! -f "$MXC_EXEC_MAC" ]; then
    echo "Error: mxc-exec-mac not found. Run ./build-mac.sh (or" \
         "'cargo build -p mxc_darwin' from src/) first." >&2
    exit 1
fi
chmod +x "$MXC_EXEC_MAC" 2>/dev/null || true

export MXC_EXEC_MAC
export UNIX_TEST_PROXY
