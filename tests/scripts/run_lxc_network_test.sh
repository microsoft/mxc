#!/bin/bash
# LXC network policy test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

echo "Running LXC network test..."

# When the network test fails it is usually the environment (no DHCP lease,
# dnsmasq not answering, blocked egress) rather than the policy code. Capture
# the container's own view first so the log distinguishes those cases. This is
# diagnostic only and never fails the suite.
if [ "${MXC_LXC_NETWORK_DIAGNOSTICS:-1}" = "1" ]; then
    echo "--- LXC network diagnostics (container) ---"
    "$LXC_EXEC" "$REPO_DIR/tests/configs/lxc_network_diagnostics.json" 2>&1 || \
        echo "(diagnostic container run failed)"
    echo "--- end diagnostics ---"
fi

"$LXC_EXEC" "$REPO_DIR/tests/configs/lxc_network_test.json"
echo "LXC network test complete."
