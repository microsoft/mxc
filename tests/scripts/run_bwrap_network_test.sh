#!/bin/bash
# Bubblewrap network block test
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

echo "Running Bubblewrap network block test..."
OUTPUT=$("$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/bubblewrap_network_block.json" 2>&1 || true)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "blocked\|network.*correctly\|connection refused\|network is unreachable"; then
    echo "PASS: Network correctly blocked."
else
    echo "FAIL: Network should have been blocked."
    exit 1
fi
echo "Bubblewrap network block test complete."
