#!/bin/bash
# Basic Bubblewrap sandbox test
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

echo "Running basic Bubblewrap test..."
if ! OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_basic.json" 2>&1); then
    echo "$OUTPUT"
    echo "FAIL: lxc-exec failed during the basic Bubblewrap test."
    exit 1
fi
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "CWD_BASELINE_OK" || {
    echo "FAIL: process.cwd under the baseline did not become the child's real cwd."
    exit 1
}
echo "Basic Bubblewrap test complete."
