#!/bin/bash
# Bubblewrap filesystem policy test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

# Set up test directories
RW_DIR="/mnt/readwrite"
RO_DIR="/mnt/readonly"
DENIED_DIR="/mnt/denied"

sudo mkdir -p "$RW_DIR" "$RO_DIR" "$DENIED_DIR"
echo "test content" | sudo tee "$RO_DIR/test.txt" > /dev/null
echo "should not see this" | sudo tee "$DENIED_DIR/secret.txt" > /dev/null

echo "Running Bubblewrap filesystem test..."
"$LXC_EXEC" --experimental "$REPO_DIR/test_configs/bubblewrap_filesystem.json"
echo "Bubblewrap filesystem test complete."

# Verify the write succeeded
if [ -f "$RW_DIR/output.txt" ]; then
    echo "PASS: Write to readwrite path succeeded."
else
    echo "FAIL: Write to readwrite path did not produce expected file."
    exit 1
fi

# Clean up
sudo rm -rf "$RW_DIR" "$RO_DIR" "$DENIED_DIR"
