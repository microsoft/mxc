#!/bin/bash
# LXC filesystem policy test
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

# Create test directories
READONLY_DIR=$(mktemp -d)
READWRITE_DIR=$(mktemp -d)
trap 'rm -rf "$READONLY_DIR" "$READWRITE_DIR"' EXIT
echo "test content" > "$READONLY_DIR/test.txt"

# Give mapped container users access to the host fixtures.
chmod 755 "$READONLY_DIR"
chmod 644 "$READONLY_DIR/test.txt"
chmod 777 "$READWRITE_DIR"

echo "Running LXC filesystem test..."
echo "Readonly dir: $READONLY_DIR"
echo "Readwrite dir: $READWRITE_DIR"

# Update config paths dynamically
CONFIG=$(cat "$REPO_DIR/tests/configs/lxc_filesystem_test.json" | \
    sed "s|/mnt/readonly|$READONLY_DIR|g" | \
    sed "s|/mnt/readwrite|$READWRITE_DIR|g")

echo "$CONFIG" | "$LXC_EXEC" --config /dev/stdin

echo "LXC filesystem test complete."
