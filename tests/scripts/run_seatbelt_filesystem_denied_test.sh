#!/bin/bash
# Seatbelt filesystem denied-path test: verifies deniedPaths blocks both read
# and write, even when nested underneath a broader readwritePaths ancestor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

RW_DIR="/tmp/mxc_seatbelt_fs_test/rw"
DENIED_DIR="$RW_DIR/denied_subdir"
rm -rf "/tmp/mxc_seatbelt_fs_test"
mkdir -p "$DENIED_DIR"
echo "DENIED_SECRET" > "$DENIED_DIR/secret.txt"
cleanup() {
    rm -rf "/tmp/mxc_seatbelt_fs_test"
}
trap cleanup EXIT

echo "Running Seatbelt filesystem denied-path test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_filesystem_denied.json" 2>&1)
echo "$OUTPUT"

FAILED=0
if ! echo "$OUTPUT" | grep -q "READ_BLOCKED_OK"; then
    echo "FAIL: reading the denied path was not blocked."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "WRITE_BLOCKED_OK"; then
    echo "FAIL: writing to the denied path was not blocked."
    FAILED=1
fi
if [ -f "$DENIED_DIR/should_not_exist.txt" ]; then
    echo "FAIL: write to denied path actually landed on the host filesystem."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt filesystem denied-path test complete."
