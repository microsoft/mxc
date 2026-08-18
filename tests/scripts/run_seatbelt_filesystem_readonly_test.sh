#!/bin/bash
# Seatbelt filesystem read-only test: verifies a readonlyPaths subtree can be
# read but not written.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

RW_DIR="/tmp/mxc_seatbelt_fs_test/rw"
RO_DIR="/tmp/mxc_seatbelt_fs_test/ro"
rm -rf "/tmp/mxc_seatbelt_fs_test"
mkdir -p "$RW_DIR" "$RO_DIR"
echo "RO_SEED_MARKER" > "$RO_DIR/seed.txt"
cleanup() {
    rm -rf "/tmp/mxc_seatbelt_fs_test"
}
trap cleanup EXIT

echo "Running Seatbelt filesystem read-only test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_filesystem_readonly.json" 2>&1)
echo "$OUTPUT"

FAILED=0
if ! echo "$OUTPUT" | grep -q "READ_OK"; then
    echo "FAIL: reading the readonly path did not succeed."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "WRITE_BLOCKED_OK"; then
    echo "FAIL: writing to the readonly path was not blocked."
    FAILED=1
fi
if [ -f "$RO_DIR/should_not_exist.txt" ]; then
    echo "FAIL: write to readonly path actually landed on the host filesystem."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt filesystem read-only test complete."
