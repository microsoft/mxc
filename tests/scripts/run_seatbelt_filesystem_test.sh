#!/bin/bash
# Seatbelt filesystem read-write test: verifies a write into a readwritePaths
# subtree succeeds and is actually visible on the host filesystem afterward
# (not just printed inside the sandbox's stdout).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

RW_DIR="/tmp/mxc_seatbelt_fs_test/rw"
rm -rf "$RW_DIR"
mkdir -p "$RW_DIR"
cleanup() {
    rm -rf "/tmp/mxc_seatbelt_fs_test"
}
trap cleanup EXIT

echo "Running Seatbelt filesystem read-write test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_filesystem_rw.json" 2>&1)
echo "$OUTPUT"

FAILED=0
if ! echo "$OUTPUT" | grep -q "WRITE_READ_OK"; then
    echo "FAIL: sandbox did not report a successful write+read."
    FAILED=1
fi
if [ ! -f "$RW_DIR/output.txt" ]; then
    echo "FAIL: expected output file was not found on the host after the run."
    FAILED=1
elif ! grep -q "sandbox wrote this" "$RW_DIR/output.txt"; then
    echo "FAIL: output file exists but does not contain the expected content."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt filesystem read-write test complete."
