#!/bin/bash
# Seatbelt filesystem nested-precedence test: verifies a readonlyPaths entry
# nested inside a broader readwritePaths root stays read-only (the "deepest
# rule wins" precedence documented in docs/macos-support/seatbelt-backend.md).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

RW_DIR="/tmp/mxc_seatbelt_fs_test/rw"
NESTED_RO_DIR="$RW_DIR/readonly_subdir"
rm -rf "/tmp/mxc_seatbelt_fs_test"
mkdir -p "$NESTED_RO_DIR"
echo "NESTED_RO_MARKER" > "$NESTED_RO_DIR/seed.txt"
cleanup() {
    rm -rf "/tmp/mxc_seatbelt_fs_test"
}
trap cleanup EXIT

echo "Running Seatbelt filesystem nested-precedence test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_filesystem_nested_precedence.json" 2>&1)
echo "$OUTPUT"

FAILED=0
if ! echo "$OUTPUT" | grep -q "READ_OK"; then
    echo "FAIL: reading the nested readonly path did not succeed."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "WRITE_BLOCKED_OK"; then
    echo "FAIL: nested readonly path did not stay read-only (parent readwrite leaked through)."
    FAILED=1
fi
if [ -f "$NESTED_RO_DIR/should_not_exist.txt" ]; then
    echo "FAIL: write to nested readonly path actually landed on the host filesystem."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt filesystem nested-precedence test complete."
