#!/bin/bash
# Seatbelt script-file execution test: writes a shell script to disk inside
# the sandbox, marks it executable, and runs the on-disk file directly (as
# opposed to an inline `commandLine` string), verifying script-file execution
# specifically.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

rm -f /tmp/mxc_seatbelt_script_test.sh

echo "Running Seatbelt script-file execution test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_script_file.json" 2>&1)
echo "$OUTPUT"

FAILED=0
if ! echo "$OUTPUT" | grep -q "SCRIPT_FILE_EXEC_OK"; then
    echo "FAIL: on-disk script file did not execute."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "arg1=hello"; then
    echo "FAIL: script file did not receive its argument correctly."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "EXIT_CODE=7"; then
    echo "FAIL: script file's own exit code (7) was not propagated."
    FAILED=1
fi

rm -f /tmp/mxc_seatbelt_script_test.sh

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt script-file execution test complete."
