#!/bin/bash
# Seatbelt Python execution test: verifies Python runs inside the sandbox and
# confirms the process environment is cleared (not inherited from the host).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

echo "Running Seatbelt Python test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_python.json" 2>&1)
echo "$OUTPUT"

FAILED=0
if ! echo "$OUTPUT" | grep -q "PYTHON_EXEC_OK"; then
    echo "FAIL: Python did not execute successfully."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "HOME_CLEARED_OK"; then
    echo "FAIL: HOME was not cleared inside the sandbox (host env leaked in)."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "PATH_BASELINE_OK"; then
    echo "FAIL: PATH inside the sandbox was not the expected baseline."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt Python test complete."
