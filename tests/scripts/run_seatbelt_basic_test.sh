#!/bin/bash
# Basic Seatbelt (macOS) sandbox smoke test.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

echo "Running basic Seatbelt test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_basic.json" 2>&1)
echo "$OUTPUT"

if ! echo "$OUTPUT" | grep -q "SEATBELT_BASIC_OK"; then
    echo "FAIL: expected sentinel SEATBELT_BASIC_OK not found."
    exit 1
fi
echo "Basic Seatbelt test complete."
