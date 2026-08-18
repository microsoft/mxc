#!/bin/bash
# Seatbelt network allow test: defaultPolicy "allow" permits all outbound.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

echo "Running Seatbelt network allow test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_allow.json" 2>&1)
echo "$OUTPUT"

FAILED=0
if ! echo "$OUTPUT" | grep -q "HOST1_ALLOW_OK"; then
    echo "FAIL: outbound to the first host was not allowed under defaultPolicy=allow."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -q "HOST2_ALLOW_OK"; then
    echo "FAIL: outbound to the second host was not allowed under defaultPolicy=allow."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt network allow test complete."
