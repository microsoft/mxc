#!/bin/bash
# Seatbelt network deny test: defaultPolicy "block" denies all outbound.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

echo "Running Seatbelt network deny test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_deny.json" 2>&1)
echo "$OUTPUT"

if ! echo "$OUTPUT" | grep -q "NETWORK_BLOCKED_OK"; then
    echo "FAIL: outbound network was not blocked under defaultPolicy=block."
    exit 1
fi
echo "Seatbelt network deny test complete."
