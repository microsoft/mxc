#!/bin/bash
# Seatbelt local-network (loopback listen/bind) tests. `allowLocalNetwork`
# gates network-inbound (listen()/accept()) independently of `defaultPolicy`;
# both cases here use `defaultPolicy: "allow"` so the outbound connect() side
# is never the confounding variable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

FAILED=0

echo "Running Seatbelt local-network test: allowLocalNetwork=true..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_local_allow.json" 2>&1)
echo "$OUTPUT"
if ! echo "$OUTPUT" | grep -q "LOCAL_LISTEN_OK"; then
    echo "FAIL: local listen()/connect() did not succeed with allowLocalNetwork=true."
    FAILED=1
fi
echo ""

echo "Running Seatbelt local-network test: allowLocalNetwork absent..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_local_deny.json" 2>&1)
echo "$OUTPUT"
if ! echo "$OUTPUT" | grep -q "LOCAL_LISTEN_BLOCKED_OK"; then
    echo "FAIL: local listen() should have been blocked without allowLocalNetwork."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt local-network tests complete."
