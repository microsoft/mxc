#!/bin/bash
# Seatbelt legacy proxy tests (schema 0.7.x `network.proxy` shape):
#  1. `builtinTestServer: true` under defaultPolicy="block" -- MXC spins up its
#     own internal test proxy and the sandboxed process should be able to
#     reach the internet exclusively through it.
#  2. A remote (non-loopback) `proxy.url` combined with defaultPolicy="block"
#     is rejected outright -- Seatbelt has no way to force traffic through an
#     external proxy, so this combination can never be honored.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

FAILED=0

echo "Running Seatbelt legacy proxy test: builtinTestServer..."
OUTPUT=$("$MXC_EXEC_MAC" --debug --allow-testing-features "$REPO_DIR/tests/configs/seatbelt_network_proxy_builtin.json" 2>&1)
echo "$OUTPUT"
if ! echo "$OUTPUT" | grep -q "PROXY_OK"; then
    echo "FAIL: request through the builtin test proxy did not succeed."
    FAILED=1
fi
echo ""

echo "Running Seatbelt legacy proxy test: remote proxy rejected under defaultPolicy=block..."
set +e
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_proxy_remote_rejected.json" 2>&1)
EXIT_CODE=$?
set -e
echo "$OUTPUT"
echo "Exit code: $EXIT_CODE"
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "FAIL: expected a non-zero exit code (config should be rejected)."
    FAILED=1
fi
if echo "$OUTPUT" | grep -q "SHOULD_NOT_RUN"; then
    echo "FAIL: the sandboxed process ran; remote proxy + defaultPolicy=block should have been rejected before execution."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -qi "remote network.proxy"; then
    echo "FAIL: expected rejection message about a remote network.proxy was not found."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt legacy proxy tests complete."
