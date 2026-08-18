#!/bin/bash
# Seatbelt blockedHosts rejection test: Seatbelt cannot enforce hostname
# blocks, so `blockedHosts` is rejected at validation rather than silently
# ignored -- the sandboxed process must never run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

echo "Running Seatbelt blockedHosts rejection test..."
set +e
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_blocked_hosts_rejected.json" 2>&1)
EXIT_CODE=$?
set -e
echo "$OUTPUT"
echo "Exit code: $EXIT_CODE"

FAILED=0
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "FAIL: expected a non-zero exit code (config should be rejected)."
    FAILED=1
fi
if echo "$OUTPUT" | grep -q "SHOULD_NOT_RUN"; then
    echo "FAIL: the sandboxed process ran; blockedHosts should have been rejected before execution."
    FAILED=1
fi
if ! echo "$OUTPUT" | grep -qi "does not support per-host network filtering"; then
    echo "FAIL: expected rejection message about per-host network filtering was not found."
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
echo "Seatbelt blockedHosts rejection test complete."
