#!/bin/bash
# Seatbelt allowedHosts degrade test: Seatbelt cannot filter DNS names, so
# `allowedHosts` is documented to degrade to allow-all outbound as best-effort
# rather than being enforced. This test pins that documented (if surprising)
# behavior: a host that is NOT in `allowedHosts` is still expected to connect
# successfully under `defaultPolicy: "block"`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=lib/seatbelt_env.sh
source "$SCRIPT_DIR/lib/seatbelt_env.sh"

echo "Running Seatbelt allowedHosts degrade-to-allow-all test..."
OUTPUT=$("$MXC_EXEC_MAC" --debug "$REPO_DIR/tests/configs/seatbelt_network_allowed_hosts_degrade.json" 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "DEGRADE_TO_ALLOW_ALL_CONFIRMED"; then
    echo "PASS (documented behavior): a non-listed host still connected -- " \
         "allowedHosts degrades to allow-all on Seatbelt, as documented in " \
         "docs/macos-support/seatbelt-backend.md."
elif echo "$OUTPUT" | grep -q "NON_LISTED_HOST_BLOCKED"; then
    echo "NOTE: the non-listed host was blocked. This contradicts the " \
         "documented degrade-to-allow-all behavior for 'allowedHosts' on " \
         "Seatbelt -- worth a closer look, but not a test-script bug."
    exit 1
else
    echo "FAIL: neither expected sentinel was found in the output."
    exit 1
fi
echo "Seatbelt allowedHosts degrade test complete."
