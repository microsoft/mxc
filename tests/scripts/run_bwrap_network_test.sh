#!/bin/bash
# Bubblewrap network block test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

echo "Running Bubblewrap network block test..."
OUTPUT=$("$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/bubblewrap_network_block.json" 2>&1 || true)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -qi "blocked\|network.*correctly\|connection refused\|network is unreachable"; then
    echo "PASS: Network correctly blocked."
else
    echo "FAIL: Network should have been blocked."
    exit 1
fi
echo "Bubblewrap network block test complete."

# Schema 0.8 must fail closed on firewall mode rather than building an iptables
# chain that is never hooked into FORWARD and reporting success.
REJECTION="enforcementMode='firewall' and 'both' are not supported"

echo "Running Bubblewrap firewall-mode rejection test (schema 0.8)..."
set +e
FIREWALL_OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_network_firewall_rejected.json" 2>&1)
FIREWALL_STATUS=$?
set -e

# Both halves matter: a regression that prints the rejection and still exits 0
# is the silent-success shape this case exists to catch.
if [ "$FIREWALL_STATUS" -eq 0 ]; then
    echo "$FIREWALL_OUTPUT"
    echo "FAIL: schema 0.8 firewall mode exited 0; the rejection must fail the run."
    exit 1
fi

if echo "$FIREWALL_OUTPUT" | grep -qF "$REJECTION"; then
    echo "PASS: schema 0.8 firewall mode rejected rather than silently unenforced."
else
    echo "$FIREWALL_OUTPUT"
    echo "FAIL: schema 0.8 firewall mode should be rejected."
    exit 1
fi

# The same policy on 0.6 keeps its existing behavior. Asserts only that the new
# gate does not fire — whether iptables itself succeeds depends on privilege.
echo "Running Bubblewrap firewall-mode legacy test (schema 0.6)..."
set +e
LEGACY_OUTPUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_network_firewall.json" 2>&1)
LEGACY_STATUS=$?
set -e

if echo "$LEGACY_OUTPUT" | grep -qF "$REJECTION"; then
    echo "$LEGACY_OUTPUT"
    echo "FAIL: schema 0.6 firewall mode must not be rejected."
    exit 1
fi

# A non-zero status here is expected without privilege (iptables itself may
# fail), but it must never be a *config* rejection -- that would mean the 0.8
# gate leaked into the legacy schema.
if echo "$LEGACY_OUTPUT" | grep -qF "Configuration parse error"; then
    echo "$LEGACY_OUTPUT"
    echo "FAIL: schema 0.6 firewall mode failed config validation (status $LEGACY_STATUS)."
    exit 1
fi
echo "PASS: schema 0.6 firewall mode still accepted."
echo "Bubblewrap firewall-mode tests complete."
