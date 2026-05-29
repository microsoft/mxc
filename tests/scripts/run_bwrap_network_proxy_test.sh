#!/bin/bash
# Bubblewrap network-proxy sandbox tests (cooperative env-var proxy).
#
# These tests do NOT require root: the builtin test proxy runs as the
# current user and the sandbox reaches it via loopback.
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

run_one() {
    local label="$1"
    local config="$2"
    local sentinel="$3"
    echo "Running Bubblewrap network proxy test: $label..."
    local out
    if ! out=$("$LXC_EXEC" --experimental "$REPO_DIR/tests/configs/$config" 2>&1); then
        echo "$out"
        echo "FAIL: $label (lxc-exec returned non-zero)"
        return 1
    fi
    if ! grep -q "$sentinel" <<<"$out"; then
        echo "$out"
        echo "FAIL: $label (sentinel '$sentinel' not found in output)"
        return 1
    fi
    echo "PASS: $label"
}

run_one "builtin proxy"    "bubblewrap_network_proxy_builtin.json"    "PROXY_OK"
run_one "proxy allowlist"  "bubblewrap_network_proxy_allowlist.json"  "BLOCKED_OK"
run_one "proxy blocklist"  "bubblewrap_network_proxy_blocklist.json"  "BLOCKED_OK"

echo "Bubblewrap network proxy tests complete."
