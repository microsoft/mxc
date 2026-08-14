#!/bin/bash
# Bubblewrap network-proxy sandbox tests.
#
# These tests do NOT require root. Proxy mode uses a private network namespace
# with rootless slirp4netns routing to the host-side builtin proxy.
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
    if ! out=$("$LXC_EXEC" --experimental --allow-testing-features "$REPO_DIR/tests/configs/$config" 2>&1); then
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

echo "Running Bubblewrap private proxy namespace test..."
HOST_NETNS="$(readlink /proc/self/ns/net)"
if ! NAMESPACE_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_proxy_namespace.json" 2>&1); then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (lxc-exec returned non-zero)"
    exit 1
fi
SANDBOX_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$NAMESPACE_OUT" | tail -n 1)"
if [ -z "$SANDBOX_NETNS" ]; then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (namespace identity not reported)"
    exit 1
fi
if [ "$SANDBOX_NETNS" = "$HOST_NETNS" ]; then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (sandbox shares host network namespace)"
    exit 1
fi
if ! grep -q "PROXY_NAMESPACE_OK" <<<"$NAMESPACE_OUT"; then
    echo "$NAMESPACE_OUT"
    echo "FAIL: private proxy namespace (proxy request did not complete)"
    exit 1
fi
echo "PASS: private proxy namespace"

echo "Bubblewrap network proxy tests complete."
