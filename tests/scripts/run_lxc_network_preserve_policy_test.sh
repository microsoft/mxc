#!/bin/bash
# LXC preserved-policy lifecycle test
#
# `preservePolicy` promises the network policy outlives the run. No other
# script asserts that promise, and asserting it needs the kernel rather than a
# log line: the runner can log that it skipped removal and have the rules
# removed anyway on its way out.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

CONFIG="$REPO_DIR/tests/configs/lxc_network_preserve_policy.json"
CONTAINER="CLI-LXC-Net-Preserve"

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables/ip6tables and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CHAIN_NAME=""

# This test deliberately leaves a container behind, so it owns the container's
# removal on every exit path rather than the runner. The policy it preserves
# lives in that container's network namespace and goes with it.
cleanup() {
    lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Guards against a stale container from an earlier failed run being mistaken
# for this run's work.
lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

echo "Running LXC preserved-policy test..."

OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

if ! grep -Fq "MXC_PRESERVE_RAN" <<<"$OUTPUT"; then
    fail "the container command did not run, so nothing below is being verified."
fi

derive_chain_name "$OUTPUT"

# The positive control. Were the chain never installed, every assertion below
# would be asserting the absence of something that was never there.
if ! grep -Fq "OUTPUT hook installed" <<<"$OUTPUT"; then
    fail "no OUTPUT hook was installed, so this run never had a policy to preserve."
fi

if ! lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
    fail "destroyOnExit was false, but the container was destroyed."
fi

# The preserved rules live in the container's network namespace, so reaching
# them means entering it. `lxc-info -p -H` prints the init PID alone.
INIT_PID="$(lxc-info -n "$CONTAINER" -p -H 2>/dev/null || true)"
if [ -z "$INIT_PID" ] || [ "$INIT_PID" = "-1" ]; then
    fail "could not read the init PID of the preserved container."
fi

in_ns() {
    nsenter -t "$INIT_PID" -n "$@"
}

if ! in_ns iptables -S "$CHAIN_NAME" >/dev/null 2>&1; then
    fail "preservePolicy was set, but iptables chain '$CHAIN_NAME' was removed."
fi

if ! in_ns ip6tables -S "$CHAIN_NAME" >/dev/null 2>&1; then
    fail "preservePolicy was set, but ip6tables chain '$CHAIN_NAME' was removed."
fi

# A surviving chain that nothing dispatches to is not a preserved policy.
if ! in_ns iptables -S OUTPUT 2>/dev/null | grep -Fq -- "$CHAIN_NAME"; then
    fail "chain '$CHAIN_NAME' survived but no OUTPUT rule reaches it, so the container is unfiltered."
fi

echo "PASS: the policy and its OUTPUT hook outlived the run."
echo "LXC preserved-policy test complete."
