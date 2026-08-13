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

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables/ip6tables and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CHAIN_NAME=""
VETH=""

# This test deliberately leaves a container, a firewall chain, and the veth
# return rules behind, so it owns their removal on every exit path rather than
# the runner.
cleanup() {
    for tool in iptables ip6tables; do
        # The return rules name only the veth and jump to ACCEPT, so a search
        # keyed on the chain name alone never sees them.
        for pattern in "$CHAIN_NAME" "$VETH"; do
            [ -n "$pattern" ] || continue
            while read -r rule; do
                [ -n "$rule" ] || continue
                # shellcheck disable=SC2086
                $tool -D FORWARD ${rule#-A FORWARD } >/dev/null 2>&1 || true
            done <<<"$($tool -S FORWARD 2>/dev/null | grep -F -- "$pattern" || true)"
        done
        if [ -n "$CHAIN_NAME" ]; then
            $tool -F "$CHAIN_NAME" >/dev/null 2>&1 || true
            $tool -X "$CHAIN_NAME" >/dev/null 2>&1 || true
        fi
    done
    lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Guards against a stale container from an earlier failed run being mistaken
# for this run's work.
lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

derive_chain_name() {
    CHAIN_NAME="$(sed -n 's/^.*Creating iptables\/ip6tables chain: \([^ ]*\).*$/\1/p' <<<"$1" | head -n 1)"
    if [ -z "$CHAIN_NAME" ]; then
        fail "no chain creation was logged, so the chain name could not be determined."
    fi
    if ! grep -Eq '^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$' <<<"$CHAIN_NAME"; then
        fail "chain name '$CHAIN_NAME' does not match the documented MXC-<slug>-<hash> shape."
    fi
    if [ "${#CHAIN_NAME}" -gt 28 ]; then
        fail "chain name '$CHAIN_NAME' exceeds the 28-character iptables ceiling."
    fi
}

echo "Running LXC preserved-policy test..."

OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

if ! grep -Fq "MXC_PRESERVE_RAN" <<<"$OUTPUT"; then
    fail "the container command did not run, so nothing below is being verified."
fi

derive_chain_name "$OUTPUT"
VETH="$(sed -n 's/^.*Discovered veth interface: \([^ ]*\).*$/\1/p' <<<"$OUTPUT" | head -n 1)"

# The positive control. Were the chain never installed, every assertion below
# would be asserting the absence of something that was never there.
if ! grep -Fq "FORWARD hook installed" <<<"$OUTPUT"; then
    fail "no FORWARD hook was installed, so this run never had a policy to preserve."
fi

if ! iptables -S "$CHAIN_NAME" >/dev/null 2>&1; then
    fail "preservePolicy was set, but iptables chain '$CHAIN_NAME' was removed."
fi

if ! ip6tables -S "$CHAIN_NAME" >/dev/null 2>&1; then
    fail "preservePolicy was set, but ip6tables chain '$CHAIN_NAME' was removed."
fi

# A surviving chain that nothing dispatches to is not a preserved policy.
if ! iptables -S FORWARD 2>/dev/null | grep -Fq -- "$CHAIN_NAME"; then
    fail "chain '$CHAIN_NAME' survived but no FORWARD rule reaches it, so the container is unfiltered."
fi

if ! lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
    fail "destroyOnExit was false, but the container was destroyed."
fi

echo "PASS: the policy and its FORWARD hook outlived the run."
echo "LXC preserved-policy test complete."
