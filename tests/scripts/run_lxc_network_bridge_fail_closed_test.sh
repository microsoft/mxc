#!/bin/bash
# LXC bridged fail-closed test
#
# On a bridged veth the physdev rule is the only one that can match, and it
# only matches while br_netfilter delivers bridged packets to iptables. The
# unit suite cannot prove the refusal, because the outcome depends on host
# state it declines to control. This turns that state off for real.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

CONFIG="$REPO_DIR/tests/configs/lxc_network_bridge_fail_closed.json"
CONTAINER="CLI-LXC-Net-FailClosed"
KNOB=/proc/sys/net/bridge/bridge-nf-call-iptables

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "requires root for sysctl and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

modprobe br_netfilter >/dev/null 2>&1 || true
[ -f "$KNOB" ] || skip "br_netfilter is not loaded, so there is no bridged delivery to disable."

ORIGINAL="$(cat "$KNOB")"

# This knob is global kernel state. Left at 0 it silently unenforces every
# bridged container on the host, including the next test to run.
restore() {
    echo "$ORIGINAL" > "$KNOB" 2>/dev/null || true
    lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
}
trap restore EXIT

lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

echo "Running LXC bridged fail-closed test..."

echo "--- refusal case: bridged delivery disabled ---"
echo 0 > "$KNOB"
[ "$(cat "$KNOB")" = "0" ] || skip "could not disable $KNOB on this host."

set +e
DENIED_OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1)
DENIED_STATUS=$?
set -e
echo "$DENIED_OUTPUT"

if [ "$DENIED_STATUS" -eq 0 ]; then
    fail "lxc-exec reported success while the policy it installed could never be reached."
fi
if ! grep -Fq "Refusing to report success for an unenforceable policy" <<<"$DENIED_OUTPUT"; then
    fail "the run failed, but not with the documented bridged refusal, so this proves nothing."
fi
if grep -Fq "MXC_SCRIPT_RAN" <<<"$DENIED_OUTPUT"; then
    fail "the container script ran with an unenforceable policy."
fi

# Without this the test would also pass on a build that refuses every run, or
# on a host where no container can start at all.
echo "--- control case: bridged delivery restored ---"
echo "$ORIGINAL" > "$KNOB"
[ "$(cat "$KNOB")" = "1" ] || skip "host does not deliver bridged packets to iptables by default."

set +e
ALLOWED_OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1)
ALLOWED_STATUS=$?
set -e
echo "$ALLOWED_OUTPUT"

if [ "$ALLOWED_STATUS" -ne 0 ]; then
    fail "the same config failed with bridged delivery restored, so the refusal above was not caused by the knob."
fi
if ! grep -Fq "MXC_SCRIPT_RAN" <<<"$ALLOWED_OUTPUT"; then
    fail "the control run installed a policy but never ran the script."
fi

echo "PASS: an unenforceable bridged policy was refused, and the same config ran once delivery was restored."
echo "LXC bridged fail-closed test complete."
