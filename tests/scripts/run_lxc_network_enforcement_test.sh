#!/bin/bash
# LXC network policy enforcement test
#
# Every other network script asserts that the FORWARD hook was *installed*.
# That is a log line, and a hook can install cleanly, name the right chain,
# and still match no packet -- which is exactly how a fully populated deny-all
# chain that filtered nothing once passed every script in this directory.
#
# This script asserts the guarantee itself rather than the log: a destination
# the policy does not allow must be unreachable from inside the container.
#
# Both directions are required, and the allow case is not decoration. A
# blocked-only assertion would also pass on a host with no working network at
# all, or on a change that broke egress outright, so it proves nothing on its
# own.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# An honest skip for a missing prerequisite: exit 77 so run_lxc_all_tests.sh
# records SKIPPED rather than PASS. A suite that could not run must not look green.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables/ip6tables and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_enforcement_deny.json"
ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_enforcement_allow.json"
DENY_CHAIN="MXC-CLI-LXC-Net-Deny"
ALLOW_CHAIN="MXC-CLI-LXC-Net-Allow"

fail() {
    echo "FAIL: $1"
    exit 1
}

assert_firewall_chain_cleaned_up() {
    if iptables -S "$1" >/dev/null 2>&1; then
        fail "iptables chain '$1' was left behind after lxc-exec completed."
    fi
    if ip6tables -S "$1" >/dev/null 2>&1; then
        fail "ip6tables chain '$1' was left behind after lxc-exec completed."
    fi
}

# A hook that references the chain but survives teardown leaves the next
# container's traffic running through a stale rule, so the reference count
# matters as much as the chain itself.
assert_no_forward_reference() {
    if iptables -S FORWARD 2>/dev/null | grep -Fq -- "$1"; then
        fail "a FORWARD rule still references chain '$1' after teardown."
    fi
}

echo "Running LXC network policy enforcement test..."

# The container reports the outcome itself rather than relying on its exit
# code, so a wrapper that swallows or rewrites the status cannot turn a
# reachable destination into an apparent block.
echo "--- deny case: default policy blocks, nothing allowed ---"
DENY_OUTPUT=$("$LXC_EXEC" --debug "$DENY_CONFIG" 2>&1 || true)
echo "$DENY_OUTPUT"

if echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "egress succeeded under a default-block policy with no allowed hosts. The chain is not filtering this container's traffic."
fi
if ! echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the deny case produced no verdict at all; the container command did not run."
fi

assert_no_forward_reference "$DENY_CHAIN"
assert_firewall_chain_cleaned_up "$DENY_CHAIN"

echo "--- allow case: same default, destination explicitly allowed ---"
ALLOW_OUTPUT=$("$LXC_EXEC" --debug "$ALLOW_CONFIG" 2>&1 || true)
echo "$ALLOW_OUTPUT"

if echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "an explicitly allowed destination was unreachable. The policy is over-blocking, so the deny case above proves nothing."
fi
if ! echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the allow case produced no verdict at all; the container command did not run."
fi

assert_no_forward_reference "$ALLOW_CHAIN"
assert_firewall_chain_cleaned_up "$ALLOW_CHAIN"

echo "PASS: a disallowed destination was blocked and an allowed destination was reachable."
echo "LXC network policy enforcement test complete."