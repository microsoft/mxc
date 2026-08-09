#!/bin/bash
# LXC deny-precedence enforcement test
#
# A destination named in both allowedHosts and blockedHosts must be blocked.
# The chain is first-match-wins, so this is decided entirely by which list is
# emitted first -- there is no separate precedence pass to assert on. That
# makes it invisible to any test that only inspects rules individually, and it
# is why this assertion is behavioral rather than a log grep.
#
# Both configs name the same destination set, 0.0.0.0/0 and ::/0, so the rules
# are literal CIDRs rather than a hostname resolved once per list entry. A
# hostname would be resolved separately for the allow entry and the block
# entry, and round-robin DNS could hand back different addresses for the two,
# which would make the outcome depend on which address wget happened to pick.
#
# The control run is what makes the overlap run mean anything. Without it, a
# host with no working egress at all -- or a change that broke networking
# outright -- would produce the same blocked verdict and look like a pass.
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

OVERLAP_CONFIG="$REPO_DIR/tests/configs/lxc_network_deny_precedence_overlap.json"
CONTROL_CONFIG="$REPO_DIR/tests/configs/lxc_network_deny_precedence_control.json"
OVERLAP_CHAIN="MXC-CLI-LXC-Net-DenyWins"
CONTROL_CHAIN="MXC-CLI-LXC-Net-DenyCtl"

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

assert_no_forward_reference() {
    if iptables -S FORWARD 2>/dev/null | grep -Fq -- "$1"; then
        fail "a FORWARD rule still references chain '$1' after teardown."
    fi
}

echo "Running LXC deny-precedence enforcement test..."

echo "--- control: destination allowed, nothing blocked ---"
CONTROL_OUTPUT=$("$LXC_EXEC" --debug "$CONTROL_CONFIG" 2>&1 || true)
echo "$CONTROL_OUTPUT"

if ! echo "$CONTROL_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the control destination was unreachable with an allow-everything policy, so this host cannot distinguish a deny-precedence failure from a broken network."
fi

assert_no_forward_reference "$CONTROL_CHAIN"
assert_firewall_chain_cleaned_up "$CONTROL_CHAIN"

echo "--- overlap: same destination in both allowedHosts and blockedHosts ---"
OVERLAP_OUTPUT=$("$LXC_EXEC" --debug "$OVERLAP_CONFIG" 2>&1 || true)
echo "$OVERLAP_OUTPUT"

if echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "a destination present in BOTH allowedHosts and blockedHosts was reachable. Allow rules are winning over deny rules, so a blocklist entry can be silently defeated by an overlapping allowlist entry."
fi
if ! echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the overlap case produced no verdict at all; the container command did not run."
fi

assert_no_forward_reference "$OVERLAP_CHAIN"
assert_firewall_chain_cleaned_up "$OVERLAP_CHAIN"

echo "PASS: a destination in both lists was blocked, and the same destination was reachable when only allowed."
echo "LXC deny-precedence enforcement test complete."
