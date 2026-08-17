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

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

# Compared against a snapshot taken before the run, so chains left behind by an
# earlier failed run are not blamed on this one.
assert_no_new_mxc_chains() {
    local tool="$1" before="$2" after="" leaked="" chain
    # Captured before iterating rather than piped in from a process
    # substitution, whose exit status is not the loop's. A failed enumeration
    # would otherwise read as zero chains and pass this assertion while
    # verifying nothing.
    if ! after="$(mxc_chains "$tool")"; then
        fail "could not enumerate $tool chains, so cleanup was not verified."
    fi
    while IFS= read -r chain; do
        [ -n "$chain" ] || continue
        grep -Fxq "$chain" <<<"$before" || leaked="$leaked $chain"
    done <<<"$after"
    if [ -n "$leaked" ]; then
        fail "$tool chain(s) left behind after lxc-exec completed:$leaked"
    fi
}

# The named chain must be gone, and the run must not have leaked any other
# MXC-owned chain either. The first check is specific to the container this
# case ran; the second catches a rename or a partial rollback that leaves a
# differently named chain behind.
assert_firewall_chain_cleaned_up() {
    local chain="$1"
    if iptables -S "$chain" >/dev/null 2>&1; then
        fail "iptables chain '$chain' was left behind after lxc-exec completed."
    fi
    if ip6tables -S "$chain" >/dev/null 2>&1; then
        fail "ip6tables chain '$chain' was left behind after lxc-exec completed."
    fi
    assert_no_new_mxc_chains iptables "$MXC_CHAINS_BEFORE_V4"
    assert_no_new_mxc_chains ip6tables "$MXC_CHAINS_BEFORE_V6"
}

assert_no_forward_reference() {
    if iptables -S FORWARD 2>/dev/null | grep -Fq -- "$1"; then
        fail "a FORWARD rule still references chain '$1' after teardown."
    fi
}

echo "Running LXC deny-precedence enforcement test..."

echo "--- control: destination allowed, nothing blocked ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
CONTROL_OUTPUT=$("$LXC_EXEC" --debug "$CONTROL_CONFIG" 2>&1 || true)
echo "$CONTROL_OUTPUT"

if ! echo "$CONTROL_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the control destination was unreachable with an allow-everything policy, so this host cannot distinguish a deny-precedence failure from a broken network."
fi

derive_chain_name "$CONTROL_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "--- overlap: same destination in both allowedHosts and blockedHosts ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
OVERLAP_OUTPUT=$("$LXC_EXEC" --debug "$OVERLAP_CONFIG" 2>&1 || true)
echo "$OVERLAP_OUTPUT"

if echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "a destination present in BOTH allowedHosts and blockedHosts was reachable. Allow rules are winning over deny rules, so a blocklist entry can be silently defeated by an overlapping allowlist entry."
fi
if ! echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the overlap case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$OVERLAP_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "PASS: a destination in both lists was blocked, and the same destination was reachable when only allowed."
echo "LXC deny-precedence enforcement test complete."
