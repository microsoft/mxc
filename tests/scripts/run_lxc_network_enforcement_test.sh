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

fail() {
    echo "FAIL: $1"
    exit 1
}

# List the MXC-owned chains a tool currently holds. The chain name is derived
# from a digest of the container name, so a hard-coded literal names a chain
# that cannot exist: `iptables -S <that name>` always fails, the cleanup check
# below reads that failure as "the chain is gone", and the assertion passes
# without inspecting anything. Matching the MXC- prefix stays correct across
# naming changes.
mxc_chains() {
    "$1" -S 2>/dev/null | sed -n 's/^-N \(MXC-.*\)$/\1/p' | sort
}

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

# A hook that references the chain but survives teardown leaves the next
# container's traffic running through a stale rule, so the reference count
# matters as much as the chain itself.
assert_no_forward_reference() {
    if iptables -S FORWARD 2>/dev/null | grep -Fq -- "$1"; then
        fail "a FORWARD rule still references chain '$1' after teardown."
    fi
}

# The chain name is a digest of the container name, so it is read back from this
# run's own debug output rather than hard-coded. Every assertion that names a
# chain depends on this having succeeded, so an unparsed name fails the test
# here instead of silently reducing those assertions to no-ops.
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

echo "Running LXC network policy enforcement test..."

# The container reports the outcome itself rather than relying on its exit
# code, so a wrapper that swallows or rewrites the status cannot turn a
# reachable destination into an apparent block.
echo "--- deny case: default policy blocks, nothing allowed ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
DENY_OUTPUT=$("$LXC_EXEC" --debug "$DENY_CONFIG" 2>&1 || true)
echo "$DENY_OUTPUT"

if echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "egress succeeded under a default-block policy with no allowed hosts. The chain is not filtering this container's traffic."
fi
if ! echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the deny case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$DENY_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "--- allow case: same default, destination explicitly allowed ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
ALLOW_OUTPUT=$("$LXC_EXEC" --debug "$ALLOW_CONFIG" 2>&1 || true)
echo "$ALLOW_OUTPUT"

if echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "an explicitly allowed destination was unreachable. The policy is over-blocking, so the deny case above proves nothing."
fi
if ! echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the allow case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$ALLOW_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "PASS: a disallowed destination was blocked and an allowed destination was reachable."
echo "LXC network policy enforcement test complete."