#!/bin/bash
# LXC inbound (ingress) default-deny test
#
# The inbound chain is the one piece of the LXC firewall that does NOT live on
# the host: it is programmed inside the container's own network namespace via
# `nsenter -t <init-pid> -n`. That is exactly why it needs a live test. Every
# unit test in `network_ingress.rs` asserts planned argv against an injected
# runner, so none of them can catch the chain being programmed into the wrong
# namespace -- and a host-execution bug of precisely that shape has already
# happened once in this file's history.
#
# Two configs are exercised:
#   * lxc_inbound_default_deny.json          -- the implemented default-deny path
#   * lxc_inbound_permissive_unsupported.json -- allowLocalNetwork: true, which
#     must fail closed with a not-yet-implemented error rather than installing
#     an over-broad accept.
#
# Assertions are on rule programming and namespace containment, not on whether
# a remote peer can reach the container: reachability depends on the host's
# bridge and uplink, but where the chain is installed does not.
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
# Presence is not usability, and the difference is load-bearing twice over.  On
# a host without kernel IPv6 the binary is normally installed and every
# invocation still fails: under `set -o pipefail` the chain snapshots below
# would then abort this script before a single assertion ran, reporting FAIL on
# a host configuration the implementation explicitly supports.  Probing here
# instead turns that into an honest SKIP.
#
# The whole test is skipped rather than just its IPv6 half.  The container
# probe runs the same binary through `nsenter`, so it fails too, and the
# inbound install's IPv6 classification -- a first-class part of what this test
# covers -- then depends on whether the *container* namespace has an
# `if_inet6`, which the host cannot predict.  Asserting the IPv4 half alone
# would be non-deterministic, and a flaky test is worse than a declared gap.
ip6tables -S >/dev/null 2>&1 || skip "ip6tables is installed but unusable here (no kernel IPv6 support), so the inbound IPv6 classification cannot be exercised."
command -v nsenter >/dev/null 2>&1 || skip "nsenter is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_inbound_default_deny.json"
PERMISSIVE_CONFIG="$REPO_DIR/tests/configs/lxc_inbound_permissive_unsupported.json"

[ -f "$DENY_CONFIG" ] || skip "missing config $DENY_CONFIG."
[ -f "$PERMISSIVE_CONFIG" ] || skip "missing config $PERMISSIVE_CONFIG."

fail() {
    echo "FAIL: $1"
    exit 1
}

# List the inbound chains a tool currently holds *on the host*. The ingress
# chain uses the MXCI- prefix, distinct from the MXC- egress chain, so this
# matches only inbound chains and cannot be confused by egress state. Matching
# the prefix rather than a literal keeps this correct across naming changes,
# since the name is a digest of the container name.
mxci_chains() {
    "$1" -S 2>/dev/null | sed -n 's/^-N \(MXCI-.*\)$/\1/p' | sort
}

mxc_egress_chains() {
    "$1" -S 2>/dev/null | sed -n 's/^-N \(MXC-.*\)$/\1/p' | sort
}

# The core containment assertion. An inbound chain must never appear in the
# host's tables: if one does, the rules were programmed outside the container
# namespace and are filtering the host instead of the sandbox. Compared against
# a snapshot so leftovers from an earlier failed run are not blamed on this one.
assert_no_new_chains() {
    local tool="$1" before="$2" lister="$3" what="$4" after="" leaked="" chain
    # Captured before iterating rather than piped in from a process
    # substitution, whose exit status is not the loop's. A failed enumeration
    # would otherwise read as zero chains and pass while verifying nothing.
    if ! after="$("$lister" "$tool")"; then
        fail "could not enumerate $tool chains, so $what was not verified."
    fi
    while IFS= read -r chain; do
        [ -n "$chain" ] || continue
        grep -Fxq "$chain" <<<"$before" || leaked="$leaked $chain"
    done <<<"$after"
    if [ -n "$leaked" ]; then
        fail "$tool: unexpected $what on the host:$leaked"
    fi
}

MXCI_BEFORE_V4="$(mxci_chains iptables)"
MXCI_BEFORE_V6="$(mxci_chains ip6tables)"
MXC_BEFORE_V4="$(mxc_egress_chains iptables)"
MXC_BEFORE_V6="$(mxc_egress_chains ip6tables)"

# ---------------------------------------------------------------------------
# Case 1: default-deny (allowLocalNetwork absent, so false)
# ---------------------------------------------------------------------------

echo "Running LXC inbound default-deny test..."

# The container command itself is trivial; a non-zero exit from an unrelated
# cause must not mask the firewall assertions below.
OUTPUT=$("$LXC_EXEC" --debug "$DENY_CONFIG" 2>&1 || true)
echo "$OUTPUT"

if ! grep -Fq "Container init PID:" <<<"$OUTPUT"; then
    fail "no container init PID was logged, so the inbound chain could not have been namespaced."
fi

INBOUND_CHAIN="$(sed -n 's/^.*Creating inbound iptables chain: \([^ ]*\).*$/\1/p' <<<"$OUTPUT" | head -n 1)"
if [ -z "$INBOUND_CHAIN" ]; then
    fail "the inbound chain was never created; default-deny was not applied."
fi

# Shape and length are asserted rather than hard-coded, so a malformed or
# over-long name fails here instead of surfacing as an opaque iptables error.
if ! grep -Eq '^MXCI-([A-Za-z0-9_-]{1,6}-)?[a-z2-7]{16}$' <<<"$INBOUND_CHAIN"; then
    fail "inbound chain name '$INBOUND_CHAIN' does not match the documented MXCI-<slug>-<hash> shape."
fi
if [ "${#INBOUND_CHAIN}" -gt 28 ]; then
    fail "inbound chain name '$INBOUND_CHAIN' exceeds the 28-character iptables ceiling."
fi

# The inbound chain must be distinct from the egress chain for the same
# container -- sharing a name would let either teardown destroy the other.
EGRESS_CHAIN="$(sed -n 's/^.*Programmed [a-z0-9]* rule: -A \([^ ]*\) .*$/\1/p' <<<"$OUTPUT" | head -n 1)"
if [ -n "$EGRESS_CHAIN" ] && [ "$EGRESS_CHAIN" = "$INBOUND_CHAIN" ]; then
    fail "inbound and egress share chain name '$INBOUND_CHAIN'."
fi

if ! grep -Fq "Inbound (allowLocalNetwork) policy: DROP new inbound connections (default-deny)" <<<"$OUTPUT"; then
    fail "the inbound policy was not the default-deny decision."
fi

# Fail-closed paths must not have been taken silently.
if grep -Fq "Inbound network policy error" <<<"$OUTPUT"; then
    fail "inbound firewall setup reported an error on the default-deny path."
fi
if grep -Fq "Failed to apply inbound network firewall rules" <<<"$OUTPUT"; then
    fail "inbound firewall rules were not applied."
fi

# The whole point of this test: the chain lives in the container namespace, so
# it must be absent from the host's tables both during and after the run.
assert_no_new_chains iptables "$MXCI_BEFORE_V4" mxci_chains "inbound chain(s)"
assert_no_new_chains ip6tables "$MXCI_BEFORE_V6" mxci_chains "inbound chain(s)"

# Egress cleanup must still hold; an inbound regression must not be masked by,
# or mask, a leaked egress chain.
assert_no_new_chains iptables "$MXC_BEFORE_V4" mxc_egress_chains "egress chain(s) left behind"
assert_no_new_chains ip6tables "$MXC_BEFORE_V6" mxc_egress_chains "egress chain(s) left behind"

echo "PASS: inbound default-deny installed in the container namespace."

# ---------------------------------------------------------------------------
# Case 2: allowLocalNetwork: true must fail closed, not install a broad accept
# ---------------------------------------------------------------------------

echo "Running LXC inbound permissive-path refusal test..."

PERMISSIVE_OUTPUT=$("$LXC_EXEC" --debug "$PERMISSIVE_CONFIG" 2>&1 || true)
echo "$PERMISSIVE_OUTPUT"

if ! grep -Fq "not yet implemented" <<<"$PERMISSIVE_OUTPUT"; then
    fail "allowLocalNetwork: true did not report a not-yet-implemented refusal."
fi

# The refusal must abort the run. If the workload echoed, the sandbox started
# with inbound enforcement silently absent -- the exact fail-open the refusal
# exists to prevent.
if grep -Fq "this-should-never-run" <<<"$PERMISSIVE_OUTPUT"; then
    fail "the workload executed despite an unenforceable inbound policy."
fi

# A refused run must leave nothing behind in either namespace's tables.
assert_no_new_chains iptables "$MXCI_BEFORE_V4" mxci_chains "inbound chain(s)"
assert_no_new_chains ip6tables "$MXCI_BEFORE_V6" mxci_chains "inbound chain(s)"
assert_no_new_chains iptables "$MXC_BEFORE_V4" mxc_egress_chains "egress chain(s) left behind"
assert_no_new_chains ip6tables "$MXC_BEFORE_V6" mxc_egress_chains "egress chain(s) left behind"

echo "PASS: permissive inbound path refused and rolled back."
echo "LXC inbound default-deny test passed."
