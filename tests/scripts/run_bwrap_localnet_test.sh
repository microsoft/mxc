#!/bin/bash
# Bubblewrap network.allowLocalNetwork honesty tests (schema 0.8+), and the
# pre-0.8 twin.
#
# No root, no slirp4netns and no outbound connectivity required: two of the
# three cases are validate-time outcomes and the third is a plain shared-
# namespace sandbox. That independence is the reason this lives in its own file
# rather than inside run_bwrap_firewall_test.sh, which exits early when
# slirp4netns is absent and skips when the internet is unreachable -- behind
# those gates these cases would go untested on exactly the hosts where they are
# cheapest to run.
#
# What is being asserted:
#
# Bubblewrap has no inbound-only primitive. The sandbox either shares the host
# network namespace or gets a private one, and neither can be narrowed further:
# unprivileged bwrap has no veth for iptables to match on, and seccomp cannot
# dereference the sockaddr passed to bind(), so an AF_INET-only filter is not
# expressible. allowLocalNetwork is therefore honorable only when it already
# agrees with the namespace the resolved mode picks. Both disagreeing
# combinations are rejected from 0.8; both must still be accepted before it.
#
# Not asserted here: the pre-0.8 warning text. Logger warnings are deliberately
# never written to the process's streams (wxc_common is linked into libraries
# whose host owns the terminal -- see logger.rs
# `warning_line_writes_nothing_to_stderr`), so an end-to-end run cannot observe
# them. The warning is covered by the bwrap_common unit tests
# `local_network_denied_on_shared_netns_warns` and
# `local_network_allowed_under_private_netns_warns`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# An explicitly set LXC_EXEC is taken literally: falling back from it would
# silently exercise a different binary than the caller named.
if [ -n "${LXC_EXEC:-}" ]; then
    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: LXC_EXEC is set to '$LXC_EXEC', which does not exist."
        exit 1
    fi
else
    LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
    if [ ! -f "$LXC_EXEC" ]; then
        LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
    fi
    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: lxc-exec not found. Run build.sh first."
        exit 1
    fi
fi

HOST_NETNS="$(readlink /proc/self/ns/net)"

# A rejection is only correct if it is the *right* rejection and the workload
# never ran: a sandbox that failed to start for an unrelated reason would
# otherwise look identical to one that fell closed on policy.
assert_rejected() {
    local label="$1"
    local config="$2"
    local fragment="$3"
    echo "Running Bubblewrap localnet test: $label..."
    local out
    local rc=0
    out=$("$LXC_EXEC" --experimental --allow-testing-features \
        "$REPO_DIR/tests/configs/$config" 2>&1) || rc=$?
    if [ "$rc" = 0 ]; then
        echo "$out"
        echo "FAIL: $label (accepted a policy it cannot honor)"
        exit 1
    fi
    if grep -q LOCALNET_SHOULD_NOT_RUN <<<"$out"; then
        echo "$out"
        echo "FAIL: $label (workload ran despite the rejection)"
        exit 1
    fi
    if ! grep -qF "$fragment" <<<"$out"; then
        echo "$out"
        echo "FAIL: $label (rejection did not explain the contract)"
        exit 1
    fi
    echo "PASS: $label"
}

# defaultPolicy=allow with no host rules and no proxy resolves to Shared, which
# keeps the host namespace -- so allowLocalNetwork=false cannot be delivered.
assert_rejected "allowLocalNetwork=false on a shared namespace" \
    "bubblewrap_network_localnet_shared_rejected.json" \
    "is not enforced while the sandbox shares the host network namespace"

# The mirror image: defaultPolicy=block with no host rules resolves to Isolated,
# which applies --unshare-net, so a listener is reachable only from inside the
# sandbox and allowLocalNetwork=true overstates what the caller gets. Covered
# because the two arms are separate branches; a fix to one can silently drop
# the other.
assert_rejected "allowLocalNetwork=true under a private namespace" \
    "bubblewrap_network_localnet_private_rejected.json" \
    "is confined to the sandbox's own network namespace"

# The pre-0.8 twin of the first case. GHCP consumes Bubblewrap proxy mode on
# 0.6/0.7, so the rejection above must be invisible there.
#
# The namespace assertion is what makes this a behavior pin rather than a parse
# check. Exit code alone would still pass if a future change routed pre-0.8
# configs down the private-namespace path -- the run would succeed and silently
# hand legacy callers a sandbox with different connectivity. Three distinct
# regressions fail here: the gate leaking (nonzero exit), the workload being
# skipped (missing sentinel), and the namespace changing.
echo "Running Bubblewrap localnet test: pre-0.8 is unchanged..."
LEGACY_RC=0
LEGACY_OUT=$("$LXC_EXEC" --experimental --allow-testing-features \
    "$REPO_DIR/tests/configs/bubblewrap_network_localnet_legacy.json" 2>&1) \
    || LEGACY_RC=$?
if [ "$LEGACY_RC" != 0 ]; then
    echo "$LEGACY_OUT"
    echo "FAIL: pre-0.8 localnet (exited $LEGACY_RC; the 0.8 rejection leaked)"
    exit 1
fi
if ! grep -q LEGACY_LOCALNET_OK <<<"$LEGACY_OUT"; then
    echo "$LEGACY_OUT"
    echo "FAIL: pre-0.8 localnet (succeeded without running the workload)"
    exit 1
fi
LEGACY_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$LEGACY_OUT" | tail -n 1)"
if [ "$LEGACY_NETNS" != "$HOST_NETNS" ]; then
    echo "$LEGACY_OUT"
    echo "FAIL: pre-0.8 localnet (expected the host namespace $HOST_NETNS, got $LEGACY_NETNS)"
    exit 1
fi
echo "PASS: pre-0.8 localnet is unchanged"

echo "Bubblewrap allowLocalNetwork tests complete."
