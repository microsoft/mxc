#!/bin/bash
# Bubblewrap ingress honesty tests for the supported directional policy.
#
# No root, slirp4netns or outbound connectivity required: unsupported inbound
# allow values are rejected before sandbox setup, while a ruleless deny runs in
# an isolated namespace. Firewall enforcement tests can skip without suppressing
# these checks.
#
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
    out=$("$LXC_EXEC" --experimental \
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

assert_rejected "ingress.default=allow is refused" \
    "bubblewrap_network_localnet_ingress_allow_rejected.json" \
    "network.ingress.default='allow' is not supported"

assert_rejected "ingress.hostLoopback=allow is refused" \
    "bubblewrap_network_localnet_hostloopback_allow_rejected.json" \
    "network.ingress.hostLoopback='allow' is not supported"

# An omitted ingress section still defaults to deny. A ruleless egress deny
# requires no slirp or firewall tools, and must put the workload in its own
# network namespace rather than accidentally sharing the host's.
echo "Running Bubblewrap localnet test: omitted ingress defaults to deny..."
IMPLICIT_RC=0
IMPLICIT_OUT=$("$LXC_EXEC" --experimental \
    "$REPO_DIR/tests/configs/bubblewrap_network_localnet_implicit_deny.json" 2>&1) \
    || IMPLICIT_RC=$?
if [ "$IMPLICIT_RC" -ne 0 ]; then
    echo "$IMPLICIT_OUT"
    echo "FAIL: implicit ingress deny (sandbox exited $IMPLICIT_RC)"
    exit 1
fi
if ! grep -qF "LOCALNET_IMPLICIT_DENY_OK" <<<"$IMPLICIT_OUT"; then
    echo "$IMPLICIT_OUT"
    echo "FAIL: implicit ingress deny (workload never ran)"
    exit 1
fi
IMPLICIT_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$IMPLICIT_OUT" | tail -n 1)"
if [ -z "$IMPLICIT_NETNS" ] || [ "$IMPLICIT_NETNS" = "$HOST_NETNS" ]; then
    echo "$IMPLICIT_OUT"
    echo "FAIL: implicit ingress deny (expected a private network namespace, got '$IMPLICIT_NETNS')"
    exit 1
fi
echo "PASS: omitted ingress denies in a private network namespace"

echo "Bubblewrap ingress tests complete."
