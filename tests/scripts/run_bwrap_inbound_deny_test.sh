#!/bin/bash
# Bubblewrap inbound (ingress) default-deny test
#
# Unlike the other Bubblewrap suites this one REQUIRES ROOT, and the reason is
# the whole design of the test. The MXC_INGRESS chain lives inside the
# sandbox's private network namespace, which the sandbox itself cannot read
# (it holds no CAP_NET_ADMIN) and which nothing on the host can reach: slirp4netns
# runs without --api-socket, so there is no host port forwarding and therefore
# no inbound path to probe from outside. Root on the host is the only vantage
# point from which the chain can be either inspected or exercised.
#
# What is NOT covered here, deliberately:
#   * Egress still working, replies still arriving (ESTABLISHED,RELATED) and
#     sandbox loopback staying exempt. The ingress chain is installed on every
#     private-namespace run, so run_bwrap_firewall_test.sh already exercises
#     all three with the chain in place; repeating them here would add no
#     coverage.
#
# What IS covered, and is covered nowhere else:
#   1. The chain exists in the sandbox's namespace with exactly the intended
#      rules, and INPUT actually jumps to it. Unit tests assert the rendered
#      payload text; only a live run can show the payload reached the right
#      namespace and was accepted by the kernel.
#   2. Unsolicited inbound is dropped as packets, not merely as policy.
#
# The instrument for (2) is a veth pair injected into the sandbox's namespace
# by this script. That is a test fixture the product never creates, so this
# proves the chain's rule semantics -- unsolicited NEW inbound on a non-loopback
# interface is dropped -- rather than proving some real inbound path is closed.
# There is no real inbound path today; when host port forwarding lands, this
# test should be rewritten to use it.
#
# A trap worth naming, because the obvious simpler test is silently worthless:
# a connection made from *inside* the namespace to the namespace's own
# non-loopback address is routed through `lo` by Linux, so it matches the
# `-i lo -j ACCEPT` rule and never reaches the NEW verdict. Such a test passes
# whether or not the DROP works. The traffic must originate outside.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Chain and rule text are duplicated from the implementation on purpose: a test
# that derived them from the source could not detect the source changing.
INGRESS_CHAIN="MXC_INGRESS"

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

# An honest skip for a missing prerequisite: exit 77 so run_bwrap_all_tests.sh
# records SKIPPED rather than PASS. A test that could not run must not look
# green -- this one is root-only, so on an ordinary developer run it always
# skips, and reporting that as a pass would claim inbound coverage that does
# not exist.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

[ "$(id -u)" -eq 0 ] || skip "requires root to inspect and inject into the sandbox's network namespace."
command -v slirp4netns >/dev/null 2>&1 || skip "slirp4netns not installed; there is no private namespace to filter."
command -v nsenter >/dev/null 2>&1 || skip "nsenter is not installed."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."

WORK_DIR="$(mktemp -d)"
RUN_PID=""
VETH_HOST="mxcprobe0"

cleanup() {
    # The namespace-side peer dies with the namespace, so only the host side
    # needs removing -- and it must be removed even on failure, or a leftover
    # interface makes the next run's `ip link add` fail for the wrong reason.
    ip link del "$VETH_HOST" 2>/dev/null || true
    if [ -n "$RUN_PID" ]; then
        kill "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() {
    echo "----- sandbox output -----"
    cat "$WORK_DIR/run.out" 2>/dev/null || true
    echo "--------------------------"
    echo "FAIL: $1"
    exit 1
}

# The workload idles so the host has a live namespace to inspect. It reports
# its namespace first, because everything below is addressed to that namespace.
CONFIG="$WORK_DIR/bubblewrap_inbound_deny.json"
cat >"$CONFIG" <<'CONFIG_JSON'
{
  "version": "0.8.0-alpha",
  "containerId": "CLI-Bubblewrap-Inbound-Deny",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "bash -c 'set -u; echo SANDBOX_NETNS=$(readlink /proc/self/ns/net); echo INBOUND_WORKLOAD_STARTED; sleep 40; echo INBOUND_WORKLOAD_DONE'"
  },
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "firewall",
    "allowedHosts": ["10.0.2.2/32"]
  }
}
CONFIG_JSON

echo "Running Bubblewrap inbound default-deny test..."
"$LXC_EXEC" --experimental --allow-testing-features "$CONFIG" >"$WORK_DIR/run.out" 2>&1 &
RUN_PID=$!

SANDBOX_NETNS=""
for _ in $(seq 1 200); do
    SANDBOX_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' "$WORK_DIR/run.out" | head -n 1)"
    [ -n "$SANDBOX_NETNS" ] && break
    if ! kill -0 "$RUN_PID" 2>/dev/null; then
        fail "the sandbox exited before reporting its network namespace."
    fi
    sleep 0.1
done
[ -n "$SANDBOX_NETNS" ] || fail "the sandbox never reported its network namespace."

HOST_NETNS="$(readlink /proc/self/ns/net)"
if [ "$SANDBOX_NETNS" = "$HOST_NETNS" ]; then
    fail "the sandbox shares the host's network namespace, so there is no private chain to test."
fi

# nsenter needs a PID, and only the namespace inode was reported. Any process
# in the namespace serves equally, so the first match is taken.
SANDBOX_PID=""
for proc_dir in /proc/[0-9]*; do
    [ -e "$proc_dir/ns/net" ] || continue
    if [ "$(readlink "$proc_dir/ns/net" 2>/dev/null)" = "$SANDBOX_NETNS" ]; then
        SANDBOX_PID="${proc_dir#/proc/}"
        break
    fi
done
[ -n "$SANDBOX_PID" ] || fail "no live process was found in namespace $SANDBOX_NETNS."
echo "  sandbox namespace $SANDBOX_NETNS is held by PID $SANDBOX_PID"

in_sandbox_net() {
    nsenter -t "$SANDBOX_PID" -n -- "$@"
}

# ---------------------------------------------------------------------------
# 1. The chain is installed, in the right namespace, with the intended rules
# ---------------------------------------------------------------------------

CHAIN_RULES="$(in_sandbox_net iptables -S "$INGRESS_CHAIN" 2>/dev/null || true)"
[ -n "$CHAIN_RULES" ] || fail "$INGRESS_CHAIN does not exist in the sandbox's namespace."

# Asserted rule by rule rather than as one blob so a failure names the rule
# that changed. iptables normalises 'ESTABLISHED,RELATED' to 'RELATED,ESTABLISHED'
# on readback, which is why the expected text is not the rendered text.
assert_rule() {
    grep -Fxq -- "$1" <<<"$CHAIN_RULES" \
        || fail "$INGRESS_CHAIN is missing the rule '$1'. Installed:
$CHAIN_RULES"
}
assert_rule "-A $INGRESS_CHAIN -i lo -j ACCEPT"
assert_rule "-A $INGRESS_CHAIN -m state --state RELATED,ESTABLISHED -j ACCEPT"
assert_rule "-A $INGRESS_CHAIN -m state --state NEW -j DROP"
assert_rule "-A $INGRESS_CHAIN -j DROP"

# A chain nothing jumps to filters nothing. This is the assertion that catches
# the hook being rendered into the wrong transaction or dropped entirely.
INPUT_RULES="$(in_sandbox_net iptables -S INPUT 2>/dev/null || true)"
grep -Fxq -- "-A INPUT -j $INGRESS_CHAIN" <<<"$INPUT_RULES" \
    || fail "INPUT does not jump to $INGRESS_CHAIN. INPUT is:
$INPUT_RULES"

echo "PASS: $INGRESS_CHAIN is installed in the sandbox namespace and hooked to INPUT"

# ---------------------------------------------------------------------------
# 2. Unsolicited inbound is dropped as packets
# ---------------------------------------------------------------------------

# Exact counters (-x): a truncated '1K' would not compare.
drop_packets() {
    in_sandbox_net iptables -L "$INGRESS_CHAIN" -n -v -x 2>/dev/null \
        | awk '/DROP/ && /state NEW/ {print $1; exit}'
}

DROPS_BEFORE="$(drop_packets)"
[ -n "$DROPS_BEFORE" ] || fail "could not read the NEW-state DROP counter."

ip link add "$VETH_HOST" type veth peer name mxcprobe1 \
    || fail "could not create the probe veth pair."
ip link set mxcprobe1 netns "$SANDBOX_PID" \
    || fail "could not move the probe interface into the sandbox namespace."
ip addr add 10.77.77.1/24 dev "$VETH_HOST"
ip link set "$VETH_HOST" up
in_sandbox_net ip addr add 10.77.77.2/24 dev mxcprobe1
in_sandbox_net ip link set mxcprobe1 up

# Nothing listens on the target port, and that is fine: INPUT is traversed
# before any socket lookup, so the drop happens either way. Deliberately not
# asserting on the connection's failure alone -- an unreachable host fails
# identically. The counter is the real evidence: it can only move if packets
# reached the chain, and the connection can only fail if they were dropped.
# Together they exclude both "filtered" and "never arrived".
timeout 4 bash -c "exec 3<>/dev/tcp/10.77.77.2/7777" >/dev/null 2>&1 && INBOUND_RC=0 || INBOUND_RC=$?
if [ "$INBOUND_RC" = 0 ]; then
    fail "an unsolicited inbound connection succeeded; the NEW-state DROP is not enforcing."
fi

DROPS_AFTER="$(drop_packets)"
[ -n "$DROPS_AFTER" ] || fail "could not re-read the NEW-state DROP counter."
if [ "$DROPS_AFTER" -le "$DROPS_BEFORE" ]; then
    fail "the NEW-state DROP counter did not move ($DROPS_BEFORE -> $DROPS_AFTER); the probe packets never reached the chain, so the connection failure proves nothing."
fi

echo "  inbound SYNs dropped: $DROPS_BEFORE -> $DROPS_AFTER"
echo "PASS: unsolicited inbound is dropped in the sandbox namespace"

cleanup
trap - EXIT
echo "Bubblewrap inbound default-deny test passed."
