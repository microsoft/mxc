#!/bin/bash
# LXC inbound default-deny: traffic-level test
#
# Requires that an unsolicited inbound connection to the container fails and
# that the chain's DROP counters move. The other inbound test asserts that the
# chain is programmed correctly; nothing puts a packet in front of it, so a
# chain that drops nothing passes today.
#
# Covers the container once the policy is installed. The unfiltered interval
# before installation is a separate open defect, and the exposure there arrives
# over lxcbr0 in a sub-second window this shape cannot sample deterministically.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# Exit 77 marks a missing prerequisite, which the suite runner counts as
# SKIPPED rather than PASS.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables/ip6tables, LXC, and moving an interface between namespaces."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "ip6tables is not installed."
command -v nsenter >/dev/null 2>&1 || skip "nsenter is not installed."
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

# A host without kernel IPv6 has the binary installed and fails every
# invocation, so probe it rather than trusting `command -v`. The whole test
# skips rather than its IPv6 half alone, because the in-container probe runs
# the same binary and fails the same way.
ip6tables -S >/dev/null 2>&1 || skip "ip6tables is installed but not usable on this host (no kernel IPv6?)."

CONFIG="$REPO_DIR/tests/configs/lxc_inbound_traffic_deny.json"
[ -f "$CONFIG" ] || skip "missing config $CONFIG."

# Must match `containerId` in the config: the runner uses that value verbatim as
# the LXC container name.
CONTAINER="CLI-LXC-Inbound-Traffic"

VETH_HOST="mxcprobe0"
VETH_PEER="mxcprobe1"
PROBE_HOST_V4="10.77.78.1"
PROBE_NS_V4="10.77.78.2"
PROBE_HOST_V6="fd00:77:78::1"
PROBE_NS_V6="fd00:77:78::2"
PROBE_PORT=7777

RUN_LOG="$(mktemp)"
RUN_PID=""
VETH_CREATED=0

cleanup() {
    if [ -n "$RUN_PID" ] && kill -0 "$RUN_PID" 2>/dev/null; then

        # SIGTERM rather than SIGKILL: the runner's signal handler is what tears
        # down the chains and the container, and SIGKILL would strand both.
        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    if [ "$VETH_CREATED" = 1 ]; then
        ip link del "$VETH_HOST" >/dev/null 2>&1 || true
    fi
    lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
    rm -f "$RUN_LOG"
}
trap cleanup EXIT

# Leftovers from an interrupted earlier run would make the setup below fail for
# a reason that has nothing to do with the code under test.
ip link del "$VETH_HOST" >/dev/null 2>&1 || true
lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

# List the inbound chains a tool holds *on the host*. The MXCI- prefix is the
# ingress chain's, distinct from the MXC- egress chain, so egress state cannot
# be mistaken for a leak here.
mxci_chains() {
    "$1" -S 2>/dev/null | sed -n 's/^-N \(MXCI-.*\)$/\1/p' | sort
}

MXCI_BEFORE_V4="$(mxci_chains iptables)"
MXCI_BEFORE_V6="$(mxci_chains ip6tables)"

echo "Running LXC inbound traffic test..."

"$LXC_EXEC" --debug "$CONFIG" >"$RUN_LOG" 2>&1 &
RUN_PID=$!

# The workload is attached only after the chains are hooked, so its marker is
# what says the container is both live and filtered.
#
# The bound is generous because a cold host downloads the Alpine image first.
WAITED=0
until grep -Fq "MXC_INBOUND_PROBE_READY" "$RUN_LOG" 2>/dev/null; do
    if ! kill -0 "$RUN_PID" 2>/dev/null; then
        echo "--- lxc-exec output ---"
        cat "$RUN_LOG"
        fail "lxc-exec exited before the workload ran; the container never reached the filtered state."
    fi
    if [ "$WAITED" -ge 600 ]; then
        echo "--- lxc-exec output ---"
        cat "$RUN_LOG"
        fail "the workload marker never appeared within 300s."
    fi
    sleep 0.5
    WAITED=$((WAITED + 1))
done

INBOUND_CHAIN="$(sed -n 's/^.*Creating inbound iptables chain: \([^ ]*\).*$/\1/p' "$RUN_LOG" | head -n 1)"
[ -n "$INBOUND_CHAIN" ] || fail "no inbound chain was created; there is no default-deny to probe."

NETNS_PID="$(sed -n 's/^.*Container init PID: \([0-9]*\).*$/\1/p' "$RUN_LOG" | head -n 1)"
[ -n "$NETNS_PID" ] || fail "no container init PID was logged; the container namespace cannot be entered."

in_container_net() {
    nsenter -t "$NETNS_PID" -n "$@"
}

# Put the probe's own interface into the container's namespace. Addressing both
# ends by hand is what removes the dependency on lxcbr0 and on the container's
# DHCP lease.
ip link add "$VETH_HOST" type veth peer name "$VETH_PEER" \
    || fail "could not create the probe veth pair."
VETH_CREATED=1
ip link set "$VETH_PEER" netns "$NETNS_PID" \
    || fail "could not move the probe interface into the container namespace."

ip addr add "$PROBE_HOST_V4/24" dev "$VETH_HOST"
ip -6 addr add "$PROBE_HOST_V6/64" dev "$VETH_HOST" nodad
ip link set "$VETH_HOST" up

in_container_net ip addr add "$PROBE_NS_V4/24" dev "$VETH_PEER"
in_container_net ip -6 addr add "$PROBE_NS_V6/64" dev "$VETH_PEER" nodad
in_container_net ip link set "$VETH_PEER" up

# The first probe has to resolve the peer's address before it can send, and
# without a moment here that resolution eats into its four-second timeout.
sleep 2

# Total packets dropped by the chain, across every DROP rule in it. -x because a
# truncated '1K' would not compare.
#
# Summing rather than reading the NEW-state rule alone: where IPv6 conntrack is
# not loaded an inbound SYN is not classified NEW and falls through to the
# chain's terminal DROP instead.
drop_packets() {
    in_container_net "$1" -L "$INBOUND_CHAIN" -n -v -x 2>/dev/null \
        | awk '$3 == "DROP" { total += $1 } END { print total + 0 }'
}

assert_inbound_dropped() {
    local tool="$1" target="$2" family="$3" before="" after="" rc=0

    before="$(drop_packets "$tool")"
    [ -n "$before" ] || fail "$family: could not read the DROP counters on $INBOUND_CHAIN."

    # Nothing listens on this port. INPUT is traversed before the socket lookup,
    # so the verdict is the chain's either way.
    timeout 4 bash -c "exec 3<>/dev/tcp/$target/$PROBE_PORT" >/dev/null 2>&1 && rc=0 || rc=$?
    if [ "$rc" = 0 ]; then
        fail "$family: an unsolicited inbound connection to the container succeeded; inbound default-deny is not enforcing."
    fi

    after="$(drop_packets "$tool")"
    [ -n "$after" ] || fail "$family: could not re-read the DROP counters on $INBOUND_CHAIN."
    if [ "$after" -le "$before" ]; then
        fail "$family: the chain's DROP counters did not move ($before -> $after); the probe packets never reached the chain, so the connection failure proves nothing."
    fi

    echo "  $family inbound dropped by the chain: $before -> $after"
}

# The address is passed bare, not bracketed: bash resolves the /dev/tcp host
# field with getaddrinfo, which rejects '[...]' as a name.
assert_inbound_dropped iptables "$PROBE_NS_V4" IPv4
assert_inbound_dropped ip6tables "$PROBE_NS_V6" IPv6

echo "PASS: unsolicited inbound is dropped inside the container namespace."

if ! in_container_net ip link show "$VETH_PEER" >/dev/null 2>&1; then
    fail "the probe interface vanished from the container namespace."
fi

# Let the workload's sleep finish so destroyOnExit tears the container down the
# way a normal run would, rather than leaving the signal path to do it.
ip link del "$VETH_HOST" >/dev/null 2>&1 || true
VETH_CREATED=0
if ! wait "$RUN_PID"; then
    echo "--- lxc-exec output ---"
    cat "$RUN_LOG"
    fail "lxc-exec exited non-zero."
fi
RUN_PID=""

# The chain belongs in the container's namespace, so one on the host means the
# rules were programmed against the wrong namespace.
leaked_chains() {
    local tool="$1" before="$2" after="" leaked="" chain
    if ! after="$(mxci_chains "$tool")"; then
        fail "could not enumerate $tool chains, so the host was not verified clean."
    fi
    while IFS= read -r chain; do
        [ -n "$chain" ] || continue
        grep -Fxq "$chain" <<<"$before" || leaked="$leaked $chain"
    done <<<"$after"
    [ -z "$leaked" ] || fail "$tool: inbound chain(s) left on the host:$leaked"
}

leaked_chains iptables "$MXCI_BEFORE_V4"
leaked_chains ip6tables "$MXCI_BEFORE_V6"

echo "PASS: LXC inbound traffic test."
