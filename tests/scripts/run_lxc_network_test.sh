#!/bin/bash
# LXC network policy test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

CONFIG="$REPO_DIR/tests/configs/lxc_network_test.json"

# run_lxc_all_tests.sh reports 77 as SKIPPED.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables and LXC."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed; the peer needs it to host a listener."

# A listener on the host or on the bridge gateway is delivered through INPUT
# and answers with no firewall in the path.  The peer lives in its own network
# namespace behind a veth, reached only through the FORWARD hook the chain
# filters on.
PEER_NETNS="mxc-nettest-peer"
PEER_HOST_VETH="mxcnth0"
PEER_VETH="mxcntp0"
# An RFC 5737 test range.  The host routes by longest matching prefix, and two
# peers sharing a range let whichever suite ran last capture the other's
# traffic.
PEER_HOST_IP="198.51.100.17"
PEER_IP="198.51.100.18"
PEER_PREFIX="29"
PEER_PORT="443"
BLOCKED_IP="198.51.100.19"

PEER_LISTENER_PID=""
PEER_LISTENER_LOG="$(mktemp)"
BLOCKED_LISTENER_PID=""
BLOCKED_LISTENER_LOG="$(mktemp)"
IP_FORWARD_WAS=""
teardown_peer() {
    if [ -n "$PEER_LISTENER_PID" ]; then
        kill "$PEER_LISTENER_PID" >/dev/null 2>&1 || true
    fi
    if [ -n "$BLOCKED_LISTENER_PID" ]; then
        kill "$BLOCKED_LISTENER_PID" >/dev/null 2>&1 || true
    fi
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    ip link del "$PEER_HOST_VETH" >/dev/null 2>&1 || true
    if [ -n "$IP_FORWARD_WAS" ]; then
        sysctl -w net.ipv4.ip_forward="$IP_FORWARD_WAS" >/dev/null 2>&1 || true
    fi
}
teardown_run() {
    teardown_peer
    rm -f "$PEER_LISTENER_LOG" "$BLOCKED_LISTENER_LOG"
}
trap teardown_run EXIT

# Clear anything an aborted earlier run left behind, then build the peer.
teardown_peer
ip netns add "$PEER_NETNS" || fail "could not create the peer namespace."
ip link add "$PEER_HOST_VETH" type veth peer name "$PEER_VETH" \
    || fail "could not create the peer veth pair."
ip link set "$PEER_VETH" netns "$PEER_NETNS" \
    || fail "could not move the peer interface into its namespace."
ip addr add "$PEER_HOST_IP/$PEER_PREFIX" dev "$PEER_HOST_VETH" \
    || fail "could not address the host side of the peer veth."
ip link set "$PEER_HOST_VETH" up || fail "could not bring up the peer veth."
ip netns exec "$PEER_NETNS" ip addr add "$PEER_IP/$PEER_PREFIX" dev "$PEER_VETH" \
    || fail "could not address the peer."
ip netns exec "$PEER_NETNS" ip addr add "$BLOCKED_IP/$PEER_PREFIX" dev "$PEER_VETH" \
    || fail "could not address the denied peer."
ip netns exec "$PEER_NETNS" ip link set "$PEER_VETH" up \
    || fail "could not bring up the peer interface."
ip netns exec "$PEER_NETNS" ip link set lo up \
    || fail "could not bring up the peer loopback."
ip netns exec "$PEER_NETNS" ip route add default via "$PEER_HOST_IP" \
    || fail "could not route the peer back to the container."

# Without this the container's packets stop at the host and never reach the peer.
IP_FORWARD_WAS="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
    || skip "could not enable IPv4 forwarding."

# The firewall matches the port and not the payload, so plain HTTP on tcp/443
# is enough.  A reply proves the SYN reached the peer.
ip netns exec "$PEER_NETNS" python3 -m http.server "$PEER_PORT" --bind "$PEER_IP" \
    >"$PEER_LISTENER_LOG" 2>&1 &
PEER_LISTENER_PID=$!
ip netns exec "$PEER_NETNS" python3 -m http.server "$PEER_PORT" --bind "$BLOCKED_IP" \
    >"$BLOCKED_LISTENER_LOG" 2>&1 &
BLOCKED_LISTENER_PID=$!

# Alive is not reachable.  A peer that never bound has to fail here as harness
# breakage, rather than later as the firewall blocking an allowed destination.
if ! PEER_PROBE_ERROR="$(await_peer_tcp "$PEER_IP" "$PEER_PORT")"; then
    fail_unreachable_peer "the peer" "$PEER_IP:$PEER_PORT" \
        "$PEER_PROBE_ERROR" "$PEER_LISTENER_LOG"
fi
if ! PEER_PROBE_ERROR="$(await_peer_tcp "$BLOCKED_IP" "$PEER_PORT")"; then
    fail_unreachable_peer "the denied peer" "$BLOCKED_IP:$PEER_PORT" \
        "$PEER_PROBE_ERROR" "$BLOCKED_LISTENER_LOG"
fi

# The fixture's directional rules must allow the peer but deny its neighbor.
python3 - "$CONFIG" "$PEER_IP/32" "$BLOCKED_IP/32" <<'PY' \
    || fail "fixture does not allow the peer and deny its neighbor."
import json, sys
egress = json.load(open(sys.argv[1]))["network"]["egress"]
assert egress["default"] == "deny"
assert any({"cidr": sys.argv[2]} in rule["to"] for rule in egress["allow"])
assert any({"cidr": sys.argv[3]} in rule["to"] for rule in egress["deny"])
PY

OUTPUT=$("$LXC_EXEC" "$CONFIG" 2>&1) || fail "lxc-exec failed: $OUTPUT"
echo "$OUTPUT"
grep -Fq "MXC_NET_ALLOWED" <<<"$OUTPUT" \
    || fail "the explicitly allowed peer was unreachable or the workload never ran."
if grep -Fq "MXC_NET_LEAK" <<<"$OUTPUT"; then
    fail "the explicitly denied peer was reachable."
fi
grep -Fq "MXC_NET_BLOCKED" <<<"$OUTPUT" \
    || fail "the denied peer produced no blocked verdict."
echo "PASS: directional rules allowed one live peer and blocked another."