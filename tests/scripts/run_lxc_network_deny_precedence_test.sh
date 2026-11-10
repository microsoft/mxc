#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"

if [ "$LXC_EXEC" = "$REPO_DIR/src/target/release/lxc-exec" ] && [ ! -f "$LXC_EXEC" ]; then
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
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed; the peer needs it to host a listener."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

OVERLAP_CONFIG="$REPO_DIR/tests/configs/lxc_network_deny_precedence_overlap.json"
CONTROL_CONFIG="$REPO_DIR/tests/configs/lxc_network_deny_precedence_control.json"

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

# shellcheck source=lib/lxc_static_network.sh
. "$SCRIPT_DIR/lib/lxc_static_network.sh"

PEER_NETNS="mxc-denyprec-peer"
PEER_HOST_VETH="mxcdph0"
PEER_VETH="mxcdpp0"
# An RFC 5737 test range.  The host routes by longest matching prefix, and two
# peers sharing a range let whichever suite ran last capture the other's
# traffic.
PEER_HOST_IP="198.51.100.9"
PEER_IP="198.51.100.10"
PEER_PREFIX="29"
PEER_PORT="443"

PEER_LISTENER_PID=""
PEER_LISTENER_LOG="$REPO_DIR/tests/configs/.lxc-precedence-peer-$$.log"
IP_FORWARD_WAS=""
teardown_peer() {
    if [ -n "$PEER_LISTENER_PID" ]; then
        kill "$PEER_LISTENER_PID" >/dev/null 2>&1 || true
    fi
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    ip link del "$PEER_HOST_VETH" >/dev/null 2>&1 || true
    if [ -n "$IP_FORWARD_WAS" ]; then
        sysctl -w net.ipv4.ip_forward="$IP_FORWARD_WAS" >/dev/null 2>&1 || true
    fi
}
teardown_run() {
    teardown_peer
    rm -f "$PEER_LISTENER_LOG"
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

# Alive is not reachable.  A peer that never bound has to fail here as harness
# breakage, rather than later as the control run being blocked.
if ! PEER_PROBE_ERROR="$(await_peer_tcp "$PEER_IP" "$PEER_PORT")"; then
    fail_unreachable_peer "the peer" "$PEER_IP:$PEER_PORT" \
        "$PEER_PROBE_ERROR" "$PEER_LISTENER_LOG"
fi

# Drift guard: both fixtures must aim at this peer, or the run would probe a
# stale address and prove nothing.
for cfg in "$OVERLAP_CONFIG" "$CONTROL_CONFIG"; do
    grep -Fq "$PEER_IP" "$cfg" \
        || fail "fixture ${cfg##*/} no longer targets the peer $PEER_IP; script and fixture drifted."
done

echo "Running LXC deny-precedence enforcement test..."

echo "--- control: destination allowed, nothing blocked ---"
BEFORE_V4="$(iptables-save | sed '/^#/d')"
BEFORE_V6="$(ip6tables-save | sed '/^#/d')"
BEFORE_NFT="$(nft -s list ruleset)"
if ! CONTROL_OUTPUT=$(run_with_static_guest_ipv4 "$CONTROL_CONFIG" 2>&1); then
    fail "the control fixture failed: $CONTROL_OUTPUT"
fi
echo "$CONTROL_OUTPUT"

if ! echo "$CONTROL_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the control destination was unreachable with an allow-everything policy, so this host cannot distinguish a deny-precedence failure from a broken network."
fi

[ "$(iptables-save | sed '/^#/d')" = "$BEFORE_V4" ] || fail "the control leaked IPv4 host rules."
[ "$(ip6tables-save | sed '/^#/d')" = "$BEFORE_V6" ] || fail "the control leaked IPv6 host rules."
[ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] || fail "the control leaked nftables host rules."

echo "--- overlap: same destination in both allowedHosts and blockedHosts ---"
if ! OVERLAP_OUTPUT=$(run_with_static_guest_ipv4 "$OVERLAP_CONFIG" 2>&1); then
    fail "the overlap fixture failed: $OVERLAP_OUTPUT"
fi
echo "$OVERLAP_OUTPUT"

if echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "a destination present in BOTH allowedHosts and blockedHosts was reachable. Allow rules are winning over deny rules, so a blocklist entry can be silently defeated by an overlapping allowlist entry."
fi
if ! echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the overlap case produced no verdict at all; the container command did not run."
fi

[ "$(iptables-save | sed '/^#/d')" = "$BEFORE_V4" ] || fail "the deny-precedence run leaked IPv4 host rules."
[ "$(ip6tables-save | sed '/^#/d')" = "$BEFORE_V6" ] || fail "the deny-precedence run leaked IPv6 host rules."
[ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] || fail "the deny-precedence run leaked nftables host rules."

echo "PASS: a destination in both lists was blocked, and the same destination was reachable when only allowed."
echo "LXC deny-precedence enforcement test complete."
