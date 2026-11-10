#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"

if [ "$LXC_EXEC" = "$REPO_DIR/src/target/release/lxc-exec" ] && [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# exit 77 so run_lxc_all_tests.sh records SKIPPED rather than PASS.
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

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_enforcement_deny.json"
ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_enforcement_allow.json"

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

# shellcheck source=lib/lxc_static_network.sh
. "$SCRIPT_DIR/lib/lxc_static_network.sh"

PEER_NETNS="mxc-enforce-peer"
PEER_HOST_VETH="mxcenh0"
PEER_VETH="mxcenp0"
# An RFC 5737 test range.  The host routes by longest matching prefix, and two
# peers sharing a range let whichever suite ran last capture the other's
# traffic.
PEER_HOST_IP="198.51.100.1"
PEER_IP="198.51.100.2"
PEER_PREFIX="29"
PEER_PORT="443"
PEER_LISTENER_PID=""
PEER_LISTENER_LOG="$REPO_DIR/tests/configs/.lxc-enforcement-peer-$$.log"
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
# breakage, rather than later as the firewall blocking the allow case.
if ! PEER_PROBE_ERROR="$(await_peer_tcp "$PEER_IP" "$PEER_PORT")"; then
    fail_unreachable_peer "the peer" "$PEER_IP:$PEER_PORT" \
        "$PEER_PROBE_ERROR" "$PEER_LISTENER_LOG"
fi

# Drift guard: both fixtures must aim at this peer, or the run would probe a
# stale address and prove nothing.
for cfg in "$DENY_CONFIG" "$ALLOW_CONFIG"; do
    grep -Fq "$PEER_IP" "$cfg" \
        || fail "fixture ${cfg##*/} no longer targets the peer $PEER_IP; script and fixture drifted."
done
python3 - "$ALLOW_CONFIG" "$PEER_IP/32" <<'PY' \
    || fail "the allow fixture no longer permits the peer under default deny."
import json, sys
egress = json.load(open(sys.argv[1]))["network"]["egress"]
assert egress["default"] == "deny"
assert any({"cidr": sys.argv[2]} in rule["to"] for rule in egress["allow"])
PY

echo "Running LXC network policy enforcement test..."

# The container reports the outcome itself rather than relying on its exit
# code, so a wrapper that swallows or rewrites the status cannot turn a
# reachable destination into an apparent block.
echo "--- deny case: default policy blocks, nothing allowed ---"
BEFORE_V4="$(iptables-save | sed '/^#/d')"
BEFORE_V6="$(ip6tables-save | sed '/^#/d')"
BEFORE_NFT="$(nft -s list ruleset)"
if ! DENY_OUTPUT=$("$LXC_EXEC" --debug "$DENY_CONFIG" 2>&1); then
    fail "the deny fixture failed: $DENY_OUTPUT"
fi
echo "$DENY_OUTPUT"

if echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "egress succeeded under a default-deny policy with no allow rules. The chain is not filtering this container's traffic."
fi
if ! echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the deny case produced no verdict at all; the container command did not run."
fi
if echo "$DENY_OUTPUT" | grep -Fq "MXC_LOOPBACK_BLOCKED"; then
    fail "the container could not reach its own loopback. Intra-container loopback must remain reachable under default deny."
fi
if ! echo "$DENY_OUTPUT" | grep -Fq "MXC_LOOPBACK_OK"; then
    fail "the deny case returned no loopback verdict; the in-container listener did not run."
fi

[ "$(iptables-save | sed '/^#/d')" = "$BEFORE_V4" ] || fail "the isolated run leaked IPv4 host rules."
[ "$(ip6tables-save | sed '/^#/d')" = "$BEFORE_V6" ] || fail "the isolated run leaked IPv6 host rules."
[ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] || fail "the isolated run leaked nftables host rules."

echo "--- allow case: same default, destination explicitly allowed ---"
if ! ALLOW_OUTPUT=$(run_with_static_guest_ipv4 "$ALLOW_CONFIG" 2>&1); then
    fail "the allow fixture failed: $ALLOW_OUTPUT"
fi
echo "$ALLOW_OUTPUT"

if echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "an explicitly allowed destination was unreachable. The policy is over-blocking, so the deny case above proves nothing."
fi
if ! echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the allow case produced no verdict at all; the container command did not run."
fi

[ "$(iptables-save | sed '/^#/d')" = "$BEFORE_V4" ] || fail "the allowed run leaked IPv4 host rules."
[ "$(ip6tables-save | sed '/^#/d')" = "$BEFORE_V6" ] || fail "the allowed run leaked IPv6 host rules."
[ "$(nft -s list ruleset)" = "$BEFORE_NFT" ] || fail "the allowed run leaked nftables host rules."

echo "PASS: a disallowed destination was blocked, an allowed destination was reachable,"
echo "      and the blocked container still reached its own loopback."
echo "LXC network policy enforcement test complete."