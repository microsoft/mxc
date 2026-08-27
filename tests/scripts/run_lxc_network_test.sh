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

# run_lxc_all_tests.sh reports 77 as SKIPPEED.
SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "requires root for iptables and LXC."
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
# lxc-exec resolves these names on the host when it builds the rules, so the
# pin below goes in the host's /etc/hosts and not the container's.  The blocked
# name needs an address only so that it resolves; nothing contacts it.
PEER_HOSTNAME="allowed.nettest.mxc.test"
BLOCKED_HOSTNAME="blocked.nettest.mxc.test"
BLOCKED_IP="198.51.100.19"

PEER_LISTENER_PID=""
HOSTS_BACKUP=""
teardown_peer() {
    if [ -n "$PEER_LISTENER_PID" ]; then
        kill "$PEER_LISTENER_PID" >/dev/null 2>&1 || true
    fi
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    ip link del "$PEER_HOST_VETH" >/dev/null 2>&1 || true
    # Restoring the whole file, rather than filtering out the two added lines,
    # cannot drop an unrelated entry the box needs.
    if [ -n "$HOSTS_BACKUP" ] && [ -f "$HOSTS_BACKUP" ]; then
        cat "$HOSTS_BACKUP" > /etc/hosts
        rm -f "$HOSTS_BACKUP"
    fi
}
trap teardown_peer EXIT

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

HOSTS_BACKUP="$(mktemp)"
cat /etc/hosts > "$HOSTS_BACKUP"
printf '%s %s\n' "$PEER_IP" "$PEER_HOSTNAME" >> /etc/hosts
printf '%s %s\n' "$BLOCKED_IP" "$BLOCKED_HOSTNAME" >> /etc/hosts

# The firewall matches the port and not the payload, so plain HTTP on tcp/443
# is enough.  A reply proves the SYN reached the peer.
ip netns exec "$PEER_NETNS" python3 -m http.server "$PEER_PORT" --bind "$PEER_IP" \
    >/dev/null 2>&1 &
PEER_LISTENER_PID=$!
sleep 1
kill -0 "$PEER_LISTENER_PID" >/dev/null 2>&1 \
    || fail "the peer listener did not start on $PEER_IP:$PEER_PORT."

# Alive is not reachable.  A peer that never bound has to fail here as harness
# breakage, rather than later as the firewall blocking an allowed destination.
python3 - "$PEER_IP" "$PEER_PORT" <<'PY' || fail "the peer is unreachable across the veth at $PEER_IP:$PEER_PORT."
import socket, sys
s = socket.socket()
s.settimeout(5)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except OSError as exc:
    print(exc)
    sys.exit(1)
finally:
    s.close()
PY

# Drift guard: the fixture must aim at this peer and name the pinned hosts, or
# the run would probe a stale address and prove nothing.
grep -Fq "$PEER_IP" "$CONFIG" \
    || fail "fixture ${CONFIG##*/} no longer targets the peer $PEER_IP; script and fixture drifted."
for host in "$PEER_HOSTNAME" "$BLOCKED_HOSTNAME"; do
    grep -Fq "$host" "$CONFIG" \
        || fail "fixture ${CONFIG##*/} no longer names $host; script and fixture drifted."
done

"$LXC_EXEC" "$CONFIG"
echo "LXC network test complete."