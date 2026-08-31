#!/bin/bash
# LXC deny-precedence enforcement test
#
# A destination named in both allowedHosts and blockedHosts must be blocked.
# The chain is first-match-wins, so this is decided entirely by which list is
# emitted first -- there is no separate precedence pass to assert on. That
# makes it invisible to any test that only inspects rules individually, and it
# is why this assertion is behavioral rather than a log grep.
#
# Both configs name the same destination set, 0.0.0.0/0 and ::/0, so the rules
# are literal CIDRs rather than a hostname resolved once per list entry. A
# hostname would be resolved separately for the allow entry and the block
# entry, and round-robin DNS could hand back different addresses for the two,
# which would make the outcome depend on which address wget happened to pick.
#
# The control run is what makes the overlap run mean anything. Without it, a
# host with no working egress at all -- or a change that broke networking
# outright -- would produce the same blocked verdict and look like a pass.
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
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed; the peer needs it to host a listener."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

OVERLAP_CONFIG="$REPO_DIR/tests/configs/lxc_network_deny_precedence_overlap.json"
CONTROL_CONFIG="$REPO_DIR/tests/configs/lxc_network_deny_precedence_control.json"

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

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

assert_no_forward_reference() {
    if iptables -S FORWARD 2>/dev/null | grep -Fq -- "$1"; then
        fail "a FORWARD rule still references chain '$1' after teardown."
    fi
}

# A listener on the host or on the bridge gateway is delivered through INPUT
# and answers with no firewall in the path.  The peer lives in its own network
# namespace behind a veth, reached only through the FORWARD hook the chain
# filters on.
#
# Both runs must aim here: the control run shows this exact address is
# reachable when only the allow list names it, which leaves the deny entry as
# the only thing that can account for the overlap run's blocked verdict.
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

# Without this the container's packets stop at the host and never reach the peer.
IP_FORWARD_WAS="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
    || skip "could not enable IPv4 forwarding."

# The firewall matches the port and not the payload, so plain HTTP on tcp/443
# is enough.  A reply proves the SYN reached the peer.
ip netns exec "$PEER_NETNS" python3 -m http.server "$PEER_PORT" --bind "$PEER_IP" \
    >/dev/null 2>&1 &
PEER_LISTENER_PID=$!
sleep 1
kill -0 "$PEER_LISTENER_PID" >/dev/null 2>&1 \
    || fail "the peer listener did not start on $PEER_IP:$PEER_PORT."

# Alive is not reachable.  A peer that never bound has to fail here as harness
# breakage, rather than later as the control run being blocked.
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

# Drift guard: both fixtures must aim at this peer, or the run would probe a
# stale address and prove nothing.
for cfg in "$OVERLAP_CONFIG" "$CONTROL_CONFIG"; do
    grep -Fq "$PEER_IP" "$cfg" \
        || fail "fixture ${cfg##*/} no longer targets the peer $PEER_IP; script and fixture drifted."
done

echo "Running LXC deny-precedence enforcement test..."

echo "--- control: destination allowed, nothing blocked ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
CONTROL_OUTPUT=$("$LXC_EXEC" --debug "$CONTROL_CONFIG" 2>&1 || true)
echo "$CONTROL_OUTPUT"

if ! echo "$CONTROL_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the control destination was unreachable with an allow-everything policy, so this host cannot distinguish a deny-precedence failure from a broken network."
fi

derive_chain_name "$CONTROL_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "--- overlap: same destination in both allowedHosts and blockedHosts ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
OVERLAP_OUTPUT=$("$LXC_EXEC" --debug "$OVERLAP_CONFIG" 2>&1 || true)
echo "$OVERLAP_OUTPUT"

if echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "a destination present in BOTH allowedHosts and blockedHosts was reachable. Allow rules are winning over deny rules, so a blocklist entry can be silently defeated by an overlapping allowlist entry."
fi
if ! echo "$OVERLAP_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the overlap case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$OVERLAP_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "PASS: a destination in both lists was blocked, and the same destination was reachable when only allowed."
echo "LXC deny-precedence enforcement test complete."
