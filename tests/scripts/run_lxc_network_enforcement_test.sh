#!/bin/bash
# LXC network policy enforcement test
#
# Every other network script asserts that the FORWARD hook was *installed*.
# That is a log line, and a hook can install cleanly, name the right chain,
# and still match no packet -- which is exactly how a fully populated deny-all
# chain that filtered nothing once passed every script in this directory.
#
# This script asserts the guarantee itself rather than the log: a destination
# the policy does not allow must be unreachable from inside the container.
#
# Both directions are required, and the allow case is not decoration. A
# blocked-only assertion would also pass on a host with no working network at
# all, or on a change that broke egress outright, so it proves nothing on its
# own.
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

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_enforcement_deny.json"
ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_enforcement_allow.json"

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

# A hook that references the chain but survives teardown leaves the next
# container's traffic running through a stale rule, so the reference count
# matters as much as the chain itself.
assert_no_forward_reference() {
    if iptables -S FORWARD 2>/dev/null | grep -Fq -- "$1"; then
        fail "a FORWARD rule still references chain '$1' after teardown."
    fi
}

# ---------------------------------------------------------------------------
# A CI-controlled peer, standing in for the destination both cases probe.
#
# A listener on the host or on the bridge gateway is delivered through INPUT
# and answers with no firewall in the path.  The peer lives in its own network
# namespace behind a veth, reached only through the FORWARD hook the chain
# filters on.
#
# Both cases must aim at this one address: the deny case shows a destination
# that is demonstrably reachable becoming unreachable under policy, rather than
# merely failing to reach something.
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
# lxc-exec resolves this name on the host when it builds the rule, so the pin
# below goes in the host's /etc/hosts and not the container's.
PEER_HOSTNAME="allowed.mxc.test"

PEER_LISTENER_PID=""
HOSTS_BACKUP=""
teardown_peer() {
    if [ -n "$PEER_LISTENER_PID" ]; then
        kill "$PEER_LISTENER_PID" >/dev/null 2>&1 || true
    fi
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    ip link del "$PEER_HOST_VETH" >/dev/null 2>&1 || true
    # Restoring the whole file, rather than filtering out the added line,
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

# The firewall matches the port and not the payload, so plain HTTP on tcp/443
# is enough.  A reply proves the SYN reached the peer.
ip netns exec "$PEER_NETNS" python3 -m http.server "$PEER_PORT" --bind "$PEER_IP" \
    >/dev/null 2>&1 &
PEER_LISTENER_PID=$!
sleep 1
kill -0 "$PEER_LISTENER_PID" >/dev/null 2>&1 \
    || fail "the peer listener did not start on $PEER_IP:$PEER_PORT."

# Alive is not reachable.  A peer that never bound has to fail here as harness
# breakage, rather than later as the firewall blocking the allow case.
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
for cfg in "$DENY_CONFIG" "$ALLOW_CONFIG"; do
    grep -Fq "$PEER_IP" "$cfg" \
        || fail "fixture ${cfg##*/} no longer targets the peer $PEER_IP; script and fixture drifted."
done
grep -Fq "$PEER_HOSTNAME" "$ALLOW_CONFIG" \
    || fail "fixture ${ALLOW_CONFIG##*/} no longer allows $PEER_HOSTNAME; script and fixture drifted."

echo "Running LXC network policy enforcement test..."

# The container reports the outcome itself rather than relying on its exit
# code, so a wrapper that swallows or rewrites the status cannot turn a
# reachable destination into an apparent block.
echo "--- deny case: default policy blocks, nothing allowed ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
DENY_OUTPUT=$("$LXC_EXEC" --debug "$DENY_CONFIG" 2>&1 || true)
echo "$DENY_OUTPUT"

if echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "egress succeeded under a default-block policy with no allowed hosts. The chain is not filtering this container's traffic."
fi
if ! echo "$DENY_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "the deny case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$DENY_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "--- allow case: same default, destination explicitly allowed ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
ALLOW_OUTPUT=$("$LXC_EXEC" --debug "$ALLOW_CONFIG" 2>&1 || true)
echo "$ALLOW_OUTPUT"

if echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "an explicitly allowed destination was unreachable. The policy is over-blocking, so the deny case above proves nothing."
fi
if ! echo "$ALLOW_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the allow case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$ALLOW_OUTPUT"
assert_no_forward_reference "$CHAIN_NAME"
assert_firewall_chain_cleaned_up "$CHAIN_NAME"

echo "PASS: a disallowed destination was blocked and an allowed destination was reachable."
echo "LXC network policy enforcement test complete."