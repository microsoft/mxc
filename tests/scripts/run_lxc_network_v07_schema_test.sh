#!/bin/bash
# LXC schema 0.7 enforcement test
#
# LXC serves both schemas, and a run carries exactly one. These two cases pin
# what the 0.7 schema is owed, using configs that declare the version rather
# than leaving it absent.
#
# The DNS case is the sharpest contrast with 0.8: a 0.7 chain carries an
# unconditional port 53 accept, and the same intent expressed in 0.8 does not.
# Run this alongside run_lxc_network_ga_egress_test.sh, whose dns-denied case
# is the other half of the pair.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# Exit 77 is what run_lxc_all_tests.sh records as SKIPPED rather than PASS.
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
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

DNS_CONFIG="$REPO_DIR/tests/configs/lxc_network_v07_dns_exemption.json"
CAPABILITIES_CONFIG="$REPO_DIR/tests/configs/lxc_network_v07_capabilities.json"

[ -f "$DNS_CONFIG" ] || skip "missing config $DNS_CONFIG."
[ -f "$CAPABILITIES_CONFIG" ] || skip "missing config $CAPABILITIES_CONFIG."

fail() {
    echo "FAIL: $1"
    exit 1
}

# ---------------------------------------------------------------------------
# A CI-controlled resolver, standing in for the address the DNS case queries.
#
# The chain hooks FORWARD, so it only ever sees traffic the host routes on the
# container's behalf.  A resolver on the host or on the bridge gateway arrives
# through INPUT instead, answers with no firewall installed at all, and so
# cannot stand in for a destination the 0.7 port 53 exemption is meant to
# reach.  The resolver lives in its own network namespace behind a veth.
#
# This replaces 8.8.8.8.  A CI network that blocks outbound DNS -- a common and
# entirely reasonable configuration -- made this case report the query as
# blocked, which reads as the 0.7 DNS exemption having been dropped when in
# fact the network had no route to Google.
PEER_NETNS="mxc-v07-peer"
PEER_HOST_VETH="mxcv7h0"
PEER_VETH="mxcv7p0"
# A dedicated slice of RFC 5737 TEST-NET-2, distinct from the ranges the
# enforcement, deny_precedence, and network peers claim.  The host routes by
# longest matching prefix, so two peers sharing a range let whichever suite ran
# last capture the other's traffic.
PEER_HOST_IP="198.51.100.25"
PEER_IP="198.51.100.26"
PEER_PREFIX="29"

PEER_LISTENER_PID=""
teardown_peer() {
    if [ -n "$PEER_LISTENER_PID" ]; then
        kill "$PEER_LISTENER_PID" >/dev/null 2>&1 || true
    fi
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    ip link del "$PEER_HOST_VETH" >/dev/null 2>&1 || true
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

# A minimal A-record responder.  It echoes the question back and appends a
# fixed answer, which is all nslookup needs to exit zero; the case asserts on
# whether the query reached a resolver at all, never on what it resolved to.
#
# Bound to the peer address rather than to every local address at once.  A
# socket bound to 0.0.0.0 picks its reply's source address by route lookup, so
# an answer can leave from an address the container never queried and be
# dropped as an unrelated flow.
ip netns exec "$PEER_NETNS" python3 - "$PEER_IP" <<'PY' >/dev/null 2>&1 &
import socket, struct, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], 53))
while True:
    query, sender = sock.recvfrom(512)
    if len(query) < 12:
        continue
    # Walk the length-prefixed QNAME labels to find where the question ends,
    # then take the terminating zero byte plus QTYPE and QCLASS with it.
    cursor = 12
    while cursor < len(query) and query[cursor] != 0:
        cursor += 1 + query[cursor]
    question = query[12:cursor + 5]
    # Flags 0x8180: a response, recursion desired and available, no error.
    header = query[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    # 0xc00c points back at the question's name rather than repeating it.
    answer = (b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">I", 60)
              + b"\x00\x04" + socket.inet_aton("192.0.2.123"))
    sock.sendto(header + question + answer, sender)
PY
PEER_LISTENER_PID=$!
sleep 1
kill -0 "$PEER_LISTENER_PID" >/dev/null 2>&1 \
    || fail "the peer resolver did not start on $PEER_IP:53."

# Alive is not the same as reachable: confirm the resolver answers across the
# veth, so a resolver that never bound is reported as harness breakage rather
# than mistaken for the 0.7 DNS exemption having been dropped.  The reply's
# source address is checked too: a resolver answering from the wrong address is
# dropped as an unrelated flow by the time a container asks.
python3 - "$PEER_IP" <<'PY' || fail "the peer resolver did not answer correctly across the veth at $PEER_IP:53."
import socket, sys
query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07example\x03com\x00\x00\x01\x00\x01")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(query, (sys.argv[1], 53))
    reply, sender = s.recvfrom(512)
except OSError as exc:
    print(exc)
    sys.exit(1)
finally:
    s.close()
if sender[0] != sys.argv[1]:
    print("answered from {} rather than {}".format(sender[0], sys.argv[1]))
    sys.exit(1)
sys.exit(0 if len(reply) > 12 and reply[:2] == b"\x12\x34" else 1)
PY

# Drift guard: the fixture must query this resolver, or the case would probe a
# stale address and prove nothing.  Fail loudly if the two disagree.
grep -Fq "$PEER_IP" "$DNS_CONFIG" \
    || fail "fixture ${DNS_CONFIG##*/} no longer queries the peer resolver $PEER_IP; script and fixture drifted."

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

# The snapshot keeps chains left behind by an earlier failed run from being
# blamed on this one.
assert_no_new_mxc_chains() {
    local tool="$1" before="$2" after="" leaked="" chain
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

CHAINS_BEFORE_V4="$(mxc_chains iptables)"
CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"

# ---------------------------------------------------------------------------
# Case 1: firewall mode keeps the 0.7 DNS exemption
# ---------------------------------------------------------------------------

echo "Running LXC schema 0.7 enforcement test..."
echo "--- dns case: 0.7 defaultPolicy block, enforcementMode firewall ---"

DNS_OUTPUT=$("$LXC_EXEC" --debug "$DNS_CONFIG" 2>&1 || true)
echo "$DNS_OUTPUT"

if echo "$DNS_OUTPUT" | grep -Fq "requests no firewall; skipping iptables"; then
    fail "enforcementMode 'firewall' installed no chain, so nothing below is being enforced."
fi

if echo "$DNS_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "a DNS query was blocked under the 0.7 schema. The unconditional port 53 accept that every 0.7 chain carries is missing, which breaks name resolution for every existing config."
fi

if ! echo "$DNS_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$DNS_OUTPUT"
assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

echo "PASS: the 0.7 chain kept its DNS exemption."

# ---------------------------------------------------------------------------
# Case 2: capabilities mode installs nothing
# ---------------------------------------------------------------------------

echo "--- capabilities case: 0.7 defaultPolicy block, enforcementMode absent ---"

CAP_OUTPUT=$("$LXC_EXEC" --debug "$CAPABILITIES_CONFIG" 2>&1 || true)
echo "$CAP_OUTPUT"

# `capabilities` is the 0.7 default, so this is what every config that never
# wrote `enforcementMode` gets. Installing a chain here would put a firewall on
# configs that predate the field.
if ! echo "$CAP_OUTPUT" | grep -Fq "requests no firewall; skipping iptables"; then
    fail "the default enforcement mode did not skip the firewall. A 0.7 config that never asked for one is being given a chain."
fi

if ! echo "$CAP_OUTPUT" | grep -Fq "MXC_WORKLOAD_RAN"; then
    fail "the workload did not run; skipping the firewall must remain a successful no-op."
fi

assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

echo "PASS: the default 0.7 enforcement mode installed nothing."
echo "LXC schema 0.7 enforcement test complete."
