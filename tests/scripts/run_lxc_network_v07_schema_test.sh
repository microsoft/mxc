#!/bin/bash
# LXC schema 0.7 enforcement test
#
# LXC serves both schemas, and a run carries exactly one. These two cases pin
# what the 0.7 schema is owed, using configs that declare the version rather
# than leaving it absent.
#
# The DNS case is the sharpest contrast with 0.8: a filtered 0.7 chain opens
# port 53 so the container can resolve the hosts it is allowed to reach, and
# the same intent expressed in 0.8 does not.
# Run this alongside run_lxc_network_ga_egress_test.sh, whose dns-denied case
# is the other half of the pair.
#
# The query goes to a resolver this script stands up in its own routed
# namespace, so the case turns on the port 53 accept rather than on whether the
# host is allowed to reach a public resolver.
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
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed; the DNS case needs it to host a resolver."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

DNS_CONFIG="$REPO_DIR/tests/configs/lxc_network_v07_dns_exemption.json"
CAPABILITIES_CONFIG="$REPO_DIR/tests/configs/lxc_network_v07_capabilities.json"

[ -f "$DNS_CONFIG" ] || skip "missing config $DNS_CONFIG."
[ -f "$CAPABILITIES_CONFIG" ] || skip "missing config $CAPABILITIES_CONFIG."

fail() {
    echo "FAIL: $1"
    exit 1
}

IP_FORWARD_WAS=""
restore_ip_forward() {
    if [ -n "$IP_FORWARD_WAS" ]; then
        sysctl -w net.ipv4.ip_forward="$IP_FORWARD_WAS" >/dev/null 2>&1 || true
    fi
}

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"
# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"
# shellcheck source=lib/lxc_dns_peer.sh
. "$SCRIPT_DIR/lib/lxc_dns_peer.sh"

# The resolver lives in its own network namespace behind a veth, reached only
# through the FORWARD hook the chain filters on.  An RFC 2544 benchmarking range
# keeps it clear of every other suite's peer, which the host would otherwise
# route to by longest matching prefix.
PEER_NETNS="mxc-v07-dns-peer"
PEER_HOST_VETH="mxcv07h0"
PEER_VETH="mxcv07p0"
PEER_HOST_IP="198.18.0.1"
PEER_DNS_IP="198.18.0.53"
PEER_DNS_ANSWER="198.18.0.99"

PEER_DNS_LISTENER_LOG="$(mktemp)"
teardown_peer() {
    stop_dns_peer
    ip netns del "$PEER_NETNS" >/dev/null 2>&1 || true
    ip link del "$PEER_HOST_VETH" >/dev/null 2>&1 || true
    restore_ip_forward
}
teardown_run() {
    teardown_peer
    rm -f "$PEER_DNS_LISTENER_LOG"
}
trap teardown_run EXIT

# Clear anything an aborted earlier run left behind, then build the resolver.
teardown_peer
ip netns add "$PEER_NETNS" || fail "could not create the resolver namespace."
ip link add "$PEER_HOST_VETH" type veth peer name "$PEER_VETH" \
    || fail "could not create the resolver veth pair."
ip link set "$PEER_VETH" netns "$PEER_NETNS" \
    || fail "could not move the resolver interface into its namespace."
ip addr add "$PEER_HOST_IP/24" dev "$PEER_HOST_VETH" \
    || fail "could not address the host side of the resolver veth."
ip link set "$PEER_HOST_VETH" up || fail "could not bring up the resolver veth."
ip netns exec "$PEER_NETNS" ip addr add "$PEER_DNS_IP/24" dev "$PEER_VETH" \
    || fail "could not address the resolver."
ip netns exec "$PEER_NETNS" ip link set "$PEER_VETH" up \
    || fail "could not bring up the resolver interface."
ip netns exec "$PEER_NETNS" ip link set lo up \
    || fail "could not bring up the resolver loopback."
ip netns exec "$PEER_NETNS" ip route add default via "$PEER_HOST_IP" \
    || fail "could not route the resolver back to the container."

# Without this the container's DNS query stops at the host and never reaches the
# resolver, and the dns case below reads that as a missing port 53 accept.
IP_FORWARD_WAS="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
    || skip "could not enable IPv4 forwarding."

# A resolver that never bound has to fail here as harness breakage, rather than
# below as a chain that dropped its port 53 accept.
start_dns_peer "$PEER_NETNS" "$PEER_DNS_LISTENER_LOG" "$PEER_DNS_ANSWER" "$PEER_DNS_IP"
if ! PEER_PROBE_ERROR="$(await_peer_dns "$PEER_DNS_IP")"; then
    fail_unreachable_peer "the 0.7 DNS case resolver" "$PEER_DNS_IP:53" \
        "$PEER_PROBE_ERROR" "$PEER_DNS_LISTENER_LOG"
fi

# Drift guard: the fixture must query the resolver above, or the case would
# probe a stale address and prove nothing.
grep -Fq "$PEER_DNS_IP" "$DNS_CONFIG" \
    || fail "fixture ${DNS_CONFIG##*/} no longer queries the resolver $PEER_DNS_IP; script and fixture drifted."

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
echo "--- dns case: 0.7 defaultPolicy block, enforcementMode firewall, one allowed host ---"

DNS_OUTPUT=$("$LXC_EXEC" --debug "$DNS_CONFIG" 2>&1 || true)
echo "$DNS_OUTPUT"

if echo "$DNS_OUTPUT" | grep -Fq "requests no firewall; skipping iptables"; then
    fail "enforcementMode 'firewall' installed no chain, so nothing below is being enforced."
fi

if echo "$DNS_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
    fail "a DNS query was blocked under the 0.7 schema. A filtered 0.7 chain opens port 53 so the container can resolve the hosts it is allowed to reach; without it every 0.7 config naming a hostname is broken."
fi

if ! echo "$DNS_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
    fail "the case produced no verdict at all; the container command did not run."
fi

derive_chain_name "$DNS_OUTPUT"
assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

echo "PASS: the 0.7 chain kept its DNS exemption."

# ---------------------------------------------------------------------------
# Case 2: capabilities mode is refused
# ---------------------------------------------------------------------------

echo "--- capabilities case: 0.7 defaultPolicy block, enforcementMode absent ---"

CAP_OUTPUT=$("$LXC_EXEC" --debug "$CAPABILITIES_CONFIG" 2>&1 || true)
echo "$CAP_OUTPUT"

# `capabilities` names Windows AppContainer capability SIDs, which LXC has no
# mechanism for. It is also the 0.7 default, so a config that never wrote
# `enforcementMode` asks for it without meaning to. Accepting it would enforce
# the policy by some means other than the one named, or by none at all.
if ! echo "$CAP_OUTPUT" | grep -Fq "which LXC has no mechanism for"; then
    fail "the default enforcement mode was not refused. A 0.7 config naming a mechanism LXC does not have is being run anyway."
fi

if echo "$CAP_OUTPUT" | grep -Fq "MXC_WORKLOAD_RAN"; then
    fail "the workload ran under a refused enforcement mode; a refusal must stop the run."
fi

assert_no_new_mxc_chains iptables "$CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$CHAINS_BEFORE_V6"

echo "PASS: the default 0.7 enforcement mode was refused."
echo "LXC schema 0.7 enforcement test complete."
