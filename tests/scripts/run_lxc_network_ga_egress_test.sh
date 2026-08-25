#!/bin/bash
# LXC schema 0.8 egress enforcement test
#
# Asserts reachability rather than a log line: a chain can install cleanly,
# name the right chain, and still filter nothing.
#
# The tcp/443 cases probe a CI-controlled peer this script stands up in its own
# routed namespace rather than a public host, so remote-service health can never
# turn the positive path red.
#
# A directional posture carries no port 53 exemption, unlike the legacy chain,
# which is what the two DNS cases pin.
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
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed; the egress peer needs it to host a listener."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_deny.json"
ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_allow.json"
WRONG_PORT_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_wrong_port.json"
DNS_DENIED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_dns_denied.json"
DNS_ALLOWED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_dns_allowed.json"
DENY_RULE_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_deny_rule.json"
EXCEPT_EXCLUDED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_except_excluded.json"
EXCEPT_SIBLING_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_except_sibling.json"

fail() {
    echo "FAIL: $1"
    exit 1
}

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

# A backend reading `enforcementMode` alone skips the chain and still reports
# success, which is a silent unenforced run rather than a failure.
assert_enforcement_not_skipped() {
    if echo "$1" | grep -Fq "requests no firewall; skipping iptables"; then
        fail "the 0.8 config was treated as not using the firewall, so no rules were installed. The directional posture is not reaching the firewall gate."
    fi
}

run_case() {
    local label="$1" config="$2" output="" 
    echo "--- $label ---"
    MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
    MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
    output=$("$LXC_EXEC" --debug "$config" 2>&1 || true)
    echo "$output"
    CASE_OUTPUT="$output"
    assert_enforcement_not_skipped "$output"
    derive_chain_name "$output"
    assert_no_forward_reference "$CHAIN_NAME"
    assert_firewall_chain_cleaned_up "$CHAIN_NAME"
}

assert_blocked() {
    if echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
        fail "$1"
    fi
    if ! echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
        fail "the case produced no verdict at all; the container command did not run."
    fi
}

assert_allowed() {
    if echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_BLOCKED"; then
        fail "$1"
    fi
    if ! echo "$CASE_OUTPUT" | grep -Fq "MXC_NET_ALLOWED"; then
        fail "the case produced no verdict at all; the container command did not run."
    fi
}

# ---------------------------------------------------------------------------
# A CI-controlled peer for the positive path.
#
# The allow case has to prove the chain admits an allowed destination, which
# only means something if the destination is one the chain actually governs.
# The chain hooks FORWARD (-i <veth> / --physdev-in <veth>), so it sees only
# traffic the host routes for the container.  A listener on the host or on the
# bridge gateway is delivered locally through INPUT, never reaches the chain,
# and would answer even with no firewall installed, so it cannot stand in for
# an allowed destination.  The peer therefore lives in its own network
# namespace, routed to over a dedicated veth, reachable only through the
# container's forwarded path.  This is the same routed-namespace peer that
# run_lxc_network_proxy_hostname_test.sh already stands up for exactly this
# reason; the mechanism is reused here rather than invented.
#
# This replaces api.github.com, whose rate-limited 403 was indistinguishable
# from over-blocking and turned a healthy firewall red when the remote service,
# not the repository, was at fault.
PEER_NETNS="mxc-ga-egress-peer"
PEER_HOST_VETH="mxcgah0"
PEER_VETH="mxcgap0"
# A different RFC 5737 range from the proxy-hostname peer's 192.0.2.0/24.  The
# host routes by longest matching prefix, so two peers sharing a range let
# whichever suite ran last capture the other's traffic.
PEER_HOST_IP="203.0.113.1"
PEER_IP="203.0.113.2"
PEER_CIDR="203.0.113.0/24"
PEER_PORT="443"

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
ip netns add "$PEER_NETNS" || fail "could not create the egress peer namespace."
ip link add "$PEER_HOST_VETH" type veth peer name "$PEER_VETH" \
    || fail "could not create the egress peer veth pair."
ip link set "$PEER_VETH" netns "$PEER_NETNS" \
    || fail "could not move the egress peer interface into its namespace."
ip addr add "$PEER_HOST_IP/24" dev "$PEER_HOST_VETH" \
    || fail "could not address the host side of the egress peer veth."
ip link set "$PEER_HOST_VETH" up || fail "could not bring up the egress peer veth."
ip netns exec "$PEER_NETNS" ip addr add "$PEER_IP/24" dev "$PEER_VETH" \
    || fail "could not address the egress peer."
ip netns exec "$PEER_NETNS" ip link set "$PEER_VETH" up \
    || fail "could not bring up the egress peer interface."
ip netns exec "$PEER_NETNS" ip link set lo up \
    || fail "could not bring up the egress peer loopback."
ip netns exec "$PEER_NETNS" ip route add default via "$PEER_HOST_IP" \
    || fail "could not route the egress peer back to the container."

# A plain HTTP listener on tcp/443.  The firewall matches the port, not the
# payload, so no TLS is needed: a reply proves the SYN reached the peer, which
# only an ACCEPT in the container's FORWARD chain permits.
ip netns exec "$PEER_NETNS" python3 -m http.server "$PEER_PORT" --bind "$PEER_IP" \
    >/dev/null 2>&1 &
PEER_LISTENER_PID=$!
sleep 1
kill -0 "$PEER_LISTENER_PID" >/dev/null 2>&1 \
    || fail "the egress peer listener did not start on $PEER_IP:$PEER_PORT."

# Alive is not the same as reachable: confirm the listener answers across the
# veth, so a peer that never bound is reported as harness breakage rather than
# mistaken for the firewall blocking the allow case.  Mirrors the reachability
# gate in run_lxc_network_proxy_hostname_test.sh.
python3 - "$PEER_IP" "$PEER_PORT" <<'PY' || fail "the egress peer is unreachable across the veth at $PEER_IP:$PEER_PORT."
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

# Drift guard: the tcp/443 fixtures must target this peer, or the run would
# probe a stale address and prove nothing.  Fail loudly if the two disagree.
for cfg in "$DENY_CONFIG" "$ALLOW_CONFIG" "$WRONG_PORT_CONFIG"; do
    grep -Fq "$PEER_IP" "$cfg" \
        || fail "fixture ${cfg##*/} no longer targets the peer $PEER_IP; script and fixture drifted."
done
for cfg in "$ALLOW_CONFIG" "$WRONG_PORT_CONFIG"; do
    grep -Fq "$PEER_CIDR" "$cfg" \
        || fail "fixture ${cfg##*/} no longer allows $PEER_CIDR; script and fixture drifted."
done

echo "Running LXC schema 0.8 egress enforcement test..."

# An egress-only config is the shape a backend claiming only the two egress
# bits would reject outright, which makes any verdict here a test of the
# support declaration.
run_case "deny case: egress.default deny, no rules" "$DENY_CONFIG"
assert_blocked "egress succeeded under egress.default deny with no allow rules. The chain is not filtering this container's traffic."

run_case "allow case: same default, destination allowed on tcp/443" "$ALLOW_CONFIG"
assert_allowed "an explicitly allowed destination was unreachable. The policy is over-blocking, so the deny case above proves nothing."

run_case "wrong-port case: same destination allowed on tcp/444" "$WRONG_PORT_CONFIG"
assert_blocked "traffic to tcp/443 succeeded while the policy allowed only tcp/444. The port selector is being dropped, so the allow case above proves only that the destination matched."

run_case "dns-denied case: egress.default deny, DNS probe to an external resolver" "$DNS_DENIED_CONFIG"
assert_blocked "a DNS query to 8.8.8.8 succeeded under egress.default deny with no allow rules. The legacy unconditional port 53 accept is still being emitted into a directional chain, which leaves this container a DNS-tunnel path out of a deny-all policy."

run_case "dns-allowed case: same probe, resolver allowed on udp/53" "$DNS_ALLOWED_CONFIG"
assert_allowed "a DNS query to an explicitly allowed resolver was unreachable. DNS is over-blocked, so the dns-denied case above proves only that this container has no DNS at all."

run_case "deny-rule case: egress.default allow, one destination denied on udp/53" "$DENY_RULE_CONFIG"
assert_blocked "a denied destination stayed reachable under egress.default allow. Entries from egress.deny are not reaching the chain, so a config written as allow-with-exceptions enforces nothing."

run_case "except case: allow 8.8.0.0/16 except 8.8.8.8/32, probe the excluded address" "$EXCEPT_EXCLUDED_CONFIG"
assert_blocked "an address named in except was reachable through the rule that excludes it. The exclusion is being dropped, so the surrounding allow is wider than written."

run_case "except case: same policy, probe an address the exclusion does not cover" "$EXCEPT_SIBLING_CONFIG"
assert_allowed "an address inside the allowed range but outside except was unreachable. The exclusion is over-blocking, so the case above proves only that the whole rule failed to install."

echo "PASS: schema 0.8 egress rules filtered by destination, by port, by resolver, by deny rule, and by exclusion."
echo "LXC schema 0.8 egress enforcement test complete."
