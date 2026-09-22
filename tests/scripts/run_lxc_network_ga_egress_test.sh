#!/bin/bash
# LXC schema 0.8 egress enforcement test
#
# Asserts reachability rather than a log line: a chain can install cleanly,
# name the right chain, and still filter nothing.
#
# The tcp/443 and ICMP cases probe a CI-controlled peer this script stands up in
# its own routed namespace.  The udp/53 cases still query a public resolver.
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
EXCEPT_SHADOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_except_shadow.json"
EXCEPT_SHADOW_CONTROL_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_except_shadow_control.json"
ICMP_ALLOWED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_icmp_allowed.json"
ICMP_NO_TCP_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_icmp_no_tcp.json"
ICMP_DENIED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_icmp_denied.json"
PORT_RANGE_INSIDE_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_port_range_inside.json"
PORT_RANGE_OUTSIDE_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_port_range_outside.json"
PORT_RANGE_ABOVE_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_port_range_above.json"
ANY_TCP_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_any_tcp.json"
ANY_ICMP_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_any_icmp.json"
ANY_PORT_MATCH_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_any_port_match.json"
ANY_WRONG_PORT_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_any_wrong_port.json"
ANY_UDP_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_any_udp.json"
ANY_UDP_WRONG_PORT_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_any_udp_wrong_port.json"
ANY_UDP_UNSCOPED_CONFIG="$REPO_DIR/tests/configs/lxc_network_ga_egress_any_udp_unscoped.json"

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

# A policy that permits nothing is served by keeping the container off the
# network entirely, so no chain is created and there is none to inspect.
assert_no_chain_installed() {
    if echo "$1" | grep -Eq "Creating iptables/ip6tables chain:|Programmed [a-z0-9]* rule:"; then
        fail "a policy permitting nothing installed a firewall chain, so the container was put on the network and then filtered instead of being left off it."
    fi
}

# Each case names the posture its policy should reach. Reading the posture back
# out of the run instead would let a filtered policy that installed nothing pass
# as an isolated one, which is the silent-unenforced case worth catching.
run_case() {
    local label="$1" config="$2" posture="${3:-filtered}" output=""
    echo "--- $label ---"
    MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
    MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
    output=$("$LXC_EXEC" --debug "$config" 2>&1 || true)
    echo "$output"
    CASE_OUTPUT="$output"

    if [ "$posture" = isolated ]; then
        assert_no_chain_installed "$output"
        assert_no_new_mxc_chains iptables "$MXC_CHAINS_BEFORE_V4"
        assert_no_new_mxc_chains ip6tables "$MXC_CHAINS_BEFORE_V6"
        return
    fi

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

# A listener on the host or on the bridge gateway is delivered through INPUT
# and answers with no firewall in the path.  The peer lives in its own network
# namespace behind a veth, reached only through the FORWARD hook the chain
# filters on (-i <veth> / --physdev-in <veth>).
PEER_NETNS="mxc-ga-egress-peer"
PEER_HOST_VETH="mxcgah0"
PEER_VETH="mxcgap0"
# An RFC 5737 test range.  The host routes by longest matching prefix, and two
# peers sharing a range let whichever suite ran last capture the other's
# traffic.
PEER_HOST_IP="203.0.113.1"
PEER_IP="203.0.113.2"
PEER_CIDR="203.0.113.0/24"
PEER_PORT="443"
# A UDP echo service, so the protocol-any fan-out can be probed on the half no
# TCP case reaches.
PEER_UDP_PORT="8053"

PEER_LISTENER_PID=""
PEER_UDP_LISTENER_PID=""
IP_FORWARD_WAS=""
teardown_peer() {
    if [ -n "$PEER_LISTENER_PID" ]; then
        kill "$PEER_LISTENER_PID" >/dev/null 2>&1 || true
    fi
    if [ -n "$PEER_UDP_LISTENER_PID" ]; then
        kill "$PEER_UDP_LISTENER_PID" >/dev/null 2>&1 || true
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
    || fail "the egress peer listener did not start on $PEER_IP:$PEER_PORT."

# Alive is not reachable.  A peer that never bound has to fail here as harness
# breakage, rather than later as the firewall blocking the allow case.
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

# UDP carries no handshake, so the probe reads a returned payload as the
# verdict.  An echo service supplies one.
ip netns exec "$PEER_NETNS" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('$PEER_IP', $PEER_UDP_PORT))
while True:
    payload, sender = s.recvfrom(1024)
    s.sendto(payload, sender)
" >/dev/null 2>&1 &
PEER_UDP_LISTENER_PID=$!
sleep 1
kill -0 "$PEER_UDP_LISTENER_PID" >/dev/null 2>&1 \
    || fail "the egress peer UDP listener did not start on $PEER_IP:$PEER_UDP_PORT."

# A silent echo service would make the udp allow case read as a firewall block.
python3 - "$PEER_IP" "$PEER_UDP_PORT" <<'PY' || fail "the egress peer does not echo UDP at $PEER_IP:$PEER_UDP_PORT."
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(b"probe", (sys.argv[1], int(sys.argv[2])))
    if s.recvfrom(1024)[0] != b"probe":
        sys.exit(1)
except OSError as exc:
    print(exc)
    sys.exit(1)
finally:
    s.close()
PY

# The ICMP cases below read an unanswered echo as a firewall verdict, so a peer
# that ignores echo has to fail here as harness breakage instead.
if command -v ping >/dev/null 2>&1; then
    ping -c 1 -W 5 "$PEER_IP" >/dev/null 2>&1 \
        || fail "the egress peer does not answer ICMP echo at $PEER_IP."
fi

# Drift guard: the peer fixtures must target this peer, or the run would probe a
# stale address and prove nothing.
PEER_TARGETING_CONFIGS=(
    "$DENY_CONFIG" "$ALLOW_CONFIG" "$WRONG_PORT_CONFIG"
    "$EXCEPT_SHADOW_CONFIG" "$EXCEPT_SHADOW_CONTROL_CONFIG"
    "$ICMP_ALLOWED_CONFIG" "$ICMP_NO_TCP_CONFIG" "$ICMP_DENIED_CONFIG"
    "$PORT_RANGE_INSIDE_CONFIG" "$PORT_RANGE_OUTSIDE_CONFIG" "$PORT_RANGE_ABOVE_CONFIG"
    "$ANY_TCP_CONFIG" "$ANY_ICMP_CONFIG"
    "$ANY_PORT_MATCH_CONFIG" "$ANY_WRONG_PORT_CONFIG"
    "$ANY_UDP_CONFIG" "$ANY_UDP_WRONG_PORT_CONFIG" "$ANY_UDP_UNSCOPED_CONFIG"
)
PEER_ALLOWING_CONFIGS=(
    "$ALLOW_CONFIG" "$WRONG_PORT_CONFIG"
    "$EXCEPT_SHADOW_CONFIG" "$EXCEPT_SHADOW_CONTROL_CONFIG"
    "$ICMP_ALLOWED_CONFIG" "$ICMP_NO_TCP_CONFIG" "$ICMP_DENIED_CONFIG"
    "$PORT_RANGE_INSIDE_CONFIG" "$PORT_RANGE_OUTSIDE_CONFIG" "$PORT_RANGE_ABOVE_CONFIG"
    "$ANY_TCP_CONFIG" "$ANY_ICMP_CONFIG"
    "$ANY_PORT_MATCH_CONFIG" "$ANY_WRONG_PORT_CONFIG"
    "$ANY_UDP_CONFIG" "$ANY_UDP_WRONG_PORT_CONFIG" "$ANY_UDP_UNSCOPED_CONFIG"
)
for cfg in "${PEER_TARGETING_CONFIGS[@]}"; do
    grep -Fq "$PEER_IP" "$cfg" \
        || fail "fixture ${cfg##*/} no longer targets the peer $PEER_IP; script and fixture drifted."
done
for cfg in "${PEER_ALLOWING_CONFIGS[@]}"; do
    grep -Fq "$PEER_CIDR" "$cfg" \
        || fail "fixture ${cfg##*/} no longer allows $PEER_CIDR; script and fixture drifted."
done

# Both udp fixtures probe the echo service, so a port the listener does not hold
# would read as the firewall blocking rather than as drift.
for cfg in "$ANY_UDP_CONFIG" "$ANY_UDP_WRONG_PORT_CONFIG" "$ANY_UDP_UNSCOPED_CONFIG"; do
    grep -Fq "$PEER_UDP_PORT" "$cfg" \
        || fail "fixture ${cfg##*/} no longer probes udp/$PEER_UDP_PORT; script and fixture drifted."
done

# An egress-only config is the shape a backend claiming only the two egress
# bits would reject outright, which makes any verdict here a test of the
# support declaration.
run_case "deny case: egress.default deny, no rules" "$DENY_CONFIG" isolated
assert_blocked "egress succeeded under egress.default deny with no allow rules, so a container that should never have reached the network reached it."

run_case "allow case: same default, destination allowed on tcp/443" "$ALLOW_CONFIG"
assert_allowed "an explicitly allowed destination was unreachable. The policy is over-blocking, so the deny case above proves nothing."

run_case "wrong-port case: same destination allowed on tcp/444" "$WRONG_PORT_CONFIG"
assert_blocked "traffic to tcp/443 succeeded while the policy allowed only tcp/444. The port selector is being dropped, so the allow case above proves only that the destination matched."

run_case "dns-denied case: egress.default deny, DNS probe to an external resolver" "$DNS_DENIED_CONFIG" isolated
assert_blocked "a DNS query to 8.8.8.8 succeeded under egress.default deny with no allow rules, which leaves this container a DNS-tunnel path out of a policy that permits nothing."

run_case "dns-allowed case: same probe, resolver allowed on udp/53" "$DNS_ALLOWED_CONFIG"
assert_allowed "a DNS query to an explicitly allowed resolver was unreachable. DNS is over-blocked, so the dns-denied case above proves only that this container has no DNS at all."

run_case "deny-rule case: egress.default allow, one destination denied on udp/53" "$DENY_RULE_CONFIG"
assert_blocked "a denied destination stayed reachable under egress.default allow. Entries from egress.deny are not reaching the chain, so a config written as allow-with-exceptions enforces nothing."

run_case "except case: allow 8.8.0.0/16 except 8.8.8.8/32, probe the excluded address" "$EXCEPT_EXCLUDED_CONFIG"
assert_blocked "an address named in except was reachable through the rule that excludes it. The exclusion is being dropped, so the surrounding allow is wider than written."

run_case "except case: same policy, probe an address the exclusion does not cover" "$EXCEPT_SIBLING_CONFIG"
assert_allowed "an address inside the allowed range but outside except was unreachable. The exclusion is over-blocking, so the case above proves only that the whole rule failed to install."

# The chain is first-match-wins, so a carve-out programmed as its own accept
# rule would answer for the peer before the second rule's deny is reached.
run_case "shadow case: deny the peer's range except the peer, then deny the peer outright" "$EXCEPT_SHADOW_CONFIG"
assert_blocked "a destination denied by its own rule was reachable because an earlier rule excluded it. An except carve-out is escaping the rule that declared it and accepting traffic a later deny names, which turns a deny into an allow."

run_case "shadow-control case: the same first rule with no second deny" "$EXCEPT_SHADOW_CONTROL_CONFIG"
assert_allowed "an address excluded from a deny was unreachable under egress.default allow. The exclusion is not narrowing its own rule, so the shadow case above proves only that everything was blocked."

run_case "icmp case: egress.default deny, peer allowed on protocol icmp" "$ICMP_ALLOWED_CONFIG"
assert_allowed "an ICMP echo to a peer allowed on protocol icmp was unreachable. Either the icmp selector never reached the chain, or the container cannot open a raw socket at all, which would make the icmp-denied case below pass without filtering anything."

run_case "icmp case: same icmp-only policy, probe tcp/443" "$ICMP_NO_TCP_CONFIG"
assert_blocked "tcp/443 succeeded while the policy allowed only icmp. The protocol selector is being dropped, so an icmp rule opens every transport to its destination."

run_case "icmp case: egress.default deny, peer allowed on tcp/443 only" "$ICMP_DENIED_CONFIG"
assert_blocked "an ICMP echo succeeded while the policy allowed only tcp/443. ICMP is not carrying the port selectors, so a policy written for one transport leaks another."

run_case "port-range case: peer allowed on tcp/440-445, probe tcp/443" "$PORT_RANGE_INSIDE_CONFIG"
assert_allowed "a port inside the allowed range 440-445 was unreachable. endPort is not reaching the chain, so a range selector blocks the traffic it was written to permit."

run_case "port-range case: peer allowed on tcp/444-446, probe tcp/443" "$PORT_RANGE_OUTSIDE_CONFIG"
assert_blocked "tcp/443 succeeded while the allowed range started at 444. The range bounds are not enforced, so the case above proves only that some rule installed."

run_case "port-range case: peer allowed on tcp/438-442, probe tcp/443" "$PORT_RANGE_ABOVE_CONFIG"
assert_blocked "tcp/443 succeeded while the allowed range ended at 442. The range's upper bound is not reaching the chain, so a range opens every port above its start."

run_case "protocol-any case: peer allowed on protocol any, probe tcp/443" "$ANY_TCP_CONFIG"
assert_allowed "tcp/443 was unreachable under protocol any, so the any selector is not reaching the chain."

run_case "protocol-any case: same policy, probe icmp" "$ANY_ICMP_CONFIG"
assert_allowed "an ICMP echo was unreachable under protocol any. The any selector is being lowered to the transports alone, so it is narrower than written."

run_case "protocol-any case: same policy, probe udp/$PEER_UDP_PORT" "$ANY_UDP_UNSCOPED_CONFIG"
assert_allowed "udp/$PEER_UDP_PORT was unreachable under protocol any carrying no port. An unscoped any is being lowered to a protocol list that omits udp, which the port-scoped cases below would not catch."

run_case "protocol-any case: peer allowed on any port 443, probe tcp/443" "$ANY_PORT_MATCH_CONFIG"
assert_allowed "tcp/443 was unreachable while protocol any allowed port 443, so the tcp/udp fan-out is not reaching the chain."

run_case "protocol-any case: peer allowed on any port 444, probe tcp/443" "$ANY_WRONG_PORT_CONFIG"
assert_blocked "tcp/443 succeeded while protocol any allowed only port 444. The fan-out drops the port selector, so any carrying a port opens every port."

run_case "protocol-any case: peer allowed on any port $PEER_UDP_PORT, probe udp/$PEER_UDP_PORT" "$ANY_UDP_CONFIG"
assert_allowed "udp/$PEER_UDP_PORT was unreachable while protocol any allowed that port. Only the TCP half of the fan-out is reaching the chain, so the tcp cases above prove nothing about udp."

run_case "protocol-any case: peer allowed on any port 8054, probe udp/$PEER_UDP_PORT" "$ANY_UDP_WRONG_PORT_CONFIG"
assert_blocked "udp/$PEER_UDP_PORT succeeded while protocol any allowed only port 8054. The UDP half of the fan-out ignores the port selector."

echo "PASS: schema 0.8 egress rules filtered by destination, by port, by port range, by protocol, by resolver, by deny rule, and by exclusion, and no exclusion answered for a destination a later rule denied."
echo "LXC schema 0.8 egress enforcement test complete."
