#!/bin/bash
# LXC raw egress test
#
# The enforcement test next door asks the container whether it got a reply.
# That question cannot see this defect.  A denied destination and a black-holed
# one look identical from inside -- no reply either way -- so a container
# reporting "blocked" proves only that nothing answered, never that nothing
# left.  Every cell of a four-way measurement of this behavior returned the
# same in-container verdict while the packets differed.
#
# This script therefore counts packets where they arrive, on the host, and asks
# the container only whether its arm ran at all.
#
# The count is taken on the way out of the host rather than on the way in.  A
# frame written to a packet socket always enters the host's stack -- that is
# what leaving the namespace means -- so a counter placed at ingress reads 1
# whether or not the host goes on to drop the packet, and would fail a correct
# fix.  The guarantee is that the packet does not reach the network, and the
# last hook before the wire is where that becomes observable.
#
# What is under test is the guarantee, not the mechanism: under a default-block
# policy with nothing allowed, a workload must not be able to put a packet on
# the wire.  Policy is enforced by netfilter hooks on the IP path, and a
# workload holding CAP_NET_RAW can open AF_PACKET and hand the kernel a
# finished Ethernet frame, which reaches the device without the IP path being
# consulted.  Whether that is closed by removing the capability, by filtering
# below IP, or by some third means is the implementation's business; this
# script asserts only that the packet does not arrive.
#
# The allow case runs first and is not decoration.  It sends the same three
# protocols to the same address through the ordinary IP stack, which the policy
# permits.  An instrument that cannot see a packet it should see cannot be
# trusted when it reports zero, and a deny-only assertion would pass on a host
# with no working network at all.
#
# Protocol is a separate axis from path.  An earlier version of this file
# compared ICMP through the stack against ARP through a packet socket and
# attributed the difference to the path, having varied both at once -- and ARP
# is not filtered by iptables at all, so its arm had nothing to evade.  All
# three protocols are sent by both paths here, and the deny case has been
# observed failing on all three.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

# exit 77 so run_lxc_all_tests.sh records SKIPPED rather than PASS.
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
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 \
    || skip "no C compiler; the probe cannot be built."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

DENY_CONFIG="$REPO_DIR/tests/configs/lxc_network_raw_egress_filtered.json"
ALLOW_CONFIG="$REPO_DIR/tests/configs/lxc_network_raw_egress_allow.json"
PROBE_SOURCE="$REPO_DIR/tests/helpers/raw_egress_probe.c"

# An RFC 5737 documentation range, and a different one from the peer the
# enforcement test builds, so neither suite captures the other's traffic.
# Nothing answers here, which is deliberate: the assertion is about departure,
# not about a reply.
DEST="203.0.113.9"

# The container reaches the wire through this directory, bind-mounted read-only
# at the same path inside.  It is fixed rather than a mktemp because the
# fixtures name it.
PROBE_DIR="/opt/mxc-raw-probe"
PROBE_DIR_CREATED=""
PROBE="$PROBE_DIR/raw_egress_probe"

BRIDGE="lxcbr0"
ip link show "$BRIDGE" >/dev/null 2>&1 \
    || skip "$BRIDGE is absent; the container has no known gateway to address."
BRIDGE_MAC="$(cat "/sys/class/net/$BRIDGE/address" 2>/dev/null || true)"
[ -n "$BRIDGE_MAC" ] || skip "could not read the $BRIDGE hardware address."

# Drift guards.  Every one of these is a value the script and a fixture must
# agree on, and a silent disagreement would leave the run probing an address
# nobody filters, or sending to a MAC the bridge drops, and reporting a pass.
grep -Fq "$DEST" "$DENY_CONFIG" \
    || fail "fixture ${DENY_CONFIG##*/} no longer targets $DEST; script and fixture drifted."
grep -Fq "$DEST" "$ALLOW_CONFIG" \
    || fail "fixture ${ALLOW_CONFIG##*/} no longer targets $DEST; script and fixture drifted."
grep -Fq "$PROBE_DIR" "$DENY_CONFIG" \
    || fail "fixture ${DENY_CONFIG##*/} no longer mounts $PROBE_DIR; the probe would not exist in the container."
grep -Fq "$BRIDGE_MAC" "$DENY_CONFIG" \
    || fail "fixture ${DENY_CONFIG##*/} addresses a MAC that is not $BRIDGE's ($BRIDGE_MAC); the frame would be sent to nobody."
# The fixture must permit an address, and must not permit the one the probe
# writes to.  A policy allowing nothing is given no network interface at all,
# which would leave the probe with nothing to write to and prove nothing about
# the chain.
grep -Eq '"allowedHosts": \[[^]]+\]' "$DENY_CONFIG" \
    || fail "fixture ${DENY_CONFIG##*/} allows nothing; the container would be given no interface and the raw path would never be exercised."
if grep -Eq "\"allowedHosts\": \[[^]]*$DEST" "$DENY_CONFIG"; then
    fail "fixture ${DENY_CONFIG##*/} allows $DEST, the address the probe writes to; there would be nothing for the chain to drop."
fi

# shellcheck source=lib/chain_name.sh
. "$SCRIPT_DIR/lib/chain_name.sh"

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

PROTOCOLS="icmp tcp udp"

# Both the delete and the count below match on this tag rather than on the
# rule specification alone.  A host can already carry a rule with the same
# destination, protocol, and target, put there by an operator or another test;
# matching the specification would delete that rule and read its packet count
# as this run's traffic.  The tag is fixed rather than per-process because the
# pre-run cleanup below has to recognize what an aborted earlier run left.
COUNTER_TAG="mxc-raw-egress-counter"

remove_counters() {
    local protocol
    for protocol in $PROTOCOLS; do
        while iptables -t mangle -D POSTROUTING -d "$DEST"/32 -p "$protocol" \
            -m comment --comment "$COUNTER_TAG" -j ACCEPT 2>/dev/null; do :; done
    done
}

cleanup() {
    remove_counters
    # The path is fixed because the fixtures name it, which means it may
    # already hold something an operator put there.  Delete it only when this
    # run is the one that made it.
    if [ -n "$PROBE_DIR_CREATED" ]; then
        rm -rf "$PROBE_DIR"
    fi
}
trap cleanup EXIT

# Clear whatever an aborted earlier run left behind before installing fresh
# rules, so a stale counter cannot be read as this run's traffic.
remove_counters

# Plain mkdir, not mkdir -p: failing on an existing path is what keeps the
# cleanup from deleting a directory this run did not create.
mkdir "$PROBE_DIR" \
    || fail "$PROBE_DIR already exists or could not be created.  This test deletes that path on exit, so it refuses to run when the path is not its own."
PROBE_DIR_CREATED=yes
COMPILER="$(command -v cc || command -v gcc)"
"$COMPILER" -static -O2 -o "$PROBE" "$PROBE_SOURCE" 2>&1 \
    || skip "the probe did not build; static linking may be unavailable here."
[ -x "$PROBE" ] || fail "the probe built but is not executable at $PROBE."

# ACCEPT in the mangle table leaves the packet's fate unchanged and only ends
# that table's traversal.  It is here to keep the counter's column layout
# stable.  POSTROUTING is the last hook a forwarded packet crosses before the
# device, so a count here means the packet went out.
for protocol in $PROTOCOLS; do
    iptables -t mangle -A POSTROUTING -d "$DEST"/32 -p "$protocol" \
        -m comment --comment "$COUNTER_TAG" -j ACCEPT \
        || fail "could not install the $protocol counter on the host; the comment match may be unavailable here."
done

protocol_number() {
    case "$1" in
        icmp) echo 1 ;;
        tcp)  echo 6 ;;
        udp)  echo 17 ;;
        *)    echo "" ;;
    esac
}

# The protocol column carries a name under iptables-legacy and a number under
# the nft backend.  Accepting only one spelling makes the count read as absent
# on the other, which is indistinguishable from a rule that was never
# installed.
counter_for() {
    local name="$1" number
    number="$(protocol_number "$name")"
    iptables -t mangle -L POSTROUTING -v -n -x 2>/dev/null \
        | awk -v n="$name" -v num="$number" -v d="$DEST" -v tag="$COUNTER_TAG" \
            '$3 == "ACCEPT" && ($4 == n || $4 == num) && $9 == d && index($0, tag) { print $1; exit }'
}

# A missing counter and a counter reading zero are the same number to a naive
# read, and only one of them means the policy held.
#
# The result comes back in a global rather than on stdout because fail() called
# inside a command substitution exits only the subshell, and its message would
# be captured as the count instead of reaching the reader.
COUNT=""
read_counter() {
    local protocol="$1"
    COUNT="$(counter_for "$protocol")"
    if [ -z "$COUNT" ]; then
        fail "the $protocol counter is not installed on the host; nothing was measured."
    fi
}

echo "Running LXC raw egress test..."

echo "--- allow case: the IP path, to a destination the policy permits ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
iptables -t mangle -Z POSTROUTING >/dev/null
ALLOW_OUTPUT=$("$LXC_EXEC" --debug "$ALLOW_CONFIG" 2>&1 || true)
echo "$ALLOW_OUTPUT"

if ! echo "$ALLOW_OUTPUT" | grep -Fq "MXC_STACK_ARMS_RAN"; then
    fail "the allow case produced no verdict at all; the container command did not run."
fi

for protocol in $PROTOCOLS; do
    read_counter "$protocol"
    echo "    allow / $protocol left the host: $COUNT"
    if [ "$COUNT" -eq 0 ]; then
        fail "an explicitly allowed $protocol packet never left the host. Either the policy is over-blocking or the counter is not in the path, and the deny case below would prove nothing."
    fi
done

assert_no_new_mxc_chains iptables "$MXC_CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$MXC_CHAINS_BEFORE_V6"

echo "--- filtered case: a packet socket writing to an address the chain drops ---"
MXC_CHAINS_BEFORE_V4="$(mxc_chains iptables)"
MXC_CHAINS_BEFORE_V6="$(mxc_chains ip6tables)"
iptables -t mangle -Z POSTROUTING >/dev/null
DENY_OUTPUT=$("$LXC_EXEC" --debug "$DENY_CONFIG" 2>&1 || true)
echo "$DENY_OUTPUT"

# The policy permits one address and drops the rest, so the container is given
# a real interface and a real chain.  Three outcomes are legitimate: the socket
# may have been refused, the send may have been refused, or a finished frame
# may have been handed to the kernel.  Only the last can put a packet on the
# wire, and the counters below settle it.  Being given no interface is no
# longer one of them -- under this policy it would mean the container never got
# the network the chain was supposed to filter.
if echo "$DENY_OUTPUT" | grep -Fq "no interface eth0"; then
    fail "the container was given no interface under a policy that permits an address. The chain under test was never exercised."
elif echo "$DENY_OUTPUT" | grep -Fq "PROBE_SETUP_FAILED"; then
    fail "the probe could not configure itself inside the container. No frame was ever built."
elif ! echo "$DENY_OUTPUT" | grep -Eq "MXC_RAW_SENT|MXC_RAW_SOCKET_REFUSED|MXC_RAW_SEND_REFUSED"; then
    fail "the filtered case produced no verdict at all; the probe did not run inside the container."
fi

LEAKED=""
for protocol in $PROTOCOLS; do
    read_counter "$protocol"
    echo "    deny / $protocol left the host: $COUNT"
    if [ "$COUNT" -ne 0 ]; then
        LEAKED="$LEAKED $protocol"
    fi
done

assert_no_new_mxc_chains iptables "$MXC_CHAINS_BEFORE_V4"
assert_no_new_mxc_chains ip6tables "$MXC_CHAINS_BEFORE_V6"

if [ -z "$LEAKED" ]; then
    fail "no packet written to a raw packet socket left the host. This test records a known gap: CAP_NET_RAW lets a workload transmit below the egress chain. If that no longer happens, the gap has closed and this test should be rewritten as an enforcement test rather than left asserting the old behavior."
fi

echo "PASS: allowed traffic left the host on all three protocols."
echo "      Under a filtering policy, packets written to a raw packet socket"
echo "      reached a dropped address on:$LEAKED"
echo "      This is the known CAP_NET_RAW bypass, recorded here on purpose."
echo "      Egress chain enforcement covers the kernel path only; closing the"
echo "      raw path needs a syscall filter, tracked separately."
echo "LXC raw egress test complete."
