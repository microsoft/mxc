#!/bin/bash
# LXC workload capability confinement test.
#
# A sandboxed workload must not be able to reconfigure the network stack it
# is confined by.  The firewall rules that carry the request's network policy
# live in the container's own network namespace, so a workload holding
# CAP_NET_ADMIN can delete them, and a workload holding CAP_NET_RAW can
# transmit below the IP layer where those rules never apply.  Either one ends
# the policy.
#
# The probe in the fixture reports its verdict as its exit status, and
# `lxc-exec` propagates the inner status.  The codes belong to this test:
#
#    0 = confined: the tamper was refused, CAP_NET_ADMIN is gone, and both
#        ordinary sockets and ICMP still work
#   10 = the workload created a network interface, so it holds CAP_NET_ADMIN
#   11 = the workload cannot open an ICMP socket, so a policy allowing
#        protocol "icmp" could never be exercised
#   12 = the workload reconfigured the network confining it
#   13 = ordinary loopback traffic broke, so the confinement is unusable
#   20 = the probe could not judge, because `ip` is missing or cannot even
#        list interfaces
#   21 = the probe could not check ICMP, because `ping` is missing
#   22 = the probe found no eth0, so it had no confining interface to attack
#
# Each denial has a control ahead of it, because a probe that cannot act and
# a workload that is forbidden to act look identical from outside.  Listing
# interfaces must work before a refused interface *creation* counts as a
# denial.  eth0 must exist before a refused shutdown of it counts as one.
#
# The ICMP check runs the opposite way round, and guards against overreach
# rather than under-reach.  The policy schema lets a request allow protocol
# "icmp", and this backend installs `-p icmp` rules for it, so what may reach
# the host is the firewall's decision to make.  Taking CAP_NET_RAW away would
# overrule that decision from underneath -- an explicitly allowed ICMP rule
# could never be exercised, because the socket would not open.  Every chain
# this backend builds accepts traffic leaving on `lo`, so a ping to 127.0.0.1
# is permitted by policy and can only fail if the capability went missing.
#
# The attack is run for real rather than inferred from the capability bits.
# Flushing the firewall needs an `iptables` the Alpine image does not ship, so
# the attempt that always runs takes the container's own interface down
# instead: an interface that is down carries no traffic to filter, which ends
# the policy as surely as deleting its rules.
#
# The sibling bubblewrap backend already asserts this, in
# tests/configs/bubblewrap_network_firewall_cidr.json, which requires
# CAP_NET_ADMIN_DROPPED_OK and TAMPER_REFUSED_OK.  LXC had no equivalent.
#
# The fixture reaches nothing off the host.  The runner's container DNS and
# outbound path are unreliable enough that one sibling test is quarantined
# over it, and a capability question does not need the internet to answer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG="$REPO_DIR/tests/configs/lxc_capability_confinement.json"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -x "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"

SKIP_EXIT=77

skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail() {
    echo "FAIL: $1"
    exit 1
}

[ "$(id -u)" -eq 0 ] || skip "must run as root."
command -v iptables >/dev/null 2>&1 || skip "iptables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "lxc-create is not installed."
[ -x "$LXC_EXEC" ] || skip "lxc-exec is not built."

[ -f "$CONFIG" ] || fail "fixture $CONFIG is missing."

# Drift guard: the exit codes above are the whole assertion, and they live in
# the fixture rather than here.  An edit to either file that leaves a code
# behind would otherwise turn this test into a check that the probe exits 0.
for code in 10 11 12 13 20 21 22; do
    if ! grep -Fq "exit $code" "$CONFIG"; then
        fail "fixture never exits $code, so this test cannot detect the case that code names."
    fi
done

for marker in MXC_LOOPBACK_OK MXC_TAMPER_REFUSED MXC_CAP_NET_ADMIN_REFUSED MXC_ICMP_OK MXC_CONFINED_OK; do
    if ! grep -Fq "$marker" "$CONFIG"; then
        fail "fixture never reports $marker, so this test cannot read its result."
    fi
done

# The rules a workload would tamper with exist only when the request carries a
# network policy.  A fixture that lost its network section would still exit 0
# while proving nothing about tampering.
grep -Fq '"network"' "$CONFIG" || fail "fixture carries no network section, so there are no firewall rules for the workload to tamper with."

CONTAINER_ID="$(sed -n 's/.*"containerId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -1)"
[ -n "$CONTAINER_ID" ] || fail "fixture declares no containerId."

cleanup() {
    lxc-destroy -n "$CONTAINER_ID" -f >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Running LXC capability confinement test..."

set +e
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1)
STATUS=$?
set -e

echo "$OUTPUT"
echo "probe exit status: $STATUS"

case "$STATUS" in
    0)
        ;;
    10)
        fail "the workload created a network interface; it holds CAP_NET_ADMIN and can delete the rules confining it."
        ;;
    11)
        fail "the workload cannot open an ICMP socket, so a policy allowing protocol \"icmp\" could never be exercised."
        ;;
    12)
        fail "the workload reconfigured the network confining it from inside the sandbox."
        ;;
    13)
        fail "the workload could not reach a listener on its own loopback; confinement cost it ordinary networking."
        ;;
    20)
        fail "the probe could not list interfaces, so its refusal to create one proves nothing."
        ;;
    21)
        fail "the probe has no ping, so it cannot check that ICMP still works."
        ;;
    22)
        fail "the container has no eth0, so the probe had no confining interface to attack."
        ;;
    *)
        fail "the run exited $STATUS before the probe reported a verdict."
        ;;
esac

# Exit 0 is the probe's verdict, and it is also what a container that never ran
# the probe would produce if the runner ever stopped propagating the status.
for marker in MXC_TAMPER_REFUSED MXC_CONFINED_OK; do
    if ! grep -qE "^${marker}[[:space:]]*$" <<<"$OUTPUT"; then
        fail "the run exited 0 without reporting $marker; its silence is not a pass."
    fi
done

# Flushing the firewall needs an iptables the image does not ship.  The
# interface-shutdown attempt above covers the same ground and always runs, so
# a missing binary is reported rather than treated as a prerequisite failure.
if grep -qE '^MXC_FLUSH_UNTESTED[[:space:]]*$' <<<"$OUTPUT"; then
    echo "SKIP: the image has no iptables, so the flush half of the tamper went unverified."
fi

echo "PASS: the workload could not reconfigure its own network, and keeps ordinary sockets and ICMP."
echo "LXC capability confinement test complete."
