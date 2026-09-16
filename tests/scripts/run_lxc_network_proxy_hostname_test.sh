#!/bin/bash
# LXC deny-all-except-proxy, off-host proxy named by hostname.
#
# The sibling test (run_lxc_network_proxy_test.sh) puts the proxy on the bridge
# gateway, and says in its own header that this leaves two things unproven.
# Traffic addressed to the gateway is delivered locally and traverses INPUT, so
# the chain never sees it and the proxy ACCEPT rule is not what admits it; and
# the fixture names the proxy by IP literal, so no hosts pin is ever written.
# This test exists to close both, which needs a proxy that is genuinely off-host
# and genuinely named.
#
# Cause  : tests/configs/lxc_network_proxy_hostname.json — allowed egress is the
#          proxy at http://proxy.mxc.test:3128, a *name*, resolved on the host
#          to an address that is not the host's own bridge.
# Effect : the container's stdout carries one sentinel per observable:
#            PROXY_OK           fetch through the named, off-host proxy worked
#            PIN_PRESENT        the container's /etc/hosts carries the pin marker
#            PIN_NAMES_PROXY    ...and the pinned line names the proxy hostname
#            DIRECT_IPV4_BLOCKED   direct egress is still dropped
#            FORWARDED_DNS_BLOCKED forwarded DNS is still dropped
#          The *_LEAK and PIN_ABSENT counterparts mean the isolation or the pin
#          failed.
#
# Why the proxy lives in a network namespace. The chain is hooked into the
# container's own OUTPUT chain, so a proxy bound anywhere — including on the
# host — traverses it. The namespace is what makes this proxy genuinely remote:
# the host must route to it, so the run covers the routed path end to end
# rather than a loopback delivery. 192.0.2.0/24 is TEST-NET-1 (RFC 5737) and is
# reserved for exactly this.
#
# What PROXY_OK proves here that it cannot prove in the sibling test:
#   1. The proxy ACCEPT rule admitted a packet that was actually routed off the
#      host, and the chain's default is DROP -- DIRECT_IPV4_BLOCKED in the same
#      run shows that default is live.
#   2. The hosts pin worked. A proxied chain opens no port 53, so the container
#      has no resolver at all; the only way "proxy.mxc.test" can become an
#      address inside the container is the pin this run wrote.
#
# Requires Linux, root, LXC, python3, and iproute2 with netns support. It runs
# under WSL on a developer box that has those, and is otherwise exercised by the
# LXC E2E Tests workflow (.github/workflows/lxc-e2e.yml) on ubuntu-latest with
# MXC_LXC_TESTS_REQUIRE_EXECUTION=1 so a missing prerequisite fails the gate
# instead of skipping quietly.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$REPO_DIR/tests/configs/lxc_network_proxy_hostname.json"

# Drift guard: these mirror the fixture. If someone edits one without the other,
# the always-run block below fails loudly rather than testing a stale assumption.
EXPECTED_PROXY_URL="http://proxy.mxc.test:3128"
EXPECTED_DEFAULT_POLICY="block"
PROXY_HOSTNAME="proxy.mxc.test"
PROXY_PORT="3128"

# The veth pair carrying the container's traffic to the proxy namespace. The
# host end is the next hop; the namespace end is where the proxy binds.
NETNS="mxcproxyns"
VETH_HOST="mxcprx-h"
VETH_NS="mxcprx-n"
HOST_SIDE_IP="192.0.2.1"
PROXY_IP="192.0.2.2"
PREFIX="30"

fail() {
    echo "FAIL: $*"
    exit 1
}

# ---------------------------------------------------------------------------
# Always-run assertions (offline-safe): the fixture must exist, parse, and still
# say what this test assumes. These run even without root/LXC/python3 so the
# file is never wholly conditional.
# ---------------------------------------------------------------------------
[ -f "$CONFIG" ] || fail "fixture not found: $CONFIG"

read_json_field() {
    # $1 = dotted path under the JSON root (python) ; prints the value.
    local path="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$CONFIG" "$path" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
cur = doc
for key in sys.argv[2].split("."):
    cur = cur[key]
print(cur)
PY
    else
        # Fallback for hosts without python3: grep the leaf key. Works because
        # the fixture keeps these on one line with simple string values.
        local leaf="${path##*.}"
        grep -o "\"$leaf\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$CONFIG" \
            | head -1 | sed 's/.*:[[:space:]]*"\([^"]*\)".*/\1/'
    fi
}

actual_url="$(read_json_field network.proxy.url)"
actual_policy="$(read_json_field network.defaultPolicy)"
[ "$actual_url" = "$EXPECTED_PROXY_URL" ] \
    || fail "fixture proxy.url is '$actual_url', test expects '$EXPECTED_PROXY_URL'"
[ "$actual_policy" = "$EXPECTED_DEFAULT_POLICY" ] \
    || fail "fixture defaultPolicy is '$actual_policy', test expects '$EXPECTED_DEFAULT_POLICY'"

# The whole point of this fixture is that the proxy is named rather than
# addressed. An IP literal produces no pin at all, so a well-meaning edit to an
# address would silently turn this back into the sibling test.
case "$actual_url" in
    *"$PROXY_HOSTNAME"*) ;;
    *) fail "fixture proxy.url must name the proxy by hostname, got '$actual_url'" ;;
esac
echo "Fixture drift guard passed (proxy.url=$actual_url, defaultPolicy=$actual_policy)."

# ---------------------------------------------------------------------------
# Conditional assertions: the live container run. Skip with exit 77 when a
# prerequisite is missing, so a skip is never tallied as a pass.
# ---------------------------------------------------------------------------
SKIP_EXIT=77

skip_live() {
    echo "SKIP: LXC off-host hostname proxy behaviour UNVERIFIED — $*"
    echo "      (fixture drift guard still ran and passed)"
    exit "$SKIP_EXIT"
}

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || skip_live "lxc-exec not built (run build.sh first)"

[ "$(id -u)" -eq 0 ] || skip_live "not root; LXC needs root for containers and iptables"
command -v python3 >/dev/null 2>&1 || skip_live "python3 not available to run the proxy"
command -v ip >/dev/null 2>&1 || skip_live "iproute2 not available to build the proxy namespace"
ip netns list >/dev/null 2>&1 || skip_live "network namespaces unavailable in this environment"

# ---------------------------------------------------------------------------
# Build the off-host proxy: a namespace on the far side of a veth pair, so the
# host must route to it and the container's packets traverse FORWARD.
# ---------------------------------------------------------------------------
PROXY_PID=""
HOSTS_BACKUP=""
NETNS_MADE=""
VETH_MADE=""
IP_FORWARD_WAS=""

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" >/dev/null 2>&1
    [ -n "$VETH_MADE" ] && ip link del "$VETH_HOST" >/dev/null 2>&1
    [ -n "$NETNS_MADE" ] && ip netns del "$NETNS" >/dev/null 2>&1
    # Restore /etc/hosts byte for byte rather than filtering it, so a failure
    # here cannot quietly drop an unrelated entry the box needs.
    if [ -n "$HOSTS_BACKUP" ] && [ -f "$HOSTS_BACKUP" ]; then
        cat "$HOSTS_BACKUP" > /etc/hosts
        rm -f "$HOSTS_BACKUP"
    fi
    if [ -n "$IP_FORWARD_WAS" ]; then
        sysctl -w net.ipv4.ip_forward="$IP_FORWARD_WAS" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Any leftovers from an interrupted earlier run would make the setup below fail
# for a reason that has nothing to do with the code under test.
ip link del "$VETH_HOST" >/dev/null 2>&1
ip netns del "$NETNS" >/dev/null 2>&1

ip netns add "$NETNS" || skip_live "could not create network namespace $NETNS"
NETNS_MADE=1
ip link add "$VETH_HOST" type veth peer name "$VETH_NS" \
    || skip_live "could not create the veth pair for the proxy namespace"
VETH_MADE=1

ip link set "$VETH_NS" netns "$NETNS" || fail "could not move $VETH_NS into $NETNS"
ip addr add "$HOST_SIDE_IP/$PREFIX" dev "$VETH_HOST" || fail "could not address $VETH_HOST"
ip link set "$VETH_HOST" up || fail "could not bring up $VETH_HOST"
ip -n "$NETNS" addr add "$PROXY_IP/$PREFIX" dev "$VETH_NS" || fail "could not address $VETH_NS"
ip -n "$NETNS" link set "$VETH_NS" up || fail "could not bring up $VETH_NS"
ip -n "$NETNS" link set lo up || fail "could not bring up loopback in $NETNS"
ip -n "$NETNS" route add default via "$HOST_SIDE_IP" \
    || fail "could not route the proxy namespace back to the host"

# Forwarding is what makes this test meaningful: without it the container's
# packets never reach the namespace and PROXY_OK could not distinguish an
# allowed path from a broken one.
IP_FORWARD_WAS="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
    || skip_live "could not enable IPv4 forwarding"

# The host resolves the proxy name when it builds the policy, and pins whatever
# it resolved into the container. Both halves read this entry.
HOSTS_BACKUP="$(mktemp)"
cat /etc/hosts > "$HOSTS_BACKUP"
printf '%s %s\n' "$PROXY_IP" "$PROXY_HOSTNAME" >> /etc/hosts

# ---------------------------------------------------------------------------
# Start the forward proxy inside the namespace. It answers any request with the
# sentinel body, so the positive path needs no real internet.
# ---------------------------------------------------------------------------
ip netns exec "$NETNS" python3 - "$PROXY_IP" "$PROXY_PORT" >/dev/null 2>&1 <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Proxy(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"MXC_PROXY_SENTINEL\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass

HTTPServer((sys.argv[1], int(sys.argv[2])), Proxy).serve_forever()
PY
PROXY_PID=$!

# Give the proxy a moment to bind, then confirm it is listening *and* reachable
# across the veth. A proxy that never came up would fail this test as though the
# firewall had blocked it, which would be a false accusation.
sleep 1
if ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
    fail "proxy process died before it could serve on $PROXY_IP:$PROXY_PORT"
fi
if ! python3 - "$PROXY_IP" "$PROXY_PORT" <<'PY'
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
then
    skip_live "the proxy namespace is not reachable from the host; \
the environment does not route to $PROXY_IP"
fi

# ---------------------------------------------------------------------------
# Run the sandbox and capture its stdout.
# ---------------------------------------------------------------------------
echo "Running LXC off-host hostname proxy test..."
if ! OUT=$("$LXC_EXEC" "$CONFIG" 2>&1); then
    echo "$OUT"
    fail "lxc-exec returned non-zero"
fi
echo "$OUT"

# ---------------------------------------------------------------------------
# Assert cause and effect.
# ---------------------------------------------------------------------------
require_sentinel() {
    grep -q "$1" <<<"$OUT" || fail "expected sentinel '$1' not in container output"
}
reject_sentinel() {
    grep -q "$1" <<<"$OUT" && fail "isolation breach: saw '$1' in container output"
    return 0
}

# The proxy is off-host and named, so this single sentinel carries both
# observables the sibling test cannot reach: the packet was routed and therefore
# entered the chain, and the name resolved with no resolver available.
require_sentinel "PROXY_OK"
reject_sentinel  "PROXY_FAIL"

# Asserted separately from PROXY_OK so a regression in the pin is reported as a
# pin failure rather than as an unexplained proxy failure.
require_sentinel "PIN_PRESENT"
reject_sentinel  "PIN_ABSENT"
require_sentinel "PIN_NAMES_PROXY"
reject_sentinel  "PIN_MISSING_PROXY"

# The pin must name the address the policy authorized. A pin naming anything
# else would send the container to a host the chain never opened, and the run
# would fail for a reason that looks like a firewall bug.
if ! grep -q "PINNED_LINE=.*$PROXY_IP" <<<"$OUT"; then
    fail "the pin does not name the authorized proxy address $PROXY_IP; output above"
fi

# Without these the run above would pass on a container that simply had open
# egress, which would make PROXY_OK meaningless.
require_sentinel "DIRECT_IPV4_BLOCKED"
reject_sentinel  "DIRECT_IPV4_LEAK"
require_sentinel "FORWARDED_DNS_BLOCKED"
reject_sentinel  "FORWARDED_DNS_LEAK"

echo "PASS: LXC off-host hostname proxy — the proxy ACCEPT rule admitted the proxy,"
echo "      the hosts pin resolved it, and direct egress stayed blocked."
echo "LXC off-host hostname proxy test complete."
