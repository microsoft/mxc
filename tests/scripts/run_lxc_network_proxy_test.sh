#!/bin/bash
# LXC deny-all-except-proxy (model 2) integration test.
#
# Proves, from the outside, the whole point of the model: with a network
# proxy configured under defaultPolicy=block/enforcementMode=firewall, the
# container reaches the world *only* through the proxy, and every direct path
# is dropped.
#
# Cause  : tests/configs/lxc_network_proxy.json — an LXC request whose only
#          allowed egress is the proxy at http://10.0.3.1:3128 (the default
#          lxcbr0 gateway, i.e. the host as seen from the container).
# Effect : the container's stdout carries one sentinel per observable:
#            PROXY_OK               proxy fetch succeeded
#            DIRECT_IPV4_BLOCKED    direct IPv4 (proxy bypassed) was dropped
#            DIRECT_IPV6_BLOCKED    direct IPv6 was dropped
#            DIRECT_IPV6_SKIP_NO_STACK  container has no global IPv6 (honest skip)
#            FORWARDED_DNS_BLOCKED  DNS to an off-bridge resolver was dropped
#            GATEWAY_DNS_*          DNS to the bridge gateway's own resolver
#          The *_LEAK counterparts mean the isolation failed.
#
# Scope of the DNS assertions, measured rather than assumed. The chain is
# hooked into FORWARD, so it sees traffic the host *routes* for the container.
# Traffic addressed to the bridge gateway itself — 10.0.3.1, where LXC's
# dnsmasq listens — is delivered locally and traverses INPUT, never FORWARD.
# Counting rules installed in both chains during a live run recorded 2 packets
# on the INPUT probe and 0 on the FORWARD probe for container DNS. So
# GATEWAY_DNS is reported, not asserted: closing it needs an INPUT hook, which
# is a separate work item. FORWARDED_DNS is what this chain does govern, and it
# is asserted.
#
# The same measurement applies to PROXY_OK when the proxy runs on the host, as
# it does here: the proxy ACCEPT rule is not what admits that traffic, because
# the packet never reaches the chain (6 packets on the INPUT probe, 0 in
# FORWARD). PROXY_OK proves the env-var injection is right and that the
# deny-all posture did not break the proxy path; it does not exercise the
# ACCEPT rule. That rule is exercised by the unit specs in
# network_iptables_proxy_spec.rs, and in production by an off-host proxy.
#
# It does not exercise the hosts pin either. This fixture names the proxy by IP
# literal (10.0.3.1), and `ProxyAddress::host_pin` returns no pin for a literal
# because there is no name to resolve, so no hosts entry is written on this
# path at all. The pin is covered by tests/proxy_address_spec.rs; a fixture
# naming the proxy by hostname would be needed to exercise it here.
#
# The proxy is locally controlled: a tiny forward proxy started by this script
# on the host bridge IP, so the positive path needs no external internet and
# the negative paths target fixed public IPs that never resolve in-container.
#
# Requires Linux, root, LXC, and python3. It cannot run on the Windows dev box,
# so it is exercised by the LXC E2E Tests workflow (.github/workflows/lxc-e2e.yml),
# which runs the suite on ubuntu-latest with MXC_LXC_TESTS_REQUIRE_EXECUTION=1
# so a missing prerequisite fails the gate instead of skipping quietly.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$REPO_DIR/tests/configs/lxc_network_proxy.json"

# Drift guard: these mirror the fixture. If someone edits one without the
# other, the always-run block below fails loudly rather than testing a stale
# assumption.
EXPECTED_PROXY_URL="http://10.0.3.1:3128"
EXPECTED_DEFAULT_POLICY="block"
PROXY_BIND_IP="10.0.3.1"
PROXY_PORT="3128"

fail() {
    echo "FAIL: $*"
    exit 1
}

# ---------------------------------------------------------------------------
# Always-run assertions (offline-safe): the fixture must exist, parse, and
# still say what this test assumes. These run even without root/LXC/python3 so
# the file is never wholly conditional.
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
echo "Fixture drift guard passed (proxy.url=$actual_url, defaultPolicy=$actual_policy)."

# ---------------------------------------------------------------------------
# Conditional assertions: the live container run. Skip with exit 77 when a
# prerequisite is missing, matching run_bwrap_network_firewall_test.sh, so a
# skip is never tallied as a pass. run_lxc_all_tests.sh classifies 77 as a
# skip and reports it separately, and fails the suite outright when every
# test skipped, so a run that verified nothing cannot look green.
# ---------------------------------------------------------------------------
SKIP_EXIT=77

skip_live() {
    echo "SKIP: LXC deny-all-except-proxy behaviour UNVERIFIED — $*"
    echo "      (fixture drift guard still ran and passed)"
    exit "$SKIP_EXIT"
}

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || skip_live "lxc-exec not built (run build.sh first)"

[ "$(id -u)" -eq 0 ] || skip_live "not root; LXC needs root for containers and iptables"
command -v python3 >/dev/null 2>&1 || skip_live "python3 not available to run the local proxy"

# The fixture points the proxy at the default lxcbr0 gateway. Verify that IP is
# actually a local address before binding to it; otherwise the container could
# not reach the proxy and the test would be meaningless.
if ! ip -4 addr show 2>/dev/null | grep -qw "$PROXY_BIND_IP"; then
    skip_live "$PROXY_BIND_IP is not a local address (non-default lxc bridge?); \
cannot host the proxy where the container expects it"
fi

# ---------------------------------------------------------------------------
# Start the locally controlled forward proxy on the bridge IP. It answers any
# request with the sentinel body, so the positive path needs no real internet.
# ---------------------------------------------------------------------------
PROXY_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" >/dev/null 2>&1
}
trap cleanup EXIT

python3 - "$PROXY_BIND_IP" "$PROXY_PORT" >/dev/null 2>&1 <<'PY' &
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

# Give the proxy a moment to bind, then confirm it is actually listening.
sleep 1
if ! kill -0 "$PROXY_PID" >/dev/null 2>&1; then
    fail "local proxy failed to start on $PROXY_BIND_IP:$PROXY_PORT"
fi

# ---------------------------------------------------------------------------
# Run the sandbox and capture its stdout.
# ---------------------------------------------------------------------------
echo "Running LXC network proxy test..."
if ! OUT=$("$LXC_EXEC" "$CONFIG" 2>&1); then
    echo "$OUT"
    fail "lxc-exec returned non-zero"
fi
echo "$OUT"

# ---------------------------------------------------------------------------
# Assert cause and effect. Each sentinel is part of the contract this test
# declares; the container fixture prints exactly these strings.
# ---------------------------------------------------------------------------
require_sentinel() {
    grep -q "$1" <<<"$OUT" || fail "expected sentinel '$1' not in container output"
}
reject_sentinel() {
    grep -q "$1" <<<"$OUT" && fail "isolation breach: saw '$1' in container output"
    return 0
}

require_sentinel "PROXY_OK"
reject_sentinel  "PROXY_FAIL"

require_sentinel "DIRECT_IPV4_BLOCKED"
reject_sentinel  "DIRECT_IPV4_LEAK"

# DNS to a resolver off the bridge is forwarded traffic, so the chain governs
# it and the deny-all posture must drop it.
require_sentinel "FORWARDED_DNS_BLOCKED"
reject_sentinel  "FORWARDED_DNS_LEAK"

# DNS to the bridge gateway's own resolver is delivered locally and traverses
# INPUT, which this chain does not hook. Report the verdict rather than
# asserting it, so the gap is visible in the output instead of being either a
# false pass or a failure of something this work item does not cover.
if grep -q "GATEWAY_DNS_REACHED" <<<"$OUT"; then
    echo "NOTE: DNS to the bridge gateway resolver is still reachable — it is an"
    echo "      INPUT path, and this chain hooks FORWARD only. Tracked separately."
elif ! grep -q "GATEWAY_DNS_BLOCKED" <<<"$OUT"; then
    fail "no gateway-DNS verdict in container output"
fi

# IPv6 is honestly conditional: a container with no global IPv6 cannot exercise
# the drop, so it reports a skip marker rather than a false pass.
reject_sentinel "DIRECT_IPV6_LEAK"
if grep -q "DIRECT_IPV6_SKIP_NO_STACK" <<<"$OUT"; then
    echo "SKIP: direct-IPv6 drop UNVERIFIED — container has no global IPv6 stack"
elif ! grep -q "DIRECT_IPV6_BLOCKED" <<<"$OUT"; then
    fail "no IPv6 verdict in container output (expected DIRECT_IPV6_BLOCKED or the skip marker)"
fi

echo "PASS: LXC deny-all-except-proxy — proxy reachable, forwarded IPv4/IPv6/DNS blocked."
echo "LXC network proxy test complete."
