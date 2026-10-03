#!/bin/bash
# Seatbelt proxy support.
#
# The claim under test is narrow and easy to get backwards: egress confinement
# is kernel-enforced, but *using* the proxy is cooperative. So this suite
# asserts both halves separately -- that a cooperative client gets through, and
# that a client ignoring HTTP_PROXY and opening a raw socket gets nowhere.
#
# The supported runtime proxy is caller-managed. This suite starts a real
# loopback test proxy and checks both the proxy route and direct-egress denial.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

require_python3_probe
command -v curl >/dev/null 2>&1 || fail "curl is required by this suite"

PROXY_BIN="$(dirname "$MXC_EXEC_MAC")/unix-test-proxy"
[ -x "$PROXY_BIN" ] || fail "unix-test-proxy not found next to mxc-exec-mac (build with: cargo build --release -p unix_test_proxy)"

PROXY_PID=""
cleanup_proxy() {
    if [ -n "$PROXY_PID" ]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    exec 9>&- 2>/dev/null || true
    rm -rf "$SEATBELT_TMP"
}
trap cleanup_proxy EXIT

mkfifo "$SEATBELT_TMP/proxy.pipe"
"$PROXY_BIN" --ready-file "$SEATBELT_TMP/proxy.port" --bind-address 127.0.0.1 \
    --allow-host mxc-test.invalid \
    <"$SEATBELT_TMP/proxy.pipe" >"$SEATBELT_TMP/proxy.log" 2>&1 &
PROXY_PID=$!
exec 9>"$SEATBELT_TMP/proxy.pipe"
for _ in $(seq 1 100); do
    [ -s "$SEATBELT_TMP/proxy.port" ] && break
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        fail "test proxy exited before publishing its port" "$(cat "$SEATBELT_TMP/proxy.log")"
    fi
    sleep 0.1
done
PROXY_PORT="$(cat "$SEATBELT_TMP/proxy.port" 2>/dev/null || true)"
[ -n "$PROXY_PORT" ] || fail "test proxy did not publish its port" "$(cat "$SEATBELT_TMP/proxy.log")"

# The DIRECT_BLOCKED assertion below opens a raw socket to this anchor. On a
# host with no direct egress it would fail for a reason unrelated to the
# profile and report a green suite having proven nothing, so the reachability
# is a hard prerequisite rather than a skip.
ALLOW_ANCHOR="1.1.1.1"
if ! /usr/bin/python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(5)
sys.exit(0 if s.connect_ex(('$ALLOW_ANCHOR',443))==0 else 1)" 2>/dev/null; then
    fail "external anchor $ALLOW_ANCHOR:443 is unreachable from the host; the direct-egress assertion cannot be verified"
fi

run_config "$(render seatbelt_proxy_env_injected.json PROXY_PORT "$PROXY_PORT")" 9>&-
expect_ok "HTTP_PROXY is injected" "HTTP_PROXY=[http://127.0.0.1:"
for v in HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
    expect_marker "$v is injected" "$v=[http://127.0.0.1:"
done

run_config "$(render seatbelt_proxy_fetch.json PROXY_PORT "$PROXY_PORT")" 9>&-
expect_ok "a cooperative client reaches the external test proxy" "PROXY_FETCH_OK"

run_config "$(render seatbelt_proxy_host_denied.json PROXY_PORT "$PROXY_PORT")" 9>&-
expect_ok "the external test proxy is reachable before denying another host" "PROXY_FETCH_OK"
expect_marker "the external test proxy rejects an unknown host" "DENIED_HOST_BLOCKED"

# The kernel-enforced half. A raw socket bypassing HTTP_PROXY must fail: the
# profile's only outbound rule is the proxy port.
run_config "$(render seatbelt_proxy_direct_blocked.json PROXY_PORT "$PROXY_PORT")" 9>&-
expect_ok "a client ignoring the proxy cannot reach the internet directly" "DIRECT_BLOCKED"

# A caller-supplied proxy variable must be replaced, not merged, or traffic
# could be steered somewhere the policy never approved.
run_config "$(render seatbelt_proxy_env_stripped.json PROXY_PORT "$PROXY_PORT")" 9>&-
expect_absent "a caller-supplied proxy variable is stripped" "attacker.invalid"
expect_marker "the injected proxy replaces the caller's value" "HTTP_PROXY=[http://127.0.0.1:"

summary "Seatbelt proxy"
