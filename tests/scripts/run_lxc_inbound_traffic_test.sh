#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="${LXC_EXEC:-$REPO_DIR/src/target/release/lxc-exec}"
if [ "$LXC_EXEC" = "$REPO_DIR/src/target/release/lxc-exec" ] && [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

fail() {
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

CONTAINER="mxc-inbound-traffic-$$"
CONFIG="$REPO_DIR/tests/configs/.lxc-inbound-$$.json"
RUN_LOG="$REPO_DIR/tests/configs/.lxc-inbound-$$.log"
LISTENER_V4_LOG="$REPO_DIR/tests/configs/.lxc-inbound-v4-$$.log"
LISTENER_V6_LOG="$REPO_DIR/tests/configs/.lxc-inbound-v6-$$.log"
HOST_V6="fd00:77:78::1"
GUEST_V6="fd00:77:78::2"
PORT=$((30000 + $$ % 10000))
RUN_PID=""
LISTENER_V4_PID=""
LISTENER_V6_PID=""
HOST_V6_ADDED=false
cleanup() {
    local status=$?
    if [ -n "$RUN_PID" ]; then
        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    for pid in "$LISTENER_V4_PID" "$LISTENER_V6_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
        python3 - "$CONFIG" <<'PY'
import json, sys
path = sys.argv[1]
config = json.load(open(path))
config["process"]["commandLine"] = "true"
config["lifecycle"] = {"destroyOnExit": True, "preservePolicy": False}
with open(path, "w") as stream:
    json.dump(config, stream)
PY
        "$LXC_EXEC" "$CONFIG" >/dev/null 2>&1 || { echo "FAIL: MXC could not clean up the ingress fixture."; status=1; }
    fi
    if [ "$HOST_V6_ADDED" = true ]; then
        ip -6 address del "$HOST_V6/64" dev lxcbr0
    fi
    rm -f "$CONFIG" "$RUN_LOG" "$LISTENER_V4_LOG" "$LISTENER_V6_LOG"
    exit "$status"
}
trap cleanup EXIT

# Address the existing managed interface rather than add an unfiltered one.
read -r GUEST_V4 PREFIX < <(
    ip -j -4 address show dev lxcbr0 | python3 -c '
import ipaddress, json, sys
address = json.load(sys.stdin)[0]["addr_info"][0]
network = ipaddress.ip_network(f"{address['\''local'\'']}/{address['\''prefixlen'\'']}", strict=False)
print(network.broadcast_address - 2, network.prefixlen)
')
[ -n "$GUEST_V4" ] && [ -n "$PREFIX" ] || fail "could not address the test guest."
ip -6 address add "$HOST_V6/64" dev lxcbr0 nodad
HOST_V6_ADDED=true
python3 - "$CONTAINER" >"$CONFIG" <<'PY'
import json, sys
print(json.dumps({
    "version": "1.0.0",
    "containerId": sys.argv[1],
    "containment": "lxc",
    "process": {"commandLine": "sh -c 'echo MXC_INBOUND_READY; while [ ! -f /mxc-inbound-finish ]; do sleep 1; done'"},
    "lifecycle": {"destroyOnExit": False, "preservePolicy": False},
    "lxc": {"distribution": "alpine", "release": "3.23"},
    "network": {"egress": {"default": "allow"}, "ingress": {"default": "deny", "hostLoopback": "deny"}}
}))
PY
: >"$RUN_LOG"
"$LXC_EXEC" "$CONFIG" >"$RUN_LOG" 2>&1 &
RUN_PID=$!
for ((attempt = 0; attempt < 600; attempt++)); do
    grep -Fq MXC_INBOUND_READY "$RUN_LOG" && break
    kill -0 "$RUN_PID" 2>/dev/null || { cat "$RUN_LOG"; fail "the ingress workload exited before readiness."; }
    sleep 0.5
done
grep -Fq MXC_INBOUND_READY "$RUN_LOG" || fail "the ingress workload never became ready."
INIT_PID="$(lxc-info -n "$CONTAINER" -p -H)"
nsenter -t "$INIT_PID" -n ip address replace "$GUEST_V4/$PREFIX" dev eth0
nsenter -t "$INIT_PID" -n ip -6 address add "$GUEST_V6/64" dev eth0 nodad
nsenter -t "$INIT_PID" -n ip link set eth0 up
nsenter -t "$INIT_PID" -n iptables -F
nsenter -t "$INIT_PID" -n iptables -X
nsenter -t "$INIT_PID" -n iptables -P INPUT ACCEPT
nsenter -t "$INIT_PID" -n ip6tables -F
nsenter -t "$INIT_PID" -n ip6tables -X
nsenter -t "$INIT_PID" -n ip6tables -P INPUT ACCEPT

nsenter -t "$INIT_PID" -n python3 -m http.server "$PORT" --bind "$GUEST_V4" >"$LISTENER_V4_LOG" 2>&1 &
LISTENER_V4_PID=$!
nsenter -t "$INIT_PID" -n python3 -m http.server "$PORT" --bind "$GUEST_V6" >"$LISTENER_V6_LOG" 2>&1 &
LISTENER_V6_PID=$!
for target in "$GUEST_V4" "$GUEST_V6"; do
    nsenter -t "$INIT_PID" -n timeout 5 bash -c \
        "until (exec 3<>/dev/tcp/$target/$PORT) 2>/dev/null; do sleep 0.1; done" \
        || fail "the guest listener at $target:$PORT never became reachable locally."
    if timeout 3 bash -c "exec 3<>/dev/tcp/$target/$PORT"; then
        fail "unsolicited ingress to $target succeeded after the guest firewall was flushed."
    fi
done
peer_listener_running "$LISTENER_V4_PID" && peer_listener_running "$LISTENER_V6_PID" \
    || fail "a guest listener exited."

lxc-attach -n "$CONTAINER" -- touch /mxc-inbound-finish
if ! wait "$RUN_PID"; then
    cat "$RUN_LOG"
    fail "the ingress workload failed."
fi
RUN_PID=""
[ "$(lxc-info -n "$CONTAINER" -s -H)" = RUNNING ] || fail "the ingress test container did not survive."

# The same listeners must be reachable over the managed interface after teardown.
for target in "$GUEST_V4" "$GUEST_V6"; do
    timeout 5 bash -c "until (exec 3<>/dev/tcp/$target/$PORT) 2>/dev/null; do sleep 0.1; done" \
        || fail "ingress to $target did not recover when preservePolicy=false removed the policy."
done
echo "PASS: IPv4 and IPv6 ingress survived guest firewall flushing and ended with policy teardown."
