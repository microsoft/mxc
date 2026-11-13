#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

CONFIG="$REPO_DIR/tests/configs/lxc_network_preserve_policy.json"
CONTAINER="CLI-LXC-Net-Preserve"

SKIP_EXIT=77
skip()
{
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

fail()
{
    echo "FAIL: $1"
    exit 1
}

# shellcheck source=lib/lxc_peer_listener.sh
. "$SCRIPT_DIR/lib/lxc_peer_listener.sh"

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC and the probe interfaces."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
command -v lxc-info >/dev/null 2>&1 || skip "LXC (lxc-info) is not installed."
command -v nsenter >/dev/null 2>&1 || skip "nsenter is not installed."
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

VETH_HOST="mxcprehost"
VETH_PEER="mxcprens"
ALLOWED_IP="140.82.112.1"
DENIED_IP="192.0.2.1"
CONTAINER_IP="192.0.2.2"
PEER_PORT=7778
PEER_LOG="$SCRIPT_DIR/.lxc-preserve-peer-$$.log"
LISTENER_PIDS=()
VETH_CREATED=0

cleanup()
{
    local status=$? pid
    trap - EXIT
    for pid in "${LISTENER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [ "$VETH_CREATED" -eq 1 ]; then
        if ! ip link del "$VETH_HOST"; then
            echo "FAIL: could not remove the preserved-policy probe link." >&2
            status=1
        fi
    fi
    if lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
        if ! timeout --kill-after=10s 30 "$LXC_EXEC" --delete --containername "$CONTAINER"; then
            echo "FAIL: could not delete retained container $CONTAINER." >&2
            status=1
        fi
    fi
    rm -f "$PEER_LOG"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if lxc-info -n "$CONTAINER" >/dev/null 2>&1; then
    timeout --kill-after=10s 30 "$LXC_EXEC" --delete --containername "$CONTAINER" \
        || fail "could not delete the previous preserved-policy container."
fi

echo "Running LXC preserved-policy test..."

if ! OUTPUT="$(timeout --kill-after=10s 300 "$LXC_EXEC" "$CONFIG" 2>&1)"; then
    echo "$OUTPUT"
    fail "lxc-exec did not finish the preserved-policy workload successfully within 300s."
fi
echo "$OUTPUT"

if ! grep -Fq "MXC_PRESERVE_RAN" <<<"$OUTPUT"; then
    fail "the preserved-policy workload did not run."
fi

INIT_PID="$(lxc-info -n "$CONTAINER" -p -H 2>/dev/null || true)"
if ! [[ "$INIT_PID" =~ ^[1-9][0-9]*$ ]]; then
    fail "destroyOnExit was false, but no running retained container was found."
fi

# Both destinations use the same private link; neither request leaves the host.
ip link add "$VETH_HOST" type veth peer name "$VETH_PEER" \
    || fail "could not create the preserved-policy probe link."
VETH_CREATED=1
ip link set "$VETH_PEER" netns "$INIT_PID" \
    || fail "could not move the probe interface into the retained container."
ip addr add "$ALLOWED_IP/32" dev "$VETH_HOST" \
    || fail "could not address the allowed HTTP peer."
ip addr add "$DENIED_IP/30" dev "$VETH_HOST" \
    || fail "could not address the denied HTTP peer."
ip link set "$VETH_HOST" up \
    || fail "could not bring up the host probe interface."
nsenter -t "$INIT_PID" -n ip addr add "$CONTAINER_IP/30" dev "$VETH_PEER" \
    || fail "could not address the retained container's probe interface."
nsenter -t "$INIT_PID" -n ip link set "$VETH_PEER" up \
    || fail "could not bring up the retained container's probe interface."
nsenter -t "$INIT_PID" -n ip route add "$ALLOWED_IP/32" dev "$VETH_PEER" \
    || fail "could not route the retained container to the allowed HTTP peer."

for address in "$ALLOWED_IP" "$DENIED_IP"; do
    python3 -m http.server "$PEER_PORT" --bind "$address" --directory "$REPO_DIR/tests/configs" \
        >>"$PEER_LOG" 2>&1 &
    LISTENER_PIDS+=("$!")
    if ! PEER_PROBE_ERROR="$(await_peer_tcp "$address" "$PEER_PORT")"; then
        fail_unreachable_peer "the preserved-policy HTTP peer" "$address:$PEER_PORT" \
            "$PEER_PROBE_ERROR" "$PEER_LOG"
    fi
done

python3 - "$INIT_PID" "$ALLOWED_IP" "$DENIED_IP" "$PEER_PORT" <<'PY'
import subprocess
import sys
import urllib.request

pid, allowed, denied, port = sys.argv[1:]
allowed_url = f"http://{allowed}:{port}/lxc_network_preserve_policy.json"
denied_url = f"http://{denied}:{port}/lxc_network_preserve_policy.json"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(allowed_url, timeout=4) as response:
    expected = response.read()
with opener.open(denied_url, timeout=4) as response:
    if response.read() != expected:
        raise SystemExit("FAIL: the denied HTTP peer did not serve its control response")

fetch = [
    "nsenter", "-t", pid, "-n", "python3", "-c",
    "import sys, urllib.request; "
    "opener = urllib.request.build_opener(urllib.request.ProxyHandler({})); "
    "response = opener.open(sys.argv[1], timeout=4); "
    "sys.stdout.buffer.write(response.read())",
]
if subprocess.check_output([*fetch, allowed_url], timeout=10) != expected:
    raise SystemExit("FAIL: the retained container did not receive the allowed HTTP response")

blocked = subprocess.run([*fetch, denied_url], capture_output=True, timeout=10)
if blocked.returncode == 0:
    raise SystemExit("FAIL: the retained container reached the denied HTTP peer after lxc-exec exited")

with opener.open(denied_url, timeout=4) as response:
    if response.read() != expected:
        raise SystemExit("FAIL: the denied HTTP peer stopped serving during the denial probe")
if subprocess.check_output([*fetch, allowed_url], timeout=10) != expected:
    raise SystemExit("FAIL: the retained container lost allowed HTTP access during the denial probe")
PY

echo "PASS: allowed HTTP traffic succeeds and denied traffic fails after lxc-exec exits."
