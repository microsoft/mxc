#!/bin/bash
# Bubblewrap ruleless-deny network isolation test.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
if [ -n "${LXC_EXEC:-}" ]; then
    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: LXC_EXEC is set to '$LXC_EXEC', which does not exist."
        exit 1
    fi
else
    LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
    if [ ! -f "$LXC_EXEC" ]; then
        LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
    fi
    if [ ! -f "$LXC_EXEC" ]; then
        echo "Error: lxc-exec not found. Run build.sh first."
        exit 1
    fi
fi
for tool in ip python3 timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "FAIL: $tool is required to establish the reachable host endpoint."
        exit 1
    fi
done

HOST_NETNS="$(readlink /proc/self/ns/net)"
if ! HOST_IP="$(ip -4 -o addr show scope global |
    awk '{split($4, address, "/"); print address[1]; exit}')"; then
    echo "FAIL: could not enumerate host IPv4 addresses for the reachable control."
    exit 1
fi
if [ -z "$HOST_IP" ]; then
    echo "FAIL: no host IPv4 address is available for the reachable control."
    exit 1
fi

WORK_DIR="$(mktemp -d)"
LISTENER_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Bind only the selected host interface, not every interface. The host probes
# the same numeric endpoint the sandbox will try, with no DNS, TLS, or wget.
python3 - "$HOST_IP" "$WORK_DIR/ready.port" >"$WORK_DIR/listener.log" 2>&1 <<'PY' &
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind((sys.argv[1], 0))
    listener.listen()
    with open(sys.argv[2], "w", encoding="ascii") as ready:
        ready.write(str(listener.getsockname()[1]))
    while True:
        connection, _ = listener.accept()
        connection.close()
PY
LISTENER_PID=$!
for _ in $(seq 1 100); do
    [ -s "$WORK_DIR/ready.port" ] && break
    if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
        cat "$WORK_DIR/listener.log"
        echo "FAIL: the host listener exited before publishing its port."
        exit 1
    fi
    sleep 0.1
done
TARGET_PORT="$(cat "$WORK_DIR/ready.port" 2>/dev/null || true)"
if ! [[ "$TARGET_PORT" =~ ^[0-9]+$ ]]; then
    cat "$WORK_DIR/listener.log"
    echo "FAIL: the host listener did not publish a port."
    exit 1
fi

assert_host_reachable() {
    if ! kill -0 "$LISTENER_PID" 2>/dev/null ||
        ! timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$HOST_IP" "$TARGET_PORT" >/dev/null 2>&1; then
        cat "$WORK_DIR/listener.log"
        echo "FAIL: $HOST_IP:$TARGET_PORT is not reachable from the host; a sandbox refusal proves nothing."
        exit 1
    fi
}

assert_host_reachable
sed -e "s/{{TARGET_IP}}/$HOST_IP/g" -e "s/{{TARGET_PORT}}/$TARGET_PORT/g" \
    "$REPO_DIR/tests/configs/bubblewrap_network_block.json" >"$WORK_DIR/network_block.json"

echo "Running Bubblewrap network block test..."
if ! OUTPUT=$("$LXC_EXEC" --experimental \
    "$WORK_DIR/network_block.json" 2>&1); then
    echo "$OUTPUT"
    echo "FAIL: network block sandbox did not complete its probe."
    exit 1
fi
assert_host_reachable
SANDBOX_NETNS="$(sed -n 's/^SANDBOX_NETNS=//p' <<<"$OUTPUT" | tail -n 1)"
if [ -z "$SANDBOX_NETNS" ] || [ "$SANDBOX_NETNS" = "$HOST_NETNS" ] ||
    ! grep -Fxq "NETWORK_BLOCKED_OK" <<<"$OUTPUT"; then
    echo "$OUTPUT"
    echo "FAIL: the live host endpoint was not blocked by an isolated sandbox."
    exit 1
fi
echo "PASS: isolated sandbox blocks a host endpoint reachable from the host."
echo "Bubblewrap network block test complete."
