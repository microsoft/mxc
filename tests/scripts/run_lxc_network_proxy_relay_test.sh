#!/bin/bash
# A workload denied all egress still reaches a proxy on the host's loopback.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG="$REPO_DIR/tests/configs/lxc_network_proxy.json"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || { echo "SKIP: lxc-exec is not built."; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is not installed."; exit 77; }

python3 - "$CONFIG" <<'PY' || { echo "FAIL: proxy relay fixture drifted."; exit 1; }
import json, sys
data = json.load(open(sys.argv[1]))
assert data["containment"] == "lxc"
assert data["runtimeConfig"]["networkProxy"] == "http://127.0.0.1:3128"
assert data["network"]["egress"] == {"default": "deny"}
PY

READY="$(mktemp -u)"
# Stand-in proxy: answers every request with a token only it can produce.
python3 - "$READY" <<'PY' &
import socket, sys
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 3128))
server.listen()
open(sys.argv[1], "w").close()
while True:
    client, _ = server.accept()
    client.recv(65536)
    body = b"MXC_PROXY_REACHED"
    client.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    client.close()
PY
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null; rm -f "$READY"' EXIT

for _ in $(seq 50); do
    [ -e "$READY" ] && break
    kill -0 "$PROXY_PID" 2>/dev/null || { echo "FAIL: the stand-in proxy could not listen on 127.0.0.1:3128."; exit 1; }
    sleep 0.1
done
[ -e "$READY" ] || { echo "FAIL: the stand-in proxy did not start."; exit 1; }

set +e
output=$("$LXC_EXEC" "$CONFIG" 2>&1)
set -e

if ! grep -Fq MXC_PROXY_REACHED <<<"$output"; then
    echo "FAIL: the workload did not reach the host's loopback proxy: $output"
    exit 1
fi
echo "PASS: the workload reached the host's loopback proxy through the relay."
