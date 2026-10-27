#!/bin/bash
# A kept container stopped between runs still reaches the host's loopback proxy when a later run starts it again.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || { echo "SKIP: lxc-exec is not built."; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is not installed."; exit 77; }

CONTAINER="CLI-LXC-Network-Proxy-Reuse"
CONFIG="$(mktemp --suffix=.json)"
cat >"$CONFIG" <<JSON
{
  "version": "0.9.0-alpha",
  "containerId": "$CONTAINER",
  "containment": "lxc",
  "process": { "commandLine": "wget -qO- http://mxc.invalid/" },
  "lifecycle": { "destroyOnExit": false },
  "lxc": { "distribution": "alpine", "release": "3.23" },
  "network": { "egress": { "default": "deny" } },
  "runtimeConfig": { "networkProxy": "http://127.0.0.1:3128" }
}
JSON

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
trap 'kill "$PROXY_PID" 2>/dev/null; rm -f "$READY" "$CONFIG"; lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true' EXIT

for _ in $(seq 50); do
    [ -e "$READY" ] && break
    kill -0 "$PROXY_PID" 2>/dev/null || { echo "FAIL: the stand-in proxy could not listen on 127.0.0.1:3128."; exit 1; }
    sleep 0.1
done
[ -e "$READY" ] || { echo "FAIL: the stand-in proxy did not start."; exit 1; }

lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true

set +e
output=$("$LXC_EXEC" "$CONFIG" 2>&1)
set -e
if ! grep -Fq MXC_PROXY_REACHED <<<"$output"; then
    echo "FAIL: the first run did not reach the host's loopback proxy, so the reuse below proves nothing: $output"
    exit 1
fi

lxc-info -n "$CONTAINER" >/dev/null 2>&1 || { echo "FAIL: destroyOnExit was false, but the first run destroyed the container."; exit 1; }
lxc-stop -n "$CONTAINER" >/dev/null 2>&1 || { echo "FAIL: could not stop the kept container between runs."; exit 1; }

set +e
output=$("$LXC_EXEC" "$CONFIG" 2>&1)
set -e
if ! grep -Fq MXC_PROXY_REACHED <<<"$output"; then
    echo "FAIL: a reused container lost its path to the host's loopback proxy: $output"
    exit 1
fi
echo "PASS: a reused container reached the host's loopback proxy through the relay again."
