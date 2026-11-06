#!/bin/bash
# Connections the host's proxy resets while the workload keeps them open do not use up the relay.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
[ -f "$LXC_EXEC" ] || LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
[ -f "$LXC_EXEC" ] || { echo "SKIP: lxc-exec is not built."; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is not installed."; exit 77; }
command -v nsenter >/dev/null 2>&1 || { echo "SKIP: nsenter is not installed."; exit 77; }

CONTAINER="CLI-LXC-Network-Proxy-Reset"
CONFIG="$(mktemp --suffix=.json)"
cat >"$CONFIG" <<JSON
{
  "version": "0.9.0-alpha",
  "containerId": "$CONTAINER",
  "containment": "lxc",
  "process": { "commandLine": "sleep 30" },
  "lxc": { "distribution": "alpine", "release": "3.23" },
  "network": { "egress": { "default": "deny" } },
  "runtimeConfig": { "networkProxy": "http://127.0.0.1:3128" }
}
JSON

READY="$(mktemp -u)"
# Stand-in proxy: resets any connection that does not open with an HTTP request, and answers the rest with a token.
python3 - "$READY" <<'PY' &
import socket, struct, sys
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 3128))
server.listen(256)
open(sys.argv[1], "w").close()
while True:
    client, _ = server.accept()
    request = client.recv(65536)
    if request.startswith(b"GET"):
        body = b"MXC_PROXY_REACHED"
        client.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    else:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    client.close()
PY
PROXY_PID=$!
LXC_PID=""
trap 'kill "$PROXY_PID" 2>/dev/null; [ -n "$LXC_PID" ] && kill "$LXC_PID" 2>/dev/null; rm -f "$READY" "$CONFIG"; lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true' EXIT

for _ in $(seq 50); do
    [ -e "$READY" ] && break
    kill -0 "$PROXY_PID" 2>/dev/null || { echo "FAIL: the stand-in proxy could not listen on 127.0.0.1:3128."; exit 1; }
    sleep 0.1
done
[ -e "$READY" ] || { echo "FAIL: the stand-in proxy did not start."; exit 1; }

lxc-destroy -n "$CONTAINER" -f >/dev/null 2>&1 || true
"$LXC_EXEC" "$CONFIG" >/dev/null 2>&1 &
LXC_PID=$!

INIT_PID=""
for _ in $(seq 120); do
    INIT_PID="$(lxc-info -n "$CONTAINER" -p -H 2>/dev/null || true)"
    [ -n "$INIT_PID" ] && break
    sleep 0.5
done
[ -n "$INIT_PID" ] || { echo "FAIL: the container never started."; exit 1; }

# Inside the container's network namespace, open and hold more connections
# than the relay will carry at once, each of which the proxy resets, then make
# one ordinary request through the relay.
set +e
output=$(nsenter -t "$INIT_PID" -n python3 - <<'PY' 2>&1
import socket, time

def connect():
    deadline = time.monotonic() + 10
    while True:
        try:
            return socket.create_connection(("127.0.0.1", 3128), timeout=5)
        except ConnectionRefusedError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)

held = []
for _ in range(100):
    s = connect()
    s.sendall(b"x")
    try:
        s.recv(1)
    except ConnectionResetError:
        pass
    held.append(s)

time.sleep(1)
s = connect()
s.sendall(b"GET http://mxc.invalid/ HTTP/1.0\r\n\r\n")
print(s.recv(65536).decode(errors="replace"))
PY
)
wait "$LXC_PID"
LXC_PID=""
set -e

if ! grep -Fq MXC_PROXY_REACHED <<<"$output"; then
    echo "FAIL: after the proxy reset connections the workload held open, the relay no longer carried a request: $output"
    exit 1
fi
echo "PASS: connections the proxy reset did not use up the relay."
