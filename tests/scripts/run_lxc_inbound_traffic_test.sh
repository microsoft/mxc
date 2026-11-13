#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

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

[ "$(id -u)" -eq 0 ] || skip "requires root for LXC and the probe interfaces."
command -v nsenter >/dev/null 2>&1 || skip "nsenter is not installed."
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC (lxc-create) is not installed."
command -v lxc-info >/dev/null 2>&1 || skip "LXC (lxc-info) is not installed."
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed."
[ -f "$LXC_EXEC" ] || skip "lxc-exec binary not built; run build.sh first."

CONFIG="$REPO_DIR/tests/configs/lxc_inbound_traffic_deny.json"
[ -f "$CONFIG" ] || skip "missing config $CONFIG."

CONTAINER="$(python3 - "$CONFIG" <<'PY'
import json
import sys

with open(sys.argv[1]) as fixture:
    config = json.load(fixture)
assert config["network"] == {
    "egress": {"default": "allow"},
    "ingress": {"default": "deny", "hostLoopback": "deny"},
}, "the inbound traffic fixture must allow egress and deny ingress"
print(config["containerId"])
PY
)"

VETH_HOST="mxcprobe0"
VETH_PEER="mxcprobe1"
PROBE_HOST_V4="10.77.78.1"
PROBE_NS_V4="10.77.78.2"
PROBE_HOST_V6="fd00:77:78::1"
PROBE_NS_V6="fd00:77:78::2"
PROBE_PORT=7777

RUN_LOG="$SCRIPT_DIR/.lxc-inbound-traffic-$$.log"
RUN_PID=""
LISTENER_PID=""
VETH_CREATED=0

cleanup()
{
    if [ -n "$LISTENER_PID" ]; then
        kill -TERM "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    if [ -n "$RUN_PID" ] && kill -0 "$RUN_PID" 2>/dev/null; then
        kill -TERM "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    if [ "$VETH_CREATED" = 1 ]; then
        ip link del "$VETH_HOST" >/dev/null 2>&1 || true
    fi
    "$LXC_EXEC" --delete --containername "$CONTAINER" >/dev/null 2>&1 || true
    rm -f "$RUN_LOG"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$LXC_EXEC" --delete --containername "$CONTAINER" >/dev/null 2>&1 || true

echo "Running LXC inbound traffic test..."

"$LXC_EXEC" "$CONFIG" >"$RUN_LOG" 2>&1 &
RUN_PID=$!

STARTED=$SECONDS
while true; do
    if ! kill -0 "$RUN_PID" 2>/dev/null; then
        echo "--- lxc-exec output ---"
        cat "$RUN_LOG"
        fail "lxc-exec exited before the HTTP probe became ready."
    fi
    NETNS_PID="$(lxc-info -n "$CONTAINER" -p -H 2>/dev/null || true)"
    if [[ "$NETNS_PID" =~ ^[1-9][0-9]*$ ]]; then
        if [ -z "$LISTENER_PID" ]; then
            nsenter -t "$NETNS_PID" -n python3 - "$PROBE_PORT" >>"$RUN_LOG" 2>&1 <<'PY' &
import http.server
import socket
import sys

class InboundResponseHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"inbound-listener"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class IPv6HTTPServer(http.server.HTTPServer):
    address_family = socket.AF_INET6

with IPv6HTTPServer(("::", int(sys.argv[1])), InboundResponseHandler, bind_and_activate=False) as server:

    # Accept IPv4-mapped connections on the IPv6 listener.
    server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.server_bind()
    server.server_activate()
    server.serve_forever()
PY
            LISTENER_PID=$!
        fi
        if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
            echo "--- probe output ---"
            cat "$RUN_LOG"
            fail "the Python HTTP listener exited before accepting requests."
        fi
        if nsenter -t "$NETNS_PID" -n python3 -c '
import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open("http://127.0.0.1:7777/", timeout=1) as response:
    assert response.read() == b"inbound-listener"
' >/dev/null 2>&1; then
            break
        fi
    fi
    if [ "$((SECONDS - STARTED))" -ge 300 ]; then
        echo "--- lxc-exec output ---"
        cat "$RUN_LOG"
        fail "the HTTP probe did not accept requests within 300s."
    fi
    sleep 0.5
done

in_container_net()
{
    nsenter -t "$NETNS_PID" -n "$@"
}

# Use a private link to avoid depending on the bridge's DHCP or forwarding.
ip link add "$VETH_HOST" type veth peer name "$VETH_PEER" \
    || fail "could not create the probe veth pair."
VETH_CREATED=1
ip link set "$VETH_PEER" netns "$NETNS_PID" \
    || fail "could not move the probe interface into the container namespace."

ip addr add "$PROBE_HOST_V4/24" dev "$VETH_HOST"
ip -6 addr add "$PROBE_HOST_V6/64" dev "$VETH_HOST" nodad
ip link set "$VETH_HOST" up

in_container_net ip addr add "$PROBE_NS_V4/24" dev "$VETH_PEER"
in_container_net ip -6 addr add "$PROBE_NS_V6/64" dev "$VETH_PEER" nodad
in_container_net ip link set "$VETH_PEER" up

python3 - "$NETNS_PID" "$PROBE_HOST_V4" "$PROBE_NS_V4" \
    "$PROBE_HOST_V6" "$PROBE_NS_V6" "$PROBE_PORT" <<'PY'
import socket
import subprocess
import sys

pid, host_v4, target_v4, host_v6, target_v6, port = sys.argv[1:]
fetch = [
    "nsenter", "-t", pid, "-n", "python3", "-c",
    "import sys, urllib.request; "
    "opener = urllib.request.build_opener(urllib.request.ProxyHandler({})); "
    "response = opener.open(sys.argv[1], timeout=10); "
    "sys.stdout.buffer.write(response.read())",
]

for family, host, target in (
    (socket.AF_INET, host_v4, target_v4),
    (socket.AF_INET6, host_v6, target_v6),
):
    label = "IPv4" if family == socket.AF_INET else "IPv6"
    listener_url = f"http://{target if family == socket.AF_INET else '[' + target + ']'}:{port}/"
    control = subprocess.check_output([*fetch, listener_url], timeout=15)
    if control != b"inbound-listener":
        raise SystemExit(f"{label}: the workload listener did not return its control response")

    with socket.socket(family) as server:
        server.settimeout(15)
        server.bind((host, 0))
        server.listen(1)
        host_url = host if family == socket.AF_INET else f"[{host}]"
        outbound = subprocess.Popen(
            [*fetch, f"http://{host_url}:{server.getsockname()[1]}/"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            connection, address = server.accept()
            with connection:
                connection.settimeout(15)
                if address[0] != target:
                    raise SystemExit(f"{label}: outbound control used {address[0]}, not {target}")
                with connection.makefile("rb") as request:
                    while request.readline() not in (b"\r\n", b""):
                        pass

                with socket.socket(family) as incoming:
                    incoming.settimeout(4)
                    try:
                        incoming.connect((target, int(port)))
                    except (TimeoutError, ConnectionRefusedError):
                        pass
                    except OSError as error:
                        raise SystemExit(f"{label}: inbound probe failed without proving denial: {error}")
                    else:
                        raise SystemExit(f"{label}: a new inbound connection reached the workload listener")

                body = b"outbound-response"
                connection.sendall(
                    b"HTTP/1.0 200 OK\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )
            output, _ = outbound.communicate(timeout=15)
            if outbound.returncode != 0 or output != body:
                raise SystemExit(f"{label}: the allowed outbound response did not return: {output!r}")
        finally:
            if outbound.poll() is None:
                outbound.kill()
            outbound.wait()

    if subprocess.check_output([*fetch, listener_url], timeout=15) != b"inbound-listener":
        raise SystemExit(f"{label}: the workload listener stopped serving during the inbound probe")
    print(f"PASS: {label} denies new inbound connections and returns allowed outbound responses")
PY

echo "PASS: LXC inbound traffic test."
