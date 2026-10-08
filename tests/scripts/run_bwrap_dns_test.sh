#!/bin/bash
# Bubblewrap name-resolution test for a host that resolves through a loopback
# stub, which is the default on Ubuntu and Fedora.
#
# The bug this suite is designed to catch: the sandbox inherited the host's
# `/etc/resolv.conf` naming a loopback nameserver, which inside a private
# network namespace is the sandbox's own empty loopback, so every lookup
# failed while every numeric-address network test kept passing.
#
# The host running this does not have to resolve through a loopback stub --
# the test builds one. It re-executes itself in a private user, mount, and
# network namespace, serves DNS on 127.0.0.53 there, and points the resolver
# at it, so the condition is identical on a developer box and on CI.
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

CONFIG="$REPO_DIR/tests/configs/bubblewrap_network_dns_stub.json"
# A reserved TLD can never resolve through a real resolver, so an answer can
# only have come from the peer below. Keep these in step with the fixture.
PROBE_NAME="mxc-dns-probe.invalid"
PROBE_ANSWER="203.0.113.99"
STUB_ADDRESS="127.0.0.53"
SEARCH_DOMAIN="mxc-test.invalid"
SLIRP_FORWARDER="10.0.2.3"

if ! grep -Fq "$PROBE_NAME" "$CONFIG"; then
    echo "FAIL: ${CONFIG##*/} no longer probes $PROBE_NAME; script and fixture drifted."
    exit 1
fi

for tool in bwrap unshare python3 timeout ip getent; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "FAIL: $tool is required to serve and query the stub resolver."
        exit 1
    fi
done
if ! command -v slirp4netns >/dev/null 2>&1; then
    echo "SKIP: slirp4netns not installed; the resolver pin needs the private namespace."
    exit 77
fi

# Everything below has to run against a loopback resolver, which this builds
# rather than requires. The namespaces are unprivileged, so the sandbox still
# launches the way it does for a real caller.
if [ "${MXC_BWRAP_DNS_INNER:-0}" != "1" ]; then
    if ! unshare -Urmn true >/dev/null 2>&1; then
        echo "SKIP: unprivileged user, mount, and network namespaces are unavailable;"
        echo "      a loopback-resolver host cannot be simulated here."
        exit 77
    fi
    exec unshare -Urmn env MXC_BWRAP_DNS_INNER=1 LXC_EXEC="$LXC_EXEC" bash "$0" "$@"
fi

# The resolver file the sandbox will read is the one the symlink chain ends at,
# so that is the path the stub has to be published at.
RESOLVER_TARGET="$(readlink -f /etc/resolv.conf || true)"
if [ -z "$RESOLVER_TARGET" ] || [ ! -f "$RESOLVER_TARGET" ]; then
    echo "SKIP: /etc/resolv.conf does not resolve to a file to publish the stub at."
    exit 77
fi

WORK_DIR="$(mktemp -d)"
PEER_PID=""
cleanup() {
    if [ -n "$PEER_PID" ]; then
        kill "$PEER_PID" 2>/dev/null || true
        wait "$PEER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Without this the stub address is unreachable and the peer cannot be bound.
ip link set lo up

# Answers every A query with one fixed record, which is enough to tell a
# resolver that reached the peer from one that reached nothing. AAAA is
# answered empty so a dual-stack lookup falls back to the A record instead of
# waiting out its timeout.
python3 - "$STUB_ADDRESS" "$PROBE_ANSWER" "$WORK_DIR/peer.ready" \
    >"$WORK_DIR/peer.log" 2>&1 <<'PY' &
import socket
import struct
import sys

address, answer, ready_path = sys.argv[1], sys.argv[2], sys.argv[3]
record = socket.inet_aton(answer)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, 53))
    with open(ready_path, "w", encoding="ascii") as ready:
        ready.write("ready")
    while True:
        query, peer = server.recvfrom(4096)
        if len(query) < 12:
            continue
        cursor = 12
        while cursor < len(query) and query[cursor] != 0:
            cursor += 1 + query[cursor]
        end = cursor + 5
        question = query[12:end]
        qtype = struct.unpack("!H", query[end - 4:end - 2])[0]
        if qtype == 1:
            header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
            body = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + record
        else:
            header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0)
            body = b""
        server.sendto(header + question + body, peer)
PY
PEER_PID=$!
for _ in $(seq 1 100); do
    [ -s "$WORK_DIR/peer.ready" ] && break
    if ! kill -0 "$PEER_PID" 2>/dev/null; then
        cat "$WORK_DIR/peer.log"
        echo "FAIL: the stub resolver exited before it was listening."
        exit 1
    fi
    sleep 0.1
done
if [ ! -s "$WORK_DIR/peer.ready" ]; then
    cat "$WORK_DIR/peer.log"
    echo "FAIL: the stub resolver never signalled readiness."
    exit 1
fi

printf 'nameserver %s\nsearch %s\noptions edns0 trust-ad\n' \
    "$STUB_ADDRESS" "$SEARCH_DOMAIN" >"$WORK_DIR/resolv.conf"
if ! mount --bind "$WORK_DIR/resolv.conf" "$RESOLVER_TARGET"; then
    echo "FAIL: could not publish the stub resolver at $RESOLVER_TARGET."
    exit 1
fi

# The control. A sandbox that cannot resolve proves nothing unless the peer
# answers the same name from outside it.
if ! HOST_ANSWER="$(timeout 10 getent hosts "$PROBE_NAME" 2>/dev/null)" ||
    ! grep -Fq "$PROBE_ANSWER" <<<"$HOST_ANSWER"; then
    cat "$WORK_DIR/peer.log"
    echo "FAIL: $PROBE_NAME does not resolve outside the sandbox either;"
    echo "      the stub resolver is broken, so a sandbox failure would prove nothing."
    exit 1
fi

echo "Running Bubblewrap loopback-resolver DNS test..."
RC=0
OUTPUT="$("$LXC_EXEC" --experimental "$CONFIG" 2>&1)" || RC=$?
if [ "$RC" -ne 0 ]; then
    echo "$OUTPUT"
    echo "FAIL: the sandbox did not complete its lookup."
    exit 1
fi

SANDBOX_RESOLV="$(sed -n '/^SANDBOX_RESOLV_BEGIN$/,/^SANDBOX_RESOLV_END$/p' <<<"$OUTPUT")"
if grep -Fq "$STUB_ADDRESS" <<<"$SANDBOX_RESOLV"; then
    echo "$OUTPUT"
    echo "FAIL: the sandbox still names $STUB_ADDRESS, which is its own empty loopback."
    exit 1
fi
if ! grep -Fq "$SLIRP_FORWARDER" <<<"$SANDBOX_RESOLV"; then
    echo "$OUTPUT"
    echo "FAIL: the sandbox was not pointed at slirp's forwarder $SLIRP_FORWARDER."
    exit 1
fi
echo "PASS: the sandbox reads slirp's forwarder instead of the host's loopback stub."

# A resolver that lost the search list resolves a different set of names than
# the host does, which the address assertions above cannot see.
if ! grep -Fq "search $SEARCH_DOMAIN" <<<"$SANDBOX_RESOLV"; then
    echo "$OUTPUT"
    echo "FAIL: the pinned resolver dropped the host's search list."
    exit 1
fi
echo "PASS: the pinned resolver keeps the host's other directives."

# The assertion the issue is actually about: a name resolves.
if grep -Fq "MXC_DNS_LOOKUP_FAILED" <<<"$OUTPUT" ||
    ! grep -Fq "$PROBE_ANSWER" <<<"$OUTPUT"; then
    echo "$OUTPUT"
    cat "$WORK_DIR/peer.log"
    echo "FAIL: $PROBE_NAME did not resolve inside the sandbox, though it resolves outside it."
    exit 1
fi
echo "PASS: a hostname resolves inside the sandbox through slirp's forwarder."
echo "Bubblewrap loopback-resolver DNS test complete."
