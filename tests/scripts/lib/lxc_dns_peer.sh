#!/bin/bash
# A CI-controlled DNS resolver for the LXC network scripts.
#
# The udp/53 cases assert what the chain does with a DNS query, not whether the
# host has working name resolution. Querying a public resolver conflates the
# two: on a network that blocks outbound 53 to anything but its own resolver,
# an allowed-resolver case fails and a denied-resolver case passes for the same
# reason, and the denied case then proves only that the container has no DNS at
# all.
#
# The resolver below answers every A query with one fixed record. That is
# enough for the property under test, because the firewall matches the address
# and port rather than the payload.
#
# The sourcing script must define `fail`.

# Emit the resolver program. Kept as a file rather than `python3 -c` so the
# backgrounded child owns a real script and its traceback keeps line numbers.
_lxc_dns_peer_program() {
    cat <<'PY'
import select
import socket
import struct
import sys

answer = socket.inet_aton(sys.argv[1])

# One socket per address rather than a single 0.0.0.0 bind. An unbound socket
# does not record which of the peer's addresses a query arrived on, so the
# kernel picks the reply's source by route lookup and answers from the
# interface's primary address. A resolver discards a reply from a server it
# never asked, which reads as the firewall having blocked the query.
socks = []
for address in sys.argv[2:]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, 53))
    socks.append(sock)

if not socks:
    # select() on empty lists blocks forever, which would surface as a readiness
    # timeout rather than as the caller having passed no address to serve.
    sys.exit("the resolver was given no address to serve")

while True:
    ready, _, _ = select.select(socks, [], [])
    for sock in ready:
        try:
            query, sender = sock.recvfrom(512)
        except OSError:
            continue
        if len(query) < 12:
            continue
        # Walk the QNAME's length-prefixed labels to find the end of the
        # question, then echo the question back verbatim: a reply whose question
        # does not match the query is discarded rather than read as an answer.
        cursor = 12
        while cursor < len(query) and query[cursor] != 0:
            cursor += 1 + query[cursor]
        cursor += 5
        question = query[12:cursor]
        qtype = question[-4:-2]
        # QR=1 RD=1 RA=1, NOERROR, one question.
        if qtype == b'\x00\x01':
            header = query[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
            # A pointer to the name at offset 12, type A, class IN, 60s TTL.
            record = (b'\xc0\x0c\x00\x01\x00\x01' + struct.pack('>I', 60)
                      + b'\x00\x04' + answer)
        else:
            # Anything else answers empty rather than with an A record in a slot
            # that did not ask for one, which a resolver would reject outright.
            header = query[:2] + b'\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00'
            record = b''
        try:
            sock.sendto(header + question + record, sender)
        except OSError:
            continue
PY
}

# Start the resolver inside a network namespace, serving each address given.
#
# Sets DNS_PEER_PID and DNS_PEER_PROGRAM for the caller to tear down.
start_dns_peer() {
    local netns="$1" log="$2" answer="$3"
    shift 3
    DNS_PEER_PROGRAM="$(mktemp)"
    _lxc_dns_peer_program >"$DNS_PEER_PROGRAM"
    ip netns exec "$netns" python3 "$DNS_PEER_PROGRAM" "$answer" "$@" >"$log" 2>&1 &
    DNS_PEER_PID=$!
}

stop_dns_peer() {
    if [ -n "${DNS_PEER_PID:-}" ]; then
        kill "$DNS_PEER_PID" >/dev/null 2>&1 || true
    fi
    if [ -n "${DNS_PEER_PROGRAM:-}" ]; then
        rm -f "$DNS_PEER_PROGRAM"
    fi
}

# Poll the resolver until it answers a query with a record.
#
# A bound socket is not a serving resolver, and a reply carrying no answer would
# make the allowed case read as a firewall block.
await_peer_dns() {
    python3 - "$1" "${2:-20}" <<'PY'
import socket
import sys
import time

host, timeout = sys.argv[1], float(sys.argv[2])
query = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
         b'\x07example\x03com\x00\x00\x01\x00\x01')
start = time.monotonic()
last = "the resolver was never probed"
while True:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.settimeout(2)
    try:
        probe.sendto(query, (host, 53))
        reply, sender = probe.recvfrom(512)
        if sender[0] != host:
            # A client discards a reply from a server it never asked, so a
            # resolver answering from another of its addresses is unusable even
            # though a probe reading any source would call it healthy.
            last = f"the reply came from {sender[0]} rather than {host}"
        elif len(reply) >= 12 and reply[:2] == query[:2] and reply[6:8] != b'\x00\x00':
            waited = time.monotonic() - start
            if waited > 1:
                print(f"the resolver answered after {waited:.1f}s", file=sys.stderr)
            sys.exit(0)
        else:
            last = "the resolver replied with no answer record"
    except OSError as exc:
        last = str(exc)
    finally:
        probe.close()
    if time.monotonic() - start >= timeout:
        break
    time.sleep(0.2)
print(last)
sys.exit(1)
PY
}
