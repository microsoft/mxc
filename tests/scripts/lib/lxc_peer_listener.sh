#!/bin/bash
# Peer-listener readiness helpers shared by the LXC network scripts.
#
# A listener started in the background is not a listener that is accepting.
# Nothing about the PID can tell the two apart: a background child that already
# exited stays a zombie until the shell reaps it, so `kill -0` keeps succeeding
# on a peer that never bound. A fixed sleep is no better, because it turns the
# interpreter's start-up time on a loaded host into a test result: the probe
# that follows reads a closed port as "the veth is broken" and blames the
# harness for a race.
#
# Polling the socket answers the only question that matters, and keeping the
# listener's own output means a peer that truly failed can say why instead of
# leaving a bare ECONNREFUSED behind.
#
# The sourcing script must define `fail`.

# Poll a TCP peer until it accepts a connection.
#
# Prints the last connection error and returns non-zero if the deadline passes.
await_peer_tcp() {
    python3 - "$1" "$2" "${3:-20}" <<'PY'
import socket
import sys
import time

host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
start = time.monotonic()
last = "the peer was never probed"
while True:
    probe = socket.socket()
    probe.settimeout(5)
    try:
        probe.connect((host, port))
        waited = time.monotonic() - start
        if waited > 1:
            print(f"the peer accepted after {waited:.1f}s", file=sys.stderr)
        sys.exit(0)
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

# Poll a UDP echo peer until it returns the payload sent to it.
#
# UDP carries no handshake, so a returned payload is the only proof the peer is
# serving rather than the port merely being unfiltered.
await_peer_udp_echo() {
    python3 - "$1" "$2" "${3:-20}" <<'PY'
import socket
import sys
import time

host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
start = time.monotonic()
last = "the peer was never probed"
while True:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.settimeout(2)
    try:
        probe.sendto(b"probe", (host, port))
        if probe.recv(64) == b"probe":
            waited = time.monotonic() - start
            if waited > 1:
                print(f"the peer echoed after {waited:.1f}s", file=sys.stderr)
            sys.exit(0)
        last = "the peer answered with something other than the payload sent"
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

# Print whatever the listener wrote, which is otherwise lost.
peer_listener_output() {
    if [ -n "$1" ] && [ -s "$1" ]; then
        tr '\n' ' ' <"$1"
    else
        printf '(the listener wrote nothing)'
    fi
}

# Fail with the listener's own output, which is otherwise lost.
fail_unreachable_peer() {
    fail "$1 is unreachable at $2: $3; listener output: $(peer_listener_output "$4")"
}
