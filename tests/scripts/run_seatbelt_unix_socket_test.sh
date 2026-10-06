#!/bin/bash
# Seatbelt AF_UNIX sockets.
#
# Seatbelt governs UNIX domain sockets through the *filesystem* rules, not the
# network ones, so bind permission follows the grant on the socket's directory.
# A backend that mapped them onto network policy instead would leave them
# reachable under a deny-all network posture.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

require_python3_probe

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-sock.XXXXXX)"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

mkdir -p "$TESTDIR/ro" "$TESTDIR/rw" "$TESTDIR/rw/open" "$TESTDIR/rw/nested"
chmod -R a+rwX "$TESTDIR"

run_config "$(render seatbelt_unix_socket_readwrite.json TESTDIR "$TESTDIR")"
expect_ok "an AF_UNIX socket binds under a readwrite grant" "UNIX_BIND_OK"

run_config "$(render seatbelt_unix_socket_readonly.json TESTDIR "$TESTDIR")"
# Assert the refusal positively before asserting the success marker is absent:
# absence alone would also hold if the interpreter never started, which is how
# a lost {{DEVDIR}} grant could report a passing test that never bound at all.
expect_marker "an AF_UNIX bind under a readonly grant is refused" "UNIX_BIND_REFUSED"
expect_absent "an AF_UNIX socket cannot bind under a readonly grant" "UNIX_BIND_SUCCEEDED"
[ ! -S "$TESTDIR/ro/s.sock" ] || fail "a socket was created in a readonly grant"
pass "the refused bind left no socket behind"

# A denied subtree inside a broader readwrite grant, under a network posture
# that emits an unfiltered `(allow network-outbound)`. Both allows cover the
# socket, so only the deniedPaths rule stands between the sandbox and whatever
# listens there -- a Docker, ssh-agent, or gpg-agent socket is a control plane,
# so reaching one would be an escape.
#
# The listeners run on the host because the sandbox is the client here: a bind
# from inside would test the wrong half.
LISTENER_SRC="$SEATBELT_TMP/listener.py"
cat >"$LISTENER_SRC" <<'PY'
import socket, sys, time
# Hold every socket: a dropped reference is closed at once, and because close()
# leaves the bound path in place the readiness check below would still pass.
listeners = []
for path in sys.argv[1:]:
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    s.listen(8)
    listeners.append(s)
time.sleep(600)
PY
/usr/bin/python3 "$LISTENER_SRC" "$TESTDIR/rw/open/agent.sock" "$TESTDIR/rw/nested/agent.sock" &
LISTENER_PID=$!
trap 'kill "$LISTENER_PID" 2>/dev/null; rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

for _ in $(seq 1 50); do
    [ -S "$TESTDIR/rw/open/agent.sock" ] && [ -S "$TESTDIR/rw/nested/agent.sock" ] && break
    sleep 0.1
done
[ -S "$TESTDIR/rw/open/agent.sock" ] && [ -S "$TESTDIR/rw/nested/agent.sock" ] ||
    fail "the host listeners never came up, so a refused connect would prove nothing"

run_config "$(render seatbelt_fs_denied_unix_socket.json TESTDIR "$TESTDIR")"
expect_marker "the denied-socket probe ran" "UNIX_PROBE_DONE"
# The control: the same run reaches an identical socket that is only covered by
# the readwrite grant, so a refusal below is the deny rule and not a listener
# that was never reachable.
expect_marker "an AF_UNIX connect succeeds elsewhere in the readwrite grant" "UNIX_GRANTED_CONNECT_SUCCEEDED"
expect_marker "an AF_UNIX connect into a denied subtree is refused" "UNIX_DENIED_CONNECT_REFUSED"
expect_absent "a denied subtree's socket is unreachable" "UNIX_DENIED_CONNECT_SUCCEEDED"
expect_marker "an AF_UNIX bind into a denied subtree is refused" "UNIX_DENIED_BIND_REFUSED"
expect_absent "a denied subtree cannot host a new socket" "UNIX_DENIED_BIND_SUCCEEDED"
[ ! -S "$TESTDIR/rw/nested/new.sock" ] || fail "a socket was created in a denied subtree"
pass "the refused denied-subtree bind left no socket behind"

summary "Seatbelt UNIX sockets"
