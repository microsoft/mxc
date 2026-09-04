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

[ -x /usr/bin/python3 ] || fail "/usr/bin/python3 is required by this suite"

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-sock.XXXXXX)"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

mkdir -p "$TESTDIR/ro" "$TESTDIR/rw"
chmod -R a+rwX "$TESTDIR"

run_config "$(render seatbelt_unix_socket_readwrite.json TESTDIR "$TESTDIR")"
expect_ok "an AF_UNIX socket binds under a readwrite grant" "UNIX_BIND_OK"

run_config "$(render seatbelt_unix_socket_readonly.json TESTDIR "$TESTDIR")"
expect_absent "an AF_UNIX socket cannot bind under a readonly grant" "UNIX_BIND_SUCCEEDED"
[ ! -S "$TESTDIR/ro/s.sock" ] || fail "a socket was created in a readonly grant"
pass "the refused bind left no socket behind"

summary "Seatbelt UNIX sockets"
