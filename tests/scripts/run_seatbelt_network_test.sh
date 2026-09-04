#!/bin/bash
# Seatbelt directional network policy (schema 0.8 `egress` / `ingress`).
#
# The headline case is the documented `hostLoopback` trap: `egress.default:
# "allow"` with no `ingress` section reaches the whole internet but *not* the
# host's own loopback, because `hostLoopback` independently defaults to "deny".
# That combination passes validation silently, so only a live run catches a
# regression in either direction -- and both directions are wrong in a way a
# user would notice: an unreachable local dev server, or a loopback hole.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

[ -x /usr/bin/python3 ] || fail "/usr/bin/python3 is required by this suite"

ALLOW_ANCHOR="1.1.1.1"

# A host that cannot reach the anchor would read every egress-allow assertion
# as "blocked" and report a green suite having proven nothing. Prerequisites
# fail here rather than skip.
if ! /usr/bin/python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(5)
sys.exit(0 if s.connect_ex(('$ALLOW_ANCHOR',443))==0 else 1)" 2>/dev/null; then
    fail "external anchor $ALLOW_ANCHOR:443 is unreachable from the host; the egress-allow assertions cannot be verified"
fi

# Host-side loopback listener: the target for the sandbox->host assertions.
/usr/bin/python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',0)); s.listen(16)
print(s.getsockname()[1],flush=True)
time.sleep(600)" >"$SEATBELT_TMP/port" &
LISTENER_PID=$!
disown $LISTENER_PID 2>/dev/null || true
trap 'kill $LISTENER_PID 2>/dev/null; rm -rf "$SEATBELT_TMP"' EXIT

for _ in $(seq 1 50); do
    PORT="$(head -1 "$SEATBELT_TMP/port" 2>/dev/null || true)"
    [ -n "${PORT:-}" ] && break
    sleep 0.1
done
[ -n "${PORT:-}" ] || fail "could not start the host loopback listener"

run_net() { run_config "$(render "$1" PORT "$PORT")"; }

run_net seatbelt_net_omitted.json
expect_marker "an omitted network section blocks outbound" "EXTERNAL_BLOCKED"
expect_marker "an omitted network section blocks host loopback" "LOOPBACK_BLOCKED"
expect_marker "an omitted network section blocks listen()" "LISTEN_BLOCKED"

run_net seatbelt_net_egress_deny.json
expect_marker "egress.default=deny blocks outbound" "EXTERNAL_BLOCKED"
expect_marker "egress.default=deny blocks host loopback" "LOOPBACK_BLOCKED"

# The trap.
run_net seatbelt_net_egress_allow_trap.json
expect_marker "egress.default=allow reaches the internet" "EXTERNAL_OK"
expect_marker "egress.default=allow alone still blocks host loopback" "LOOPBACK_BLOCKED"

run_net seatbelt_net_egress_allow_loopback_allow.json
expect_marker "an explicit hostLoopback=allow reaches the internet" "EXTERNAL_OK"
expect_marker "an explicit hostLoopback=allow reaches host loopback" "LOOPBACK_OK"
expect_marker "ingress.default=allow permits listen()" "LISTEN_OK"

# network-bind alone does not permit listen(); ingress.default is what does.
run_net seatbelt_net_ingress_deny.json
expect_marker "ingress.default=deny blocks listen() even under egress allow" "LISTEN_BLOCKED"
expect_marker "hostLoopback=deny blocks host loopback under egress allow" "LOOPBACK_BLOCKED"

# The trap's shape, not just its effect: a broad allow followed by a narrower
# localhost deny, in that order. Seatbelt takes the last matching rule, so a
# reordering silently reopens loopback while every behavioral assertion above
# still passes on a host with no listener.
run_config "$(render seatbelt_net_egress_allow_trap.json PORT "$PORT")" --debug
grep -qF "(allow network-outbound)" <<<"$OUT" || fail "egress allow emits a broad outbound rule" "$OUT"
ALLOW_LINE=$(grep -nF "(allow network-outbound)" <<<"$OUT" | head -1 | cut -d: -f1)
DENY_LINE=$(grep -n "deny network-outbound.*localhost" <<<"$OUT" | head -1 | cut -d: -f1)
[ -n "$DENY_LINE" ] || fail "the trap emits a localhost deny rule" "$OUT"
[ "$DENY_LINE" -gt "$ALLOW_LINE" ] || fail "the localhost deny must follow the broad allow (last match wins)" "$OUT"
pass "the generated profile denies localhost after the broad outbound allow"

summary "Seatbelt directional network"
