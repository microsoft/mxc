#!/bin/bash
# Seatbelt legacy 0.7 network fields (`defaultPolicy` / `allowLocalNetwork`).
#
# Separate from run_seatbelt_network_test.sh because these fill different
# policy fields and the profile builder only falls back to them when the
# directional section is absent. A regression in the fallback is invisible to
# the 0.8 suite, and vice versa.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

require_python3_probe

ALLOW_ANCHOR="1.1.1.1"

if ! /usr/bin/python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(5)
sys.exit(0 if s.connect_ex(('$ALLOW_ANCHOR',443))==0 else 1)" 2>/dev/null; then
    fail "external anchor $ALLOW_ANCHOR:443 is unreachable from the host; the allow assertions cannot be verified"
fi

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

run_net seatbelt_net_legacy_block.json
expect_marker "legacy defaultPolicy=block blocks outbound" "EXTERNAL_BLOCKED"
expect_marker "legacy defaultPolicy=block blocks host loopback" "LOOPBACK_BLOCKED"

# 0.7 has no hostLoopback concept, so it emits no host-loopback rule at all
# and defaultPolicy=allow leaves loopback OPEN. This is the documented
# migration hazard, and it is the opposite of the 0.8 default -- see the
# cross-shape assertion below.
run_net seatbelt_net_legacy_allow.json
expect_marker "legacy defaultPolicy=allow reaches the internet" "EXTERNAL_OK"
expect_marker "legacy defaultPolicy=allow leaves host loopback open" "LOOPBACK_OK"
# allowLocalNetwork maps to ingress.default, which is what permits listen().
expect_marker "legacy defaultPolicy=allow alone does not permit listen()" "LISTEN_BLOCKED"

run_net seatbelt_net_legacy_localnet.json
expect_marker "legacy allowLocalNetwork=true reaches the internet" "EXTERNAL_OK"
expect_marker "legacy allowLocalNetwork=true reaches host loopback" "LOOPBACK_OK"
expect_marker "legacy allowLocalNetwork=true permits listen()" "LISTEN_OK"

# The migration hazard, asserted as a difference rather than trusted to two
# suites that could drift apart: the same intent expressed in each shape must
# produce loopback open on 0.7 and closed on 0.8. If a future change unified
# them, one of these two markers flips and this fails.
run_net seatbelt_net_legacy_allow.json
LEGACY_LOOPBACK="$(grep -o 'LOOPBACK_[A-Z]*' <<<"$OUT" | head -1)"
run_net seatbelt_net_egress_allow_trap.json
MODERN_LOOPBACK="$(grep -o 'LOOPBACK_[A-Z]*' <<<"$OUT" | head -1)"
[ "$LEGACY_LOOPBACK" = "LOOPBACK_OK" ] && [ "$MODERN_LOOPBACK" = "LOOPBACK_BLOCKED" ] ||
    fail "the documented 0.7->0.8 loopback hazard (legacy open, directional closed) no longer holds: legacy=$LEGACY_LOOPBACK directional=$MODERN_LOOPBACK"
pass "translating defaultPolicy=allow to egress.default=allow closes loopback"

# Mixing the two shapes in one config is rejected.
expect_rejected "mixing legacy and directional network fields is refused" \
    "seatbelt_net_mixed_shapes_rejected.json" \
    "cannot mix" \
    "NET_MIXED_SHOULD_NOT_RUN"

summary "Seatbelt legacy network"
