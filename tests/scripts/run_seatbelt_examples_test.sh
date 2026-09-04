#!/bin/bash
# The shipped macOS examples in tests/examples/.
#
# These are what a user copies first, so a broken one is a bad first
# impression and, worse, a config that silently stopped meaning what its name
# says. Every example must still pass validation, and the hermetic ones are
# executed to prove they do what they claim.
#
# 27_mac_terminal_sandboxed is validated but never executed: it uses
# launchMethod "open", which is excluded from this suite pending a fix.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

EXAMPLES="$REPO_DIR/tests/examples"

# Deliberately unsupported: it exists to demonstrate a rejection.
REJECTED_BY_DESIGN="23_mac_blocked_hosts_unsupported"

for f in "$EXAMPLES"/*mac*.json; do
    name="$(basename "$f" .json)"
    out=$("$MXC_EXEC_MAC" --dry-run "$f" 2>&1) || true
    if [ "$name" = "$REJECTED_BY_DESIGN" ]; then
        grep -qF "validation failed" <<<"$out" ||
            fail "$name must fail validation (it documents an unsupported config)" "$out"
        pass "$name is rejected, as the example intends"
    else
        grep -qF "validation passed" <<<"$out" ||
            fail "$name no longer passes validation" "$out"
        pass "$name passes validation"
    fi
done

# Hermetic examples that are meant to succeed: no network, no GUI, no
# launchMethod "open".
for name in 15_mac_hello_world 17_mac_deny_filesystem 21_mac_python_info \
    34_mac_offline_build; do
    RC=0
    OUT=$("$MXC_EXEC_MAC" "$EXAMPLES/$name.json" 2>&1) || RC=$?
    [ "$RC" = 0 ] || fail "$name failed to run (exit $RC)" "$OUT"
    pass "$name runs successfully"
done

# This example exists to demonstrate a denial: it pipes through pbcopy/pbpaste
# with ui.disable=true, so the pasteboard is unreachable and the command is
# supposed to fail. Asserting success here would mean UI policy stopped being
# enforced.
RC=0
OUT=$("$MXC_EXEC_MAC" "$EXAMPLES/24_mac_ui_disabled.json" 2>&1) || RC=$?
[ "$RC" != 0 ] || fail "24_mac_ui_disabled should fail: ui.disable=true must block the pasteboard" "$OUT"
grep -qF "sandbox_clip_test" <<<"$OUT" &&
    fail "24_mac_ui_disabled read back clipboard content despite ui.disable=true" "$OUT"
pass "24_mac_ui_disabled demonstrates the pasteboard denial"

summary "Seatbelt examples"
