#!/bin/bash
# The shipped macOS examples in tests/examples/.
#
# These are what a user copies first, so a broken one is a bad first
# impression and, worse, a config that silently stopped meaning what its name
# says. Every example must still pass validation, and the hermetic ones are
# executed to prove they do what they claim.
#
# 27_mac_terminal_sandboxed is validated but never executed: it uses
# launchMethod "open", which this suite does not run.
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

# Hermetic examples that are meant to succeed, each with the marker that proves
# it did what its name claims. Exit status alone does not: several print their
# verdict and exit 0 whichever way it went.
run_example() {
    local name="$1" marker="$2"
    RC=0
    OUT=$("$MXC_EXEC_MAC" "$EXAMPLES/$name.json" 2>&1) || RC=$?
    [ "$RC" = 0 ] || fail "$name failed to run (exit $RC)" "$OUT"
    expect_marker "$name prints '$marker'" "$marker"
}

run_example 15_mac_hello_world "hi from seatbelt"

run_example 17_mac_deny_filesystem "FS_BLOCKED"
expect_absent "17_mac_deny_filesystem cannot read the denied /Users" "FS_ALLOWED"

run_example 21_mac_python_info "Python Version:"

run_example 34_mac_offline_build "Offline build test complete!"
expect_absent "34_mac_offline_build reports no failed check" "ERROR"

# The clipboard pair: same command, opposite ui policy. 25 is the positive
# control that keeps 24 meaningful -- a pbcopy failing for any other reason
# would otherwise read as enforcement.
run_example 25_mac_ui_clipboard_enabled "PBCOPY_OK"
expect_marker "25_mac_ui_clipboard_enabled reads the value back" "sandbox_clip_test"

run_example 24_mac_ui_disabled "PBCOPY_DENIED"
expect_marker "24_mac_ui_disabled cannot read the pasteboard" "PBPASTE_DENIED"
expect_absent "24_mac_ui_disabled gets nothing back from pbpaste" "sandbox_clip_test"

summary "Seatbelt examples"
