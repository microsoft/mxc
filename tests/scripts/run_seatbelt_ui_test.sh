#!/bin/bash
# Seatbelt UI policy.
#
# WindowServer reachability is probed through CGMainDisplayID(), which returns
# a real display id when the sandbox can reach WindowServer and 0 when it
# cannot. Chosen deliberately: `osascript` and `launchctl` both exit 0 either
# way, so a suite built on them passes against a completely unenforced policy.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

require_python3_probe

run_config "$(render seatbelt_ui_disabled.json)"
expect_ok "ui.disable=true blocks WindowServer" "DISPLAY_ID=0"

run_config "$(render seatbelt_ui_enabled.json)"
expect_marker "ui.disable=false reaches WindowServer" "DISPLAY_ID="
grep -qF "DISPLAY_ID=0" <<<"$OUT" && fail "ui.disable=false should reach WindowServer" "$OUT"
pass "ui.disable=false returns a real display id"

run_config "$(render seatbelt_ui_clipboard_none.json)"
expect_ok "ui.clipboard=none blocks the pasteboard" "CLIPBOARD_BLOCKED"

run_config "$(render seatbelt_ui_clipboard_all.json)"
expect_ok "ui.clipboard=all permits the pasteboard" "CLIPBOARD_OK"

summary "Seatbelt UI"
