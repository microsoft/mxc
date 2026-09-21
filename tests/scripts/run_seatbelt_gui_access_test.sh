#!/bin/bash
# Seatbelt guiAccess.
#
# guiAccess deliberately trades precision for breadth: rather than maintain a
# fragile allowlist of the Mach services window drawing needs, it emits a
# blanket `(allow mach-lookup)` plus `mach-register`, `iokit-open`,
# `pseudo-tty` and POSIX shared memory. That breadth is the reason it needs
# testing in both directions -- it must widen what it claims to widen, and it
# must NOT silently re-open the things UI policy separately denies.
#
# The deny rules are emitted after the blanket allows and Seatbelt takes the
# last matching rule, so their survival is purely an ordering property: a
# refactor that hoisted the guiAccess block would defeat ui.clipboard and
# ui.injection without failing any single-config assertion.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

BEGIN="Seatbelt: --- begin generated profile ---"
END="Seatbelt: --- end generated profile ---"
extract() { sed -n "/^${BEGIN}\$/,/^${END}\$/p" <<<"$1" | sed '1d;$d'; }

# --- behavioral: guiAccess widens Mach lookup -------------------------------

# opendirectoryd is not in the baseline, so `id -un` degrades to the raw uid
# unless something grants the lookup. Here that something is guiAccess alone,
# with no extraMachLookups entry.
run_config "$(render seatbelt_gui_access_off.json)"
expect_ok "without guiAccess the user name cannot be resolved" "$(id -u)"
expect_absent "without guiAccess opendirectoryd is unreachable" "$(id -un)"

run_config "$(render seatbelt_gui_access_on.json)"
expect_ok "guiAccess grants blanket Mach lookup" "$(id -un)"

# --- ordering: UI denies must survive the blanket allow ----------------------

run_config "$(render seatbelt_gui_access_clipboard_none.json)"
expect_ok "ui.clipboard=none still blocks the pasteboard under guiAccess" "CLIPBOARD_BLOCKED"

run_config "$(render seatbelt_gui_access_clipboard_all.json)"
expect_ok "ui.clipboard=all permits the pasteboard under guiAccess" "CLIPBOARD_OK"

# --- profile: the documented rules are present and correctly ordered ---------

run_config "$(render seatbelt_gui_access_on.json)" --debug
P="$(extract "$OUT")"
for rule in "(allow mach-lookup)" "(allow mach-register)" "(allow iokit-open)" "(allow pseudo-tty)"; do
    grep -qF "$rule" <<<"$P" || fail "guiAccess emits $rule" "$P"
    pass "guiAccess emits $rule"
done
grep -qF '(subpath "/private/var/folders")' <<<"$P" ||
    fail "guiAccess grants the per-user temp/cache subpath" "$P"
pass "guiAccess grants the per-user temp/cache subpath"

run_config "$(render seatbelt_gui_access_off.json)" --debug
P_OFF="$(extract "$OUT")"
for rule in "(allow mach-lookup)" "(allow mach-register)" "(allow iokit-open)"; do
    grep -qF "$rule" <<<"$P_OFF" && fail "guiAccess=false must not emit $rule" "$P_OFF"
done
pass "the blanket GUI allows are absent without guiAccess"

# The ordering property itself: the pasteboard deny must come after the blanket
# mach-lookup allow, or the deny is dead text.
run_config "$(render seatbelt_gui_access_clipboard_none.json)" --debug
P_CLIP="$(extract "$OUT")"
ALLOW_AT=$(grep -nF "(allow mach-lookup)" <<<"$P_CLIP" | head -1 | cut -d: -f1)
DENY_AT=$(grep -n 'deny mach-lookup.*pasteboard' <<<"$P_CLIP" | head -1 | cut -d: -f1)
[ -n "$ALLOW_AT" ] && [ -n "$DENY_AT" ] ||
    fail "expected both a blanket mach-lookup allow and a pasteboard deny" "$P_CLIP"
[ "$DENY_AT" -gt "$ALLOW_AT" ] ||
    fail "the pasteboard deny must follow the blanket allow (last match wins)" "$P_CLIP"
pass "the pasteboard deny is emitted after the blanket Mach allow"

# Same ordering property for HID injection.
run_config "$(render seatbelt_gui_access_injection_off.json)" --debug
P_INJ="$(extract "$OUT")"
IALLOW=$(grep -nF "(allow iokit-open)" <<<"$P_INJ" | head -1 | cut -d: -f1)
IDENY=$(grep -n 'deny iokit-open.*IOHIDLibUserClient' <<<"$P_INJ" | head -1 | cut -d: -f1)
[ -n "$IALLOW" ] && [ -n "$IDENY" ] ||
    fail "expected both a blanket iokit-open allow and an IOHIDLibUserClient deny" "$P_INJ"
[ "$IDENY" -gt "$IALLOW" ] ||
    fail "the HID deny must follow the blanket iokit-open allow" "$P_INJ"
pass "the HID injection deny is emitted after the blanket IOKit allow"

summary "Seatbelt guiAccess"
