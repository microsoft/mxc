#!/bin/bash
# Seatbelt guiAccess.
#
# guiAccess deliberately trades precision for breadth: rather than maintain a
# fragile allowlist of the Mach services window drawing needs, it emits a
# blanket `(allow mach-lookup)` plus `mach-register`, `iokit-open`, POSIX
# shared memory, and per-user temp/cache writes. That breadth is the reason it
# needs testing in both directions -- it must widen what it claims to widen,
# and it must NOT re-open what an explicit setting (ui.clipboard, ui.injection,
# keychainAccess, nestedPty, filesystem rules) decides. The custom* blocks
# replace the blanket grants with explicit lists.
#
# The deny rules are emitted after the blanket allows and Seatbelt takes the
# last matching rule, so their survival is purely an ordering property: a
# refactor that hoisted the guiAccess block would defeat those settings
# without failing any single-config assertion.
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

# --- customMachLookups replaces the blanket lookup grant ----------------------

run_config "$(render seatbelt_gui_access_custom_lookups_allow.json)"
expect_ok "customMachLookups.allow reaches opendirectoryd by prefix" "$(id -un)"

run_config "$(render seatbelt_gui_access_custom_lookups_deny.json)"
expect_ok "the default-allow customMachLookups run started" "$(id -u)"
expect_absent "customMachLookups.deny blocks opendirectoryd" "$(id -un)"

# --- explicit settings win over guiAccess --------------------------------------

run_config "$(render seatbelt_gui_access_keychain_off.json HOME "$HOME")"
expect_ok "keychainAccess=false blocks the Keychain under guiAccess" "KEYCHAIN_BLOCKED"

require_python3_probe
run_config "$(render seatbelt_gui_access_nested_pty_off.json)"
expect_ok "nestedPty=false blocks pty allocation under guiAccess" "PTY_BLOCKED"

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-gui.XXXXXX)"
# POSIX shared memory names are limited to 31 bytes.
SHM="/mxc$$"
shm_cleanup() {
    /usr/bin/python3 -c '
import _posixshmem as s, sys
for n in sys.argv[2:]:
    try: s.shm_unlink(sys.argv[1] + n)
    except OSError: pass' "$SHM" .ro .rw .c.a .c.no .other
}
trap 'shm_cleanup; rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT
mkdir -p "$TESTDIR/ro"
echo "GUI_TMP_ORIGINAL" >"$TESTDIR/ro/file.txt"
chmod -R a+rX "$TESTDIR"
run_config "$(render seatbelt_gui_access_readonly_tmp.json TESTDIR "$TESTDIR")"
expect_ok "readonlyPaths inside /private/tmp stay readable under guiAccess" "GUI_TMP_ORIGINAL"
expect_ok "readonlyPaths inside /private/tmp stay read-only under guiAccess" "TMP_WRITE_BLOCKED"
grep -qx "GUI_TMP_ORIGINAL" "$TESTDIR/ro/file.txt" ||
    fail "the read-only file was modified" "$(cat "$TESTDIR/ro/file.txt")"
pass "the read-only file is unchanged"

# --- customPosixShm replaces the shared memory grant ---------------------------

cat >"$TESTDIR/shm_probe.py" <<'PROBE'
import _posixshmem as s, os, sys

prefix = sys.argv[1]


def probe(label, name, flags):
    try:
        os.close(s.shm_open(prefix + name, flags, 0o600))
        print(label + "_OK")
    except OSError:
        print(label + "_BLOCKED")


probe("RO_READ", ".ro", os.O_RDONLY)
probe("RO_WRITE", ".ro", os.O_RDWR)
probe("RW_WRITE", ".rw", os.O_RDWR)
probe("RW_CREAT", ".rw", os.O_RDWR | os.O_CREAT)
probe("CREATE", ".c.a", os.O_RDWR | os.O_CREAT | os.O_EXCL)
probe("DENY", ".c.no", os.O_RDWR | os.O_CREAT | os.O_EXCL)
probe("UNLISTED", ".other", os.O_RDWR | os.O_CREAT | os.O_EXCL)
try:
    s.shm_unlink(prefix + ".c.a")
    print("UNLINK_OK")
except OSError:
    print("UNLINK_BLOCKED")
PROBE
chmod a+r "$TESTDIR/shm_probe.py"
/usr/bin/python3 -c '
import _posixshmem as s, os, sys
for n in sys.argv[2:]: os.close(s.shm_open(sys.argv[1] + n, os.O_RDWR | os.O_CREAT, 0o600))' "$SHM" .ro .rw ||
    fail "could not create the host shared memory regions"
run_config "$(render seatbelt_gui_access_custom_posix_shm.json TESTDIR "$TESTDIR" SHM "$SHM")"
expect_ok "customPosixShm.read opens a region read-only" "RO_READ_OK"
expect_ok "customPosixShm.read does not grant write" "RO_WRITE_BLOCKED"
expect_ok "customPosixShm.readWrite opens a region read-write" "RW_WRITE_OK"
expect_ok "customPosixShm.readWrite does not grant create" "RW_CREAT_BLOCKED"
expect_ok "customPosixShm.own creates a region by prefix" "CREATE_OK"
expect_ok "customPosixShm.own deletes the region it names" "UNLINK_OK"
expect_ok "customPosixShm.deny wins over an own prefix" "DENY_BLOCKED"
expect_ok "customPosixShm replaces guiAccess's shared memory grant" "UNLISTED_BLOCKED"

# --- ordering: UI denies must survive the blanket allow ----------------------

run_config "$(render seatbelt_gui_access_clipboard_none.json)"
expect_ok "ui.clipboard=none still blocks the pasteboard under guiAccess" "CLIPBOARD_BLOCKED"

run_config "$(render seatbelt_gui_access_clipboard_all.json)"
expect_ok "ui.clipboard=all permits the pasteboard under guiAccess" "CLIPBOARD_OK"

run_config "$(render seatbelt_gui_access_custom_clipboard_none.json)"
expect_ok "ui.clipboard=none blocks the pasteboard over a broad customMachLookups allow" "CLIPBOARD_BLOCKED"

# --- profile: the documented rules are present and correctly ordered ---------

run_config "$(render seatbelt_gui_access_on.json)" --debug
P="$(extract "$OUT")"
for rule in "(allow mach-lookup)" "(allow mach-register)" "(allow iokit-open)"; do
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

# Each custom block replaces only its own grant; registers split by scope.
run_config "$(render seatbelt_gui_access_custom_registers.json)" --debug
P_CUSTOM="$(extract "$OUT")"
for rule in "(allow mach-lookup)" \
    '(allow iokit-open (iokit-user-client-class "AGXDeviceUserClient")' \
    '(iokit-user-client-class-regex #"^IOSurface")' \
    '(deny iokit-open' \
    '(global-name-prefix "com.example.mxc.")' \
    '(allow mach-register (local-name-prefix ""))'; do
    grep -qF "$rule" <<<"$(tr '\n' ' ' <<<"$P_CUSTOM" | sed 's/  */ /g')" ||
        fail "custom blocks emit $rule" "$P_CUSTOM"
done
for rule in "(allow iokit-open)" "(allow mach-register)" '(allow mach-register (global-name-prefix ""))'; do
    grep -qF "$rule" <<<"$P_CUSTOM" && fail "custom blocks must replace $rule" "$P_CUSTOM"
done
pass "custom blocks replace only the guiAccess grants they name"

run_config "$(render seatbelt_gui_access_custom_lookups_allow.json)" --debug
grep -qF "(allow mach-lookup)" <<<"$(extract "$OUT")" &&
    fail "customMachLookups must replace the blanket lookup grant" "$(extract "$OUT")"
pass "customMachLookups replaces the blanket lookup grant"

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
