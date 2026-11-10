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

# An exact deny wins over an allow prefix in the same block.
CFG="$(render seatbelt_gui_access_custom_lookups_allow.json)"
edit_config "$CFG" 'config["seatbelt"]["customMachLookups"]["deny"] = ["com.apple.system.opendirectoryd.libinfo"]'
run_config "$CFG"
expect_ok "an exact customMachLookups.deny run started" "$(id -u)"
expect_absent "an exact customMachLookups.deny wins over an allow prefix" "$(id -un)"

# Custom lists grant on their own, without guiAccess or UI.
CFG="$(render seatbelt_gui_access_custom_lookups_allow.json)"
edit_config "$CFG" 'config["seatbelt"]["guiAccess"] = False; config["ui"]["disable"] = True'
run_config "$CFG"
expect_ok "customMachLookups.allow works without guiAccess" "$(id -un)"

# captureDenials "allow" mode still applies deny entries.
CFG="$(render seatbelt_gui_access_custom_lookups_deny.json)"
edit_config "$CFG" 'config["seatbelt"]["captureDenials"] = {"mode": "allow", "outputPath": "'"$SEATBELT_TMP"'/lookups_deny.json"}'
run_config "$CFG"
expect_ok "the allow-mode customMachLookups.deny run started" "$(id -u)"
expect_absent "customMachLookups.deny still blocks in captureDenials allow mode" "$(id -un)"

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
    except OSError: pass' "$SHM" .ro .rw .c.a .c.no .other \
        .r1 .r2 .w1 .wp.a .wp.no .o1 .op.a .op.no
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
# Start each run with only the host's .ro and .rw regions.
shm_setup() {
    shm_cleanup
    /usr/bin/python3 -c '
import _posixshmem as s, os, sys
for n in sys.argv[2:]: os.close(s.shm_open(sys.argv[1] + n, os.O_RDWR | os.O_CREAT, 0o600))' "$SHM" .ro .rw ||
        fail "could not create the host shared memory regions"
}
shm_config() {
    local cfg
    cfg="$(render seatbelt_gui_access_custom_posix_shm.json TESTDIR "$TESTDIR" SHM "$SHM")"
    [ $# -eq 0 ] || edit_config "$cfg" "$1"
    echo "$cfg"
}
shm_setup
run_config "$(shm_config)"
expect_ok "customPosixShm.read opens a region read-only" "RO_READ_OK"
expect_ok "customPosixShm.read does not grant write" "RO_WRITE_BLOCKED"
expect_ok "customPosixShm.readWrite opens a region read-write" "RW_WRITE_OK"
expect_ok "customPosixShm.readWrite does not grant create" "RW_CREAT_BLOCKED"
expect_ok "customPosixShm.own creates a region by prefix" "CREATE_OK"
expect_ok "customPosixShm.own deletes the region it names" "UNLINK_OK"
expect_ok "customPosixShm.deny wins over an own prefix" "DENY_BLOCKED"
expect_ok "customPosixShm replaces guiAccess's shared memory grant" "UNLISTED_BLOCKED"

shm_setup
run_config "$(shm_config 'config["seatbelt"]["guiAccess"] = False; config["ui"]["disable"] = True')"
expect_ok "customPosixShm.read works without guiAccess" "RO_READ_OK"
expect_ok "customPosixShm.readWrite works without guiAccess" "RW_WRITE_OK"
expect_ok "customPosixShm.own works without guiAccess" "UNLINK_OK"
expect_ok "customPosixShm.deny applies without guiAccess" "DENY_BLOCKED"

# default "allow" grants read, write, and create for every name, but not delete.
shm_setup
run_config "$(shm_config 'config["seatbelt"]["customPosixShm"] = {"default": "allow", "deny": ["'"$SHM"'.c.no"]}')"
expect_ok "customPosixShm default allow grants write" "RO_WRITE_OK"
expect_ok "customPosixShm default allow grants create" "UNLISTED_OK"
expect_ok "customPosixShm default allow does not grant delete" "UNLINK_BLOCKED"
expect_ok "customPosixShm.deny wins over default allow" "DENY_BLOCKED"

# In captureDenials "allow" mode unlisted names are allowed; deny still applies.
shm_setup
run_config "$(shm_config 'config["seatbelt"]["captureDenials"] = {"mode": "allow", "outputPath": "'"$SEATBELT_TMP"'/shm.json"}')"
expect_ok "captureDenials allow mode lets unlisted shared memory through" "UNLISTED_OK"
expect_ok "customPosixShm.deny still blocks in captureDenials allow mode" "DENY_BLOCKED"

# --- all four custom blocks together, several entries per list ---------------

# Mach lookups and registers use made-up names: bootstrap_look_up returns 1102
# for an unknown service the sandbox allows and 1100 for one it blocks, and
# sandbox_check reports registers without registering anything.
cat >"$TESTDIR/all_probe.py" <<'PROBE'
import _posixshmem as s, ctypes, os, sys

prefix, unlisted_iokit = sys.argv[1:]
libc = ctypes.CDLL(None)


def mark(label, ok):
    print(label + ("_OK" if ok else "_BLOCKED"))


bootstrap_port = ctypes.c_uint.in_dll(libc, "bootstrap_port").value
look_up = libc.bootstrap_look_up
look_up.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
for label, name in [
    ("LOOKUP_ONE", "one"), ("LOOKUP_TWO", "two"), ("LOOKUP_PREFIX", "app.yes"),
    ("LOOKUP_DENY", "app.no"), ("LOOKUP_DENY_PREFIX", "app.secret.x"),
    ("LOOKUP_UNLISTED", "other"),
]:
    port = ctypes.c_uint()
    result = look_up(bootstrap_port, ("com.example.mxc.lookup." + name).encode(), ctypes.byref(port))
    if result not in (0, 1100, 1102):
        print(label + "_UNEXPECTED_" + str(result))
    mark(label, result != 1100)

# sandbox_check is variadic: the name must be passed as an extra argument.
check = libc.sandbox_check
check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
for scope, kind in [("GLOBAL", 2), ("LOCAL", 3)]:
    for label, name in [
        ("ONE", "one"), ("TWO", "two"), ("PREFIX", "app.yes"), ("DENY", "app.no"),
        ("DENY_PREFIX", "app.secret.x"), ("UNLISTED", "other"),
    ]:
        full = "com.example.mxc." + scope.lower() + "." + name
        mark("REGISTER_" + scope + "_" + label,
             check(os.getpid(), b"mach-register", kind, ctypes.c_char_p(full.encode())) == 0)

iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
iokit.IOServiceMatching.restype = ctypes.c_void_p
iokit.IOServiceMatching.argtypes = [ctypes.c_char_p]
iokit.IOServiceGetMatchingService.restype = ctypes.c_uint
iokit.IOServiceGetMatchingService.argtypes = [ctypes.c_uint, ctypes.c_void_p]
iokit.IOServiceOpen.restype = ctypes.c_int
iokit.IOServiceOpen.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
iokit.IOServiceClose.argtypes = [ctypes.c_uint]
task = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
for label, service in [
    ("IOKIT_EXACT", "IOSurfaceRoot"), ("IOKIT_PREFIX", "IOPMrootDomain"),
    ("IOKIT_DENY", "AppleAPFSContainer"), ("IOKIT_UNLISTED", unlisted_iokit),
]:
    connection = ctypes.c_uint()
    service_port = iokit.IOServiceGetMatchingService(0, iokit.IOServiceMatching(service.encode()))
    opened = service_port != 0 and iokit.IOServiceOpen(service_port, task, 0, ctypes.byref(connection)) == 0
    if opened:
        iokit.IOServiceClose(connection.value)
    mark(label, opened)


def shm(label, name, flags):
    try:
        os.close(s.shm_open(prefix + name, flags, 0o600))
        mark(label, True)
    except OSError:
        mark(label, False)


def unlink(label, name):
    try:
        s.shm_unlink(prefix + name)
        mark(label, True)
    except OSError:
        mark(label, False)


create = os.O_RDWR | os.O_CREAT | os.O_EXCL
shm("SHM_READ_ONE", ".r1", os.O_RDONLY)
shm("SHM_READ_TWO", ".r2", os.O_RDONLY)
shm("SHM_READ_WRITE", ".r2", os.O_RDWR)
shm("SHM_RW_ONE", ".w1", os.O_RDWR)
shm("SHM_RW_PREFIX", ".wp.a", os.O_RDWR)
shm("SHM_RW_DENY", ".wp.no", os.O_RDWR)
shm("SHM_OWN_ONE", ".o1", create)
shm("SHM_OWN_PREFIX", ".op.a", create)
shm("SHM_OWN_DENY", ".op.no", create)
shm("SHM_UNLISTED", ".other", create)
unlink("SHM_UNLINK_ONE", ".o1")
unlink("SHM_UNLINK_PREFIX", ".op.a")
PROBE
chmod a+r "$TESTDIR/all_probe.py"

# The unlisted IOKit check needs a service this host can open unsandboxed.
UNLISTED_IOKIT=""
for service in AppleSMC IODisplayWrangler AppleKeyStore; do
    if /usr/bin/python3 - "$service" <<'OPEN'; then
import ctypes, sys
iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
iokit.IOServiceMatching.restype = ctypes.c_void_p
iokit.IOServiceMatching.argtypes = [ctypes.c_char_p]
iokit.IOServiceGetMatchingService.restype = ctypes.c_uint
iokit.IOServiceGetMatchingService.argtypes = [ctypes.c_uint, ctypes.c_void_p]
iokit.IOServiceOpen.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
task = ctypes.c_uint.in_dll(ctypes.CDLL(None), "mach_task_self_").value
service = iokit.IOServiceGetMatchingService(0, iokit.IOServiceMatching(sys.argv[1].encode()))
connection = ctypes.c_uint()
sys.exit(0 if service and iokit.IOServiceOpen(service, task, 0, ctypes.byref(connection)) == 0 else 1)
OPEN
        UNLISTED_IOKIT="$service"
        break
    fi
done
[ -n "$UNLISTED_IOKIT" ] || fail "no unlisted IOKit service opens on this host"

shm_cleanup
/usr/bin/python3 -c '
import _posixshmem as s, os, sys
for n in sys.argv[2:]: os.close(s.shm_open(sys.argv[1] + n, os.O_RDWR | os.O_CREAT, 0o600))' \
    "$SHM" .r1 .r2 .w1 .wp.a .wp.no || fail "could not create the host shared memory regions"
run_config "$(render seatbelt_gui_access_custom_all.json TESTDIR "$TESTDIR" SHM "$SHM" UNLISTED_IOKIT "$UNLISTED_IOKIT")"
grep -q "_UNEXPECTED_" <<<"$OUT" && fail "bootstrap_look_up returned an unexpected code" "$OUT"
for marker in \
    LOOKUP_ONE_OK LOOKUP_TWO_OK LOOKUP_PREFIX_OK \
    LOOKUP_DENY_BLOCKED LOOKUP_DENY_PREFIX_BLOCKED LOOKUP_UNLISTED_BLOCKED \
    REGISTER_GLOBAL_ONE_OK REGISTER_GLOBAL_TWO_OK REGISTER_GLOBAL_PREFIX_OK \
    REGISTER_GLOBAL_DENY_BLOCKED REGISTER_GLOBAL_DENY_PREFIX_BLOCKED REGISTER_GLOBAL_UNLISTED_BLOCKED \
    REGISTER_LOCAL_ONE_OK REGISTER_LOCAL_TWO_OK REGISTER_LOCAL_PREFIX_OK \
    REGISTER_LOCAL_DENY_BLOCKED REGISTER_LOCAL_DENY_PREFIX_BLOCKED REGISTER_LOCAL_UNLISTED_BLOCKED \
    IOKIT_EXACT_OK IOKIT_PREFIX_OK IOKIT_DENY_BLOCKED IOKIT_UNLISTED_BLOCKED \
    SHM_READ_ONE_OK SHM_READ_TWO_OK SHM_READ_WRITE_BLOCKED \
    SHM_RW_ONE_OK SHM_RW_PREFIX_OK SHM_RW_DENY_BLOCKED \
    SHM_OWN_ONE_OK SHM_OWN_PREFIX_OK SHM_OWN_DENY_BLOCKED SHM_UNLISTED_BLOCKED \
    SHM_UNLINK_ONE_OK SHM_UNLINK_PREFIX_OK; do
    expect_ok "all custom blocks together: $marker" "$marker"
done

# In captureDenials "allow" mode the same lists let unlisted names through and
# record them; deny entries still block, and granted names aren't recorded.
shm_cleanup
/usr/bin/python3 -c '
import _posixshmem as s, os, sys
for n in sys.argv[2:]: os.close(s.shm_open(sys.argv[1] + n, os.O_RDWR | os.O_CREAT, 0o600))' \
    "$SHM" .r1 .r2 .w1 .wp.a .wp.no || fail "could not create the host shared memory regions"
CFG="$(render seatbelt_gui_access_custom_all.json TESTDIR "$TESTDIR" SHM "$SHM" UNLISTED_IOKIT "$UNLISTED_IOKIT")"
edit_config "$CFG" 'config["seatbelt"]["captureDenials"] = {"mode": "allow", "outputPath": "'"$TESTDIR"'/all.json"}'
run_config "$CFG"
for marker in \
    LOOKUP_ONE_OK LOOKUP_PREFIX_OK LOOKUP_DENY_BLOCKED LOOKUP_DENY_PREFIX_BLOCKED LOOKUP_UNLISTED_OK \
    REGISTER_GLOBAL_ONE_OK REGISTER_GLOBAL_DENY_BLOCKED REGISTER_GLOBAL_DENY_PREFIX_BLOCKED REGISTER_GLOBAL_UNLISTED_OK \
    REGISTER_LOCAL_ONE_OK REGISTER_LOCAL_DENY_BLOCKED REGISTER_LOCAL_DENY_PREFIX_BLOCKED REGISTER_LOCAL_UNLISTED_OK \
    IOKIT_EXACT_OK IOKIT_DENY_BLOCKED IOKIT_UNLISTED_OK \
    SHM_READ_WRITE_OK SHM_RW_DENY_BLOCKED SHM_OWN_DENY_BLOCKED SHM_UNLISTED_OK SHM_UNLINK_ONE_OK; do
    expect_ok "allow mode with all custom blocks: $marker" "$marker"
done
REPORT="$(/usr/bin/python3 -c 'import json,sys
for line in sys.stdin:
    if line.startswith("{\"type\":\"captureDenials\""): print(json.loads(line)["outputPath"]); break' <<<"$OUT")"
[ -f "$REPORT" ] || fail "the allow-mode run with all custom blocks writes a report" "$OUT"
/usr/bin/python3 - "$REPORT" "$SHM" <<'EOF' || fail "the allow-mode report lists unlisted and denied names only" "$(cat "$REPORT")"
import json, sys
path, shm = sys.argv[1:]
listed = {d["resource"] for d in json.load(open(path))["denials"]}
expected = {
    "mach-lookup:com.example.mxc.lookup.other",
    "mach-lookup:com.example.mxc.lookup.app.no",
    "mach-register:com.example.mxc.global.other",
    "mach-register:com.example.mxc.global.app.no",
    "mach-register:com.example.mxc.local.other (per-pid)",
    "mach-register:com.example.mxc.local.app.no (per-pid)",
    "iokit-open-user-client:AppleAPFSUserClient",
    "ipc-posix-shm-write-data:" + shm + ".r2",
    "ipc-posix-shm-read-data:" + shm + ".wp.no",
    "ipc-posix-shm-write-create:" + shm + ".op.no",
    "ipc-posix-shm-write-create:" + shm + ".other",
}
granted = [r for r in listed if any(n in r for n in (
    ".one", ".two", ".app.yes", "IOSurfaceRootUserClient", "RootDomain",
    shm + ".w1", shm + ".wp.a", shm + ".o1", shm + ".op.a"))]
missing = expected - listed
if missing or granted:
    sys.exit(f"missing: {sorted(missing)}; granted but listed: {granted}")
EOF
pass "the allow-mode report lists unlisted and denied names, not granted ones"

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
