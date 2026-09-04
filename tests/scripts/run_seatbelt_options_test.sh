#!/bin/bash
# Seatbelt-specific options under the top-level "seatbelt" key.
#
# Each option is asserted as a *difference* between two otherwise identical
# configs. An option that silently stopped being applied would still let a
# single-config assertion pass whenever the baseline already permitted the
# operation, which is true for most of these.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

require_python3_probe

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-opt.XXXXXX)"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT
mkdir -p "$TESTDIR/denied"
echo "OPT_SECRET_CONTENT" >"$TESTDIR/denied/secret.txt"
chmod -R a+rX "$TESTDIR"

# nestedPty: anything that spawns a shell (test runners, git, REPLs) needs it.
run_config "$(render seatbelt_opt_nested_pty_default.json)"
expect_ok "nestedPty defaults to true" "PTY_OK"

run_config "$(render seatbelt_opt_nested_pty_off.json)"
expect_ok "nestedPty=false denies pty allocation" "PTY_BLOCKED"

# extraMachLookups: without opendirectoryd the sandbox cannot resolve a uid to
# a name, so `id -un` degrades to the raw uid.
run_config "$(render seatbelt_opt_mach_lookup_absent.json)"
MACH_ABSENT="$(grep -v confstr <<<"$OUT" | head -1)"
run_config "$(render seatbelt_opt_mach_lookup_present.json)"
expect_ok "extraMachLookups reaches opendirectoryd" "$(id -un)"
[ "$MACH_ABSENT" != "$(id -un)" ] ||
    fail "the baseline already resolved the user name, so extraMachLookups proves nothing"
pass "the same config without extraMachLookups cannot resolve the user name"

# keychainAccess: HOME must be set either way, or Security.framework fails for
# an unrelated reason and both halves look identical.
run_config "$(render seatbelt_opt_keychain_off.json HOME "$HOME")"
expect_ok "keychainAccess defaults to denying the Keychain" "KEYCHAIN_BLOCKED"

run_config "$(render seatbelt_opt_keychain_on.json HOME "$HOME")"
expect_ok "keychainAccess=true reaches the Keychain" "KEYCHAIN_OK"

# profileOverride replaces generation outright, so filesystem policy in the
# same config is ignored -- including a deniedPaths entry, which is the
# dangerous direction and the reason this is documented as a last resort.
run_config "$(render seatbelt_opt_profile_override.json TESTDIR "$TESTDIR")"
expect_ok "profileOverride replaces the generated profile" "OVERRIDE_READ_OK"
expect_marker "profileOverride causes deniedPaths to be ignored" "OPT_SECRET_CONTENT"

# The permissive override above cannot distinguish "the override was applied"
# from "the override was accepted and discarded" -- (allow default) and a
# working sandbox look the same. A restrictive override that denies what the
# config granted separates the two, and covers network policy as well.
mkdir -p "$TESTDIR/allowed"
echo "OPT_ALLOWED_CONTENT" >"$TESTDIR/allowed/data.txt"
chmod -R a+rX "$TESTDIR"

run_config "$(render seatbelt_opt_profile_override_restrictive.json TESTDIR "$TESTDIR")"
expect_marker "a restrictive profileOverride outranks a readwritePaths grant" "FS_BLOCKED"
expect_marker "profileOverride causes network policy to be ignored" "EXTERNAL_BLOCKED"

# --- profile contents --------------------------------------------------------
#
# The assertions above prove each option changes behavior; these pin the rules
# it emits, so a change that keeps the observable effect but drops one of the
# documented grants is still caught.

BEGIN="Seatbelt: --- begin generated profile ---"
END="Seatbelt: --- end generated profile ---"
extract() { sed -n "/^${BEGIN}\$/,/^${END}\$/p" <<<"$1" | sed '1d;$d'; }

run_config "$(render seatbelt_opt_keychain_on.json HOME "$HOME")" --debug
KC="$(extract "$OUT")"
for svc in com.apple.SecurityServer com.apple.securityd com.apple.trustd \
    com.apple.trustd.agent com.apple.ocspd com.apple.cfprefsd.daemon \
    com.apple.cfprefsd.agent com.apple.xpcd; do
    grep -qF "(global-name \"$svc\")" <<<"$KC" ||
        fail "keychainAccess grants a Mach lookup for $svc" "$KC"
done
pass "keychainAccess grants the documented Keychain Mach services"

# lsd.modifydb / lsd.mapdb / lsd.openurl are a family, and Seatbelt has no
# glob in (global-name), so this must stay a regex anchored at com.apple.lsd.
grep -qF 'global-name-regex #"^com\.apple\.lsd\.' <<<"$KC" ||
    fail "keychainAccess matches the com.apple.lsd.* family by anchored regex" "$KC"
pass "keychainAccess matches the com.apple.lsd.* family by anchored regex"

for sp in /private/var/protected/trustd /private/var/db/mds; do
    grep -qF "(subpath \"$sp\")" <<<"$KC" ||
        fail "keychainAccess grants a read of $sp" "$KC"
done
pass "keychainAccess grants the trustd store and MDS keychain metadata"

grep -qF "$HOME/Library/Keychains" <<<"$KC" ||
    fail "keychainAccess grants the user keychain directory" "$KC"
pass "keychainAccess grants the user keychain directory"

run_config "$(render seatbelt_opt_keychain_off.json HOME "$HOME")" --debug
KC_OFF="$(extract "$OUT")"
grep -qF 'com.apple.SecurityServer' <<<"$KC_OFF" &&
    fail "the Keychain services must be absent without keychainAccess" "$KC_OFF"
pass "the Keychain grants are absent without keychainAccess"

# extraMachLookups is passed through verbatim, so every listed service must
# appear and nothing else may be added alongside them.
run_config "$(render seatbelt_opt_mach_lookup_multi.json)" --debug
ML="$(extract "$OUT")"
for svc in com.apple.system.opendirectoryd.api \
    com.apple.system.opendirectoryd.libinfo \
    com.apple.system.notification_center; do
    grep -qF "(global-name \"$svc\")" <<<"$ML" ||
        fail "extraMachLookups emits $svc verbatim" "$ML"
done
pass "extraMachLookups emits every listed service verbatim"

grep -qF 'com.apple.FontServer' <<<"$ML" &&
    fail "extraMachLookups must not grant services the caller did not list" "$ML"
pass "extraMachLookups grants nothing the caller did not list"

# An override is used as-is: the generated rules must not be appended to it.
run_config "$(render seatbelt_opt_profile_override.json TESTDIR "$TESTDIR")" --debug
OV="$(extract "$OUT")"
grep -qF '(allow default)' <<<"$OV" ||
    fail "the logged profile is the caller's override" "$OV"
grep -qF 'deniedPaths' <<<"$OV" &&
    fail "generated rules must not be merged into a profileOverride" "$OV"
pass "profileOverride is logged verbatim with no generated rules merged in"

summary "Seatbelt options"
