#!/bin/bash
# Seatbelt filesystem policy: read-only, read-write, denied, and the baseline
# grants the profile always emits.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

require_python3_probe

# Under /private/tmp, not $TMPDIR: the per-user TMPDIR sits below
# /var/folders, whose ancestors are not readable under a narrow grant, so a
# fixture there fails to open for reasons unrelated to the policy under test.
TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-fs.XXXXXX)"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

mkdir -p "$TESTDIR/ro" "$TESTDIR/rw" "$TESTDIR/denied" "$TESTDIR/rw/nested" "$TESTDIR/dac"
echo "FS_SECRET_CONTENT" >"$TESTDIR/ro/secret.txt"
echo "FS_SECRET_CONTENT" >"$TESTDIR/denied/secret.txt"
echo "FS_SECRET_CONTENT" >"$TESTDIR/rw/nested/secret.txt"
chmod -R a+rX "$TESTDIR"
# The SIP probe's discretionary-permission control: granted by the profile,
# refused by the mode.
chmod 555 "$TESTDIR/dac"

run_config "$(render seatbelt_fs_readonly_readable.json TESTDIR "$TESTDIR")"
expect_ok "a readonly path is readable" "FS_SECRET_CONTENT"

run_config "$(render seatbelt_fs_readonly_not_writable.json TESTDIR "$TESTDIR")"
expect_marker "the readonly-write probe ran" "FS_PROBE_DONE"
expect_absent "a readonly path is not writable" "FS_RO_WRITE_SUCCEEDED"
[ ! -f "$TESTDIR/ro/written.txt" ] || fail "a readonly path is not writable (the file was created on the host)"
pass "a readonly write left no file behind"

run_config "$(render seatbelt_fs_readwrite_writable.json TESTDIR "$TESTDIR")"
expect_ok "a readwrite path is writable" "written"

run_config "$(render seatbelt_fs_denied_unreadable.json TESTDIR "$TESTDIR")"
expect_marker "the denied-read probe ran" "FS_PROBE_DONE"
expect_absent "a denied path is unreadable" "FS_DENIED_READ_SUCCEEDED"
expect_absent "a denied path leaks no content" "FS_SECRET_CONTENT"

# The documented precedence: deny wins over an enclosing readwrite grant.
run_config "$(render seatbelt_fs_denied_nested_in_readwrite.json TESTDIR "$TESTDIR")"
expect_marker "the nested-denied probe ran" "FS_PROBE_DONE"
expect_absent "a denied path nested in a readwrite grant stays denied" "FS_NESTED_DENIED_READ_SUCCEEDED"
expect_absent "a nested denied path leaks no content" "FS_SECRET_CONTENT"

run_config "$(render seatbelt_fs_ungranted_denied.json TESTDIR "$TESTDIR")"
expect_marker "the ungranted-read probe ran" "FS_PROBE_DONE"
expect_absent "an ungranted path is denied by default" "FS_UNGRANTED_READ_SUCCEEDED"
expect_absent "an ungranted path leaks no content" "FS_SECRET_CONTENT"

# SIP.
#
# That the write fails proves nothing on its own: /usr is root-owned and this
# suite runs unprivileged, so ordinary permissions would refuse it even if the
# profile granted the write. The probe reports errno instead, which separates
# the two -- non-discretionary protection answers EPERM or EROFS, discretionary
# permissions answer EACCES -- and carries both controls in the same run: a
# granted non-SIP path that must be CREATED, and a mode-555 directory that must
# be EACCES.
#
# Which non-discretionary errno to expect is a property of the host, so it is
# read from csrutil rather than guessed or skipped: rootless answers EPERM,
# while on a host with SIP off the sealed read-only system volume still refuses
# the write and answers EROFS. The grant must not lift either one.
#
# The sandbox also denies with EPERM, so the profile is checked separately to
# confirm the write really was granted.
SIP_STATUS="$(csrutil status 2>/dev/null)"
case "$SIP_STATUS" in
    *enabled*)
        SIP_EXPECT=("FS_SIP_EPERM")
        SIP_REFUSER="rootless" ;;
    *disabled*)
        # EPERM stays acceptable: SIP is not the only source of it.
        SIP_EXPECT=("FS_SIP_EROFS" "FS_SIP_EPERM")
        SIP_REFUSER="the sealed read-only system volume (SIP is off)" ;;
    *)
        SIP_EXPECT=("FS_SIP_EROFS" "FS_SIP_EPERM")
        SIP_REFUSER="the system volume (SIP state unreadable)" ;;
esac
echo "Host SIP: ${SIP_STATUS:-<csrutil unavailable>}"

SIP_CFG="$(render seatbelt_fs_sip_beats_grant.json TESTDIR "$TESTDIR")"

run_config "$SIP_CFG" --debug
grep -F -B1 '(subpath "/usr")' <<<"$OUT" | grep -qF "file-write*" ||
    fail "the profile grants write to /usr, so a denial is not the sandbox's" "$OUT"
pass "the generated profile grants write to the SIP-protected path"

run_config "$SIP_CFG"
expect_marker "the SIP probe ran" "FS_PROBE_DONE"
expect_marker "the same identity writes a granted non-SIP path" "FS_GRANT_WRITE_CREATED"
expect_marker "a discretionary denial is distinguishable" "FS_DAC_EACCES"
expect_marker_any "the SIP-protected write is refused by $SIP_REFUSER, not by mode" \
    "${SIP_EXPECT[@]}"
expect_absent "a readwrite grant does not lift SIP" "FS_SIP_CREATED"
[ ! -f /usr/mxc-sip-probe ] || fail "SIP probe wrote to /usr, which must be impossible"
pass "the SIP probe left nothing behind"

run_config "$(render seatbelt_fs_baseline_reads.json)"
expect_ok "the baseline profile allows reading system binaries" "FS_BASELINE_BIN_OK"
expect_ok "the baseline profile allows writing /dev/null" "FS_DEVNULL_OK"

# The baseline exists "so the dynamic linker, shells, and standard tools work".
# /usr/bin/python3 is an xcrun shim that dlopens libxcrun.dylib from the active
# developer directory; the baseline grants /Library (covering
# CommandLineTools) but not /Applications, so on an Xcode-selected host a
# standard tool cannot start. Host-dependent by nature -- that is the point.
run_config "$(render seatbelt_fs_baseline_standard_tool.json)"
if grep -qF "FS_BASELINE_TOOL_OK" <<<"$OUT"; then
    pass "the baseline profile runs a standard system tool (/usr/bin/python3)"
else
    fail_soft "the baseline profile runs a standard system tool (/usr/bin/python3)" \
        "active developer dir $(xcode-select -p 2>/dev/null) is not in the baseline grants"
fi

summary "Seatbelt filesystem"
