#!/bin/bash
# Seatbelt filesystem policy: read-only, read-write, denied, and the baseline
# grants the profile always emits.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

# Under /private/tmp, not $TMPDIR: the per-user TMPDIR sits below
# /var/folders, whose ancestors are not readable under a narrow grant, so a
# fixture there fails to open for reasons unrelated to the policy under test.
TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-fs.XXXXXX)"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

mkdir -p "$TESTDIR/ro" "$TESTDIR/rw" "$TESTDIR/denied" "$TESTDIR/rw/nested"
echo "FS_SECRET_CONTENT" >"$TESTDIR/ro/secret.txt"
echo "FS_SECRET_CONTENT" >"$TESTDIR/denied/secret.txt"
echo "FS_SECRET_CONTENT" >"$TESTDIR/rw/nested/secret.txt"
chmod -R a+rX "$TESTDIR"

run_config "$(render seatbelt_fs_readonly_readable.json TESTDIR "$TESTDIR")"
expect_ok "a readonly path is readable" "FS_SECRET_CONTENT"

run_config "$(render seatbelt_fs_readonly_not_writable.json TESTDIR "$TESTDIR")"
expect_absent "a readonly path is not writable" "FS_RO_WRITE_SUCCEEDED"
[ ! -f "$TESTDIR/ro/written.txt" ] || fail "a readonly path is not writable (the file was created on the host)"
pass "a readonly write left no file behind"

run_config "$(render seatbelt_fs_readwrite_writable.json TESTDIR "$TESTDIR")"
expect_ok "a readwrite path is writable" "written"

run_config "$(render seatbelt_fs_denied_unreadable.json TESTDIR "$TESTDIR")"
expect_absent "a denied path is unreadable" "FS_DENIED_READ_SUCCEEDED"
expect_absent "a denied path leaks no content" "FS_SECRET_CONTENT"

# The documented precedence: deny wins over an enclosing readwrite grant.
run_config "$(render seatbelt_fs_denied_nested_in_readwrite.json TESTDIR "$TESTDIR")"
expect_absent "a denied path nested in a readwrite grant stays denied" "FS_NESTED_DENIED_READ_SUCCEEDED"
expect_absent "a nested denied path leaks no content" "FS_SECRET_CONTENT"

run_config "$(render seatbelt_fs_ungranted_denied.json TESTDIR "$TESTDIR")"
expect_absent "an ungranted path is denied by default" "FS_UNGRANTED_READ_SUCCEEDED"
expect_absent "an ungranted path leaks no content" "FS_SECRET_CONTENT"

# SIP is enforced by the kernel above the sandbox profile, so a grant cannot
# lift it. Documented as a Seatbelt-specific limit.
run_config "$(render seatbelt_fs_sip_beats_grant.json)"
expect_absent "a readwrite grant on a SIP-protected path does not lift SIP" "FS_SIP_WRITE_SUCCEEDED"
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
