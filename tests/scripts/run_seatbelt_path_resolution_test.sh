#!/bin/bash
# Seatbelt path resolution: rejected path shapes, /tmp symlink aliasing, and
# how overlapping grants on the same directory resolve.
#
# These matter because a grant that silently resolves to a different directory
# than the caller wrote is either a hole (too broad) or a mystery denial (too
# narrow), and neither is visible from the config text alone.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-path.XXXXXX)"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT

# The same directory addressed two ways: /private/tmp/... and /tmp/...
TESTDIR_TMP="/tmp/${TESTDIR#/private/tmp/}"

mkdir -p "$TESTDIR/alias" "$TESTDIR/rw/inner"
echo "PATH_SECRET_CONTENT" >"$TESTDIR/alias/secret.txt"
echo "PATH_SECRET_CONTENT" >"$TESTDIR/rw/inner/secret.txt"
chmod -R a+rX "$TESTDIR"

# Refused rather than resolved: macOS applies '..' after following symlinks,
# so the rule the profile would carry need not name the directory the caller
# meant.
expect_rejected "a path containing '..' is refused" \
    "seatbelt_path_dotdot_rejected.json" \
    "contains a '..' segment" \
    "PATH_DOTDOT_SHOULD_NOT_RUN"

# A grant written as /tmp/x must cover the same bytes reached as /private/tmp/x.
run_config "$(render seatbelt_path_tmp_alias.json TESTDIR "$TESTDIR" TESTDIR_TMP "$TESTDIR_TMP")"
expect_ok "a /tmp grant covers the /private/tmp it resolves to" "PATH_SECRET_CONTENT"

# Both spellings name one directory, so the sandbox must settle on one posture.
# Read-only is the safe resolution and is what the backend picks.
run_config "$(render seatbelt_path_alias_conflict.json TESTDIR "$TESTDIR" TESTDIR_TMP "$TESTDIR_TMP")"
expect_marker "an aliased readonly/readwrite pair still grants read" "PATH_SECRET_CONTENT"
expect_absent "an aliased readonly/readwrite pair resolves to read-only" "PATH_ALIAS_WRITE_SUCCEEDED"

# deniedPaths is emitted after the allow rules so it outranks them regardless
# of depth, but that only holds if the alias resolution runs first: here the
# deny is written as /tmp/... while the grants name /private/tmp/... and a
# redundant spelling of it.
run_config "$(render seatbelt_path_alias_denied.json TESTDIR "$TESTDIR" TESTDIR_TMP "$TESTDIR_TMP")"
expect_marker "the aliased-denied probe ran" "PATH_PROBE_DONE"
expect_absent "an aliased deny outranks a readonly grant" "PATH_ALIAS_DENIED_READ_SUCCEEDED"
expect_absent "an aliased deny leaks no content" "PATH_SECRET_CONTENT"
expect_absent "an aliased deny outranks a readwrite grant" "PATH_ALIAS_DENIED_WRITE_SUCCEEDED"
[ ! -f "$TESTDIR/alias/d.txt" ] || fail "an aliased deny was written through on the host"
pass "an aliased deny left no file behind"

run_config "$(render seatbelt_path_readonly_nested_in_readwrite.json TESTDIR "$TESTDIR")"
expect_marker "a readonly path nested in a readwrite grant is readable" "PATH_SECRET_CONTENT"
expect_absent "a readonly path nested in a readwrite grant stays read-only" "PATH_NESTED_RO_WRITE_SUCCEEDED"

summary "Seatbelt path resolution"
