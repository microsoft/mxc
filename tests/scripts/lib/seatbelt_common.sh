#!/bin/bash
# Shared setup and assertions for the Seatbelt suites.
#
# Prerequisites are hard failures here, never skips. A Seatbelt suite only ever
# runs on a host that is supposed to be able to execute it, so an absent binary
# or wrong OS means the harness is misconfigured -- reporting that as "skipped"
# is how a gate goes green having verified nothing.

SEATBELT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR="$(dirname "$SEATBELT_LIB_DIR")"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

PASS_COUNT=0
FAIL_COUNT=0

fail() {
    echo "FAIL: $1"
    [ $# -gt 1 ] && echo "--- output ---" && echo "$2" && echo "--------------"
    exit 1
}

pass() {
    echo "PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

# A failure that does not abort, so one known-failing assertion cannot hide the
# assertions after it. Use where the expected behavior is specified but not
# implemented yet; `summary` still exits non-zero.
fail_soft() {
    echo "FAIL: $1"
    if [ $# -gt 1 ] && [ -n "$2" ]; then
        echo "      $2"
    fi
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

if [ "$(uname -s)" != "Darwin" ]; then
    fail "the Seatbelt suite requires macOS (found $(uname -s))"
fi

if [ -n "${MXC_EXEC_MAC:-}" ]; then
    [ -f "$MXC_EXEC_MAC" ] || fail "MXC_EXEC_MAC is set to '$MXC_EXEC_MAC', which does not exist"
else
    MXC_EXEC_MAC="$REPO_DIR/src/target/release/mxc-exec-mac"
    [ -f "$MXC_EXEC_MAC" ] || MXC_EXEC_MAC="$REPO_DIR/src/target/debug/mxc-exec-mac"
    [ -f "$MXC_EXEC_MAC" ] || fail "mxc-exec-mac not found. Run ./build-mac.sh first."
fi

SEATBELT_TMP="$(mktemp -d "${TMPDIR:-/tmp}/mxc-seatbelt.XXXXXX")"
trap 'rm -rf "$SEATBELT_TMP"' EXIT

# Substitute {{TESTDIR}} and friends, emitting a runnable config path.
render() {
    local config="$1"
    shift
    local src="$CONFIG_DIR/$config"
    # `render` is called inside $( ), so `fail`'s exit would only end the
    # subshell and its message would be captured as the config path. Report on
    # stderr; run_config re-checks the path in the caller's shell and aborts.
    [ -f "$src" ] || { echo "FAIL: config not found: $src" >&2; exit 1; }
    local dst="$SEATBELT_TMP/$config"
    local script=""
    while [ $# -gt 0 ]; do
        script="$script;s|{{$1}}|$2|g"
        shift 2
    done
    if [ -n "$script" ]; then
        sed "${script#;}" "$src" >"$dst"
    else
        cp "$src" "$dst"
    fi
    echo "$dst"
}

# Run a config. Sets OUT and RC; never aborts, so callers assert on both.
run_config() {
    local config_path="$1"
    shift
    # A path that is not a real file means `render` failed. Without this, an
    # unreadable config makes every expect_absent assertion pass vacuously.
    [ -f "$config_path" ] || fail "config was not rendered: $config_path"
    RC=0
    OUT=$("$MXC_EXEC_MAC" "$@" "$config_path" 2>&1) || RC=$?
}

expect_ok() {
    local label="$1" marker="$2"
    [ "$RC" = 0 ] || fail "$label (exit $RC, expected 0)" "$OUT"
    grep -qF "$marker" <<<"$OUT" || fail "$label (missing '$marker')" "$OUT"
    pass "$label"
}

# Marker-only, for assertions about runs that are expected to fail.
expect_marker() {
    local label="$1" marker="$2"
    grep -qF "$marker" <<<"$OUT" || fail "$label (missing '$marker')" "$OUT"
    pass "$label"
}

expect_absent() {
    local label="$1" marker="$2"
    ! grep -qF "$marker" <<<"$OUT" || fail "$label (unexpected '$marker')" "$OUT"
    pass "$label"
}

# Assert a config was refused for the stated reason, and that the workload
# never ran. Exit code alone would also match a sandbox that started the
# command and failed later for an unrelated reason.
expect_rejected() {
    local label="$1" config="$2" marker="$3" sentinel="$4"
    shift 4
    run_config "$(render "$config")" "$@"
    [ "$RC" != 0 ] || fail "$label (the config was accepted)" "$OUT"
    if [ -n "$sentinel" ] && grep -qF "$sentinel" <<<"$OUT"; then
        fail "$label (the workload ran before the config was refused)" "$OUT"
    fi
    grep -qF "$marker" <<<"$OUT" || fail "$label (refused, but not for '$marker')" "$OUT"
    pass "$label"
}

summary() {
    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo "$1: $PASS_COUNT assertion(s) passed, $FAIL_COUNT failed"
        exit 1
    fi
    echo "$1: $PASS_COUNT assertion(s) passed"
}
