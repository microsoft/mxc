#!/bin/bash
# Bubblewrap process environment.
#
# The sandbox is built with `--clearenv`, so whatever the child gets comes from
# MXC. Before schema 0.9 that was only `process.env` — with none supplied the
# child had no `PATH` at all and command resolution fell through to the shell's
# own fallback, which varies by distribution. 0.9 adds a default block and gives
# `process.env` a four-state contract; this asserts all four, plus that the host
# environment still never leaks in.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

PASS_COUNT=0
OUT=""
RC=0

fail() {
    echo "FAIL: $1"
    [ $# -gt 1 ] && echo "--- output ---" && echo "$2" && echo "--------------"
    exit 1
}

pass() {
    echo "PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

run_config() {
    RC=0
    OUT=$("$LXC_EXEC" --experimental "$CONFIG_DIR/$1" 2>&1) || RC=$?
}

expect_ok() {
    local label="$1" marker="$2"
    [ "$RC" = 0 ] || fail "$label (exit $RC, expected 0)" "$OUT"
    grep -qF "$marker" <<<"$OUT" || fail "$label (missing '$marker')" "$OUT"
    pass "$label"
}

expect_absent() {
    local label="$1" marker="$2"
    ! grep -qF "$marker" <<<"$OUT" || fail "$label (unexpected '$marker')" "$OUT"
    pass "$label"
}

DEFAULT_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Exported here rather than set by a config: the guarantee is unconditional, so
# it must hold for a request that never mentions it.
export MXC_LEAK_PROBE="BWRAP_HOST_ENV_LEAKED"

run_config bwrap_env_09_default_block.json
expect_ok "an omitted env gets the default PATH" "PATH=[$DEFAULT_PATH]"
expect_ok "an omitted env gets HOME" "HOME=[/tmp]"
expect_ok "an omitted env gets TERM" "TERM=[xterm-256color]"
expect_absent "a host environment variable does not leak in" "BWRAP_HOST_ENV_LEAKED"

run_config bwrap_env_09_empty.json
expect_ok "an empty env runs" "ENV_PROBE_DONE"
expect_ok "an empty env suppresses the default PATH" "PATH=[]"
expect_ok "an empty env suppresses HOME" "HOME=[]"
expect_ok "an empty env suppresses TERM" "TERM=[]"

run_config bwrap_env_09_verbatim.json
expect_ok "a supplied env is honored" "FOO=[bar]"
expect_ok "a supplied env is verbatim, with no implicit PATH" "PATH=[]"

run_config bwrap_env_09_inherit.json
expect_ok "inheritDefaultEnv keeps the default PATH" "PATH=[$DEFAULT_PATH]"
expect_ok "inheritDefaultEnv keeps the default HOME" "HOME=[/tmp]"
expect_ok "inheritDefaultEnv adds the caller's variable" "FOO=[bar]"
expect_ok "a caller entry overrides the same-named default" "TERM=[dumb]"

echo "All $PASS_COUNT Bubblewrap environment assertions passed."
