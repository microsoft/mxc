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

# Nonzero exit, the reason named, and no workload output.
expect_rejected() {
    local label="$1" reason="$2" sentinel="$3"
    [ "$RC" != 0 ] || fail "$label (exit 0, expected nonzero)" "$OUT"
    grep -qF "$reason" <<<"$OUT" || fail "$label (missing '$reason')" "$OUT"
    ! grep -qF "$sentinel" <<<"$OUT" || fail "$label (workload ran)" "$OUT"
    pass "$label"
}

DEFAULT_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Exported here rather than set by a config: the guarantee is unconditional, so
# it must hold for a request that never mentions it.
export MXC_LEAK_PROBE="BWRAP_HOST_ENV_LEAKED"

# The cases below that supply no PATH assert HOME rather than PATH or TERM.
# Bubblewrap runs the workload under the *host's* `/bin/sh`, which differs by
# distro, and a shell started without these assigns its own: dash (Debian,
# Ubuntu) fabricates a PATH that is byte-for-byte DEFAULT_PATH, while bash
# (RHEL) fabricates both a shorter PATH -- `/usr/local/bin:/usr/bin`, the very
# gap issue #1153 is about -- and `TERM=dumb`. So neither reports what MXC
# passed, and neither their presence nor their absence proves anything. HOME is
# not fabricated by either, so it is what witnesses the default block. Where a
# case must still show the default block was not added, it asserts the block's
# own TERM value is absent, which no shell fabricates. That `resolved_env` is
# exactly empty is asserted directly by `an_explicitly_empty_env_stays_empty` /
# `a_supplied_env_is_used_verbatim` in `bwrap_command.rs`, which reads the env
# MXC builds instead of the child's.

run_config bwrap_env_09_default_block.json
expect_ok "an omitted env gets the default PATH" "PATH=[$DEFAULT_PATH]"
expect_ok "an omitted env gets HOME" "HOME=[/tmp]"
expect_ok "an omitted env gets TERM" "TERM=[xterm-256color]"
expect_ok "a host environment variable does not leak in" "LEAK=[]"
expect_absent "the host value itself does not appear" "BWRAP_HOST_ENV_LEAKED"

# No `process.cwd` resolves no directory, so no HOME -- policy mounts land
# after `--tmpfs /tmp`, so /tmp is not guaranteed private.
run_config bwrap_env_09_no_cwd.json
expect_ok "an unresolved working directory leaves HOME unset" "HOME=[]"
expect_ok "the rest of the default block still applies" "PATH=[$DEFAULT_PATH]"
expect_ok "an unset HOME is not the host's" "LEAK=[]"

run_config bwrap_env_09_empty.json
expect_ok "an empty env runs" "ENV_PROBE_DONE"
expect_ok "an empty env suppresses HOME" "HOME=[]"
expect_absent "an empty env adds no default TERM" "TERM=[xterm-256color]"
expect_ok "an empty env inherits nothing from the host" "LEAK=[]"

run_config bwrap_env_09_verbatim.json
expect_ok "a supplied env is honored" "FOO=[bar]"
expect_ok "a supplied env adds no default HOME" "HOME=[]"
expect_absent "a supplied env adds no default TERM" "TERM=[xterm-256color]"
# A supplied PATH is the one case no shell can fabricate over: the variable is
# set, so the child reports exactly what MXC passed and no fragment of the
# default block's PATH survives.
expect_ok "a supplied PATH is used verbatim" "PATH=[/mxc-probe/bin:/usr/bin:/bin]"
expect_absent "a supplied PATH is not merged with the default" "PATH=[$DEFAULT_PATH"

run_config bwrap_env_09_inherit.json
expect_ok "inheritDefaultEnv keeps the default PATH" "PATH=[$DEFAULT_PATH]"
expect_ok "inheritDefaultEnv keeps the default HOME" "HOME=[/tmp]"
expect_ok "inheritDefaultEnv adds the caller's variable" "FOO=[bar]"
expect_ok "a caller entry overrides the same-named default" "TERM=[vt100]"

# inheritDefaultEnv is a 0.9 field, so the 0.8 contract rejects the document.
run_config bwrap_env_08_inherit_rejected.json
expect_rejected "sub-0.9 inheritDefaultEnv is rejected" \
    "unknown field \`inheritDefaultEnv\`" "INHERIT_08_SHOULD_NOT_RUN"

echo "All $PASS_COUNT Bubblewrap environment assertions passed."
